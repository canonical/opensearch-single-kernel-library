# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Provider readiness must converge before the cluster can finish bootstrapping."""

import json
from unittest.mock import PropertyMock

import pytest

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    KIBANA_SERVER_USER,
    OLD_CA_ALIAS,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    CertType,
    DeploymentType,
    HealthColors,
    Scope,
)
from opensearch_single_kernel.common.exceptions import OpenSearchError
from opensearch_single_kernel.core.models import App, PeerClusterOrchestrators
from opensearch_single_kernel.utils.secrets import hash_key, password_key
from tests.unit.helpers import deployment_descriptions


@pytest.fixture(autouse=True)
def juju_with_secrets(monkeypatch):
    monkeypatch.setenv("JUJU_VERSION", "3.6.0")


@pytest.fixture
def provider(harness, mocker):
    """A cluster-manager-only failover with credentials but unfinished TLS."""
    charm = harness.charm
    desc = deployment_descriptions["cm-only"].model_copy(deep=True)
    desc.typ = DeploymentType.FAILOVER_ORCHESTRATOR
    mocker.patch.object(
        type(charm.state.application),
        "deployment_desc",
        new_callable=PropertyMock,
        return_value=desc,
    )
    with harness.hooks_disabled():
        harness.set_leader(True)
        relation_id = harness.add_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, "data")
        harness.add_relation_unit(relation_id, "data/0")
    charm.state.application.orchestrators = PeerClusterOrchestrators(
        main_app=App(model_uuid="model-uuid", name="main"),
        failover_app=desc.app,
    )
    charm.state.application.is_admin_user_initialized = True
    for user in (ADMIN_USER, KIBANA_SERVER_USER):
        charm.state.secrets.put(Scope.APP, password_key(user), "password")
        charm.state.secrets.put(Scope.APP, hash_key(user), "password-hash")
    charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "cert": "admin-cert",
            "chain": "ca",
            "subject": "admin",
            "truststore-password": "truststore-password",
        },
    )
    # Keep relation publication and TLS readiness bookkeeping real; stub workload I/O.
    mocker.patch.object(charm.tls_manager, "store_new_tls_resources", return_value=True)
    mocker.patch.object(charm.tls_manager, "is_fully_configured", return_value=True)
    mocker.patch.object(charm.config_manager, "update_opensearch_config")
    mocker.patch.object(charm.peer_cluster_orchestrator_manager, "_nodes", return_value=[])
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=False
    )
    charm.peer_cluster_orchestrator_manager.refresh_relation_data()
    relation = charm.state.peer_cluster_by_relation_id(
        relation_id=relation_id, is_provider=True, remote=False
    )
    assert "TLS not fully configured" in relation.error_data.blocked_message
    return relation


@pytest.fixture
def certificate_event(harness, provider, mocker):
    """Deliver the last unit certificate through the production TLS callback."""
    charm = harness.charm
    charm.state.secrets.put_object(Scope.UNIT, CertType.UNIT_HTTP.val, {"csr": "http-csr"})
    mocker.patch.object(
        charm.tls_manager,
        "read_stored_ca",
        side_effect=lambda alias=None: None if alias == OLD_CA_ALIAS else "ca",
    )
    mocker.patch.object(charm.tls_manager, "update_request_ca_bundle", return_value=True)
    return mocker.Mock(
        certificate_signing_request="http-csr", certificate="http-cert", ca="ca", chain=["ca"]
    )


@pytest.mark.parametrize(
    "provider_type", [DeploymentType.MAIN_ORCHESTRATOR, DeploymentType.FAILOVER_ORCHESTRATOR]
)
def test_initial_tls_completion_clears_provider_error(
    harness, provider, certificate_event, provider_type
):
    """Local TLS completion releases consumers without waiting for OpenSearch to start."""
    charm = harness.charm
    desc = charm.state.application.deployment_desc
    desc.typ = provider_type
    if provider_type == DeploymentType.MAIN_ORCHESTRATOR:
        charm.state.application.orchestrators = PeerClusterOrchestrators(main_app=desc.app)
    charm.tls_events._on_certificate_available(certificate_event)

    assert charm.state.server.tls_configured
    assert not charm.state.server.started
    assert not charm.state.application.is_security_index_initialised
    assert provider.error_data is None
    credentials = json.loads(provider.relation_data["data"])["credentials"]
    assert (
        charm.model.get_secret(id=credentials["admin_tls"]).get_content()["truststore-password"]
        == "truststore-password"
    )


@pytest.mark.parametrize("health", [HealthColors.UNKNOWN, HealthColors.YELLOW_TEMP])
def test_last_peer_tls_completion_refreshes_before_health(
    harness, mocker, provider, certificate_event, health
):
    """The leader publishes fleet readiness even while cluster health requires waiting."""
    charm = harness.charm
    peer_id = charm.state.peer_relation.id
    peer_unit = f"{charm.app.name}/1"
    with harness.hooks_disabled():
        harness.add_relation_unit(peer_id, peer_unit)
    charm.tls_events._on_certificate_available(certificate_event)
    assert "TLS not fully configured" in provider.error_data.blocked_message

    with harness.hooks_disabled():
        harness.update_relation_data(peer_id, peer_unit, {"tls_configured": "True"})
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=True
    )
    mocker.patch.object(charm, "apply_health", return_value=health)
    event = mocker.Mock()
    charm.opensearch_events._on_peer_relation_changed(event)

    assert provider.error_data is None
    event.defer.assert_called_once()


def test_incomplete_local_tls_keeps_provider_error(harness, mocker, provider, certificate_event):
    """Storing admin resources alone must not advertise TLS readiness."""
    charm = harness.charm
    mocker.patch.object(charm.tls_manager, "is_fully_configured", return_value=False)
    charm.tls_events._on_certificate_available(certificate_event)

    assert not charm.state.server.tls_configured
    assert "TLS not fully configured" in provider.error_data.blocked_message


@pytest.mark.parametrize(
    "leader, deployment_type",
    [(False, DeploymentType.FAILOVER_ORCHESTRATOR), (True, DeploymentType.OTHER)],
)
def test_only_provider_leader_publishes_tls_readiness(
    harness, provider, certificate_event, leader, deployment_type
):
    """Other units publish their own TLS flag without writing provider application data."""
    charm = harness.charm
    charm.state.application.deployment_desc.typ = deployment_type
    before = dict(harness.get_relation_data(provider.relation.id, charm.app.name))
    with harness.hooks_disabled():
        harness.set_leader(leader)

    charm.tls_events._on_certificate_available(certificate_event)

    assert charm.state.server.tls_configured
    assert harness.get_relation_data(provider.relation.id, charm.app.name) == before


def test_tls_completion_preserves_security_index_gate(harness, provider, certificate_event):
    """A provider with data roles still waits for security-index initialization."""
    charm = harness.charm
    charm.state.application.deployment_desc.config.roles = ["cluster-manager", "data"]

    charm.tls_events._on_certificate_available(certificate_event)

    assert charm.state.server.tls_configured
    assert "Security index not initialized" in provider.error_data.blocked_message


@pytest.mark.parametrize("reload_fails", [False, True])
def test_certificate_renewal_publishes_readiness(
    harness, mocker, provider, certificate_event, reload_fails
):
    """Renewal publishes configured TLS even when workload reload needs a retry."""
    charm = harness.charm
    charm.state.server.started = "True"
    charm.state.secrets.put_object(
        Scope.UNIT, CertType.UNIT_HTTP.val, {"cert": "old-http-cert"}, merge=True
    )
    mocker.patch.object(
        charm.tls_manager,
        "reload_tls_certificates",
        return_value=True,
        side_effect=OpenSearchError("reload failed") if reload_fails else None,
    )

    charm.tls_events._on_certificate_available(certificate_event)

    assert charm.state.server.tls_configured
    assert provider.error_data is None
    if reload_fails:
        certificate_event.defer.assert_called_once()
    else:
        certificate_event.defer.assert_not_called()
