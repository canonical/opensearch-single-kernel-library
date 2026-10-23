# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for peer-cluster provider and consumer events."""

import json
from unittest.mock import MagicMock, PropertyMock

import pytest
from ops import ModelError, Secret

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    KIBANA_SERVER_USER,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    CertType,
    DeploymentType,
    Scope,
    StartMode,
)
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    PeerClusterApp,
    PeerClusterConfig,
    PeerClusterOrchestrators,
    PluginConfigInfo,
)
from opensearch_single_kernel.utils.secrets import hash_key, password_key


@pytest.fixture
def peer_provider(harness, mocker):
    """Real provider relation, credential storage and publication; no running OpenSearch."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
        charm.state.application.deployment_desc = DeploymentDescription(
            app=App(name=charm.app.name, model_uuid=harness.model.uuid),
            config=PeerClusterConfig(cluster_name="cluster", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
        )
        relation_id = harness.add_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, "data")
        harness.add_relation_unit(relation_id, "data/0")
        remote = PeerClusterApp(
            app=App(name="data", model_uuid=harness.model.uuid),
            planned_units=1,
            units=["data/0"],
            roles=["data"],
        )
        harness.update_relation_data(relation_id, "data", {"app": remote.to_str()})
        charm.state.application.is_admin_user_initialized = True
        for user in (ADMIN_USER, KIBANA_SERVER_USER):
            charm.state.secrets.put(Scope.APP, password_key(user), "original-password")
            charm.state.secrets.put(Scope.APP, hash_key(user), "original-hash")
        charm.state.secrets.put_object(
            Scope.APP, CertType.APP_ADMIN.val, {"truststore-password": "existing-password"}
        )
    secrets = charm.state.secrets
    secrets.put_object(Scope.APP, "jwt", {"signing-key": "existing-signing-key"})
    charm.state.application.plugin_config_info = {
        "jwt": PluginConfigInfo(
            secret_id=secrets.get_secret_id(Scope.APP, "jwt"), relation_name="jwt-configuration"
        )
    }
    manager = charm.peer_cluster_orchestrator_manager
    mocker.patch.object(manager, "fetch_current_app_cm_nodes", return_value=[])
    mocker.patch.object(manager, "build_peer_cluster_rel_err_data", return_value=None)
    mocker.patch.object(charm.tls_manager, "is_fully_configured", return_value=False)
    assert manager.refresh_relation_data(relation_id)
    return charm, harness.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, relation_id)


@pytest.mark.parametrize(
    "handler_name",
    [
        "_on_peer_cluster_orchestrator_relation_joined",
        "_on_peer_cluster_orchestrator_relation_changed",
    ],
)
@pytest.mark.parametrize("failure", ["read", "grant", "plugin-grant"])
def test_provider_retries_credentials_without_publishing_incomplete_data(
    peer_provider, harness, mocker, handler_name, failure, caplog
):
    charm, relation = peer_provider
    secrets = charm.state.secrets
    key = password_key(ADMIN_USER)
    label = secrets.label(Scope.APP, key)
    secret_id = secrets.get_secret_id(Scope.APP, key)
    previous_data = relation.data[charm.app]["data"]
    previous_hash = relation.data[charm.app]["rel_data_hash"]
    secrets.put(Scope.APP, key, "updated-password")
    secrets.cached_secrets.delete(Scope.APP, label)
    harness.model.get_secret(id=secret_id).get_content(refresh=True)
    get_secret = harness.model.get_secret
    grant = Secret.grant
    denied_id = secrets.get_secret_id(Scope.APP, "jwt") if failure == "plugin-grant" else secret_id

    def lookup(*args, **kwargs):
        if kwargs.get("label") == label:
            raise ModelError("Juju temporarily unavailable")
        return get_secret(*args, **kwargs)

    def grant_secret(secret, target, **kwargs):
        if secret.id == denied_id:
            raise ModelError("Juju temporarily unavailable")
        return grant(secret, target, **kwargs)

    failed = (
        mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
        if failure == "read"
        else mocker.patch.object(Secret, "grant", grant_secret)
    )
    handler = getattr(charm.peer_cluster_events, handler_name)
    event = MagicMock(relation=relation, app=relation.app)
    handler(event)
    event.defer.assert_called_once()
    assert "Juju temporarily unavailable" in caplog.text
    assert relation.data[charm.app]["data"] == previous_data
    assert relation.data[charm.app]["rel_data_hash"] == previous_hash

    mocker.stop(failed)
    event.reset_mock()
    handler(event)
    event.defer.assert_not_called()
    assert relation.data[charm.app]["rel_data_hash"] != previous_hash
    assert secrets.get_secret_id(Scope.APP, key) == secret_id
    assert relation.app.name in harness.get_secret_grants(secret_id, relation.id)


def test_failover_provider_retries_tls_read_before_promotion(peer_provider, harness, mocker):
    """Failover readiness consumes credentials before normal relation publication."""
    charm, relation = peer_provider
    desc = charm.state.application.deployment_desc
    desc.typ = DeploymentType.FAILOVER_ORCHESTRATOR
    charm.state.application.deployment_desc = desc
    mocker.stop(charm.tls_manager.is_fully_configured)
    secrets = charm.state.secrets
    label = secrets.label(Scope.APP, CertType.APP_ADMIN.val)
    secrets.cached_secrets.delete(Scope.APP, label)
    promote = mocker.patch.object(charm.cluster_manager, "promote_deployment_type")
    get_secret = harness.model.get_secret

    def lookup(*args, **kwargs):
        if kwargs.get("label") == label:
            raise ModelError("Juju temporarily unavailable")
        return get_secret(*args, **kwargs)

    failed = mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
    event = MagicMock(relation=relation, app=relation.app)
    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)
    event.defer.assert_called_once()
    promote.assert_not_called()
    mocker.stop(failed)
    event.reset_mock()
    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)
    event.defer.assert_not_called()


def test_consumer_retries_unreadable_provider_credentials(harness, mocker):
    """A consumer waits for a grant instead of treating an unreadable credential as absent."""
    charm = harness.charm
    provider_app = App(name="main", model_uuid=harness.model.uuid)
    with harness.hooks_disabled():
        harness.set_leader(True)
        desc = DeploymentDescription(
            app=App(name=charm.app.name, model_uuid=harness.model.uuid),
            config=PeerClusterConfig(cluster_name="cluster", init_hold=True, roles=["data"]),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[],
            typ=DeploymentType.OTHER,
        )
        charm.state.application.deployment_desc = desc
        rel_id = harness.add_relation(PEER_CLUSTER_RELATION, "main")
        harness.add_relation_unit(rel_id, "main/0")
        secret_id = harness.add_model_secret("main", {"admin-password": "provider-password"})
        harness.grant_secret(secret_id, charm.app)
        data = {
            "cluster_name": "cluster",
            "cm_nodes": [],
            "security_index_initialised": True,
            "deployment_desc": None,
            "credentials": {
                "admin_username": "admin",
                "admin_password": secret_id.replace("secret:", "secret://"),
                "admin_password_hash": "admin-hash",
                "kibana_password": "kibana-password",
                "kibana_password_hash": "kibana-hash",
                "monitor_password": None,
                "admin_tls": {"truststore-password": "existing-password"},
                "s3": None,
                "azure": None,
                "gcs": None,
            },
        }
        harness.update_relation_data(
            rel_id,
            "main",
            {
                "data": json.dumps(data),
                "trigger": "main",
                "orchestrators": PeerClusterOrchestrators(
                    main_app=provider_app, main_rel_id=rel_id
                ).to_str(),
            },
        )
    relation = harness.model.get_relation(PEER_CLUSTER_RELATION, rel_id)
    event = MagicMock(relation=relation, app=relation.app)
    # Workload writes happen only after credentials have been resolved.
    configure = mocker.patch.object(charm.peer_cluster_events, "_set_security_conf")
    mocker.patch.object(charm.tls_manager, "peer_cluster_error_from_tls", return_value=None)
    mocker.patch.object(
        charm.peer_cluster_events, "_reconcile_deployment_desc_from_peer_cluster_data"
    )
    get_secret = harness.model.get_secret

    def lookup(*args, **kwargs):
        if kwargs.get("id") == secret_id.replace("secret:", "secret://"):
            raise ModelError("ERROR permission denied")
        return get_secret(*args, **kwargs)

    failed = mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
    charm.peer_cluster_events._on_peer_cluster_relation_changed(event)
    event.defer.assert_called_once()
    configure.assert_not_called()
    assert not charm.state.application.is_security_index_initialised

    mocker.stop(failed)
    event.reset_mock()
    charm.peer_cluster_events._on_peer_cluster_relation_changed(event)
    event.defer.assert_not_called()
    configure.assert_called_once()
    assert configure.call_args.args[0].credentials.admin_password == "provider-password"
    assert charm.state.application.is_security_index_initialised


def test_provider_waiting_for_readiness_still_processes_joining_data_node(peer_provider, mocker):
    """A readiness wait must not prevent the data-node join that can unblock the provider."""
    charm, relation = peer_provider
    mocker.patch.object(
        charm.peer_cluster_orchestrator_manager, "refresh_relation_data", return_value=False
    )
    charm.tls_manager.is_fully_configured.return_value = True
    joining = mocker.patch.object(charm.peer_cluster_events, "handle_joining_data_node")
    event = MagicMock(relation=relation, app=relation.app)

    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)

    event.defer.assert_called()
    joining.assert_called_once()
    assert charm.state.application.cluster_fleet_apps


def test_promoted_provider_does_not_try_to_grant_previous_main_plugin_secrets(
    peer_provider, harness
):
    """Both promotion paths must drop plugin IDs owned by the previous main orchestrator."""
    charm, relation = peer_provider
    desc = charm.state.application.deployment_desc
    desc.typ = DeploymentType.FAILOVER_ORCHESTRATOR
    charm.state.application.deployment_desc = desc
    charm.state.application.orchestrators = PeerClusterOrchestrators(
        failover_app=desc.app, failover_rel_id=relation.id
    )
    with harness.hooks_disabled():
        harness.update_relation_data(
            relation.id, relation.app.name, {"main_orchestrator_registered": "false"}
        )
    with harness.hooks_disabled():
        harness.add_relation(PEER_CLUSTER_RELATION, "previous-main")
    secret_id = harness.add_model_secret("previous-main", {"signing-key": "existing-key"})
    harness.grant_secret(secret_id, charm.app)
    charm.state.application.plugin_config_info = {
        "jwt": PluginConfigInfo(secret_id=secret_id, relation_name="jwt-configuration")
    }
    charm.tls_manager.is_fully_configured.return_value = True
    event = MagicMock(relation=relation, app=relation.app)

    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)

    event.defer.assert_not_called()
    assert charm.state.application.deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
    assert charm.state.application.plugin_config_info["jwt"].secret_id is None
    assert charm.state.application.missing_relations
    assert json.loads(relation.data[charm.app]["data"])["plugins"] == {}
