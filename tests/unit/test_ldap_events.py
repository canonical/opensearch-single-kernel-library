# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the LDAP events handler."""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest

from tests.unit.helpers import deployment_descriptions

LDAPS_DATA = SimpleNamespace(
    ldaps_urls=["ldaps://ldap.local:636"], bind_dn="cn=bind", bind_password="secret"
)
CERTIFICATES = {"cert-b", "cert-a"}
CERTIFICATES_HANDLERS = ["_on_ldap_certificate_available", "_on_ldap_certificate_removed"]
ALL_HANDLERS = ["_on_ldap_ready", "_on_ldap_unavailable"] + CERTIFICATES_HANDLERS


@pytest.fixture
def ldap_ready(harness, mocker, substrate):
    """Leader of a running main orchestrator with LDAPS data and certificates available."""
    with harness.hooks_disabled():
        harness.set_leader(True)

    mocker.patch.object(harness.charm, "is_unit_going_away", return_value=False)

    workload_class = "VMWorkload" if substrate == "vm" else "K8sWorkload"
    mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.is_service_started",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.admin_secrets",
        new_callable=PropertyMock,
        return_value={"chain": "admin-chain"},
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.is_main_orchestrator",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.lib.charms.glauth_k8s.v0.ldap.LdapRequirer.consume_ldap_relation_data",
        return_value=LDAPS_DATA,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.ldap_certificates",
        new_callable=PropertyMock,
        return_value=CERTIFICATES,
    )


@pytest.fixture
def reconcile_security_config(harness, mocker) -> MagicMock:
    return mocker.patch.object(harness.charm, "reconcile_security_config")


@pytest.mark.parametrize("handler_name", ALL_HANDLERS)
def test_security_config_reconciled(
    harness, mocker, ldap_ready, reconcile_security_config, handler_name
):
    # the certificates directory does not exist in the K8s test container
    mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.write_text")
    mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.unlink")

    event = MagicMock()
    getattr(harness.charm.ldap_events, handler_name)(event)

    reconcile_security_config.assert_called_once_with(event)
    event.defer.assert_not_called()


@pytest.mark.parametrize(
    "ldap_data, certificates",
    [
        (None, CERTIFICATES),
        (SimpleNamespace(ldaps_urls=[]), CERTIFICATES),
        (LDAPS_DATA, set()),
    ],
    ids=["no-provider-data", "ldaps-disabled", "no-certificates"],
)
def test_ldap_disabled_in_security_config_until_ldaps_is_usable(
    harness, mocker, ldap_ready, ldap_data, certificates
):
    mocker.patch(
        "opensearch_single_kernel.lib.charms.glauth_k8s.v0.ldap.LdapRequirer.consume_ldap_relation_data",
        return_value=ldap_data,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.ldap_relation",
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.ldap_certificates",
        new_callable=PropertyMock,
        return_value=certificates,
    )
    config_manager = harness.charm.config_manager

    assert config_manager._security_authc_ldap_config()["ldap"]["http_enabled"] is False
    assert config_manager._security_authz_ldap_config() == {}


def test_ldap_certificates_kept_when_unit_goes_away(
    harness, mocker, ldap_ready, reconcile_security_config
):
    mocker.patch.object(harness.charm, "is_unit_going_away", return_value=True)
    unlink = mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.unlink")

    event = MagicMock()
    harness.charm.ldap_events._on_ldap_certificate_removed(event)

    unlink.assert_not_called()
    reconcile_security_config.assert_not_called()
    event.defer.assert_not_called()


def test_certificates_written(harness, mocker, ldap_ready, reconcile_security_config):
    write_text = mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.write_text")

    harness.charm.ldap_events._on_ldap_certificate_available(MagicMock())

    write_text.assert_called_once_with("cert-a\ncert-b", harness.charm.workload.paths.ldap_chain)


def test_certificates_deleted(harness, mocker, ldap_ready, reconcile_security_config):
    unlink = mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.unlink")

    harness.charm.ldap_events._on_ldap_certificate_removed(MagicMock())

    unlink.assert_called_once_with(harness.charm.workload.paths.ldap_chain, missing_ok=True)


def test_withdrawn_certificates_deleted(harness, mocker, ldap_ready, reconcile_security_config):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.ldap_certificates",
        new_callable=PropertyMock,
        return_value=set(),
    )
    write_text = mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.write_text")
    unlink = mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.unlink")

    event = MagicMock()
    harness.charm.ldap_events._on_ldap_certificate_available(event)

    write_text.assert_not_called()
    unlink.assert_called_once_with(harness.charm.workload.paths.ldap_chain, missing_ok=True)
    reconcile_security_config.assert_called_once_with(event)


@pytest.mark.parametrize("handler_name", CERTIFICATES_HANDLERS)
def test_certificates_await_the_workload(
    harness, mocker, substrate, ldap_ready, reconcile_security_config, handler_name
):
    workload_class = "VMWorkload" if substrate == "vm" else "K8sWorkload"
    mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.can_connect",
        new_callable=PropertyMock,
        return_value=False,
    )

    event = MagicMock()
    getattr(harness.charm.ldap_events, handler_name)(event)

    event.defer.assert_called_once()
    reconcile_security_config.assert_not_called()


@pytest.mark.parametrize("is_bind_password", [True, False], ids=["bind-password", "other-secret"])
def test_security_config_reconciled_on_bind_password_rotation(
    harness, mocker, ldap_ready, reconcile_security_config, is_bind_password
):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.is_ldap_bind_password_secret",
        return_value=is_bind_password,
    )

    event = MagicMock()
    harness.charm.ldap_events._on_secret_changed(event)

    assert event.secret.get_content.called is is_bind_password
    assert reconcile_security_config.called is is_bind_password


@pytest.mark.parametrize(
    "databag_secret_id, event_secret_id, expected",
    [
        ("secret:abc123", "secret:abc123", True),
        ("secret://model-uuid/abc123", "secret:abc123", True),
        ("secret:abc123", "secret://model-uuid/abc123", True),
        ("secret:abc123", "secret:other", False),
        (None, "secret:abc123", False),
    ],
    ids=["same", "databag-with-model", "event-with-model", "other", "no-secret-in-databag"],
)
def test_ldap_bind_password_secret_matched_by_id(
    harness, mocker, databag_secret_id, event_secret_id, expected
):
    relation = MagicMock()
    relation.data = {
        relation.app: {"bind_password_secret": databag_secret_id} if databag_secret_id else {}
    }
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.ldap_relation",
        new_callable=PropertyMock,
        return_value=relation,
    )
    secret = MagicMock(
        unique_identifier=event_secret_id.rsplit("/", 1)[-1].removeprefix("secret:")
    )

    assert harness.charm.state.is_ldap_bind_password_secret(secret) is expected


def test_client_users_skipped_by_ldap_authorization(harness, mocker, ldap_ready):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.ldap_data",
        new_callable=PropertyMock,
        return_value=LDAPS_DATA,
    )
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.client_users_dict",
        new_callable=PropertyMock,
        return_value={"7": "opensearch-client_7"},
    )
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.client_groups_dict",
        new_callable=PropertyMock,
        return_value={"8": "devs_group"},
    )

    config = harness.charm.config_manager._security_authz_ldap_config()
    skipped_users = config["ldap_roles"]["authorization_backend"]["config"]["skip_users"]

    assert {"admin", "opensearch-client_7"} <= set(skipped_users)
    assert "devs_group" not in skipped_users
    assert skipped_users == sorted(skipped_users)
