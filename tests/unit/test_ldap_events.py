# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the LDAP events handler."""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest

from tests.unit.helpers import deployment_descriptions

LDAPS_DATA = SimpleNamespace(ldaps_urls=["ldaps://ldap.local:636"])
CERTIFICATES = {"cert-b", "cert-a"}
HANDLERS_ON_MAIN_ORCHESTRATOR_ONLY = [
    "_on_ldap_ready",
    "_on_ldap_unavailable",
    "_on_config_changed",
]
ALL_HANDLERS = HANDLERS_ON_MAIN_ORCHESTRATOR_ONLY + [
    "_on_ldap_certificate_available",
    "_on_ldap_certificate_removed",
]


@pytest.fixture
def ldap_ready(harness, mocker, substrate):
    """Leader of a running main orchestrator with LDAPS data and certificates available."""
    with harness.hooks_disabled():
        harness.set_leader(True)

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
def update_security_config(mocker) -> MagicMock:
    return mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_security_config"
    )


@pytest.fixture
def apply_security_config(mocker) -> MagicMock:
    return mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.apply_security_config",
        return_value=True,
    )


@pytest.mark.parametrize("handler_name", ALL_HANDLERS)
def test_security_config_applied(
    harness, ldap_ready, update_security_config, apply_security_config, handler_name
):
    event = MagicMock()
    getattr(harness.charm.ldap_events, handler_name)(event)

    update_security_config.assert_called_once()
    apply_security_config.assert_called_once()
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
def test_ldap_ready_ignored_until_ldaps_is_usable(
    harness, mocker, ldap_ready, update_security_config, ldap_data, certificates
):
    mocker.patch(
        "opensearch_single_kernel.lib.charms.glauth_k8s.v0.ldap.LdapRequirer.consume_ldap_relation_data",
        return_value=ldap_data,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.ldap_certificates",
        new_callable=PropertyMock,
        return_value=certificates,
    )

    harness.charm.ldap_events._on_ldap_ready(MagicMock())

    update_security_config.assert_not_called()


@pytest.mark.parametrize("handler_name", HANDLERS_ON_MAIN_ORCHESTRATOR_ONLY)
def test_ldap_ignored_outside_main_orchestrator(
    harness, mocker, ldap_ready, update_security_config, handler_name
):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.is_main_orchestrator",
        new_callable=PropertyMock,
        return_value=False,
    )

    getattr(harness.charm.ldap_events, handler_name)(MagicMock())

    update_security_config.assert_not_called()


@pytest.mark.parametrize("is_main_orchestrator", [True, False], ids=["main", "non-main"])
def test_certificates_written_on_every_orchestrator(
    harness,
    mocker,
    ldap_ready,
    update_security_config,
    apply_security_config,
    is_main_orchestrator,
):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.is_main_orchestrator",
        new_callable=PropertyMock,
        return_value=is_main_orchestrator,
    )
    write_text = mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.write_text")

    harness.charm.ldap_events._on_ldap_certificate_available(MagicMock())

    write_text.assert_called_once_with("cert-a\ncert-b", harness.charm.workload.paths.ldap_chain)
    assert apply_security_config.called is is_main_orchestrator


@pytest.mark.parametrize("is_main_orchestrator", [True, False], ids=["main", "non-main"])
def test_certificates_deleted_on_every_orchestrator(
    harness,
    mocker,
    ldap_ready,
    update_security_config,
    apply_security_config,
    is_main_orchestrator,
):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.is_main_orchestrator",
        new_callable=PropertyMock,
        return_value=is_main_orchestrator,
    )
    unlink = mocker.patch("opensearch_single_kernel.workload.base.BaseWorkload.unlink")

    harness.charm.ldap_events._on_ldap_certificate_removed(MagicMock())

    unlink.assert_called_once_with(harness.charm.workload.paths.ldap_chain, missing_ok=True)
    assert apply_security_config.called is is_main_orchestrator


def test_security_config_left_to_leader(
    harness, ldap_ready, update_security_config, apply_security_config
):
    with harness.hooks_disabled():
        harness.set_leader(False)

    event = MagicMock()
    harness.charm.ldap_events._on_ldap_ready(event)

    update_security_config.assert_not_called()
    apply_security_config.assert_not_called()
    event.defer.assert_not_called()


@pytest.mark.parametrize(
    "is_node_up, applied", [(False, True), (True, False)], ids=["node-down", "apply-failed"]
)
def test_security_config_application_retried(
    harness, mocker, ldap_ready, update_security_config, apply_security_config, is_node_up, applied
):
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
        return_value=is_node_up,
    )
    apply_security_config.return_value = applied

    event = MagicMock()
    harness.charm.ldap_events._on_ldap_ready(event)

    event.defer.assert_called_once()


@pytest.mark.parametrize("handler_name", ALL_HANDLERS)
def test_unreachable_workload_defers(
    harness, mocker, substrate, ldap_ready, update_security_config, handler_name
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
    update_security_config.assert_not_called()
