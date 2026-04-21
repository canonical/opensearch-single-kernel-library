# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit Tests for Charm related operations."""

from unittest.mock import MagicMock, PropertyMock, call, patch

import pytest
from ops import ActiveStatus, BlockedStatus

from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchInstallError,
)
from opensearch_single_kernel.events.custom_events import StartOpenSearch
from tests.unit.helpers import deployment_descriptions


def test_on_install(harness, substrate):
    """Test the install event callback on success."""
    workload_class = "VMWorkload" if substrate == "vm" else "K8sWorkload"
    with patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.install"
    ) as install:
        harness.charm.on.install.emit()
        # For K8s, install is not operational
        if substrate == "vm":
            install.assert_called_once()
        else:
            install.assert_not_called()


def test_on_install_error(harness, substrate):
    """Test the install event callback on error."""
    workload_class = "VMWorkload" if substrate == "vm" else "K8sWorkload"
    with patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.install"
    ) as install:
        install.side_effect = OpenSearchInstallError()
        # For K8s, install is not operational
        if substrate == "vm":
            with pytest.raises(OpenSearchInstallError):
                harness.charm.on.install.emit()
            assert isinstance(harness.model.unit.status, BlockedStatus)
        else:
            harness.charm.on.install.emit()
            assert not isinstance(harness.model.unit.status, BlockedStatus)


def test_k8s_pebble_plan_uses_opensearch_binary(harness, substrate, mocker):
    """K8s Pebble plan should launch the image-provided `opensearch` binary."""
    if substrate == "vm":
        pytest.skip("K8s-only workload launcher test")

    add_layer = mocker.patch.object(harness.charm.workload.container, "add_layer")

    harness.charm.workload._configure_pebble_plan()

    add_layer.assert_called_once()
    added_layer = add_layer.call_args.args[1]
    assert added_layer.to_dict()["services"]["opensearch"]["command"] == (
        "/usr/share/opensearch/bin/opensearch"
    )


def test_unit_allowed_to_start_non_leader_not_allowed_when_no_alt_hosts(
    harness, mocker, substrate
):
    """When security index is not initialised and alt_hosts is empty, only leader can start.

    A non-leader unit is not allowed to start in this case, is_cluster_healthy_to_start
    is only used when the cluster is already initialised or alt_hosts is set.
    """
    from opensearch_single_kernel.events.opensearch import OpenSearchEventsHandler

    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=False,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.base.BaseManager.alt_hosts",
        new_callable=PropertyMock,
        return_value=None,
    )
    is_cluster_healthy = mocker.patch.object(
        OpenSearchEventsHandler,
        "is_cluster_healthy_to_start",
        return_value=True,
    )

    harness.set_leader(False)
    event = StartOpenSearch(
        MagicMock(),  # handle
        is_first_data_node=False,
    )

    result = harness.charm.opensearch_events.unit_allowed_to_start(event)

    assert result is False
    is_cluster_healthy.assert_not_called()


def test_on_leader_elected(harness, mocker):
    """Test on leader elected event."""
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        return_value=deployment_descriptions["ok"],
        new_callable=PropertyMock,
    )
    purge_initial_default_users = mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    put_or_update_internal_user_leader = mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )

    harness.set_leader(True)

    # Make sure that we are removing initial users
    purge_initial_default_users.assert_called_once()

    # Make sure thate we create system users
    put_or_update_internal_user_leader.assert_has_calls(
        [
            call("admin", update=False),
            call("kibanaserver", update=False),
        ],
        any_order=True,
    )
    assert isinstance(harness.model.unit.status, ActiveStatus)

    # Reset mocks
    purge_initial_default_users.reset_mock()
    put_or_update_internal_user_leader.reset_mock()

    # Set admin user initialized
    harness.charm.state.application.is_admin_user_initialized = True
    # Make sure that admin user is updated even if it is already initialised
    harness.charm.on.leader_elected.emit()
    purge_initial_default_users.assert_called_once()
    put_or_update_internal_user_leader.assert_has_calls(
        [
            call("admin", update=False),
            call("kibanaserver", update=False),
        ],
        any_order=True,
    )


def test_on_leader_elected_index_initialised(harness, mocker):
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        return_value=deployment_descriptions["ok"],
        new_callable=PropertyMock,
    )
    purge_initial_default_users = mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    put_or_update_internal_user_leader = mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )

    # Make sure users are not initialised when security index is already initialised

    # security_index_initialised
    harness.set_leader(True)
    harness.charm.state.application.is_security_index_initialised = True

    # Reset mocks
    purge_initial_default_users.reset_mock()
    put_or_update_internal_user_leader.reset_mock()

    harness.charm.on.leader_elected.emit()
    put_or_update_internal_user_leader.assert_not_called()
    purge_initial_default_users.assert_not_called()

    # admin_user_initialized
    harness.charm.state.application.is_security_index_initialised = False
    harness.charm.state.application.is_admin_user_initialized = True
    harness.charm.on.leader_elected.emit()
    put_or_update_internal_user_leader.assert_has_calls(
        [
            call("admin", update=False),
            call("kibanaserver", update=False),
        ],
        any_order=True,
    )
    purge_initial_default_users.assert_called_once()


# TODO: Add large deployment unit tests


def test_on_start(harness, mocker, substrate, mock_fs_interactions):
    """Test on start event."""
    lock_acquire = mocker.patch("opensearch_single_kernel.managers.lock.LockManager.acquire")
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    check_blocking_directives = mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.check_blocking_directives"
    )
    should_ignore_lock = mocker.patch(
        "opensearch_single_kernel.managers.lock.LockManager.should_ignore_lock"
    )
    is_fully_configured = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.is_fully_configured"
    )
    is_admin_user_initialized = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.is_admin_user_initialized",
        new_callable=PropertyMock,
    )
    update_opensearch_config = mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_opensearch_config"
    )
    get_nodes = mocker.patch("opensearch_single_kernel.managers.cluster.ClusterManager.get_nodes")
    can_service_start = mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.can_service_start"
    )
    check_profile_missing_requirements = mocker.patch(
        "opensearch_single_kernel.events.opensearch.OpenSearchEventsHandler.check_profile_missing_requirements"
    )
    unit_allowed_to_start = mocker.patch(
        "opensearch_single_kernel.events.opensearch.OpenSearchEventsHandler.unit_allowed_to_start"
    )
    initialise_security_index = mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.initialise_security_index"
    )
    _post_start_init = mocker.patch(
        "opensearch_single_kernel.events.opensearch.OpenSearchEventsHandler._post_start_init"
    )

    is_node_up = mocker.patch("opensearch_single_kernel.common.client.OpenSearchClient.is_node_up")
    workload_class = "VMWorkload" if substrate == "vm" else "K8sWorkload"
    mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.is_service_started"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )

    # test when setup complete
    should_ignore_lock.return_value = False
    harness.set_leader(True)
    is_node_up.return_value = True
    harness.charm.state.application.is_security_index_initialised = True
    harness.charm.on.start.emit()
    is_fully_configured.assert_not_called()
    is_admin_user_initialized.assert_not_called()

    # test when setup not complete
    is_node_up.return_value = False
    harness.charm.state.application.update({"security_index_initialised": ""})
    is_fully_configured.return_value = False
    is_admin_user_initialized.return_value = False
    harness.charm.on.start.emit()
    update_opensearch_config.assert_not_called()

    mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.is_service_started"
    )
    # when _get_nodes fails
    get_nodes.side_effect = OpenSearchHttpError()
    harness.charm.on.start.emit()
    update_opensearch_config.assert_not_called()

    get_nodes.reset_mock()

    mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.is_failed",
        return_value=False,
    )
    start = mocker.patch("opensearch_single_kernel.managers.cluster.ClusterManager.start")
    # _get_nodes succeeds
    is_fully_configured.return_value = True
    is_admin_user_initialized.return_value = True
    get_nodes.side_effect = None
    can_service_start.return_value = False
    check_profile_missing_requirements.return_value = True
    harness.charm.on.start.emit()
    update_opensearch_config.assert_not_called()
    initialise_security_index.assert_not_called()
    get_nodes.assert_called_once()

    # initialisation of the security index
    get_nodes.reset_mock()
    update_opensearch_config.reset_mock()
    harness.charm.state.application.update({"security_index_initialised": ""})
    can_service_start.return_value = True
    check_profile_missing_requirements.return_value = False
    harness.set_leader(True)
    lock_acquire.return_value = True
    unit_allowed_to_start.return_value = True

    harness.charm.on.start.emit()

    # peer cluster manager
    deployment_desc.return_value = deployment_descriptions["ok"]
    check_blocking_directives.return_value = True

    get_nodes.side_effect = None
    get_nodes.assert_called()
    start.assert_called_once()
    _post_start_init.assert_called_once()
    update_opensearch_config.assert_called()


def test_app_peers_data(harness):
    """Test getting data from the app relation data bag."""
    # Need to set leader to update the application state
    harness.set_leader(True)

    assert harness.charm.state.application.relation_data.get("app-key") is None

    harness.charm.state.application.relation_data.update({"app-key": "app-val"})
    assert harness.charm.state.application.relation_data.get("app-key") == "app-val"


def test_unit_peers_data(harness):
    """Test getting data from the unit relation data bag."""
    assert harness.charm.state.server.relation_data.get("app-key") is None

    harness.charm.state.server.relation_data.update({"app-key": "app-val"})
    assert harness.charm.state.server.relation_data.get("app-key") == "app-val"


def test_host_ip(harness):
    """Test current unit ip value."""
    assert harness.charm.state.host_ip == "1.1.1.1"


def test_unit_name(harness, mocker):
    """Test current unit name."""
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    deployment_desc.return_value = deployment_descriptions["ok"]

    app_short_id = deployment_desc().app.short_id
    assert (
        harness.charm.state.unit_name == f"{harness.charm.state.application.name}-0.{app_short_id}"
    )


def test_unit_id(harness):
    """Test retrieving the integer id pf a unit."""
    assert harness.charm.state.server.unit_id == 0
