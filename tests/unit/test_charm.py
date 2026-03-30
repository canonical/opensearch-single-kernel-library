# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit Tests for Charm related operations."""

from unittest.mock import MagicMock, PropertyMock, call, patch

import pytest
from ops import ActiveStatus, BlockedStatus
from ops.pebble import ConnectionError as PebbleConnectionError

from opensearch_single_kernel.common.constants import HealthColors
from opensearch_single_kernel.common.exceptions import (
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchInstallError,
    OpenSearchNotFullyReadyError,
)
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.events.custom_events import StartOpenSearch
from tests.unit.helpers import deployment_descriptions


def test_on_install(harness, substrate):
    """Test the install event callback on success."""
    workload_class = "VMWorkload" if substrate == "vm" else "K8sWorkload"
    with patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.install"
    ) as install:
        harness.charm.on.install.emit()
        # For K8s, install is not operational, container preparation is handled in pebble-ready.
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
        # For K8s, install is not operational, container preparation is handled in pebble-ready.
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


def test_alt_hosts_uses_dns_for_k8s(harness, mocker, substrate):
    """K8s alt_hosts should use DNS identities, not pod IPs."""
    if substrate == "vm":
        pytest.skip("K8s-only host selection test")

    peer_rel_id = harness.charm.state.peer_relation.id
    harness.add_relation_unit(peer_rel_id, f"{harness.charm.app.name}/1")
    harness.add_relation_unit(peer_rel_id, f"{harness.charm.app.name}/2")

    app_name = harness.charm.app.name
    dns_hosts = {
        f"{app_name}-1": f"{app_name}-1.{app_name}-endpoints.ktest1.svc.cluster.local",
        f"{app_name}-2": f"{app_name}-2.{app_name}-endpoints.ktest1.svc.cluster.local",
    }
    mocker.patch(
        "opensearch_single_kernel.managers.base.get_k8s_seed_host",
        side_effect=lambda unit_name, app_name: dns_hosts[unit_name],
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
        return_value=True,
    )

    alt_hosts = harness.charm.cluster_manager.alt_hosts

    assert set(alt_hosts) == set(dns_hosts.values())


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


def test_start_opensearch_releases_lock_when_post_start_init_not_ready(harness, mocker):
    """Release lock if post-start init defers on an already-started node."""
    mocker.patch.object(
        harness.charm.opensearch_events,
        "_ensure_k8s_runtime_ready",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.is_opensearch_started",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(harness.charm.workload, "is_failed", return_value=False)
    mocker.patch.object(
        harness.charm.opensearch_events,
        "_post_start_init",
        side_effect=OpenSearchNotFullyReadyError("not ready"),
    )
    release_lock = mocker.patch.object(harness.charm.lock_manager, "release")
    event = MagicMock()

    harness.charm.opensearch_events._on_start_opensearch(event)

    release_lock.assert_called_once()
    event.defer.assert_called_once()


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
    lock_acquired = mocker.patch("opensearch_single_kernel.managers.lock.LockManager.acquired")
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
    lock_acquired.return_value = True
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


@pytest.mark.skip_if_substrate("vm")
def test_peer_relation_changed_defers_when_k8s_container_not_ready(harness, mocker):
    """K8s peer relation changes should defer until Pebble is connectable."""
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
        return_value=False,
    )
    update_seeds_config = mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_seeds_config"
    )
    event = MagicMock()

    harness.charm.state.server.update({"started": "true"})
    harness.set_can_connect("opensearch", False)

    harness.charm.opensearch_events._on_peer_relation_changed(event)

    event.defer.assert_called_once()
    update_seeds_config.assert_not_called()


@pytest.mark.skip_if_substrate("vm")
def test_restart_opensearch_defers_before_lock_when_k8s_container_not_ready(harness, mocker):
    """K8s restart should not hold the lock when the container is unavailable."""
    acquired = mocker.patch(
        "opensearch_single_kernel.managers.lock.LockManager.acquired",
        new_callable=PropertyMock,
    )
    event = MagicMock()

    harness.set_can_connect("opensearch", False)

    harness.charm.opensearch_events._on_restart_opensearch(event)

    event.defer.assert_called_once()
    acquired.assert_not_called()


@pytest.mark.skip_if_substrate("vm")
def test_restart_opensearch_releases_lock_on_k8s_pebble_error(harness, mocker):
    """K8s restart should release the node lock if Pebble disconnects mid-restart."""
    mocker.patch(
        "opensearch_single_kernel.managers.lock.LockManager.acquired",
        new_callable=PropertyMock,
        return_value=True,
    )
    release = mocker.patch("opensearch_single_kernel.managers.lock.LockManager.release")
    mocker.patch.object(
        harness.charm,
        "stop_opensearch",
        side_effect=PebbleConnectionError(),
    )
    event = MagicMock()

    harness.charm.opensearch_events._on_restart_opensearch(event)

    event.defer.assert_called_once()
    release.assert_called_once()


@pytest.mark.skip_if_substrate("vm")
def test_storage_detaching_skips_local_stop_when_k8s_container_not_ready(harness, mocker):
    """K8s unit removal should keep remote cleanup working if the container is already gone."""
    mocker.patch.object(harness.charm.app, "planned_units", return_value=2)
    mocker.patch(
        "opensearch_single_kernel.managers.lock.LockManager.acquired",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.alt_hosts",
        new_callable=PropertyMock,
        return_value=["10.0.0.2"],
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.reconcile_before_unit_removal"
    )
    mocker.patch("opensearch_single_kernel.managers.cluster.ClusterManager.flush_translog_to_disk")
    delete_current = mocker.patch(
        "opensearch_single_kernel.managers.exclusions.NodesExclusionsManager.delete_current"
    )
    apply_health = mocker.patch(
        "opensearch_single_kernel.utils.status.Status.apply_health",
        return_value=HealthColors.GREEN,
    )
    release = mocker.patch("opensearch_single_kernel.managers.lock.LockManager.release")
    stop_opensearch = mocker.patch.object(harness.charm, "stop_opensearch")

    harness.set_leader(True)
    harness.set_can_connect("opensearch", False)

    harness.charm.opensearch_events._on_opensearch_data_storage_detaching(MagicMock())

    stop_opensearch.assert_not_called()
    delete_current.assert_called_once()
    apply_health.assert_called_once()
    release.assert_called_once()


@pytest.mark.skip_if_substrate("vm")
def test_config_changed_defers_before_ip_rewrite_when_k8s_container_not_ready(harness, mocker):
    """K8s config-changed should not touch files before Pebble is connectable."""
    update_opensearch_config = mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_opensearch_config"
    )
    event = MagicMock()
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchServer.last_host_ip",
        new_callable=PropertyMock,
        return_value="10.0.0.1",
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.host_ip",
        new_callable=PropertyMock,
        return_value="10.0.0.2",
    )

    harness.set_can_connect("opensearch", False)
    harness.charm.opensearch_events._on_config_changed(event)

    event.defer.assert_called_once()
    update_opensearch_config.assert_not_called()


@pytest.mark.skip_if_substrate("vm")
def test_config_changed_defers_when_k8s_profile_update_hits_file_error(harness, mocker):
    """K8s config-changed should defer if profile writes lose container connectivity."""
    event = MagicMock()
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.managers.profiles.ProfilesManager.config_profile",
        new_callable=PropertyMock,
        return_value=MagicMock(),
    )
    mocker.patch(
        "opensearch_single_kernel.events.opensearch.OpenSearchEventsHandler.check_profile_missing_requirements",
        return_value=False,
    )
    update_profile_configuration = mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_profile_configuration",
        side_effect=OpenSearchFileOperationError("container disconnected"),
    )

    harness.charm.opensearch_events._on_config_changed(event)

    event.defer.assert_called_once()
    update_profile_configuration.assert_called_once()


def test_check_profile_missing_requirements_sets_invalid_profile_status(harness, mocker):
    """Invalid profile config should set blocked status and skip requirement checks."""
    get_missing_requirements = mocker.patch.object(
        harness.charm.profiles_manager, "get_missing_requirements"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.profiles.ProfilesManager.config_profile",
        new_callable=PropertyMock,
        side_effect=ValueError("invalid profile"),
    )

    missing_requirements = harness.charm.opensearch_events.check_profile_missing_requirements()

    assert missing_requirements == [CharmStatuses.INVALID_PROFILE_CONFIG_OPTION.value.message]
    get_missing_requirements.assert_not_called()
    assert (
        harness.model.unit.status.message
        == CharmStatuses.INVALID_PROFILE_CONFIG_OPTION.value.message
    )


def test_config_changed_sets_invalid_profile_status_and_returns(harness, mocker):
    """Config-changed should stop before profile updates when profile config is invalid."""
    event = MagicMock()
    update_profile_configuration = mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_profile_configuration"
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.managers.profiles.ProfilesManager.config_profile",
        new_callable=PropertyMock,
        side_effect=ValueError("invalid profile"),
    )

    harness.charm.opensearch_events._on_config_changed(event)

    update_profile_configuration.assert_not_called()
    assert (
        harness.model.unit.status.message
        == CharmStatuses.INVALID_PROFILE_CONFIG_OPTION.value.message
    )


@pytest.mark.skip_if_substrate("vm")
def test_reconcile_tls_resources_restores_tls_files_on_k8s(harness, mocker):
    """K8s TLS reconciliation should prepare the container and restore TLS files."""
    mocker.patch.object(
        harness.charm.tls_manager,
        "_k8s_runtime_tls_artifacts_ready",
        return_value=False,
    )
    prepare_container = mocker.patch.object(harness.charm.workload, "prepare_container")
    restore_tls_files = mocker.patch.object(
        harness.charm.tls_manager, "restore_tls_files_from_secrets"
    )

    harness.charm.tls_manager.reconcile_k8s_runtime_resources()

    prepare_container.assert_called_once()
    restore_tls_files.assert_called_once()


@pytest.mark.skip_if_substrate("vm")
def test_pebble_ready_defers_when_tls_reconcile_fails_on_k8s(harness, mocker):
    """K8s pebble-ready should defer when TLS material cannot be restored yet."""
    event = MagicMock()
    reconcile_k8s = mocker.patch.object(
        harness.charm.tls_manager,
        "reconcile_k8s_runtime_resources",
        side_effect=OpenSearchFileOperationError("container disconnected"),
    )

    harness.charm.opensearch_events._on_pebble_ready(event)

    reconcile_k8s.assert_called_once()
    event.defer.assert_called_once()


@pytest.mark.skip_if_substrate("vm")
def test_pebble_ready_reconciles_tls_resources_on_k8s(harness, mocker):
    """K8s pebble-ready should run TLS reconciliation when the container is ready."""
    event = MagicMock()
    reconcile_k8s = mocker.patch.object(
        harness.charm.tls_manager, "reconcile_k8s_runtime_resources"
    )

    harness.charm.opensearch_events._on_pebble_ready(event)

    reconcile_k8s.assert_called_once()
    event.defer.assert_not_called()


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
