# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit Tests for Charm related operations."""

from unittest.mock import MagicMock, PropertyMock, call, patch

import pytest
from ops import LeaderElectedEvent
from ops.pebble import APIError

from opensearch_single_kernel.common.constants import STATUS_PEERS_RELATION, HealthColors
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHAError,
    OpenSearchHttpError,
    OpenSearchNotFullyReadyError,
    OpenSearchStopError,
)
from opensearch_single_kernel.common.statuses import GeneralStatuses, InternalUsersStatuses
from tests.unit.helpers import deployment_descriptions


def test_stop_wait_failure_leaves_workload_running(harness, mocker):
    """A relocation timeout follows the stop-error contract used by restart and upgrade."""
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=False
    )
    mocker.patch.object(
        harness.charm.health_manager,
        "wait_for_shards_relocation",
        side_effect=OpenSearchHAError("Shards haven't completed relocating."),
    )
    stop = mocker.patch.object(harness.charm.cluster_manager, "stop_workload")

    with pytest.raises(OpenSearchStopError, match="Shards haven't completed relocating"):
        harness.charm.stop_opensearch(restart=True)

    stop.assert_not_called()


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
    set_running_status = mocker.patch(
        "data_platform_helpers.advanced_statuses.StatusHandler.set_running_status"
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
    set_running_status.assert_has_calls(
        [
            call(
                InternalUsersStatuses.ADMIN_USER_INIT_IN_PROGRESS.value,
                "unit",
                statuses_state=harness.charm.state.statuses,
                component_name=harness.charm.internal_users_manager.name,
            )
        ]
    )

    # Reset mocks
    purge_initial_default_users.reset_mock()
    put_or_update_internal_user_leader.reset_mock()
    set_running_status.reset_mock()

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
    set_running_status.assert_not_called()


@pytest.mark.parametrize("security_index_initialised", [False, True])
def test_on_leader_elected_workload_unavailable(harness, mocker, security_index_initialised):
    """Leader election defers before operational work if the workload is unavailable."""
    with harness.hooks_disabled():
        harness.set_leader(True)
    harness.charm.state.application.is_security_index_initialised = security_index_initialised
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        return_value=deployment_descriptions["ok"],
        new_callable=PropertyMock,
    )
    mocker.patch.object(
        type(harness.charm.workload),
        "workload_present",
        new_callable=PropertyMock,
        return_value=False,
    )
    purge = mocker.patch.object(
        harness.charm.internal_users_manager, "purge_initial_default_users"
    )
    put_user = mocker.patch.object(
        harness.charm.internal_users_manager, "put_or_update_internal_user_leader"
    )
    is_node_up = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=False
    )
    event = mocker.Mock(spec=LeaderElectedEvent)

    harness.charm.opensearch_events._on_leader_elected(event)

    event.defer.assert_called_once()
    is_node_up.assert_not_called()
    purge.assert_not_called()
    put_user.assert_not_called()
    assert not harness.charm.state.application.is_admin_user_initialized


@pytest.mark.skip_if_substrate("vm")
@pytest.mark.parametrize("operation", ["list_files", "pull", "push"])
def test_on_leader_elected_filesystem_access_denied(harness, mocker, caplog, operation):
    """A ready container can still reject file operations without resetting credentials."""
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        return_value=deployment_descriptions["ok"],
        new_callable=PropertyMock,
    )
    container = harness.charm.workload.container
    path = str(harness.charm.workload.paths.conf / "opensearch-security/internal_users.yml")
    content = "_meta:\n  type: internalusers\nadmin:\n  hash: existing-hash\n"
    container.push(path, content, make_dirs=True)
    event = mocker.Mock(spec=LeaderElectedEvent)

    with patch.object(
        container, operation, side_effect=APIError({}, 403, "Forbidden", "access denied")
    ):
        # Repeated denials must remain visible and must not enter user initialization.
        for _ in range(2):
            harness.charm.opensearch_events._on_leader_elected(event)

    assert event.defer.call_count == 2
    assert (
        caplog.text.count("An error occurred while purging initial default users: access denied")
        == 2
    )
    assert not harness.charm.state.application.is_admin_user_initialized
    assert harness.charm.state.application.get_user_password("admin") is None
    with container.pull(path) as file:
        assert file.read() == content

    # Once file access recovers, the same deferred bootstrap can complete.
    harness.charm.opensearch_events._on_leader_elected(event)
    assert event.defer.call_count == 2
    assert harness.charm.state.application.is_admin_user_initialized
    password = harness.charm.state.application.get_user_password("admin")
    assert password

    # Further bootstrap replays must reuse the credentials already stored in Juju.
    harness.charm.opensearch_events._on_leader_elected(event)
    assert harness.charm.state.application.get_user_password("admin") == password


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
    deployment_desc.return_value = deployment_descriptions["ok"]
    no_blocking_directives = mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.no_blocking_directives"
    )
    should_ignore_lock = mocker.patch(
        "opensearch_single_kernel.managers.lock.LockManager.should_ignore_lock"
    )
    all_tls_resources_stored = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.all_tls_resources_stored"
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
    check_profile_requirements = mocker.patch(
        "opensearch_single_kernel.managers.profiles.ProfilesManager.check_profile_requirements"
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
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch.object(harness.charm, "is_unit_going_away", return_value=False)

    # test when setup complete
    should_ignore_lock.return_value = False
    harness.set_leader(True)
    is_node_up.return_value = True
    harness.charm.state.application.is_security_index_initialised = True
    is_admin_user_initialized.reset_mock()
    harness.charm.on.start.emit()
    all_tls_resources_stored.assert_not_called()
    is_admin_user_initialized.assert_not_called()

    # test when setup not complete
    is_node_up.return_value = False
    harness.charm.state.application.update({"security_index_initialised": ""})
    all_tls_resources_stored.return_value = False
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
    all_tls_resources_stored.return_value = True
    is_admin_user_initialized.return_value = True
    get_nodes.side_effect = None
    can_service_start.return_value = False
    check_profile_requirements.return_value = False
    harness.charm.on.start.emit()
    update_opensearch_config.assert_not_called()
    initialise_security_index.assert_not_called()
    get_nodes.assert_called_once()

    # initialisation of the security index
    get_nodes.reset_mock()
    update_opensearch_config.reset_mock()
    harness.charm.state.application.update({"security_index_initialised": ""})
    can_service_start.return_value = True
    check_profile_requirements.return_value = True
    harness.set_leader(True)
    lock_acquire.return_value = True
    unit_allowed_to_start.return_value = True

    harness.charm.on.start.emit()

    # peer cluster manager
    no_blocking_directives.return_value = True

    get_nodes.side_effect = None
    get_nodes.assert_called()
    start.assert_called_once()
    _post_start_init.assert_called_once()
    update_opensearch_config.assert_called()


@pytest.mark.parametrize(
    "deployment_desc",
    [None, deployment_descriptions["ok"]],
    ids=["peer-data-gone", "peer-data-exists"],
)
def test_start_dropped_when_unit_removed(harness, mocker, deployment_desc):
    """A deferred start during removal is dropped."""
    mocker.patch.object(harness.charm, "is_unit_going_away", return_value=True)
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_desc,
    )
    is_opensearch_started = mocker.patch.object(
        type(harness.charm.cluster_manager), "is_opensearch_started", new_callable=PropertyMock
    )
    event = MagicMock()

    harness.charm.opensearch_events._on_start_opensearch(event)

    is_opensearch_started.assert_not_called()
    event.defer.assert_not_called()


@pytest.mark.parametrize("main_orchestrator", [False, True])
@pytest.mark.parametrize("already_waiting_to_start", [False, True])
def test_running_node_defers_with_startup_status(
    harness, mocker, main_orchestrator, already_waiting_to_start
):
    """Failed post-start checks leave Waiting or the existing, stronger startup error."""
    charm = harness.charm
    with harness.hooks_disabled():
        harness.add_relation(STATUS_PEERS_RELATION, charm.app.name)
    manager = charm.cluster_manager
    charm.status_handler.components = (manager, charm.health_manager)
    mocker.patch.object(charm.health_manager, "get", return_value=HealthColors.UNKNOWN)
    waiting = GeneralStatuses.WAITING_TO_START.value
    if already_waiting_to_start:
        charm.status_handler.set_running_status(
            waiting, "unit", statuses_state=charm.state.statuses, component_name=manager.name
        )
    mocker.patch.object(charm.state, "is_peer_cluster_consumer", return_value=False)
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=main_orchestrator)
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    for name in (
        "is_data_role_in_cluster_fleet_apps",
        "bootstrapped",
        "is_security_index_initialised",
    ):
        mocker.patch.object(
            type(charm.state.application), name, new_callable=PropertyMock, return_value=True
        )
    mocker.patch.object(
        type(charm.cluster_manager),
        "is_opensearch_started",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(type(charm.workload), "is_failed", return_value=False)
    mocker.patch.object(
        manager,
        "wait_for_opensearch_up",
        side_effect=OpenSearchNotFullyReadyError("Node started but not fully ready yet."),
    )
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    event = mocker.Mock(after_upgrade=False)

    charm.opensearch_events._on_start_opensearch(event)

    event.defer.assert_called_once()
    expected = GeneralStatuses.SERVICE_START_ERROR.value if main_orchestrator else waiting
    stored = charm.state.statuses.get("unit", manager.name).root
    assert (waiting in stored) == (already_waiting_to_start or not main_orchestrator)
    assert expected in stored
    assert expected in manager.get_statuses("unit", recompute=True)
    assert charm.health_manager.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]
    charm.status_handler._recompute_statuses_for_scope("unit", charm.health_manager)
    collect = mocker.Mock()
    charm.status_handler._on_collect_unit_status(collect)
    assert collect.add_status.call_args.args[0].name == expected.status


@pytest.mark.parametrize(
    "readiness_check", ["wait_for_opensearch_up", "assert_current_node_joined_cluster"]
)
def test_post_start_waiting_survives_failure_and_clears_on_retry(harness, mocker, readiness_check):
    """Post-start work must complete before its persisted Waiting status is cleared."""
    charm = harness.charm
    with harness.hooks_disabled():
        harness.add_relation(STATUS_PEERS_RELATION, charm.app.name)
    manager = charm.cluster_manager
    waiting = GeneralStatuses.WAITING_TO_START.value
    charm.state.add_status_if_not_present(waiting, "unit", manager.name)
    mocker.patch.object(manager, "wait_for_opensearch_up")
    mocker.patch.object(manager, "assert_current_node_joined_cluster")
    failed_check = getattr(manager, readiness_check)
    failed_check.side_effect = OpenSearchNotFullyReadyError("Node is not ready")
    mocker.patch.object(charm.exclusions_manager, "delete_current")
    mocker.patch.object(charm.lock_manager, "release")
    mocker.patch.object(manager, "apply_upstream_fixes")
    mocker.patch.object(charm, "apply_health")
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=False)
    ca_rotation = mocker.patch.object(charm.opensearch_events, "post_start_ca_rotation")
    event = mocker.Mock(after_upgrade=False)

    with pytest.raises(OpenSearchNotFullyReadyError):
        charm.opensearch_events._post_start_init(event)

    assert waiting in manager.get_statuses("unit", recompute=True)
    ca_rotation.assert_not_called()

    failed_check.side_effect = None
    charm.opensearch_events._post_start_init(event)

    assert waiting not in manager.get_statuses("unit", recompute=True)
    ca_rotation.assert_called_once()
    event.defer.assert_not_called()

    # CA rotation can synchronously initiate another startup attempt.
    def restart_during_ca_rotation():
        assert waiting not in manager.get_statuses("unit", recompute=True)
        charm.state.add_status_if_not_present(waiting, "unit", manager.name)

    ca_rotation.side_effect = restart_during_ca_rotation
    charm.opensearch_events._post_start_init(event)
    assert waiting in manager.get_statuses("unit", recompute=True)


@pytest.fixture
def reconcile_security_config(harness, mocker) -> MagicMock:
    """Leader of a main orchestrator, able to reconcile its security config."""
    with harness.hooks_disabled():
        harness.set_leader(True)

    mocker.patch.object(harness.charm, "is_unit_going_away", return_value=False)
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch.object(
        type(harness.charm.upgrades_manager),
        "in_progress",
        new_callable=PropertyMock,
        return_value=False,
    )
    return mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.reconcile_security_config",
        return_value=True,
    )


@pytest.mark.parametrize("force", [True, False], ids=["forced", "not-forced"])
def test_security_config_reconciled_by_leader_of_main_orchestrator(
    harness, reconcile_security_config, force
):
    event = MagicMock()
    harness.charm.reconcile_security_config(event, force=force)

    reconcile_security_config.assert_called_once_with(force)
    event.defer.assert_not_called()


def test_security_config_reconciliation_retried(harness, reconcile_security_config):
    reconcile_security_config.return_value = False

    event = MagicMock()
    harness.charm.reconcile_security_config(event)

    event.defer.assert_called_once()


@pytest.mark.parametrize("reason", ["upgrade-in-progress", "no-deployment-description"])
def test_security_config_reconciliation_postponed(
    harness, mocker, reconcile_security_config, reason
):
    if reason == "upgrade-in-progress":
        mocker.patch.object(
            type(harness.charm.upgrades_manager),
            "in_progress",
            new_callable=PropertyMock,
            return_value=True,
        )
    else:
        mocker.patch(
            "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
            new_callable=PropertyMock,
            return_value=None,
        )

    event = MagicMock()
    harness.charm.reconcile_security_config(event)

    reconcile_security_config.assert_not_called()
    event.defer.assert_called_once()


@pytest.mark.parametrize("reason", ["non-leader", "non-main", "going-away"])
def test_security_config_left_untouched(harness, mocker, reconcile_security_config, reason):
    if reason == "non-leader":
        with harness.hooks_disabled():
            harness.set_leader(False)
    elif reason == "non-main":
        mocker.patch(
            "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
            new_callable=PropertyMock,
            return_value=deployment_descriptions["ko"],
        )
    else:
        mocker.patch.object(harness.charm, "is_unit_going_away", return_value=True)

    event = MagicMock()
    harness.charm.reconcile_security_config(event, force=True)

    reconcile_security_config.assert_not_called()
    event.defer.assert_not_called()


def test_security_config_reconciled_on_config_changed(harness, mocker):
    """Some options are part of the security config."""
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.reconcile_cluster_config",
        return_value=False,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.profiles.ProfilesManager.check_profile_requirements",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_profile_configuration",
        return_value=False,
    )
    reconcile_security_config = mocker.patch.object(harness.charm, "reconcile_security_config")

    event = MagicMock()
    harness.charm.opensearch_events._on_config_changed(event)

    reconcile_security_config.assert_called_once_with(event)


def test_security_config_applied_by_new_leader(harness, mocker):
    """The security config file of a unit tells nothing about what the former leader applied."""
    with harness.hooks_disabled():
        harness.set_leader(True)

    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=True
    )
    mocker.patch.object(harness.charm, "apply_health", return_value=HealthColors.GREEN)
    mocker.patch("opensearch_single_kernel.managers.cluster.ClusterManager.get_nodes")
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.compute_and_broadcast_updated_topology",
        return_value=False,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.update_all_external_clients_relation_endpoints"
    )
    reconcile_security_config = mocker.patch.object(harness.charm, "reconcile_security_config")

    event = MagicMock()
    harness.charm.opensearch_events._on_leader_elected(event)

    reconcile_security_config.assert_called_once_with(event, force=True)


def test_security_config_updated_for_the_security_index_initialisation(harness, mocker):
    """The security index is initialised with the content of the security config file."""
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.should_initialise_security_index",
        return_value=True,
    )
    calls = MagicMock()
    mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_security_config",
        calls.update_security_config,
    )
    # the rest of the post start initialisation is out of scope
    calls.initialise_security_index.side_effect = OpenSearchHttpError()
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.initialise_security_index",
        calls.initialise_security_index,
    )
    with harness.hooks_disabled():
        harness.set_leader(True)

    with pytest.raises(OpenSearchHttpError):
        harness.charm.opensearch_events._post_start_init(MagicMock())

    assert calls.mock_calls == [call.update_security_config(), call.initialise_security_index()]


def test_on_start_restores_ldap_ca(harness, mocker):
    """LDAP CA must be back on disk before OpenSearch starts, e.g. after a K8s pod restart."""
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=False
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.no_blocking_directives",
        return_value=True,
    )
    mocker.patch("opensearch_single_kernel.managers.cluster.ClusterManager.get_nodes")
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.is_admin_user_initialized",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.all_tls_resources_stored",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.save_user_locally"
    )
    start_opensearch = mocker.patch(
        "opensearch_single_kernel.events.opensearch.OpenSearchEventsHandler._on_start_opensearch"
    )
    restore_ldap_ca = mocker.patch(
        "opensearch_single_kernel.managers.ldap.LdapManager.restore_ldap_ca"
    )

    harness.charm.on.start.emit()

    restore_ldap_ca.assert_called_once()
    start_opensearch.assert_called_once()


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
