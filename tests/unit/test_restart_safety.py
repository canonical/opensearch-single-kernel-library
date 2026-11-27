# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Controlled restarts preserve the remaining cluster managers."""

from unittest.mock import PropertyMock

import pytest

from opensearch_single_kernel.common.constants import STATUS_PEERS_RELATION, Scope
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError, OpenSearchStopError
from opensearch_single_kernel.common.statuses import GeneralStatuses, LockStatuses
from opensearch_single_kernel.core.models import Node


@pytest.fixture
def restart_node(harness, mocker, patch_deployment_desc):
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.set_planned_units(3)
        harness.add_relation(STATUS_PEERS_RELATION, harness.charm.app.name)
    charm = harness.charm
    node = Node(
        name=charm.state.unit_name,
        roles=["cluster_manager"],
        ip="10.0.0.1",
        app=charm.state.application.deployment_desc.app,
        unit_number=0,
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=True
    )
    mocker.patch.object(charm.health_manager, "wait_for_shards_relocation")
    mocker.patch.object(charm.health_manager, "wait_for_only_copies_to_move")
    mocker.patch.object(charm.cluster_manager, "stop_workload")
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_current_node",
        return_value=node,
    )
    return node


@pytest.mark.parametrize(
    "planned,survivor_roles,allowed",
    [
        (3, ["data"], False),
        (3, ["cluster_manager", "voting_only"], False),
        (3, ["cluster_manager"], True),
        (1, ["data"], True),
    ],
)
def test_restart_respects_planned_managers(
    harness, restart_node, planned, survivor_roles, allowed
):
    harness.set_planned_units(planned)
    manager = harness.charm.cluster_manager
    survivor = restart_node.model_copy(update={"name": "other-0", "roles": survivor_roles})

    assert manager.can_restart_node([restart_node, survivor]) == allowed


def test_restart_does_not_use_a_stale_local_planned_count(harness, restart_node):
    charm = harness.charm
    app = charm.state.current_peer_cluster_app.model_copy(update={"planned_units": 1})
    charm.state.application.cluster_fleet_apps = {app.app.id: app}

    assert not charm.cluster_manager.can_restart_node([restart_node])
    assert charm.state.application.cluster_fleet_apps[app.app.id].planned_units == 1


def test_restart_requires_current_node_when_local_api_is_up(harness, restart_node):
    other = restart_node.model_copy(update={"name": "other-0"})
    assert not harness.charm.cluster_manager.can_restart_node([other])


@pytest.mark.parametrize("service_running", [False, True])
def test_restart_recovers_an_unreachable_node_without_cached_topology(
    harness, mocker, restart_node, service_running
):
    charm = harness.charm
    charm.state.application.nodes_config = {}
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=False
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_current_node",
        return_value=None,
    )
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=service_running)
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    nodes = mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[])
    exclusions = mocker.patch.object(charm.exclusions_manager, "add_current")
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    start = mocker.patch.object(charm, "start_opensearch_event").emit
    event = mocker.Mock()

    charm.opensearch_events._on_restart_opensearch(event)

    nodes.assert_not_called()
    exclusions.assert_not_called()
    charm.health_manager.wait_for_shards_relocation.assert_called_once()
    charm.cluster_manager.stop_workload.assert_called_once()
    start.assert_called_once()
    event.defer.assert_not_called()


def test_restart_waits_for_another_planned_manager(harness, mocker, restart_node):
    charm = harness.charm
    data = restart_node.model_copy(update={"name": "data-0", "roles": ["data"]})
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[restart_node, data])
    exclusions = mocker.patch.object(charm.exclusions_manager, "add_current")

    with pytest.raises(OpenSearchStopError):
        charm.stop_opensearch(restart=True)

    exclusions.assert_not_called()
    charm.cluster_manager.stop_workload.assert_not_called()
    assert GeneralStatuses.SERVICE_IS_STOPPING.value not in (
        charm.state.statuses.get("unit", charm.cluster_manager.name).root
    )
    collected = mocker.Mock()
    charm.status_handler._on_collect_unit_status(collected)
    assert all(
        call.args[0].message != GeneralStatuses.SERVICE_IS_STOPPING.value.message
        for call in collected.add_status.call_args_list
    )


@pytest.mark.parametrize("restart", [False, True])
@pytest.mark.parametrize("survivor_roles", [["data"], ["cluster_manager", "voting_only"]])
def test_sole_manager_is_not_excluded(harness, mocker, restart_node, restart, survivor_roles):
    harness.set_planned_units(1)
    charm = harness.charm
    other = restart_node.model_copy(update={"name": "other-0", "roles": survivor_roles})
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[restart_node, other])
    exclusions = mocker.patch.object(charm.exclusions_manager, "add_current")

    charm.stop_opensearch(restart=restart)

    assert exclusions.call_args.kwargs["voting"] is False
    assert exclusions.call_args.kwargs["allocation"] == (not restart)
    charm.cluster_manager.stop_workload.assert_called_once()


@pytest.mark.parametrize("exclusion_succeeds", [False, True])
def test_restart_requires_successful_voting_exclusion(
    harness, mocker, restart_node, exclusion_succeeds
):
    charm = harness.charm
    other = restart_node.model_copy(update={"name": "other-0"})
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[restart_node, other])
    vote = mocker.patch.object(
        charm.exclusions_manager, "_add_voting", return_value=exclusion_succeeds
    )

    if exclusion_succeeds:
        charm.stop_opensearch(restart=True)
        charm.cluster_manager.stop_workload.assert_called_once()
    else:
        with pytest.raises(OpenSearchStopError):
            charm.stop_opensearch(restart=True)
        charm.cluster_manager.stop_workload.assert_not_called()
    vote.assert_called_once_with(Scope.APP, restart_node)


def test_restart_node_lookup_failure_keeps_workload_running(harness, mocker, restart_node):
    charm = harness.charm
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=True
    )
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(
        charm.cluster_manager, "get_nodes", side_effect=OpenSearchHttpError("API unavailable")
    )

    with pytest.raises(OpenSearchStopError):
        charm.stop_opensearch(restart=True)

    charm.cluster_manager.stop_workload.assert_not_called()


def test_unsafe_restart_releases_lock_and_defers(harness, mocker, restart_node):
    charm = harness.charm
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[restart_node])
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    release = mocker.patch.object(charm.lock_manager, "release")
    start = mocker.patch.object(charm, "start_opensearch_event").emit
    event = mocker.Mock()

    charm.opensearch_events._on_restart_opensearch(event)

    charm.cluster_manager.stop_workload.assert_not_called()
    start.assert_not_called()
    release.assert_called_once()
    event.defer.assert_called_once()


def test_role_change_waits_for_lock_without_reporting_startup(harness, mocker, restart_node):
    """A node waiting for its restart lock keeps running without reporting startup."""
    charm = harness.charm
    charm.state.server.started = "2026-11-13T11:00:00Z"
    mocker.patch.object(charm.config_manager, "update_opensearch_config", return_value=True)
    mocker.patch.object(charm.lock_manager, "acquire", return_value=False)
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(
        type(charm.cluster_manager),
        "is_opensearch_started",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )

    assert charm.opensearch_events._reconfigure_and_restart_if_needed()

    charm.cluster_manager.stop_workload.assert_not_called()
    assert LockStatuses.REQUEST_LOCK_ON_START.value in (
        charm.state.statuses.get("unit", charm.lock_manager.name).root
    )
    assert GeneralStatuses.WAITING_TO_START.value not in charm.cluster_manager.get_statuses("unit")


def test_vm_upgrade_checks_manager_survival_before_disabling_allocation(
    harness, mocker, restart_node, substrate
):
    if substrate != "vm":
        pytest.skip("VM controls the workload stop before installing the new snap")
    charm = harness.charm
    mocker.patch.object(
        type(charm.state),
        "upgrade_membership_complete",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[restart_node])
    mocker.patch.object(charm.upgrade_events, "_publish_app_upgrade_status")
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    release = mocker.patch.object(charm.lock_manager, "release")
    allocation = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.disable_shard_allocation",
        side_effect=AssertionError("Allocation must remain enabled when a restart is unsafe"),
    )
    event = mocker.Mock()

    charm.upgrade_events._upgrade_opensearch(event)

    allocation.assert_not_called()
    charm.cluster_manager.stop_workload.assert_not_called()
    release.assert_called_once()
    event.defer.assert_called_once()


@pytest.mark.parametrize("restore_fails", [False, True])
def test_vm_upgrade_restores_allocation_if_final_stop_check_fails(
    harness, mocker, restart_node, substrate, restore_fails
):
    if substrate != "vm":
        pytest.skip("VM controls shard allocation before stopping the workload")
    charm = harness.charm
    original_state = charm.state.server_upgrade.unit_state
    other = restart_node.model_copy(update={"name": "other-0"})
    mocker.patch.object(
        type(charm.state),
        "upgrade_membership_complete",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(
        charm.cluster_manager,
        "get_nodes",
        side_effect=[[restart_node, other], [restart_node]],
    )
    mocker.patch.object(charm.upgrade_events, "_publish_app_upgrade_status")
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    release = mocker.patch.object(charm.lock_manager, "release")
    install = mocker.patch.object(type(charm.workload), "install")
    disable = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.disable_shard_allocation"
    )
    enable = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.enable_shard_allocation",
        side_effect=OpenSearchHttpError() if restore_fails else None,
    )
    mocker.patch("opensearch_single_kernel.common.client.OpenSearchClient.flush_translog")
    event = mocker.Mock()

    charm.upgrade_events._upgrade_opensearch(event)

    disable.assert_called_once()
    enable.assert_called_once()
    charm.cluster_manager.stop_workload.assert_not_called()
    install.assert_not_called()
    assert charm.state.server_upgrade.unit_state == original_state
    release.assert_called_once()
    event.defer.assert_called_once()


def test_vm_upgrade_of_unreachable_node_reaches_allocation_preparation(
    harness, mocker, restart_node, substrate
):
    if substrate != "vm":
        pytest.skip("VM prepares allocation before replacing the snap")
    charm = harness.charm
    charm.state.application.nodes_config = {}
    mocker.patch.object(
        type(charm.state),
        "upgrade_membership_complete",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=False
    )
    nodes = mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[])
    mocker.patch.object(charm.upgrade_events, "_publish_app_upgrade_status")
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    allocation = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.disable_shard_allocation",
        side_effect=OpenSearchHttpError("Allocation request failed"),
    )
    event = mocker.Mock()

    charm.upgrade_events._upgrade_opensearch(event)

    nodes.assert_not_called()
    allocation.assert_called_once()
    charm.cluster_manager.stop_workload.assert_not_called()
    event.defer.assert_called_once()


@pytest.mark.parametrize("goal_status", [None, "dying"])
def test_deferred_restart_is_discarded_when_unit_is_removed(
    harness, mocker, restart_node, goal_status
):
    charm = harness.charm
    with harness.hooks_disabled():
        harness.remove_relation(charm.state.peer_relation.id)
    goals = {} if goal_status is None else {charm.unit.name: mocker.Mock(status=goal_status)}
    mocker.patch(
        "opensearch_single_kernel.core.state.hookcmds.goal_state",
        return_value=mocker.Mock(units=goals),
    )
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    acquire = mocker.spy(charm.lock_manager, "acquire")
    start = mocker.patch.object(charm, "start_opensearch_event").emit
    event = mocker.Mock()

    charm.opensearch_events._on_restart_opensearch(event)

    acquire.assert_not_called()
    charm.cluster_manager.stop_workload.assert_not_called()
    start.assert_not_called()
    event.defer.assert_not_called()
