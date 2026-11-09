# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Recovery of Kubernetes rolling upgrades through lifecycle events."""

from types import SimpleNamespace
from unittest.mock import PropertyMock

import pytest
from ops.testing import ActionFailed

from opensearch_single_kernel.common.constants import UPGRADE_RELATION, HealthColors, Substrates
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchK8sError,
    OpenSearchNotFullyReadyError,
)
from opensearch_single_kernel.common.k8s import K8sClient
from opensearch_single_kernel.core.models import UnitUpgradesState, UpgradeVersions
from opensearch_single_kernel.core.upgrade_relation import UpgradeServerState
from opensearch_single_kernel.managers.upgrades_k8s import UpgradesManagerK8s
from tests.unit.helpers import deployment_descriptions


@pytest.fixture
def recovering_upgrade(harness, mocker, substrate):
    if substrate != "k8s":
        pytest.skip("Kubernetes rolling upgrade recovery")
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
        charm.state.application_upgrade.versions = UpgradeVersions(charm="1", workload="2.19.5")
        charm.state.application.is_security_index_initialised = True
        charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
        harness.set_leader(False)
    mocker.patch.object(
        type(charm.state.application),
        "deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=True
    )
    compatible = mocker.patch.object(
        type(charm.upgrades_manager), "is_compatible", new_callable=PropertyMock, return_value=True
    )
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    ready = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=True
    )
    allocation = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.enable_shard_allocation"
    )
    mocker.patch.object(
        type(charm.cluster_manager), "alt_hosts", new_callable=PropertyMock, return_value=[]
    )
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[])
    mocker.patch.object(charm.cluster_manager, "assert_current_node_joined_cluster")
    mocker.patch.object(charm.profiles_manager, "check_profile_requirements", return_value=True)
    mocker.patch.object(charm.config_manager, "update_seeds_config")
    mocker.patch.object(charm.exclusions_manager, "cleanup")
    mocker.patch.object(charm, "apply_health", return_value=HealthColors.GREEN)
    mocker.patch.object(charm.health_manager, "get", return_value=HealthColors.GREEN)
    mocker.patch.object(charm.tls_manager, "read_stored_ca", return_value=None)
    return SimpleNamespace(charm=charm, ready=ready, allocation=allocation, compatible=compatible)


@pytest.mark.parametrize("hook", ["_on_start", "_on_peer_relation_changed", "_on_update_status"])
def test_lifecycle_recovers_upgrade_without_another_upgrade_event(
    recovering_upgrade, mocker, hook
):
    """A later lifecycle event records readiness after an early upgrade event saw a down node."""
    charm = recovering_upgrade.charm
    recovering_upgrade.ready.return_value = False
    charm.upgrade_events._reconcile_upgrade()
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING

    recovering_upgrade.ready.return_value = True
    getattr(charm.opensearch_events, hook)(mocker.Mock())

    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY


@pytest.mark.parametrize(
    "blocker",
    [
        "uninitialised",
        "unavailable",
        "incompatible",
        "membership",
        "allocation",
        "recovering",
        "red",
        "unknown",
    ],
)
def test_reconciliation_keeps_unready_unit_pending(recovering_upgrade, harness, blocker):
    charm = recovering_upgrade.charm
    if blocker == "uninitialised":
        with harness.hooks_disabled():
            harness.set_leader(True)
            charm.state.application.is_security_index_initialised = False
            harness.set_leader(False)
    elif blocker == "unavailable":
        recovering_upgrade.ready.return_value = False
    elif blocker == "incompatible":
        recovering_upgrade.compatible.return_value = False
    elif blocker == "membership":
        charm.cluster_manager.assert_current_node_joined_cluster.side_effect = (
            OpenSearchNotFullyReadyError("Node has not rejoined the cluster")
        )
    elif blocker == "allocation":
        recovering_upgrade.allocation.side_effect = OpenSearchHttpError()
    else:
        charm.health_manager.get.return_value = {
            "recovering": HealthColors.YELLOW_TEMP,
            "red": HealthColors.RED,
            "unknown": HealthColors.UNKNOWN,
        }[blocker]

    charm.upgrade_events._reconcile_upgrade()

    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING


def test_upgrade_relation_does_not_replace_post_upgrade_checks(recovering_upgrade, harness):
    """Receiving upgrade peer data must not by itself declare this unit healthy."""
    relation = harness.model.get_relation(UPGRADE_RELATION)
    recovering_upgrade.charm.on[UPGRADE_RELATION].relation_changed.emit(relation)

    assert recovering_upgrade.charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING


@pytest.mark.parametrize("after_upgrade", [False, True])
def test_successful_start_completes_upgrade_recovery(recovering_upgrade, mocker, after_upgrade):
    charm = recovering_upgrade.charm
    for method in (
        "wait_for_opensearch_up",
        "assert_current_node_joined_cluster",
        "apply_upstream_fixes",
    ):
        mocker.patch.object(charm.cluster_manager, method)
    mocker.patch.object(charm.exclusions_manager, "delete_current")
    mocker.patch.object(charm.lock_manager, "release")
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=False)
    mocker.patch.object(charm.opensearch_events, "post_start_ca_rotation")

    charm.opensearch_events._post_start_init(mocker.Mock(after_upgrade=after_upgrade))

    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY


@pytest.mark.parametrize(
    "unit_one_ready,partition,expected", [(False, 2, 2), (False, 1, 1), (True, 1, 0)]
)
def test_periodic_reconciliation_preserves_pause_and_advances_ready_units(
    recovering_upgrade, harness, mocker, unit_one_ready, partition, expected
):
    """The leader advances after recovery, but not past the manual pause or an unready peer."""
    charm = recovering_upgrade.charm
    relation = harness.model.get_relation(UPGRADE_RELATION)
    app = charm.app.name
    with harness.hooks_disabled():
        harness.set_leader(True)
        for unit in (1, 2):
            harness.add_relation_unit(relation.id, f"{app}/{unit}")
            harness.update_relation_data(
                relation.id,
                f"{app}/{unit}",
                {
                    "state": "healthy" if unit == 2 or unit_one_ready else "restarting",
                },
            )
        charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    revisions = {f"{app}/0": "old", f"{app}/1": "new", f"{app}/2": "new"}
    mocker.patch(
        "opensearch_single_kernel.common.k8s.K8sClient.list_revisions", return_value=revisions
    )
    mocker.patch("opensearch_single_kernel.common.k8s.K8sClient.get_revision", return_value="new")
    current_partition = [partition]
    mocker.patch(
        "opensearch_single_kernel.common.k8s.K8sClient.get_partition",
        side_effect=lambda: current_partition[0],
    )
    mocker.patch(
        "opensearch_single_kernel.common.k8s.K8sClient.set_partition",
        side_effect=lambda value: current_partition.__setitem__(0, value),
    )
    mocker.patch.object(
        charm.external_clients_manager, "update_all_external_clients_relation_endpoints"
    )

    charm.opensearch_events._on_update_status(mocker.Mock())

    assert current_partition[0] == expected


@pytest.mark.parametrize("in_progress", [False, True])
def test_shutdown_without_upgrade_relation_preserves_partition_protection(mocker, in_progress):
    """Protect the partition before skipping work that needs the upgrade relation."""
    state = SimpleNamespace(
        substrate=Substrates.K8S,
        pod_name="opensearch-2",
        namespace="testing",
        upgrade_relation=None,
        server_upgrade=UpgradeServerState(
            None, mocker.Mock(), SimpleNamespace(name="opensearch/2")
        ),
    )
    manager = UpgradesManagerK8s(state, mocker.Mock())
    mocker.patch.object(K8sClient, "get_revision", return_value="new")
    mocker.patch.object(
        K8sClient, "list_revisions", return_value={"opensearch/2": "old" if in_progress else "new"}
    )
    mocker.patch.object(K8sClient, "get_partition", return_value=0)
    partition = mocker.patch.object(K8sClient, "set_partition")
    client = mocker.patch.object(
        UpgradesManagerK8s, "opensearch_client", new_callable=PropertyMock
    )

    manager.prepare_for_shutdown()

    if in_progress:
        partition.assert_called_once_with(value=2)
    else:
        partition.assert_not_called()
    client.assert_not_called()


@pytest.mark.parametrize("in_progress", [False, True])
def test_shutdown_preserves_upgrade_preparation(recovering_upgrade, mocker, in_progress):
    """Only an upgrade needs partition protection, allocation changes and a flush."""
    charm = recovering_upgrade.charm
    charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    mocker.patch.object(
        UpgradesManagerK8s, "in_progress", new_callable=PropertyMock, return_value=in_progress
    )
    mocker.patch.object(
        UpgradeServerState, "unit_number", new_callable=PropertyMock, return_value=2
    )
    mocker.patch.object(K8sClient, "get_partition", return_value=0)
    mocker.patch.object(
        UpgradesManagerK8s, "alt_hosts", new_callable=PropertyMock, return_value=[]
    )
    operations = mocker.Mock()
    operations.attach_mock(mocker.patch.object(K8sClient, "set_partition"), "partition")
    operations.attach_mock(
        mocker.patch(
            "opensearch_single_kernel.common.client.OpenSearchClient.disable_shard_allocation"
        ),
        "allocation",
    )
    operations.attach_mock(
        mocker.patch("opensearch_single_kernel.common.client.OpenSearchClient.flush_translog"),
        "flush",
    )
    operations.attach_mock(mocker.patch.object(charm.pebble_observer, "stop"), "observer")
    event = mocker.Mock()

    charm.opensearch_events._on_stop(event)

    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING
    expected = (
        [
            mocker.call.partition(value=2),
            mocker.call.allocation(alt_hosts=[]),
            mocker.call.flush(alt_hosts=[]),
        ]
        if in_progress
        else []
    )
    assert operations.mock_calls == [*expected, mocker.call.observer()]
    event.defer.assert_not_called()


@pytest.mark.parametrize("failure_stage", ["upgrade-state", "partition", "write", "write-applied"])
def test_failed_shutdown_invalidates_readiness_before_replacement(
    recovering_upgrade, harness, mocker, failure_stage
):
    """A new pod revision must not inherit the old pod's HEALTHY state after an API failure."""
    charm = recovering_upgrade.charm
    charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    stop = mocker.patch.object(charm.pebble_observer, "stop")
    unit_number = mocker.patch.object(
        UpgradeServerState, "unit_number", new_callable=PropertyMock, return_value=2
    )
    error = OpenSearchK8sError("Kubernetes is unavailable during shutdown")
    if failure_stage == "upgrade-state":
        failed = mocker.patch.object(
            type(charm.upgrades_manager),
            "in_progress",
            new_callable=PropertyMock,
            side_effect=error,
        )
    elif failure_stage == "partition":
        failed = mocker.patch.object(K8sClient, "get_partition", side_effect=error)
    else:
        partition_before_shutdown = [0]
        mocker.patch.object(
            K8sClient, "get_partition", side_effect=lambda: partition_before_shutdown[0]
        )

        def fail_partition_write(value):
            assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING
            if failure_stage == "write-applied":
                partition_before_shutdown[0] = value
            raise error

        failed = mocker.patch.object(K8sClient, "set_partition", side_effect=fail_partition_write)

    charm.opensearch_events._on_stop(mocker.Mock())

    stopped_state = charm.state.server_upgrade.unit_state
    assert stopped_state == UnitUpgradesState.RESTARTING
    stop.assert_called_once_with()
    if failure_stage in ("write", "write-applied"):
        failed.assert_called_once_with(value=2)
        assert partition_before_shutdown[0] == (2 if failure_stage == "write-applied" else 0)
    mocker.stop(failed)
    mocker.stop(unit_number)

    # The leader receives this state from a stopped peer, whose new pod is not ready yet.
    relation = harness.model.get_relation(UPGRADE_RELATION)
    app = charm.app.name
    with harness.hooks_disabled():
        harness.set_leader(True)
        charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
        for unit, state in [(2, UnitUpgradesState.HEALTHY), (1, stopped_state)]:
            harness.add_relation_unit(relation.id, f"{app}/{unit}")
            harness.update_relation_data(relation.id, f"{app}/{unit}", {"state": state.value})
    mocker.patch.object(K8sClient, "get_revision", return_value="new")
    mocker.patch.object(
        K8sClient,
        "list_revisions",
        return_value={
            f"{app}/0": "old",
            f"{app}/1": "new",
            f"{app}/2": "new",
        },
    )
    partition = [1]
    mocker.patch.object(K8sClient, "get_partition", side_effect=lambda: partition[0])
    mocker.patch.object(
        K8sClient, "set_partition", side_effect=lambda value: partition.__setitem__(0, value)
    )

    charm.upgrades_manager.reconcile_partition()
    assert partition[0] == 1

    # Continue the upgrade only after the peer passes its post-start health checks.
    with harness.hooks_disabled():
        harness.update_relation_data(relation.id, f"{app}/1", {"state": "healthy"})
    charm.upgrades_manager.reconcile_partition()
    assert partition[0] == 0


@pytest.mark.parametrize("patch_applied", [False, True])
def test_lost_partition_response_preserves_resume_decision(
    recovering_upgrade, harness, mocker, patch_applied
):
    """A timeout must not resume a paused upgrade or undo a resume that succeeded."""
    charm = recovering_upgrade.charm
    relation = harness.model.get_relation(UPGRADE_RELATION)
    app = charm.app.name
    with harness.hooks_disabled():
        harness.set_leader(True)
        for unit in (1, 2):
            harness.add_relation_unit(relation.id, f"{app}/{unit}")
            harness.update_relation_data(relation.id, f"{app}/{unit}", {"state": "healthy"})
    mocker.patch.object(K8sClient, "get_revision", return_value="new")
    mocker.patch.object(
        K8sClient,
        "list_revisions",
        return_value={
            f"{app}/0": "old",
            f"{app}/1": "old",
            f"{app}/2": "new",
        },
    )
    partition = [2]
    mocker.patch.object(K8sClient, "get_partition", side_effect=lambda: partition[0])

    def patch_then_lose_response(value):
        if patch_applied:
            partition[0] = value
        raise OpenSearchK8sError("Partition response timed out")

    patch = mocker.patch.object(K8sClient, "set_partition", side_effect=patch_then_lose_response)
    with pytest.raises(ActionFailed, match="Partition response timed out"):
        harness.run_action("resume-upgrade")

    # Read the partition from Kubernetes again without repeating the resume action.
    charm.upgrades_manager.reconcile_partition()
    assert partition[0] == (1 if patch_applied else 2)
    patch.assert_called_once_with(1)


def test_ready_state_survives_failed_partition_reconciliation(recovering_upgrade, harness, mocker):
    """Keep HEALTHY after health checks pass, even if the next Kubernetes request fails."""
    charm = recovering_upgrade.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(K8sClient, "list_revisions", return_value={charm.unit.name: "revision-0"})
    partition = mocker.patch.object(
        K8sClient, "get_partition", side_effect=OpenSearchK8sError("Cannot read partition")
    )
    event = mocker.Mock()
    charm.opensearch_events._on_peer_relation_changed(event)
    event.defer.assert_called_once_with()
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY

    partition.side_effect = None
    partition.return_value = 0
    charm.upgrade_events._reconcile_upgrade()
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY
