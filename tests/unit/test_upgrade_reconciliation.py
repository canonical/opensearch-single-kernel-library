# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Recovery of Kubernetes rolling upgrades through lifecycle events."""

from types import SimpleNamespace
from unittest.mock import PropertyMock

import pytest
from ops.testing import ActionFailed

from opensearch_single_kernel.common.constants import UPGRADE_RELATION, HealthColors, Substrates
from opensearch_single_kernel.common.exceptions import (
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchK8sError,
    OpenSearchNotFullyReadyError,
    OpenSearchUpgradePrecheckError,
)
from opensearch_single_kernel.common.k8s import K8sClient
from opensearch_single_kernel.core.models import UnitUpgradesState, UpgradeVersions
from opensearch_single_kernel.core.upgrade_relation import UpgradeServerState
from opensearch_single_kernel.managers.upgrades_k8s import UpgradesManagerK8s
from tests.unit.helpers import deployment_descriptions


@pytest.mark.parametrize("units", [1, 3])
@pytest.mark.parametrize("initial_partition", [0, 5])
def test_precheck_protects_first_replacement_before_refresh(
    harness, mocker, substrate, units, initial_partition
):
    """Keep the K8s partition in place between the successful check and the refresh."""
    charm = harness.charm
    relation = harness.model.get_relation(UPGRADE_RELATION)
    with harness.hooks_disabled():
        harness.set_leader(True)
        for number in range(1, units):
            harness.add_relation_unit(relation.id, f"{charm.app.name}/{number}")
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(charm.upgrade_events, "_run_general_prechecks")
    mocker.patch.object(charm.upgrades_manager, "pre_upgrade_check")
    partition = [initial_partition]
    mocker.patch.object(K8sClient, "get_partition", side_effect=lambda: partition[0])
    patch = mocker.patch.object(
        K8sClient, "set_partition", side_effect=lambda value: partition.__setitem__(0, value)
    )

    result = harness.run_action("pre-upgrade-check")

    assert result.results["result"] == "Charm is ready for upgrade"
    if substrate == "vm":
        patch.assert_not_called()
        return
    assert partition[0] == units - 1

    # A peer event before juju refresh must not undo the protection.
    charm.upgrades_manager.reconcile_partition()
    assert partition[0] == units - 1


@pytest.mark.parametrize("write_applied", [False, True])
def test_precheck_fails_if_partition_write_is_not_confirmed(
    harness, mocker, substrate, write_applied
):
    if substrate != "k8s":
        pytest.skip("Kubernetes rollout protection")
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
        relation = harness.model.get_relation(UPGRADE_RELATION)
        for number in (1, 2):
            harness.add_relation_unit(relation.id, f"{charm.app.name}/{number}")
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(charm.upgrade_events, "_run_general_prechecks")
    mocker.patch.object(charm.upgrades_manager, "pre_upgrade_check")
    partition = [0]

    def failed_patch(value):
        if write_applied:
            partition[0] = value
        raise OpenSearchK8sError("Partition write timed out")

    patch = mocker.patch.object(K8sClient, "set_partition", side_effect=failed_patch)

    with pytest.raises(ActionFailed, match="Cannot protect the Kubernetes rolling upgrade"):
        harness.run_action("pre-upgrade-check")
    assert partition[0] == (2 if write_applied else 0)

    patch.side_effect = lambda value: partition.__setitem__(0, value)
    assert (
        harness.run_action("pre-upgrade-check").results["result"] == "Charm is ready for upgrade"
    )
    assert partition[0] == 2


def test_failed_health_precheck_does_not_change_partition(harness, mocker):
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(
        charm.upgrade_events,
        "_run_general_prechecks",
        side_effect=OpenSearchUpgradePrecheckError("Cluster health is red"),
    )
    patch = mocker.patch.object(K8sClient, "set_partition")

    with pytest.raises(ActionFailed, match="Cluster health is red"):
        harness.run_action("pre-upgrade-check")

    patch.assert_not_called()


def test_replacement_cannot_reuse_the_previous_revision_health(paused_upgrade, harness, mocker):
    """Pod revisions can arrive before the old pod's RESTARTING relation update."""
    trial = paused_upgrade
    app = trial.charm.app.name
    with harness.hooks_disabled():
        harness.update_relation_data(trial.relation.id, f"{app}/2", {"state-revision": "new"})
        harness.update_relation_data(trial.relation.id, f"{app}/1", {"state-revision": "old"})
    mocker.patch.object(
        K8sClient,
        "list_revisions",
        return_value={f"{app}/0": "old", f"{app}/1": "new", f"{app}/2": "new"},
    )
    trial.partition[0] = 1

    trial.charm.upgrades_manager.reconcile_partition()

    assert trial.partition[0] == 1
    trial.patch.assert_not_called()

    with harness.hooks_disabled():
        harness.update_relation_data(trial.relation.id, f"{app}/1", {"state-revision": "new"})
    trial.charm.upgrades_manager.reconcile_partition()
    assert trial.partition[0] == 0


def test_replacement_checks_health_even_if_old_state_says_healthy(recovering_upgrade, mocker):
    charm = recovering_upgrade.charm
    charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    charm.state.server_upgrade.relation_data["state-revision"] = "old"
    mocker.patch.object(K8sClient, "list_revisions", return_value={charm.unit.name: "new"})
    charm.cluster_manager.assert_current_node_joined_cluster.side_effect = (
        OpenSearchNotFullyReadyError("Replacement has not rejoined")
    )

    charm.upgrade_events._reconcile_upgrade()

    charm.cluster_manager.assert_current_node_joined_cluster.assert_called_once()
    assert charm.state.server_upgrade.relation_data["state-revision"] == "old"

    charm.cluster_manager.assert_current_node_joined_cluster.side_effect = None
    charm.upgrade_events._reconcile_upgrade()
    assert charm.state.server_upgrade.relation_data["state-revision"] == "new"


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
    mocker.patch.object(K8sClient, "list_revisions", return_value={charm.unit.name: "new"})
    mocker.patch.object(K8sClient, "get_revision", return_value="new")
    mocker.patch.object(
        type(charm.upgrades_manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=UpgradeVersions(charm="1", workload="2.19.6"),
    )
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


@pytest.mark.parametrize("previous,version", [("2.19.6", "2.19.5"), ("2.19.5", "2.19.6")])
@pytest.mark.parametrize(
    "health", [HealthColors.RED, HealthColors.YELLOW_TEMP, HealthColors.GREEN]
)
def test_final_unit_records_version_only_after_health_checks(
    recovering_upgrade, mocker, previous, version, health
):
    """The final pod can finish through normal startup after all pod revisions match."""
    charm = recovering_upgrade.charm
    charm.state.server_upgrade.workload_version = previous
    charm.state.server_upgrade.unit_state_revision = "old"
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(
        type(charm.upgrades_manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=UpgradeVersions(charm="1", workload=version),
    )
    charm.health_manager.get.return_value = health

    charm.upgrade_events._reconcile_upgrade()

    if health == HealthColors.GREEN:
        assert charm.state.server_upgrade.workload_version == version
        assert charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY
        assert charm.state.server_upgrade.unit_state_revision == "new"
    else:
        assert charm.state.server_upgrade.workload_version == previous
        assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING
        assert charm.state.server_upgrade.unit_state_revision == "old"
        assert charm.state.server_upgrade.post_upgrade_health == health


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

    def check_health_after_allocation(**kwargs):
        recovering_upgrade.allocation.assert_called()
        return HealthColors.GREEN

    charm.apply_health.side_effect = check_health_after_allocation
    charm.opensearch_events._post_start_init(mocker.Mock(after_upgrade=after_upgrade))

    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY


def test_replacement_retries_allocation_before_waiting_for_health(recovering_upgrade, mocker):
    charm = recovering_upgrade.charm
    mocker.patch.object(charm.cluster_manager, "wait_for_opensearch_up")
    mocker.patch.object(charm.cluster_manager, "apply_upstream_fixes")
    mocker.patch.object(charm.exclusions_manager, "delete_current")
    mocker.patch.object(charm.lock_manager, "release")
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=False)
    mocker.patch.object(charm.opensearch_events, "post_start_ca_rotation")
    recovering_upgrade.allocation.side_effect = OpenSearchHttpError()
    event = mocker.Mock(after_upgrade=False)

    charm.opensearch_events._post_start_init(event)

    event.defer.assert_called_once()
    charm.apply_health.assert_not_called()
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING


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
                    "state-revision": "new",
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
    charm.state.server_upgrade.post_upgrade_health = HealthColors.RED
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

    assert charm.state.server_upgrade.post_upgrade_health is None

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


def test_stop_without_upgrade_relation(recovering_upgrade, harness, mocker):
    charm = recovering_upgrade.charm
    with harness.hooks_disabled():
        harness.remove_relation(charm.state.upgrade_relation.id)
    mocker.patch.object(
        UpgradesManagerK8s, "in_progress", new_callable=PropertyMock, return_value=False
    )
    stop = mocker.patch.object(charm.pebble_observer, "stop")

    charm.opensearch_events._on_stop(mocker.Mock())

    stop.assert_called_once_with()


@pytest.mark.parametrize("failure_stage", ["upgrade-state", "partition", "write", "write-applied"])
def test_failed_shutdown_invalidates_readiness_before_replacement(
    recovering_upgrade, harness, mocker, failure_stage
):
    """A new pod revision must not inherit the old pod's HEALTHY state after an API failure."""
    charm = recovering_upgrade.charm
    charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    charm.state.server_upgrade.post_upgrade_health = HealthColors.RED
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

    assert charm.state.server_upgrade.post_upgrade_health is None

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
            harness.update_relation_data(
                relation.id, f"{app}/{unit}", {"state": state.value, "state-revision": "new"}
            )
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
        harness.update_relation_data(
            relation.id, f"{app}/1", {"state": "healthy", "state-revision": "new"}
        )
    charm.upgrades_manager.reconcile_partition()
    assert partition[0] == 0


@pytest.mark.parametrize("patch_applied", [False, True])
def test_lost_partition_response_preserves_resume_decision(
    recovering_upgrade, harness, mocker, patch_applied
):
    """Keep the request if the write failed, or clear it if Kubernetes applied the partition."""
    charm = recovering_upgrade.charm
    relation = harness.model.get_relation(UPGRADE_RELATION)
    app = charm.app.name
    with harness.hooks_disabled():
        harness.set_leader(True)
        for unit in (1, 2):
            harness.add_relation_unit(relation.id, f"{app}/{unit}")
            harness.update_relation_data(
                relation.id, f"{app}/{unit}", {"state": "healthy", "state-revision": "new"}
            )
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
    harness.run_action("resume-upgrade")
    patch.assert_not_called()

    with pytest.raises(OpenSearchK8sError, match="Partition response timed out"):
        charm.upgrade_events._reconcile_upgrade(during_upgrade=True)

    if patch_applied:
        # Read the partition from Kubernetes again without repeating the resume action.
        charm.upgrade_events._reconcile_upgrade(during_upgrade=True)
        assert charm.state.application_upgrade.resume_request is None
    else:
        assert charm.state.application_upgrade.resume_request is not None
    assert partition[0] == (1 if patch_applied else 2)
    patch.assert_called_once_with(1)


@pytest.fixture
def paused_upgrade(recovering_upgrade, harness, mocker):
    charm = recovering_upgrade.charm
    relation = harness.model.get_relation(UPGRADE_RELATION)
    app = charm.app.name
    with harness.hooks_disabled():
        harness.set_leader(True)
        for unit in (1, 2):
            harness.add_relation_unit(relation.id, f"{app}/{unit}")
            harness.update_relation_data(
                relation.id, f"{app}/{unit}", {"state": "healthy", "state-revision": "new"}
            )
    revisions = {f"{app}/0": "old", f"{app}/1": "old", f"{app}/2": "new"}
    mocker.patch.object(K8sClient, "list_revisions", return_value=revisions)
    revision = mocker.patch.object(K8sClient, "get_revision", return_value="new")
    partition = [2]
    mocker.patch.object(K8sClient, "get_partition", side_effect=lambda: partition[0])
    patch = mocker.patch.object(
        K8sClient, "set_partition", side_effect=lambda value: partition.__setitem__(0, value)
    )
    return SimpleNamespace(
        charm=charm, partition=partition, patch=patch, revision=revision, relation=relation
    )


def test_resume_action_finishes_before_replacing_any_pod(paused_upgrade, harness):
    trial = paused_upgrade

    result = harness.run_action("resume-upgrade")

    assert "requested" in result.results["result"].lower()
    assert trial.partition[0] == 2
    trial.patch.assert_not_called()
    assert trial.charm.state.application_upgrade.resume_request.partition == 1

    trial.charm.upgrade_events._reconcile_upgrade(during_upgrade=True)

    assert trial.partition[0] == 1
    assert trial.charm.state.application_upgrade.resume_request is None


def test_resume_request_does_not_apply_to_a_later_refresh(paused_upgrade, harness):
    trial = paused_upgrade
    harness.run_action("resume-upgrade")
    trial.revision.return_value = "another-refresh"

    trial.charm.upgrade_events._reconcile_upgrade(during_upgrade=True)

    trial.patch.assert_not_called()
    assert trial.charm.state.application_upgrade.resume_request is None


def test_resume_rechecks_health_before_advancing(paused_upgrade, harness):
    trial = paused_upgrade
    harness.run_action("resume-upgrade")
    with harness.hooks_disabled():
        harness.update_relation_data(
            trial.relation.id, f"{trial.charm.app.name}/2", {"state": "restarting"}
        )

    trial.charm.upgrade_events._reconcile_upgrade(during_upgrade=True)

    trial.patch.assert_not_called()
    assert trial.charm.state.application_upgrade.resume_request is not None


def test_forced_resume_only_approves_one_step(paused_upgrade, harness):
    trial = paused_upgrade
    with harness.hooks_disabled():
        harness.update_relation_data(
            trial.relation.id, f"{trial.charm.app.name}/2", {"state": "restarting"}
        )
    harness.run_action("resume-upgrade", {"force": True})
    trial.patch.assert_not_called()

    trial.charm.upgrade_events._reconcile_upgrade(during_upgrade=True)
    trial.charm.upgrade_events._reconcile_upgrade(during_upgrade=True)

    trial.patch.assert_called_once_with(1)
    assert trial.partition[0] == 1


def test_resume_request_waits_for_leader_and_survives_leadership_change(paused_upgrade, harness):
    trial = paused_upgrade
    harness.run_action("resume-upgrade")
    saved = harness.get_relation_data(trial.relation.id, trial.charm.app.name)["resume-request"]
    with harness.hooks_disabled():
        harness.set_leader(False)

    trial.charm.upgrade_events._reconcile_upgrade(during_upgrade=True)
    trial.patch.assert_not_called()
    assert (
        harness.get_relation_data(trial.relation.id, trial.charm.app.name)["resume-request"]
        == saved
    )

    with harness.hooks_disabled():
        harness.set_leader(True)
    trial.charm.upgrade_events._reconcile_upgrade(during_upgrade=True)

    assert trial.partition[0] == 1
    assert "resume-request" not in harness.get_relation_data(
        trial.relation.id, trial.charm.app.name
    )


def test_refresh_during_resume_validation_cannot_approve_the_new_revision(
    paused_upgrade, harness, mocker
):
    trial = paused_upgrade

    def refresh_during_validation(**kwargs):
        trial.revision.return_value = "later-refresh"
        return 1

    mocker.patch.object(
        trial.charm.upgrades_manager, "get_resume_partition", side_effect=refresh_during_validation
    )
    harness.run_action("resume-upgrade")
    assert trial.charm.state.application_upgrade.resume_request.revision == "new"

    trial.charm.upgrade_events._reconcile_upgrade(during_upgrade=True)

    trial.patch.assert_not_called()
    assert trial.charm.state.application_upgrade.resume_request is None


def test_accepted_resume_does_not_keep_asking_for_the_action(paused_upgrade, harness):
    trial = paused_upgrade
    assert trial.charm.upgrades_manager.app_status.status == "blocked"

    harness.run_action("resume-upgrade")

    assert trial.charm.upgrades_manager.app_status.status == "waiting"
    assert "requested" in trial.charm.upgrades_manager.app_status.message.lower()


@pytest.mark.parametrize("health", [HealthColors.RED, HealthColors.YELLOW])
def test_pending_resume_does_not_hide_cluster_health_failure(
    paused_upgrade, harness, mocker, health
):
    charm = paused_upgrade.charm
    harness.run_action("resume-upgrade")
    mocker.patch.object(
        type(charm.upgrades_manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=UpgradeVersions(charm="1", workload="2.19.6"),
    )
    charm.health_manager.get.return_value = health
    charm.status_handler.components = (charm.upgrades_manager, charm.health_manager)
    event = mocker.Mock()

    charm.status_handler._on_collect_app_status(event)

    status = event.add_status.call_args.args[0]
    assert status.name == "blocked"
    assert "unassigned" in status.message.lower()


def test_forced_resume_progresses_when_leader_workload_is_down(paused_upgrade, harness, mocker):
    trial = paused_upgrade
    trial.charm.status_handler.components = ()
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=False
    )
    harness.run_action("resume-upgrade", {"force": True})

    trial.charm.on.update_status.emit()

    assert trial.partition[0] == 1
    assert trial.charm.state.application_upgrade.resume_request is None


def test_pending_resume_does_not_prevent_local_upgrade_recovery(paused_upgrade, harness, mocker):
    trial = paused_upgrade
    harness.run_action("resume-upgrade")
    # This unit has rejoined, but normal start still needs to mark it HEALTHY.
    with harness.hooks_disabled():
        trial.charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING

    trial.charm.upgrade_events._reconcile_upgrade()

    assert trial.charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY
    assert trial.partition[0] == 1


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


@pytest.mark.parametrize("previous_failure", [None, HealthColors.RED])
def test_reconciliation_records_first_and_repeated_upgrade_health_failure(
    recovering_upgrade, previous_failure
):
    charm = recovering_upgrade.charm
    charm.state.server_upgrade.post_upgrade_health = previous_failure
    charm.health_manager.get.return_value = HealthColors.RED

    charm.upgrade_events._reconcile_upgrade()

    assert charm.state.server_upgrade.post_upgrade_health == HealthColors.RED
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING
    charm.health_manager.get.return_value = HealthColors.GREEN
    charm.upgrade_events._reconcile_upgrade()
    assert charm.state.server_upgrade.post_upgrade_health is None
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY


@pytest.mark.skip_if_substrate("vm")
@pytest.mark.parametrize("condition", ["last-pod", "incompatible", "rollback", "tls-error"])
def test_upgrade_restores_tls_without_bypassing_startup_checks(harness, mocker, condition):
    """Runtime files are needed even when no pod revisions remain to be replaced."""
    charm = harness.charm
    mocker.patch.object(charm.config_manager, "update_opensearch_config")
    restore = mocker.patch.object(
        charm.tls_manager,
        "reconcile_k8s_runtime_resources",
        side_effect=OpenSearchFileOperationError("Cannot restore chain.pem")
        if condition == "tls-error"
        else None,
    )
    mocker.patch.object(
        type(charm.upgrades_manager),
        "in_progress",
        new_callable=PropertyMock,
        return_value=condition != "last-pod",
    )
    mocker.patch.object(
        type(charm.upgrades_manager),
        "is_compatible",
        new_callable=PropertyMock,
        return_value=condition != "incompatible",
    )
    mocker.patch.object(
        type(charm.upgrades_manager),
        "is_rollback",
        new_callable=PropertyMock,
        return_value=condition == "rollback",
    )
    start = mocker.patch.object(type(charm.start_opensearch_event), "emit")
    partition = mocker.patch.object(K8sClient, "set_partition")
    event = mocker.Mock()

    charm.upgrade_events.kubernetes_upgrade(event)

    restore.assert_called_once_with()
    start.assert_not_called()
    partition.assert_not_called()
    assert event.defer.call_count == (condition in ("rollback", "tls-error"))


@pytest.mark.parametrize("failure_stage", ["configuration", "tls", "post-start"])
@pytest.mark.parametrize(
    "initial_state", [UnitUpgradesState.HEALTHY, UnitUpgradesState.RESTARTING]
)
def test_deferred_upgrade_preserves_current_health_failure(
    recovering_upgrade, mocker, failure_stage, initial_state
):
    charm = recovering_upgrade.charm
    charm.state.server_upgrade.unit_state = initial_state
    charm.state.server_upgrade.post_upgrade_health = HealthColors.RED
    mocker.patch.object(
        type(charm.upgrades_manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=UpgradeVersions(charm="1", workload="2.19.6"),
    )
    mocker.patch.object(
        charm.config_manager,
        "update_opensearch_config",
        side_effect=(
            OpenSearchFileOperationError("Cannot write configuration")
            if failure_stage == "configuration"
            else None
        ),
    )
    mocker.patch.object(charm.cluster_manager, "no_blocking_directives", return_value=True)
    mocker.patch.object(
        charm.tls_manager, "all_tls_resources_stored", return_value=failure_stage != "tls"
    )
    mocker.patch.object(charm.ldap_manager, "restore_ldap_ca")
    mocker.patch.object(charm.snapshots_events, "restore_stored_credentials")
    mocker.patch.object(charm.notifications_events, "restore_keystore_credentials")
    mocker.patch.object(charm.upgrade_events, "_publish_app_upgrade_status")

    def fail_new_health_check(event):
        assert event.after_upgrade
        assert event.ignore_lock
        assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING
        assert charm.state.server_upgrade.post_upgrade_health == HealthColors.RED
        charm.upgrades_manager.record_upgrade_health(HealthColors.RED)

    start = mocker.patch.object(
        charm.opensearch_events, "_start_opensearch", side_effect=fail_new_health_check
    )
    event = mocker.Mock()

    charm.upgrade_events.kubernetes_upgrade(event)

    if failure_stage == "post-start":
        start.assert_called_once()
        assert charm.state.server_upgrade.post_upgrade_health == HealthColors.RED
    else:
        start.assert_not_called()
        event.defer.assert_called_once_with()
        assert charm.state.server_upgrade.post_upgrade_health == HealthColors.RED


@pytest.mark.parametrize("initial_state", [None, UnitUpgradesState.RESTARTING])
def test_reconciliation_does_not_label_initial_or_unchanged_start_as_failed_upgrade(
    recovering_upgrade, initial_state
):
    charm = recovering_upgrade.charm
    if initial_state is None:
        charm.state.server_upgrade.relation_data.pop("state")
    else:
        charm.state.server_upgrade.unit_state = initial_state
        charm.state.server_upgrade.unit_state_revision = "new"
    charm.health_manager.get.return_value = HealthColors.RED

    charm.upgrade_events._reconcile_upgrade()

    assert charm.state.server_upgrade.post_upgrade_health is None


def test_new_revision_cannot_keep_old_healthy_state_after_failed_validation(recovering_upgrade):
    charm = recovering_upgrade.charm
    charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    charm.state.server_upgrade.unit_state_revision = "old"
    charm.health_manager.get.return_value = HealthColors.RED

    charm.upgrade_events._reconcile_upgrade()

    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING
    assert charm.state.server_upgrade.unit_state_revision == "old"
    assert charm.state.server_upgrade.post_upgrade_health == HealthColors.RED


@pytest.mark.parametrize("compatible", [False, True])
def test_final_validation_preserves_previous_app_version_until_success(
    recovering_upgrade, harness, mocker, compatible
):
    charm = recovering_upgrade.charm
    previous = charm.state.application_upgrade.versions
    with harness.hooks_disabled():
        harness.set_leader(True)
    charm.state.server_upgrade.unit_state_revision = "old"
    recovering_upgrade.compatible.return_value = compatible
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(charm.upgrades_manager, "reconcile_partition")
    charm.health_manager.get.return_value = HealthColors.RED

    charm.upgrade_events._reconcile_upgrade()

    assert charm.state.application_upgrade.versions == previous
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING
    assert charm.state.server_upgrade.post_upgrade_health == HealthColors.RED

    charm.health_manager.get.return_value = HealthColors.GREEN
    charm.upgrade_events._reconcile_upgrade()

    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY
    assert charm.state.server_upgrade.unit_state_revision == "new"
    assert charm.state.application_upgrade.versions == charm.upgrades_manager.current_versions


@pytest.mark.skip_if_substrate("vm")
@pytest.mark.parametrize("running,start_failed", [(False, False), (True, False), (False, True)])
def test_k8s_refresh_reports_pending_start_before_preparing_workload(
    harness, mocker, running, start_failed
):
    from ops import ActiveStatus, BlockedStatus

    from opensearch_single_kernel.common.statuses import GeneralStatuses

    charm = harness.charm
    charm.state.server.start_failed = start_failed
    charm.unit.status = (
        BlockedStatus(GeneralStatuses.SERVICE_START_ERROR.value.message)
        if start_failed
        else ActiveStatus("OpenSearch running")
    )
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=running)
    observed = []
    mocker.patch.object(
        charm.upgrades_manager,
        "reconcile_compatibility_matrix",
        side_effect=lambda: observed.append(charm.unit.status),
    )
    mocker.patch.object(charm.upgrades_manager, "update_grafana_dashboards_title")
    mocker.patch("opensearch_single_kernel.events.upgrades.get_charm_revision", return_value="1")
    mocker.patch.object(charm.upgrade_events, "kubernetes_upgrade")

    charm.upgrade_events._on_upgrade_charm(mocker.Mock())

    if start_failed:
        assert observed[0] == BlockedStatus(GeneralStatuses.SERVICE_START_ERROR.value.message)
    elif running:
        assert observed[0] == ActiveStatus("OpenSearch running")
    else:
        assert observed[0].name == "waiting"
        assert observed[0].message == GeneralStatuses.WAITING_TO_START.value.message
