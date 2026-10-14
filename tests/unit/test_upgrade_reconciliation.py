# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Recovery of Kubernetes rolling upgrades through lifecycle events."""

from types import SimpleNamespace
from unittest.mock import PropertyMock

import pytest

from opensearch_single_kernel.common.constants import UPGRADE_RELATION, HealthColors
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchNotFullyReadyError,
)
from opensearch_single_kernel.core.models import UnitUpgradesState, UpgradeVersions
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
