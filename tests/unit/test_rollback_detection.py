# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Rollback recovery remains available to units after the first one."""

from unittest.mock import PropertyMock

import pytest
from ops.testing import ActionFailed

from opensearch_single_kernel.common.constants import UPGRADE_RELATION
from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.common.statuses import UpgradesStatuses
from opensearch_single_kernel.core.models import UnitUpgradesState, UpgradeVersions


@pytest.fixture
def rollback_unit(harness, mocker):
    charm = harness.charm
    manager = charm.upgrades_manager
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.set_planned_units(3)
        relation = harness.model.get_relation(UPGRADE_RELATION)
        for number in (1, 2):
            harness.add_relation_unit(relation.id, f"{charm.app.name}/{number}")
        charm.state.application_upgrade.versions = UpgradeVersions(charm="1", workload="2.19.4")
        charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
        charm.state.server_upgrade.workload_version = "2.19.6"
        charm.state.server_upgrade.snap_revision = "193"
    mocker.patch(
        "opensearch_single_kernel.managers.upgrades_vm.pinned_snap_revision", return_value="98"
    )
    mocker.patch.object(
        type(manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=UpgradeVersions(charm="1", workload="2.19.4"),
    )
    mocker.patch.object(manager.workload, "is_service_started", return_value=False)
    for method in ("run_cmd", "run_script"):
        mocker.patch.object(
            manager.workload,
            method,
            side_effect=OpenSearchCmdError(
                cmd="override-version",
                err="This data was last written by OpenSearch version [2.19.6]",
            ),
        )
    mocker.patch.object(
        manager, "reconcile_compatibility_matrix", return_value={"2.19.6": {"2.19.4"}}
    )
    return manager


@pytest.mark.parametrize("in_progress", [True, False])
def test_lower_unit_detects_rollback_until_validation_finishes(rollback_unit, mocker, in_progress):
    manager = rollback_unit
    mocker.patch.object(
        type(manager), "in_progress", new_callable=PropertyMock, return_value=in_progress
    )

    assert manager.is_rollback
    assert manager.can_rollback
    assert manager.unit_status[0] == UpgradesStatuses.UPGRADES_ROLLBACK_INCOMPATIBLE.value


@pytest.mark.parametrize("in_progress", [True, False])
def test_lower_unit_recovery_requires_explicit_override(
    rollback_unit, harness, mocker, in_progress
):
    mocker.patch.object(
        type(rollback_unit), "in_progress", new_callable=PropertyMock, return_value=in_progress
    )

    with pytest.raises(ActionFailed, match="check-compatibility"):
        harness.run_action("force-refresh-start")


@pytest.mark.parametrize("in_progress", [True, False])
def test_lower_unit_override_uses_the_existing_recovery_flow(
    rollback_unit, harness, mocker, substrate, in_progress
):
    charm = harness.charm
    mocker.patch.object(
        type(rollback_unit), "in_progress", new_callable=PropertyMock, return_value=in_progress
    )
    override = mocker.patch.object(rollback_unit, "override_version")
    upgrade = mocker.patch.object(charm.upgrade_events, "_upgrade_opensearch")
    start = mocker.patch.object(charm.opensearch_events, "_on_start_opensearch")

    result = harness.run_action("force-refresh-start", {"check-compatibility": False})

    assert "Requested startup" in result.results["result"]
    if substrate == "vm":
        upgrade.assert_called_once()
        assert upgrade.call_args.args[0].override_version
        assert not upgrade.call_args.args[0].ignore_lock
        override.assert_not_called()
        start.assert_not_called()
    else:
        override.assert_called_once_with()
        start.assert_called_once()
        assert start.call_args.args[0].after_upgrade
        assert not start.call_args.args[0].ignore_lock
        upgrade.assert_not_called()


def test_lower_unit_preserves_rollback_compatibility_guidance(rollback_unit, mocker):
    mocker.patch.object(
        type(rollback_unit), "in_progress", new_callable=PropertyMock, return_value=True
    )
    mocker.patch.object(rollback_unit, "reconcile_compatibility_matrix", return_value={})

    assert rollback_unit.is_rollback
    assert not rollback_unit.can_rollback
    assert rollback_unit.unit_status[0] == UpgradesStatuses.UPGRADES_ROLLBACK_UNSUPPORTED.value


def test_lower_unit_can_start_after_version_override(rollback_unit, mocker):
    mocker.patch.object(
        type(rollback_unit), "in_progress", new_callable=PropertyMock, return_value=True
    )
    mocker.patch.object(rollback_unit, "get_version_before_override", return_value=None)

    assert not rollback_unit.is_rollback


@pytest.mark.parametrize("previous", [None, "2.19.5", "2.19.6"])
def test_rollback_detection_requires_the_previous_validated_version(
    rollback_unit, mocker, previous
):
    manager = rollback_unit
    if previous:
        manager.state.application_upgrade.versions = UpgradeVersions(charm="1", workload=previous)
    else:
        manager.state.application_upgrade.update({"versions": None})
    mocker.patch.object(type(manager), "in_progress", new_callable=PropertyMock, return_value=True)
    probe = mocker.patch.object(manager, "get_version_before_override")

    assert not manager.is_rollback
    probe.assert_not_called()


def test_finished_upgrade_does_not_probe_for_rollback(rollback_unit, mocker):
    manager = rollback_unit
    manager.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    mocker.patch.object(
        type(manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    probe = mocker.patch.object(manager, "get_version_before_override")

    assert not manager.is_rollback
    probe.assert_not_called()


def test_rollback_to_validated_revision_still_checks_newer_workload(
    rollback_unit, harness, mocker
):
    manager = rollback_unit
    unit = harness.charm.state.server_upgrade
    unit.unit_state_revision = "original"
    mocker.patch.object(
        type(manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(
        type(manager),
        "_unit_workload_container_versions",
        new_callable=PropertyMock,
        return_value={harness.charm.unit.name: "original"},
    )

    assert manager.upgrade_checks_pending
    assert manager.is_rollback
    assert manager.can_rollback
    assert manager.unit_status[0] == UpgradesStatuses.UPGRADES_ROLLBACK_INCOMPATIBLE.value
    with pytest.raises(ActionFailed, match="check-compatibility"):
        harness.run_action("force-refresh-start")
