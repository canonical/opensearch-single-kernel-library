# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Upgrade decisions require every planned unit to be visible."""

from unittest.mock import PropertyMock

import pytest
from ops.testing import ActionFailed

from opensearch_single_kernel.common.exceptions import OpenSearchUpgradePrecheckError
from opensearch_single_kernel.common.statuses import UpgradesStatuses
from opensearch_single_kernel.core.models import UnitUpgradesState, UpgradeVersions


@pytest.fixture
def incomplete_upgrade(harness, mocker):
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.set_planned_units(3)
        charm.state.application_upgrade.versions = UpgradeVersions(charm="1", workload="2.19.4")
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    return charm


def test_incomplete_membership_does_not_commit_application_versions(incomplete_upgrade, mocker):
    charm = incomplete_upgrade
    previous = charm.state.application_upgrade.versions
    mocker.patch.object(
        type(charm.upgrades_manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=UpgradeVersions(charm="2", workload="2.19.6"),
    )
    charm.upgrade_events._reconcile_upgrade()
    assert charm.state.application_upgrade.versions == previous


def test_precheck_rejects_incomplete_upgrade_membership(incomplete_upgrade):
    with pytest.raises(OpenSearchUpgradePrecheckError, match="upgrade peer"):
        incomplete_upgrade.upgrades_manager.pre_upgrade_check()


def test_resume_rejects_incomplete_upgrade_membership(incomplete_upgrade, harness, mocker):
    charm = incomplete_upgrade
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=True
    )
    with pytest.raises(ActionFailed, match="upgrade peer"):
        harness.run_action("resume-upgrade")


@pytest.mark.parametrize("revision", [None, "old"])
@pytest.mark.parametrize("state", [UnitUpgradesState.RESTARTING, UnitUpgradesState.UPGRADING])
def test_app_remains_upgrading_until_pending_unit_checks_finish(harness, mocker, revision, state):
    manager = harness.charm.upgrades_manager
    unit = harness.charm.state.server_upgrade
    unit.unit_state = state
    if revision:
        unit.unit_state_revision = revision
    mocker.patch.object(
        type(manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(
        type(manager),
        "_unit_workload_container_versions",
        new_callable=PropertyMock,
        return_value={harness.charm.unit.name: "same"},
    )
    assert manager.app_status == UpgradesStatuses.UPGRADES_UPGRADING.value
    unit.unit_state = UnitUpgradesState.HEALTHY
    unit.unit_state_revision = "same"
    assert manager.app_status is None


def test_deferred_machine_upgrade_waits_for_membership(incomplete_upgrade, mocker, substrate):
    if substrate != "vm":
        pytest.skip("Machine upgrade event")
    charm = incomplete_upgrade
    lock = mocker.patch.object(charm.lock_manager, "acquire")
    event = mocker.Mock()
    charm.upgrade_events._upgrade_opensearch(event)
    lock.assert_not_called()
    event.defer.assert_called_once()


def test_unchanged_revision_without_old_receipts_can_record_charm_version(harness, mocker):
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
        charm.state.application_upgrade.versions = UpgradeVersions(charm="1", workload="2.19.5")
    current = UpgradeVersions(charm="2", workload="2.19.5")
    for name, value in {"in_progress": False, "current_versions": current}.items():
        mocker.patch.object(
            type(charm.upgrades_manager), name, new_callable=PropertyMock, return_value=value
        )
    charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    mocker.patch.object(charm.upgrades_manager, "reconcile_partition")

    charm.upgrade_events._reconcile_upgrade(during_upgrade=True)

    assert charm.state.application_upgrade.versions == current
