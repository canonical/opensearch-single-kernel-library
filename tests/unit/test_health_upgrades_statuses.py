# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for health and upgrades pure status compute."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from opensearch_single_kernel.common.constants import HealthColors
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    HealthStatuses,
    UpgradesStatuses,
)
from opensearch_single_kernel.managers.health import HealthManager
from opensearch_single_kernel.managers.upgrades_base import UpgradesManagerBase


class _UpgradesManager(UpgradesManagerBase):
    """Minimal concrete upgrades manager for unit tests."""

    def __init__(self, state, workload, unit_status=None, unit_params=None, app_status=None):
        # Skip base __init__ reconcile of compatibility matrix.
        self.state = state
        self.workload = workload
        self.name = "upgrades_manager"
        self._unit_status = unit_status
        self._unit_params = unit_params
        self._app_status = app_status

    @property
    def in_progress(self) -> bool:
        return bool(self._app_status)

    @property
    def unit_status(self):
        return self._unit_status, self._unit_params

    @property
    def app_status(self):
        return self._app_status

    @property
    def unit_state(self):
        return None

    def reconcile_partition(self, *, action_event=None, force=False) -> None:
        return None

    def save_upgrades_versions(self) -> None:
        return None

    @property
    def _unit_workload_container_versions(self) -> dict[str, str]:
        return {}

    @property
    def _app_workload_container_version(self) -> str:
        return ""


def test_health_red_app_status_merges_running():
    state = MagicMock()
    running = SimpleNamespace(status="maintenance", message="something")
    state.statuses.get.return_value = SimpleNamespace(root=[running])
    mgr = HealthManager(state, MagicMock())
    mgr.get = MagicMock(return_value=HealthColors.RED)

    statuses = mgr.get_statuses("app", recompute=False)

    assert running in statuses
    assert HealthStatuses.CLUSTER_HEALTH_RED.value in statuses
    mgr.get.assert_called_once_with(wait_for_green_first=False)


def test_health_recompute_waits_for_green():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    mgr = HealthManager(state, MagicMock())
    mgr.get = MagicMock(return_value=HealthColors.GREEN)

    assert mgr.get_statuses("app", recompute=True) == [GeneralStatuses.ACTIVE_IDLE.value]
    mgr.get.assert_called_once_with(wait_for_green_first=True)


def test_upgrades_unit_status_merged_with_running():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    mgr = _UpgradesManager(
        state,
        MagicMock(),
        unit_status=UpgradesStatuses.UPGRADES_UPGRADING.value,
        unit_params=None,
    )

    statuses = mgr.get_statuses("unit")

    assert UpgradesStatuses.UPGRADES_UPGRADING.value in statuses


def test_upgrades_app_incompatible():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    mgr = _UpgradesManager(
        state,
        MagicMock(),
        app_status=UpgradesStatuses.UPGRADES_INCOMPATIBLE.value,
    )

    statuses = mgr.get_statuses("app")

    assert UpgradesStatuses.UPGRADES_INCOMPATIBLE.value in statuses


def test_upgrades_vm_precheck_failed_message():
    from opensearch_single_kernel.common.constants import OPENSEARCH_SNAP_REVISION
    from opensearch_single_kernel.managers.upgrades_vm import UpgradesManagerVM

    state = MagicMock()
    state.upgrade_relation = object()
    state.server_upgrade.precheck_failed_message = "Cluster health is yellow"
    state.server_upgrade.snap_revision = "old-revision"

    mgr = UpgradesManagerVM.__new__(UpgradesManagerVM)
    mgr.state = state
    mgr.workload = MagicMock()
    mgr.name = "upgrades_manager"

    status, params = mgr.unit_status
    assert status == UpgradesStatuses.UPGRADES_PRE_UPGRADE_CHECK_FAILED.value
    assert params == {"message": "Cluster health is yellow"}

    # Once upgraded, precheck flag must not shadow active status
    state.server_upgrade.snap_revision = OPENSEARCH_SNAP_REVISION
    state.server_upgrade.workload_version = "2.0.0"
    type(mgr).in_progress = property(lambda self: True)  # type: ignore[method-assign]
    type(mgr).is_rollback = property(lambda self: False)  # type: ignore[method-assign]
    type(mgr).current_versions = property(  # type: ignore[method-assign]
        lambda self: SimpleNamespace(charm="1", workload="2.0.0")
    )

    status, params = mgr.unit_status
    assert status == UpgradesStatuses.UPGRADES_ACTIVE.value
    assert params is not None
