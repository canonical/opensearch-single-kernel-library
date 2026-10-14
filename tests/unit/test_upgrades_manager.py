# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for upgrade manager statuses."""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest

from opensearch_single_kernel.common.constants import Substrates
from opensearch_single_kernel.common.statuses import UpgradesStatuses
from opensearch_single_kernel.managers.upgrades_base import UpgradesManagerBase
from opensearch_single_kernel.managers.upgrades_k8s import UpgradesManagerK8s
from opensearch_single_kernel.managers.upgrades_vm import UpgradesManagerVM
from opensearch_single_kernel.utils.status import format_status


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

    @property
    def upgrade_resumed(self):
        return False

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


def test_upgrades_merges_cached_precheck_failed():
    cached = format_status(
        UpgradesStatuses.UPGRADES_PRE_UPGRADE_CHECK_FAILED.value,
        {"message": "Cluster health is yellow"},
    )
    state = MagicMock()
    state.statuses.get.side_effect = lambda *a, **k: SimpleNamespace(
        root=[] if k.get("running_status_only") else [cached]
    )
    mgr = _UpgradesManager(state, MagicMock())

    statuses = mgr.get_statuses("unit")

    assert cached in statuses


@pytest.mark.parametrize(
    "manager_class,substrate,partition,resumed,expected",
    [
        (
            UpgradesManagerK8s,
            Substrates.K8S,
            2,
            True,
            UpgradesStatuses.UPGRADES_WAITING_FOR_RESUME,
        ),
        (UpgradesManagerK8s, Substrates.K8S, 1, False, UpgradesStatuses.UPGRADES_UPGRADING),
        (UpgradesManagerK8s, Substrates.K8S, 0, False, UpgradesStatuses.UPGRADES_UPGRADING),
        (
            UpgradesManagerVM,
            Substrates.VM,
            None,
            False,
            UpgradesStatuses.UPGRADES_WAITING_FOR_RESUME,
        ),
        (UpgradesManagerVM, Substrates.VM, None, True, UpgradesStatuses.UPGRADES_UPGRADING),
    ],
)
def test_app_upgrade_resume_status(mocker, manager_class, substrate, partition, resumed, expected):
    """K8s status follows its partition; VM status follows the stored resume flag."""
    manager = manager_class.__new__(manager_class)
    manager.state = MagicMock()
    manager.state.substrate = substrate
    manager.state.application_upgrade.upgrade_resumed = resumed
    manager.state.sorted_upgrades_units = [SimpleNamespace(unit_number=i) for i in (2, 1, 0)]
    mocker.patch.object(manager_class, "in_progress", new_callable=PropertyMock, return_value=True)
    mocker.patch.object(
        manager_class, "is_compatible", new_callable=PropertyMock, return_value=True
    )
    k8s_client = MagicMock()
    k8s_client.get_partition.return_value = partition
    mocker.patch.object(
        manager_class, "k8s_client", new_callable=PropertyMock, return_value=k8s_client
    )

    assert manager.app_status == expected.value
