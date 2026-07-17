# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for snapshots pure status compute (failure flags)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from opensearch_single_kernel.common.statuses import GeneralStatuses, SnapshotsStatuses
from opensearch_single_kernel.managers.snapshots import SnapshotsManager
from opensearch_single_kernel.utils.status import format_status


def _mgr(state) -> SnapshotsManager:
    mgr = SnapshotsManager.__new__(SnapshotsManager)
    mgr.state = state
    mgr.workload = MagicMock()
    mgr.name = "snapshots_manager"
    return mgr


def test_get_statuses_repo_misconfigured_from_flag():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.application.backup_repo_misconfigured_storage_type = "s3"
    state.application.backup_credentials_cleanup_failed = False
    state.application.deployment_desc = None

    statuses = _mgr(state).get_statuses("app")

    expected = format_status(
        SnapshotsStatuses.BACKUP_REPOSITORY_MISCONFIGURED.value,
        {"storage_type": "s3", "integrator": "s3 integrator"},
    )
    assert expected in statuses


def test_get_statuses_cleanup_failed_from_flag():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.application.backup_repo_misconfigured_storage_type = None
    state.application.backup_credentials_cleanup_failed = True
    state.application.deployment_desc = None

    statuses = _mgr(state).get_statuses("app")

    assert SnapshotsStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED.value in statuses


def test_get_statuses_unit_scope_idle():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])

    assert _mgr(state).get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]
