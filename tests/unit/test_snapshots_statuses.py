# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for snapshots status compute (cached failure merge)."""

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


def test_get_statuses_merges_cached_repo_misconfigured():
    cached = format_status(
        SnapshotsStatuses.BACKUP_REPOSITORY_MISCONFIGURED.value,
        {"storage_type": "s3", "integrator": "s3 integrator"},
    )
    state = MagicMock()
    # running_statuses uses running_status_only; failure merge uses full get
    state.statuses.get.side_effect = lambda *a, **k: SimpleNamespace(
        root=[] if k.get("running_status_only") else [cached]
    )
    state.application.deployment_desc = None

    statuses = _mgr(state).get_statuses("app")

    assert cached in statuses


def test_get_statuses_merges_cached_cleanup_failed():
    cached = SnapshotsStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED.value
    state = MagicMock()
    state.statuses.get.side_effect = lambda *a, **k: SimpleNamespace(
        root=[] if k.get("running_status_only") else [cached]
    )
    state.application.deployment_desc = None

    statuses = _mgr(state).get_statuses("app")

    assert cached in statuses


def test_get_statuses_unit_scope_idle():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])

    assert _mgr(state).get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]
