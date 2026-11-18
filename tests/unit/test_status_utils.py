# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for status utility helpers."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from opensearch_single_kernel.common.statuses import GeneralStatuses, SnapshotsStatuses
from opensearch_single_kernel.utils.status import cached_non_running_statuses


def test_cached_non_running_matches_exact_and_message():
    exact = SnapshotsStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED.value
    misconfigured = SimpleNamespace(
        status="blocked",
        message="OpenSearch s3 repository setup failed. Check the s3 integrator config.",
        running=None,
    )
    running = SnapshotsStatuses.BACKUP_IN_PROGRESS.value
    idle = GeneralStatuses.ACTIVE_IDLE.value

    statuses = MagicMock()
    statuses.get.return_value = SimpleNamespace(root=[exact, misconfigured, running, idle])

    found = cached_non_running_statuses(
        statuses,
        "app",
        "snapshots_manager",
        matches=[exact],
        message_contains=["repository setup failed"],
    )

    assert exact in found
    assert misconfigured in found
    assert running not in found
    assert idle not in found
