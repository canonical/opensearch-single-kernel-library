# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for lock / internal_users statuses.

Lock status uses an async running status (REQUEST_LOCK_ON_START) set by event
handlers via ``StatusHandler.set_running_status`` and cleared by
``PeerLockManager.acquire`` / ``release``. The base ``BaseManager.get_statuses``
merges cached running statuses; ``PeerLockManager`` no longer overrides it.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    InternalUsersStatuses,
    LockStatuses,
)
from opensearch_single_kernel.managers.internal_users import InternalUsersManager
from opensearch_single_kernel.managers.lock import PeerLockManager


def test_lock_status_returned_from_cache():
    """REQUEST_LOCK_ON_START is an async status cached in the status-peers databag."""
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(
        root=[LockStatuses.REQUEST_LOCK_ON_START.value]
    )
    mgr = PeerLockManager(state, MagicMock())

    statuses = mgr.get_statuses("unit", recompute=True)

    assert LockStatuses.REQUEST_LOCK_ON_START.value in statuses
    state.statuses.get.assert_called_with("unit", "lock_manager", running_status_only=True)


def test_lock_status_idle_when_no_cached_statuses():
    """No cached running statuses -> ACTIVE_IDLE."""
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    mgr = PeerLockManager(state, MagicMock())

    assert mgr.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]


def test_lock_status_idle_when_recompute_clears_cache():
    """On recompute, if no async status is cached, the unit is idle."""
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    mgr = PeerLockManager(state, MagicMock())

    assert mgr.get_statuses("unit", recompute=True) == [GeneralStatuses.ACTIVE_IDLE.value]


def test_internal_users_returns_cached_running_status_only():
    state = MagicMock()
    running = InternalUsersStatuses.ADMIN_USER_INIT_IN_PROGRESS.value
    state.statuses.get.return_value = SimpleNamespace(root=[running])
    mgr = InternalUsersManager(state, MagicMock())

    statuses = mgr.get_statuses("unit", recompute=True)

    assert statuses == [running]
    state.statuses.get.assert_called_with(
        "unit", "internal_users_manager", running_status_only=True
    )


def test_internal_users_idle_when_no_running_statuses():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.application.is_admin_user_initialized = False
    mgr = InternalUsersManager(state, MagicMock())

    assert mgr.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]
