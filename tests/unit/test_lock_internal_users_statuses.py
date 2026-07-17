# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for lock / internal_users pure status computation (PR5)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    InternalUsersStatuses,
    LockStatuses,
)
from opensearch_single_kernel.managers.internal_users import InternalUsersManager
from opensearch_single_kernel.managers.lock import PeerLockManager


def test_lock_status_waiting_when_lock_requested_not_held():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.lock_relation = object()
    state.server_lock.lock_requested = True
    state.application_lock.unit_with_lock = "other-unit"
    state.unit_name = "this-unit"
    mgr = PeerLockManager(state, MagicMock())

    statuses = mgr.get_statuses("unit", recompute=True)

    assert LockStatuses.REQUEST_LOCK_ON_START.value in statuses


def test_lock_status_idle_when_lock_not_requested():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.lock_relation = object()
    state.server_lock.lock_requested = False
    mgr = PeerLockManager(state, MagicMock())

    assert mgr.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]


def test_lock_status_idle_when_lock_relation_missing():
    """Call get_statuses safely before the lock relation exists."""
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.lock_relation = None
    mgr = PeerLockManager(state, MagicMock())

    assert mgr.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]


def test_lock_status_idle_when_requested_and_held():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.lock_relation = object()
    state.server_lock.lock_requested = True
    state.unit_name = "this-unit"
    state.application_lock.unit_with_lock = "this-unit"
    mgr = PeerLockManager(state, MagicMock())

    assert mgr.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]


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
