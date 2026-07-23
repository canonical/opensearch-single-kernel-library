#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for Charm."""

import logging
from typing import Any

from data_platform_helpers.advanced_statuses import StatusesState, StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope

logger = logging.getLogger(__name__)


def running_statuses(
    statuses: StatusesState,
    scope: AdvancedStatusesScope,
    component: str,
) -> list[StatusObject]:
    """Copy of cached running (blocking/async) statuses. Returns a new list."""
    return list(statuses.get(scope, component, running_status_only=True).root)


def cached_non_running_statuses(
    statuses: StatusesState,
    scope: AdvancedStatusesScope,
    component: str,
    *,
    matches: list[StatusObject] | None = None,
    message_contains: list[str] | None = None,
) -> list[StatusObject]:
    """Cached event/apply failures, filtered by status match or message substring."""
    if matches is None:
        matches = []
    if message_contains is None:
        message_contains = []
    if not matches and not message_contains:
        return []

    found: list[StatusObject] = []
    for status in statuses.get(scope, component).root:
        if status.running:
            continue
        if status in matches or any(needle in status.message for needle in message_contains):
            found.append(status)
    return found


def format_status(status: StatusObject, params: dict[str, Any] | None) -> StatusObject:
    """Get the copy of the status object with the message formatted to params.

    If params are empty, returns original status.
    """
    if params is None:
        return status

    class SafeDict(dict):
        def __missing__(self, key):
            return "{}"

    return StatusObject(
        status=status.status,
        message=status.message.format_map(SafeDict(params)),
        short_message=status.short_message,
        check=status.check,
        action=status.action,
        running=status.running,
        approved_critical_component=status.approved_critical_component,
    )
