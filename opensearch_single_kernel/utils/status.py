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
    """Return a copy of cached running (blocking/async) statuses for a component.

    Used by managers that pure-compute non-running statuses and must preserve
    mid-operation running statuses set via ``set_running_status``.

    Always returns a new list so callers can append without mutating the cache.
    """
    return list(statuses.get(scope, component, running_status_only=True).root)


def cached_non_running_statuses(
    statuses: StatusesState,
    scope: AdvancedStatusesScope,
    component: str,
    *,
    matches: list[StatusObject] | None = None,
    message_contains: list[str] | None = None,
) -> list[StatusObject]:
    """Return non-running statuses written by apply/event paths (cache re-merge).

    Episodic failures that cannot be derived from relations alone (SMTP apply
    errors, precheck failures, repository registration failures, start errors)
    are stored in the advanced-status cache by the event/apply path and merged
    back here so pure ``get_statuses`` reasserts them without status-only
    databag flags.

    Match by exact ``StatusObject`` equality and/or message substring.
    """
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
