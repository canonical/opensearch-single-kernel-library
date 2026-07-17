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
    """Return cached running (blocking/async) statuses for a component.

    Used by managers that pure-compute non-running statuses and must preserve
    mid-operation running statuses set via ``set_running_status``.
    """
    return statuses.get(scope, component, running_status_only=True).root


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
