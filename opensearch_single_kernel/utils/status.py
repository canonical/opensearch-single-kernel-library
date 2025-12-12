#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for Charm."""

import logging
import re
from typing import TYPE_CHECKING

from ops.model import ActiveStatus, StatusBase

from opensearch_single_kernel.utils.enum import BaseStrEnum

logger = logging.getLogger()

if TYPE_CHECKING:
    from opensearch_single_kernel.events.base_charm import OpenSearchBaseCharm


class Status:
    """Class for managing the various status changes in a charm."""

    class CheckPattern(BaseStrEnum):
        """Enum for types of status comparison."""

        Equal = "equal"
        Start = "start"
        End = "end"
        Contain = "contain"
        Interpolated = "interpolated"

    def __init__(self, charm: "OpenSearchBaseCharm"):
        self.charm = charm

    def clear(
        self, status: StatusBase, pattern: CheckPattern = CheckPattern.Equal, app: bool = False
    ):
        """Resets the unit status if it was previously blocked/maintenance with message."""
        status_message = status.message
        context = self.charm.app if app else self.charm.unit

        condition: bool
        if pattern == Status.CheckPattern.Equal:
            condition = context.status.message == status_message
        elif pattern == Status.CheckPattern.Start:
            condition = context.status.message.startswith(status_message)
        elif pattern == Status.CheckPattern.End:
            condition = context.status.message.endswith(status_message)
        elif pattern == Status.CheckPattern.Interpolated:
            condition = (
                re.fullmatch(status_message.replace("{}", "(?s:.*?)"), context.status.message)
                is not None
            )
        else:
            condition = status_message in context.status.message

        if condition:
            # if (
            # not app
            # TODO: Make sure to revisit this once we take upgrade as a refactoring subject
            # and self.charm._upgrade
            # and (status := self.charm._upgrade.get_unit_juju_status())
            # ):
            # context.status = status
            # else:
            context.status = ActiveStatus()

    def set(self, status: StatusBase, app: bool = False):
        """Set status on unit or app IF not already set.

        This is seemingly useless, but it is unfortunately needed to avoid updating unnecessarily
        the "last active since" field on the model, which prevents it from stabilizing on small
        machines on integration tests (colliding with "idle period").
        """
        context = self.charm.app if app else self.charm.unit
        # TODO: Make sure to uncomment and handle this once we take upgrade for refactor
        # Upgrade app status takes priority over other app statuses
        # if app and self.charm._upgrade and (upgrade_status := self.charm._upgrade.app_status):
        # context.status = upgrade_status
        # return
        if context.status == status:
            return

        context.status = status
