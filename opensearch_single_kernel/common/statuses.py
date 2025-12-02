# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Statuses for the OpenSearch Charm.

This module defines various status enums that represent the state of the charm,
"""
from enum import Enum

from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus


class CharmStatuses(Enum):
    """Collection of possible statuses for the charm."""

    ACTIVE_IDLE = ActiveStatus("")
    INSTALL_IN_PROGRESS = MaintenanceStatus("Installing OpenSearch...")
    INSTALL_ERROR = BlockedStatus("Could not install OpenSearch.")
