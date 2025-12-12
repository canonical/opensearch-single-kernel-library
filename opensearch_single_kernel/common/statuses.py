# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Statuses for the OpenSearch Charm.

This module defines various status enums that represent the state of the charm,
"""
from enum import Enum

from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus


class CharmStatuses(Enum):
    """Collection of possible statuses for the charm."""

    ACTIVE_IDLE = ActiveStatus("")
    INSTALL_IN_PROGRESS = MaintenanceStatus("Installing OpenSearch...")
    INSTALL_ERROR = BlockedStatus("Could not install OpenSearch.")

    # TLS Status
    TLS_RELATION_MISSING = BlockedStatus("Missing TLS relation with this cluster.")
    TLS_NOT_FULLY_CONFIGURED = MaintenanceStatus("Waiting for TLS to be fully configured...")

    # Configuration Status
    ADMIN_USER_NOT_CONFIGURED = MaintenanceStatus(
        "Waiting for the admin user to be fully configured..."
    )

    # Lock Status
    REQUEST_LOCK_ON_START = WaitingStatus("Requesting lock on operation: start")

    # Security Index
    SECURITY_INDEX_INIT_IN_PROGRESS = MaintenanceStatus("Initializing the security index...")

    # Start
    SERVICE_START_ERROR = BlockedStatus(
        "An error occurred during the start of the OpenSearch service."
    )
    WAITING_TO_START = WaitingStatus("Waiting for OpenSearch to start...")

    # Peer Cluster
    PEER_CLUSTER_NO_DATA_NODE = BlockedStatus(
        "Cannot run cluster with current roles. Waiting for data node..."
    )
    PEER_CLUSTER_NO_RELATION = BlockedStatus("Cannot start. Waiting for peer cluster relation...")
