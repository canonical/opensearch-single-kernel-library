# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Statuses for the OpenSearch Charm.

This module defines various status enums that represent the state of the charm.
"""

from enum import Enum

from data_platform_helpers.advanced_statuses import StatusObject


class GeneralStatuses(Enum):
    """Collection of common charm statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")
    INSTALL_IN_PROGRESS = StatusObject(
        status="maintenance", message="Installing OpenSearch...", running="blocking"
    )
    SECURITY_INDEX_INIT_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Initializing the security index...",
        running="blocking",
    )
    WAITING_TO_START = StatusObject(
        status="waiting", message="Waiting for OpenSearch to start...", running="async"
    )
    SERVICE_START_ERROR = StatusObject(
        status="blocked",
        message="An error occurred during the start of the OpenSearch service.",
    )
    SERVICE_IS_STOPPING = StatusObject(
        status="waiting",
        message="The OpenSearch service is stopping.",
        running="blocking",
    )


class HealthStatuses(Enum):
    """Collection of charm statuses related to health manager."""

    CLUSTER_HEALTH_RED = StatusObject(
        status="blocked",
        message="1 or more 'primary' shards are not assigned, please scale your application up.",
    )
    CLUSTER_HEALTH_YELLOW = StatusObject(
        status="blocked",
        message="1 or more 'replica' shards are not assigned, please scale your application up.",
    )
    WAITING_FOR_BUSY_SHARDS = StatusObject(
        status="maintenance", message="Some shards are still initializing / relocating."
    )
    WAITING_FOR_SPECIFIC_BUSY_SHARDS = StatusObject(
        status="waiting", message="The shards {shards} need to complete building"
    )


class ProfileStatuses(Enum):
    """Collection of charm statuses related to profiles manager."""

    INVALID_PROFILE_CONFIG_OPTION = StatusObject(
        status="blocked",
        message="Invalid profile configuration option. Only `production` and `testing` values are allowed.",
    )
    MISSING_PROFILE_REQUIREMENTS = StatusObject(
        status="blocked",
        message="Missing requirements: {requirements}",
    )


class InternalUsersStatuses(Enum):
    """Collection of charm statuses related to internal users manager."""

    ADMIN_USER_INIT_IN_PROGRESS = StatusObject(
        status="maintenance", message="Configuring admin user...", running="blocking"
    )


class TlsStatuses(Enum):
    """Collection of charm statuses related to tls manager."""

    TLS_RELATION_MISSING = StatusObject(
        status="blocked", message="Missing TLS relation with this cluster."
    )
    TLS_NOT_FULLY_CONFIGURED = StatusObject(
        status="maintenance", message="Waiting for TLS to be fully configured..."
    )
    TLS_CA_ROTATION = StatusObject(status="maintenance", message="Applying new CA certificate...")
    TLS_CERTS_EXPIRATION_ERROR = StatusObject(
        status="blocked",
        message="The certificates: {certificates} need to be refreshed.",
    )


class LockStatuses(Enum):
    """Collection of charm statuses related to lock manager."""

    REQUEST_LOCK_ON_START = StatusObject(
        status="waiting", message="Requesting lock on operation: start", running="async"
    )


class NotificationsStatuses(Enum):
    """Collection of charm statuses related to notification manager."""

    SMTP_RELATION_INVALID = StatusObject(
        status="blocked",
        message="SMTP relations must be established with the main-orchestrator cluster.",
    )
    SMTP_WAITING_RECIPIENTS = StatusObject(
        status="waiting",
        message="SMTP relation {id} sender configured; waiting for recipients to create email group/channel.",
    )
    SMTP_NO_RELATION_DATA = StatusObject(
        status="blocked",
        message="SMTP relation {id} has no data. Configure smtp-integrator and check unit logs.",
    )
    SMTP_CONFIGURATION_ERROR = StatusObject(
        status="blocked",
        message="SMTP relation {id} configuration failed. Check smtp-integrator and unit logs.",
    )
    SMTP_MISSING_REQUIRED_PARAMETERS = StatusObject(
        status="blocked", message="SMTP relation {id} parameters missing: {params}."
    )
    SMTP_COULD_NOT_READ_DATA = StatusObject(
        status="blocked", message="Could not read smtp relation {id} data: {exc}."
    )


class ExternalClientsStatuses(Enum):
    """Collection of charm statuses related to external clients manager."""

    NEW_INDEX_REQUESTED = StatusObject(
        status="maintenance",
        message="New index {index} requested on client relation {id}",
        running="blocking",
    )
    INDEX_CREATION_FAILED = StatusObject(
        status="blocked",
        message="Failed to create {index} index on client relation {id} - see the logs...",
    )
    INVALID_INDEX_NAME = StatusObject(
        status="blocked",
        message="Invalid index name on client relation {id}: {index}",
    )
    USER_CREATION_FAILED = StatusObject(
        status="blocked",
        message="Failed to create users for client relation {id}",
    )


class PeerClusterStatuses(Enum):
    """Collection of charm statuses related to peer cluster relation."""

    PEER_CLUSTER_NO_DATA_NODE = StatusObject(
        status="blocked",
        message="Cannot run cluster with current roles. Waiting for data node...",
    )
    PEER_CLUSTER_NO_RELATION = StatusObject(
        status="blocked", message="Cannot start. Waiting for peer cluster relation..."
    )
    PEER_CLUSTER_WRONG_RELATION = StatusObject(
        status="blocked",
        message="Cluster name doesn't match with related cluster. Remove relation.",
    )
    PEER_CLUSTER_WRONG_ROLES_PROVIDED = StatusObject(
        status="blocked", message="Cannot start cluster with current set of roles."
    )
    CM_ROLE_REMOVAL_FORBIDDEN = StatusObject(
        status="blocked",
        message="Removal of cluster_manager role from deployment not allowed.",
    )
    CM_VO_PROVIDED_INVALID = StatusObject(
        status="blocked",
        message="cluster_manager and voting_only roles cannot be both set on the same nodes.",
    )
    DATA_ROLE_REMOVAL_FORBIDDEN = StatusObject(
        status="blocked",
        message="Removal of data role from current deployment not allowed - the data cannot be reallocated.",
    )


class SnapshotsStatuses(Enum):
    """Collection of charm statuses related to snapshots manager."""

    BACKUP_RELATION_CONFLICT = StatusObject(
        status="blocked",
        message="Too many object storage relations. Only one is supported.",
    )
    BACKUP_RELATION_DATA_INCOMPLETE = StatusObject(
        status="blocked",
        message="Backup relation data missing or incomplete.",
    )
    BACKUP_CREDENTIALS_INCORRECT = StatusObject(
        status="blocked",
        message="Backup configuration error: bad credentials, permissions, invalid CA, or unsupported configuration.",
    )
    BACKUP_REPOSITORY_MISCONFIGURED = StatusObject(
        status="blocked",
        message="opensearch {storage_type} repository setup failed. Check the {integrator} config.",
    )
    # TODO: large deployments.
    BACKUP_RELATION_SHOULD_NOT_EXIST = StatusObject(
        status="blocked",
        message="This application should not be related to backup relation.",
    )
    BACKUP_CREDENTIALS_CLEANUP_FAILED = StatusObject(
        status="blocked",
        message="Failed to remove keystore credentials or snapshot repository. Please check the logs for more details.",
    )
    BACKUP_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Backup in progress...",
        running="blocking",
    )
    RESTORE_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="restore in progress...",
        running="blocking",
    )


class OAuthStatuses(Enum):
    """Collection of charm statuses related to OAuth relation."""

    OAUTH_RELATION_INVALID = StatusObject(
        status="blocked",
        message="OAuth relation must be created with Main-cluster-orchestrator",
    )


class JwtStatuses(Enum):
    """Collection of charm statuses related to JWT relation."""

    JWT_RELATION_INVALID = StatusObject(
        status="blocked",
        message="JWT relation must be created with Main-cluster-orchestrator.",
    )
    JWT_AUTH_CONFIG_INVALID = StatusObject(
        status="blocked",
        message="Configuration for JWT authentication is invalid. Check and correct parameters.",
    )
