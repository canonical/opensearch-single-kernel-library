# Copyright 2026 Canonical Ltd.
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

    # Blocking directive should be a running status since it is set based on the presence
    # of a SHOW_STATUS directive and once the status set we remove the directive
    BLOCKING_DIRECTIVE = StatusObject(
        status="blocked",
        message="{directive}",
        running="async",
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

    # TODO; Think about a better name
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
    DATA_ROLE_REMOVAL_FORBIDDEN = StatusObject(
        status="blocked",
        message="Removal of data role from current deployment not allowed - the data cannot be reallocated.",
    )
    PEER_CLUSTER_MISSING_RELATIONS = StatusObject(
        status="blocked",
        message="Found credentials with missing relations. Add relation for {relation} and any client applications.",
    )
    PEER_CLUSTER_ORCHESTRATORS_REMOVED = StatusObject(
        status="blocked",
        message="Main-cluster-orchestrator removed, and no failover cluster related.",
        running="async",
    )
    PEER_CLUSTER_WAITING_FOR_FAILOVER_PROMOTION = StatusObject(
        status="waiting",
        message="Main-cluster-orchestrator removed, waiting for failover promotion.",
        running="async",
    )


class PeerClusterErrorDataStatuses(Enum):
    """Collection of charm statuses that are propagated from provider."""

    MAIN_OR_FAILOVER_NOT_CONFIGURED = StatusObject(
        status="waiting", message="'main/failover'-orchestrators not configured yet."
    )
    RELATED_TO_NON_MAIN_OR_FAILOVER = StatusObject(
        status="blocked", message="Related to non 'main/failover'-orchestrator cluster"
    )
    WAITING_FOR_PEER_RELATION_CREATED = StatusObject(
        status="waiting",
        message="Waiting for peer cluster relation to be created {message_suffix}.",
    )
    CANNOT_HAVE_TWO_FAILOVERS = StatusObject(
        status="blocked",
        message="Cannot have 2 'failover'-orchestrators. Relate to the existing failover.",
    )
    ADMIN_USER_NOT_FULLY_CONFIGURED = StatusObject(
        status="waiting", message="Admin user not fully configured {message_suffix}."
    )
    TLS_NOT_FULLY_CONFIGURED = StatusObject(
        status="waiting", message="TLS not fully configured {message_suffix}."
    )
    SECURITY_INDEX_NOT_INITIALIZED = StatusObject(
        status="waiting", message="Security index not initialized {message_suffix}."
    )
    WAITING_FOR_EVERY_UNIT_TO_START = StatusObject(
        status="waiting", message="Waiting for every unit {message_suffix} to start."
    )
    COS_USER_NOT_CREATED = StatusObject(
        status="waiting", message="'{COS_USER}' user not created yet."
    )
    NO_CLUSTER_MANAGER_ELIGIBLE_NODES = StatusObject(
        status="waiting", message="No 'cluster_manager' eligible nodes found {message_suffix}"
    )
    COULD_NOT_FETCH_NODES = StatusObject(
        status="waiting", message="Could not fetch nodes {message_suffix}"
    )
    COULD_NOT_FETCH_NODES_IN_RELATED_CLUSTER = StatusObject(
        status="waiting",
        message="Could not fetch nodes in related {deployment_desc.typ} sub-cluster.",
    )
    PEER_CLUSTER_MAIN_IS_REQUIRER = StatusObject(
        status="blocked", message="Main orchestrator cannot be a requirer"
    )
    CLUSTER_CAN_ONLY_HAVE_ONE_MAIN_OR_FAILOVER = StatusObject(
        status="blocked",
        message="A cluster can only be related to 1 main and 1 failover-clusters at most.",
    )
    CANNOT_RELATE_TO_CLUSTER_WITH_DIFFERENT_NAME = StatusObject(
        status="blocked", message="Cannot relate 2 clusters with different 'cluster_name' values."
    )
    CA_CERTIFICATE_MISMATCH_BETWEEN_CLUSTERS = StatusObject(
        status="blocked", message="CA certificate mismatch between clusters."
    )
    CA_TRUSTSTORE_PASSWORD_NOT_AVAILABLE = StatusObject(
        status="blocked", message="CA truststore-password not available."
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
        message="OpenSearch {storage_type} repository setup failed. Check the {integrator} config.",
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
        message="Restore in progress...",
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


class UpgradesStatuses(Enum):
    """Collection of charm statuses related to upgrades manager."""

    UPGRADES_ACTIVE = StatusObject(
        status="active",
        message="OpenSearch {workload_version} running; Snap rev {snap_revision}; Charmed operator {charm_version}",
        approved_critical_component=True,
    )
    UPGRADES_ACTIVE_OUTDATED = StatusObject(
        status="active",
        message="OpenSearch {workload_version} running; Snap rev {snap_revision} (outdated); Charmed operator {charm_version}",
        approved_critical_component=True,
    )
    UPGRADES_UPGRADING = StatusObject(
        status="maintenance",
        message="Upgrading.",
        approved_critical_component=True,
    )
    UPGRADES_WAITING_FOR_RESUME = StatusObject(
        status="blocked",
        message="Upgrading. Verify highest unit is healthy & run `resume upgrade action.",
        approved_critical_component=True,
    )
    UPGRADES_INCOMPATIBLE = StatusObject(
        status="blocked",
        message="Upgrade incompatible. Rollback to previous revision with `juju refresh`.",
        approved_critical_component=True,
    )
    UPGRADES_PRE_UPGRADE_CHECK_FAILED = StatusObject(
        status="blocked",
        message="Pre upgrade check failed: please check the logs for more details.",
        approved_critical_component=True,
    )
    UPGRADES_ROLLBACK_UNSUPPORTED = StatusObject(
        status="blocked",
        message="Rollback unsupported. Refresh to a newer revision or consult the recovery documentation",
        approved_critical_component=True,
    )
    UPGRADES_ROLLBACK_INCOMPATIBLE = StatusObject(
        status="blocked",
        message="Rollback incompatible. Run 'juju run <unit> force-refresh-start' with `check-compatibility` set to false to override node version and attempt startup procedure",
        approved_critical_component=True,
    )
