# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Statuses for the OpenSearch Charm.

This module defines various status enums that represent the state of the charm.
StatusObject fields (DA147 / DA161):
- short_message: multi-status aggregation, required only when message is longer
  than 40 characters (max ~40 chars)
- check: what was evaluated
- action: what the operator should do (especially for blocked statuses)
"""

from enum import Enum

from data_platform_helpers.advanced_statuses import StatusObject


class GeneralStatuses(Enum):
    """Collection of common charm statuses."""

    ACTIVE_IDLE = StatusObject(status="active", message="")
    INSTALL_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Installing OpenSearch...",
        check="OpenSearch package / snap install progress.",
        running="blocking",
    )
    SECURITY_INDEX_INIT_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Initializing the security index...",
        check="Security index bootstrap completion.",
        running="async",
    )
    WAITING_TO_START = StatusObject(
        status="waiting",
        message="Waiting for OpenSearch to start...",
        check="OpenSearch service readiness.",
        running="async",
    )
    SERVICE_START_ERROR = StatusObject(
        status="blocked",
        message="An error occurred during the start of the OpenSearch service.",
        short_message="OpenSearch start failed",
        check="Service start / process health after start attempt.",
        action="Inspect unit logs, then retry start or re-deploy the unit.",
    )
    SERVICE_IS_STOPPING = StatusObject(
        status="waiting",
        message="The OpenSearch service is stopping.",
        check="Service stop sequence.",
        running="blocking",
    )

    # Blocking directive is pure-computed from deployment_desc.state when not ACTIVE.
    BLOCKING_DIRECTIVE = StatusObject(
        status="blocked",
        message="{directive}",
        short_message="Config / deployment blocked",
        check="Deployment description blocking message.",
        action="Read the status message and fix the configuration or relations.",
    )


class HealthStatuses(Enum):
    """Collection of charm statuses related to health manager."""

    CLUSTER_HEALTH_RED = StatusObject(
        status="blocked",
        message="1 or more 'primary' shards are not assigned, please scale your application up.",
        short_message="Primary shards unassigned",
        check="Cluster health API (red).",
        action="Scale the application up so all primary shards can be assigned.",
    )
    CLUSTER_HEALTH_YELLOW = StatusObject(
        status="blocked",
        message="1 or more 'replica' shards are not assigned, please scale your application up.",
        short_message="Replica shards unassigned",
        check="Cluster health API (yellow, permanent).",
        action="Scale the application up so replica shards can be assigned.",
    )
    WAITING_FOR_BUSY_SHARDS = StatusObject(
        status="maintenance",
        message="Some shards are still initializing / relocating.",
        short_message="Shards relocating",
        check="Initializing or relocating shard counts.",
        action="Wait for shard activity to finish.",
    )
    WAITING_FOR_SPECIFIC_BUSY_SHARDS = StatusObject(
        status="waiting",
        message="The shards {shards} need to complete building",
        short_message="Waiting on specific shards",
        check="Per-unit busy shard list.",
        action="Wait for the listed shards to finish building.",
    )


class ProfileStatuses(Enum):
    """Collection of charm statuses related to profiles manager."""

    INVALID_PROFILE_CONFIG_OPTION = StatusObject(
        status="blocked",
        message=(
            "Invalid profile configuration option. "
            "Only `production` and `testing` values are allowed."
        ),
        short_message="Invalid profile config",
        check="Config option `profile`.",
        action="Set profile to `production` or `testing`.",
    )
    MISSING_PROFILE_REQUIREMENTS = StatusObject(
        status="blocked",
        message="Missing requirements: {requirements}",
        short_message="Profile requirements missing",
        check="Machine resources against selected profile.",
        action="Provide the missing resources or switch profile.",
    )


class InternalUsersStatuses(Enum):
    """Collection of charm statuses related to internal users manager."""

    ADMIN_USER_INIT_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Configuring admin user...",
        check="Admin user initialization.",
        running="async",
    )


class TlsStatuses(Enum):
    """Collection of charm statuses related to tls manager."""

    TLS_RELATION_MISSING = StatusObject(
        status="blocked",
        message="Missing TLS relation with this cluster.",
        check="TLS certificates relation presence.",
        action="Relate a TLS certificates provider to this application.",
    )
    TLS_NOT_FULLY_CONFIGURED = StatusObject(
        status="maintenance",
        message="Waiting for TLS to be fully configured...",
        short_message="TLS not fully configured",
        check="TLS certificates and keystores on disk.",
        action="Wait for certificates to be issued, or check the TLS provider.",
    )
    TLS_CA_ROTATION = StatusObject(
        status="maintenance",
        message="Applying new CA certificate...",
        check="CA rotation / renewal flags.",
        action="Wait for CA rotation to complete on all units.",
    )
    TLS_CERTS_EXPIRATION_ERROR = StatusObject(
        status="blocked",
        message="The certificates: {certificates} need to be refreshed.",
        short_message="Certificates expiring",
        check="Certificate remaining validity.",
        action="Refresh certificates via the TLS provider relation.",
    )


class LockStatuses(Enum):
    """Collection of charm statuses related to lock manager."""

    REQUEST_LOCK_ON_START = StatusObject(
        status="waiting",
        message="Requesting lock on operation: start",
        check="Peer / OpenSearch start lock ownership.",
        action="Wait for the start lock; another unit may be starting.",
        running="async",
    )


class NotificationsStatuses(Enum):
    """Collection of charm statuses related to notification manager."""

    SMTP_RELATION_INVALID = StatusObject(
        status="blocked",
        message="SMTP relations must be established with the main-orchestrator cluster.",
        short_message="SMTP only on main",
        check="SMTP related to main orchestrator.",
        action="Remove SMTP from this app; relate smtp-integrator to main-orchestrator.",
    )
    SMTP_WAITING_RECIPIENTS = StatusObject(
        status="waiting",
        message=(
            "SMTP relation {id} sender configured; "
            "waiting for recipients to create email group/channel."
        ),
        short_message="SMTP waiting recipients",
        check="SMTP relation data includes recipients.",
        action="Configure recipients on smtp-integrator.",
    )
    SMTP_NO_RELATION_DATA = StatusObject(
        status="blocked",
        message="SMTP relation {id} has no data. Configure smtp-integrator and check unit logs.",
        short_message="SMTP has no data",
        check="SMTP relation app databag content.",
        action="Configure smtp-integrator (host, port, sender, auth) and check logs.",
    )
    SMTP_CONFIGURATION_ERROR = StatusObject(
        status="blocked",
        message="SMTP relation {id} configuration failed. Check smtp-integrator and unit logs.",
        short_message="SMTP config failed",
        check="Apply of SMTP notification configs to OpenSearch.",
        action="Check smtp-integrator and unit logs, then re-trigger the relation.",
    )
    SMTP_MISSING_REQUIRED_PARAMETERS = StatusObject(
        status="blocked",
        message="SMTP relation {id} parameters missing: {params}.",
        short_message="SMTP params missing",
        check="Required SMTP relation parameters.",
        action="Set the missing parameters on smtp-integrator.",
    )
    SMTP_COULD_NOT_READ_DATA = StatusObject(
        status="blocked",
        message="Could not read smtp relation {id} data: {exc}.",
        short_message="SMTP data unreadable",
        check="Ability to read SMTP secrets / relation data.",
        action="Grant secret access and verify smtp-integrator configuration.",
    )


class ExternalClientsStatuses(Enum):
    """Collection of charm statuses related to external clients manager."""

    NEW_INDEX_REQUESTED = StatusObject(
        status="maintenance",
        message="New index {index} requested on client relation {id}",
        short_message="Creating client index",
        check="Client relation requested index creation.",
        running="blocking",
    )
    INDEX_CREATION_FAILED = StatusObject(
        status="blocked",
        message="Failed to create {index} index on client relation {id} - see the logs...",
        short_message="Index creation failed",
        check="Index existence after client relation handling.",
        action="Check unit logs and OpenSearch health, then re-relate the client.",
    )
    INVALID_INDEX_NAME = StatusObject(
        status="blocked",
        message="Invalid index name on client relation {id}: {index}",
        short_message="Invalid index name",
        check="Client relation index name validation.",
        action="Correct the index name on the client / data-integrator relation.",
    )
    USER_CREATION_FAILED = StatusObject(
        status="blocked",
        message="Failed to create users for client relation {id}",
        short_message="Client user create failed",
        check="OpenSearch user for client relation.",
        action="Check unit logs and retry the client relation.",
    )


class PeerClusterStatuses(Enum):
    """Collection of charm statuses related to peer cluster relation."""

    # TODO; Think about a better name
    PEER_CLUSTER_NO_DATA_NODE = StatusObject(
        status="blocked",
        message="Cannot run cluster with current roles. Waiting for data node...",
        short_message="Waiting for data node",
        check="Cluster roles include a data node path.",
        action="Add a data node role or relate a data sub-cluster.",
    )
    PEER_CLUSTER_NO_RELATION = StatusObject(
        status="blocked",
        message="Cannot start. Waiting for peer cluster relation...",
        short_message="Wait peer-cluster rel",
        check="Peer-cluster relation for init_hold deployments.",
        action="Relate this app to a main/failover orchestrator.",
    )
    PEER_CLUSTER_WRONG_RELATION = StatusObject(
        status="blocked",
        message="Cluster name doesn't match with related cluster. Remove relation.",
        short_message="Cluster name mismatch",
        check="cluster_name vs related orchestrator name.",
        action="Remove the relation or align cluster_name with the related cluster.",
    )
    PEER_CLUSTER_WRONG_ROLES_PROVIDED = StatusObject(
        status="blocked",
        message="Cannot start cluster with current set of roles.",
        short_message="Invalid role set",
        check="Role configuration for independent start.",
        action="Adjust the roles config to include a startable role set.",
    )
    INVALID_CM_AND_VOTING_ONLY_ROLES = StatusObject(
        status="blocked",
        message="cluster_manager and voting_only roles cannot be both set on the same node.",
        short_message="Invalid CM+voting roles",
        check="Config roles exclude invalid cluster_manager + voting_only combo.",
        action="Remove either `cluster_manager` or `voting_only` from roles.",
    )
    CM_ROLE_REMOVAL_FORBIDDEN = StatusObject(
        status="blocked",
        message="Removal of cluster_manager role from deployment not allowed.",
        short_message="Cannot remove CM role",
        check="Attempted removal of cluster_manager role.",
        action="Restore the cluster_manager role in the config.",
    )
    DATA_ROLE_REMOVAL_FORBIDDEN = StatusObject(
        status="blocked",
        message=(
            "Removal of data role from current deployment not allowed - "
            "the data cannot be reallocated."
        ),
        short_message="Cannot remove data role",
        check="Attempted removal of data role without reallocation path.",
        action="Restore the data role or reallocate data via large deployment design.",
    )
    PEER_CLUSTER_MISSING_RELATIONS = StatusObject(
        status="blocked",
        message=(
            "Found credentials with missing relations. "
            "Add relation for {relation} and any client applications."
        ),
        short_message="Missing plugin relation",
        check="Stored plugin credentials vs present relations.",
        action="Re-add the missing relation for {relation}.",
    )
    PEER_CLUSTER_ORCHESTRATORS_REMOVED = StatusObject(
        status="blocked",
        message="Main-cluster-orchestrator removed, and no failover cluster related.",
        short_message="Orchestrators removed",
        check="Main/failover orchestrator presence for large deploy.",
        action="Relate a main or failover orchestrator again.",
    )
    PEER_CLUSTER_WAITING_FOR_FAILOVER_PROMOTION = StatusObject(
        status="waiting",
        message="Main-cluster-orchestrator removed, waiting for failover promotion.",
        short_message="Waiting failover promotion",
        check="Failover promotion after main removal.",
        action="Wait for failover promotion or re-relate main orchestrator.",
    )


class PeerClusterErrorDataStatuses(Enum):
    """Collection of charm statuses that are propagated from provider."""

    MAIN_OR_FAILOVER_NOT_CONFIGURED = StatusObject(
        status="waiting",
        message="'main/failover'-orchestrators not configured yet.",
        short_message="Orchestrators not ready",
        check="Main/failover configuration on provider.",
        action="Wait until main/failover orchestrators finish configuring.",
    )
    RELATED_TO_NON_MAIN_OR_FAILOVER = StatusObject(
        status="blocked",
        message="Related to non 'main/failover'-orchestrator cluster",
        short_message="Wrong orchestrator type",
        check="Remote cluster is main or failover orchestrator.",
        action="Relate only to main- or failover-orchestrator applications.",
    )
    WAITING_FOR_PEER_RELATION_CREATED = StatusObject(
        status="waiting",
        message="Waiting for peer cluster relation to be created {message_suffix}.",
        short_message="Wait peer relation",
        check="Peer-cluster relation creation on provider side.",
        action="Ensure peer-cluster relations are established.",
    )
    CANNOT_HAVE_TWO_FAILOVERS = StatusObject(
        status="blocked",
        message="Cannot have 2 'failover'-orchestrators. Relate to the existing failover.",
        short_message="Two failover clusters",
        check="Only one failover orchestrator relation.",
        action="Remove the extra failover relation.",
    )
    ADMIN_USER_NOT_FULLY_CONFIGURED = StatusObject(
        status="waiting",
        message="Admin user not fully configured {message_suffix}.",
        short_message="Admin user incomplete",
        check="Admin user fully initialized on provider.",
        action="Wait for admin user configuration on the orchestrator.",
    )
    TLS_NOT_FULLY_CONFIGURED = StatusObject(
        status="blocked",
        message="TLS not fully configured {message_suffix}.",
        short_message="TLS incomplete (remote)",
        check="TLS readiness on related orchestrator.",
        action="Complete TLS on the related orchestrator cluster.",
    )
    SECURITY_INDEX_NOT_INITIALIZED = StatusObject(
        status="waiting",
        message="Security index not initialized {message_suffix}.",
        short_message="Security index not ready",
        check="Security index initialization on provider.",
        action="Wait for security index initialization.",
    )
    WAITING_FOR_EVERY_UNIT_TO_START = StatusObject(
        status="waiting",
        message="Waiting for every unit {message_suffix} to start.",
        short_message="Waiting remote units",
        check="All units of the related cluster started.",
        action="Wait for all units of the related application to start.",
    )
    COS_USER_NOT_CREATED = StatusObject(
        status="waiting",
        message="'{COS_USER}' user not created yet.",
        short_message="COS user missing",
        check="COS monitoring user existence.",
        action="Wait for the COS user to be created on the orchestrator.",
    )
    NO_CLUSTER_MANAGER_ELIGIBLE_NODES = StatusObject(
        status="waiting",
        message="No 'cluster_manager' eligible nodes found {message_suffix}",
        short_message="No CM-eligible nodes",
        check="Presence of cluster_manager eligible nodes.",
        action="Add cluster_manager capable nodes to the deployment.",
    )
    COULD_NOT_FETCH_NODES = StatusObject(
        status="waiting",
        message="Could not fetch nodes {message_suffix}",
        short_message="Could not fetch nodes",
        check="OpenSearch nodes API reachability.",
        action="Check OpenSearch health and network connectivity.",
    )
    COULD_NOT_FETCH_NODES_IN_RELATED_CLUSTER = StatusObject(
        status="waiting",
        message="Could not fetch nodes in related {deployment_desc.typ} sub-cluster.",
        short_message="Related cluster unreachable",
        check="Node fetch against related sub-cluster.",
        action="Check connectivity and health of the related sub-cluster.",
    )
    PEER_CLUSTER_MAIN_IS_REQUIRER = StatusObject(
        status="blocked",
        message="Main orchestrator cannot be a requirer",
        check="Main orchestrator is not on peer-cluster requirer side.",
        action="Invert peer-cluster roles so main is the provider.",
    )
    CLUSTER_CAN_ONLY_HAVE_ONE_MAIN_OR_FAILOVER = StatusObject(
        status="blocked",
        message="A cluster can only be related to 1 main and 1 failover-clusters at most.",
        short_message="Too many orchestrators",
        check="At most one main and one failover relation.",
        action="Remove extra main/failover relations.",
    )
    CANNOT_RELATE_TO_CLUSTER_WITH_DIFFERENT_NAME = StatusObject(
        status="blocked",
        message="Cannot relate 2 clusters with different 'cluster_name' values.",
        short_message="Different cluster_name",
        check="Matching cluster_name across related clusters.",
        action="Align cluster_name config or remove the relation.",
    )
    CA_CERTIFICATE_MISMATCH_BETWEEN_CLUSTERS = StatusObject(
        status="blocked",
        message="CA certificate mismatch between clusters.",
        short_message="CA mismatch",
        check="CA certificates match across clusters.",
        action="Use the same CA for all related clusters.",
    )
    CA_TRUSTSTORE_PASSWORD_NOT_AVAILABLE = StatusObject(
        status="blocked",
        message="CA truststore-password not available.",
        check="Truststore password secret availability.",
        action="Ensure TLS secrets are published by the orchestrator.",
    )


class SnapshotsStatuses(Enum):
    """Collection of charm statuses related to snapshots manager."""

    BACKUP_RELATION_CONFLICT = StatusObject(
        status="blocked",
        message="Too many object storage relations. Only one is supported.",
        short_message="Too many backup relations",
        check="At most one object-storage relation.",
        action="Remove extra s3/azure/gcs relations; keep only one.",
    )
    BACKUP_RELATION_DATA_INCOMPLETE = StatusObject(
        status="blocked",
        message="Backup relation data missing or incomplete.",
        short_message="Backup data incomplete",
        check="Object-storage relation data completeness.",
        action="Complete the integrator configuration (bucket, path, credentials).",
    )
    BACKUP_CREDENTIALS_INCORRECT = StatusObject(
        status="blocked",
        message=(
            "Backup configuration error: bad credentials, permissions, "
            "invalid CA, or unsupported configuration."
        ),
        short_message="Backup creds invalid",
        check="Storage credentials and repository validation.",
        action="Fix integrator credentials / CA / permissions.",
    )
    BACKUP_REPOSITORY_MISCONFIGURED = StatusObject(
        status="blocked",
        message="OpenSearch {storage_type} repository setup failed. Check the {integrator} config.",
        short_message="Snapshot repo failed",
        check="OpenSearch snapshot repository registration.",
        action="Check the {integrator} config and unit logs.",
    )
    # TODO: large deployments.
    BACKUP_RELATION_SHOULD_NOT_EXIST = StatusObject(
        status="blocked",
        message="This application should not be related to backup relation.",
        short_message="Backup rel not allowed",
        check="Whether this app role accepts backup relations.",
        action="Remove the backup relation from this application.",
    )
    BACKUP_CREDENTIALS_CLEANUP_FAILED = StatusObject(
        status="blocked",
        message=(
            "Failed to remove keystore credentials or snapshot repository. "
            "Please check the logs for more details."
        ),
        short_message="Backup cleanup failed",
        check="Credentials / repository removal result.",
        action="Check unit logs and retry removing the backup relation.",
    )
    BACKUP_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Backup in progress...",
        check="Snapshot create action running.",
        running="blocking",
    )
    RESTORE_IN_PROGRESS = StatusObject(
        status="maintenance",
        message="Restore in progress...",
        check="Snapshot restore action running.",
        running="blocking",
    )


class OAuthStatuses(Enum):
    """Collection of charm statuses related to OAuth relation."""

    OAUTH_RELATION_INVALID = StatusObject(
        status="blocked",
        message="OAuth relation must be created with Main-cluster-orchestrator",
        short_message="OAuth only on main",
        check="OAuth related to main orchestrator.",
        action="Relate OAuth only to the main-cluster-orchestrator.",
    )


class JwtStatuses(Enum):
    """Collection of charm statuses related to JWT relation."""

    JWT_RELATION_INVALID = StatusObject(
        status="blocked",
        message="JWT relation must be created with Main-cluster-orchestrator.",
        short_message="JWT only on main",
        check="JWT related to main orchestrator.",
        action="Relate JWT only to the main-cluster-orchestrator.",
    )
    JWT_AUTH_CONFIG_INVALID = StatusObject(
        status="blocked",
        message="Configuration for JWT authentication is invalid. Check and correct parameters.",
        short_message="JWT config invalid",
        check="JWT authentication configuration validity.",
        action="Correct JWT configuration parameters on the relation.",
    )


class UpgradesStatuses(Enum):
    """Collection of charm statuses related to upgrades manager."""

    UPGRADES_ACTIVE = StatusObject(
        status="active",
        message=(
            "OpenSearch {workload_version} running; Snap rev {snap_revision}; "
            "Charmed operator {charm_version}"
        ),
        short_message="OpenSearch running",
        check="Installed workload and charm versions.",
        approved_critical_component=True,
    )
    K8S_UPGRADES_ACTIVE = StatusObject(
        status="active",
        message="OpenSearch {workload_version} running; Charmed operator {charm_version}",
        short_message="OpenSearch running",
        check="Installed workload and charm versions.",
        approved_critical_component=True,
    )
    K8S_UPGRADES_ACTIVE_OUTDATED = StatusObject(
        status="active",
        message=(
            "OpenSearch {workload_version} running (restart pending); "
            "Charmed operator {charm_version}"
        ),
        short_message="Restart pending",
        check="Kubernetes controller revision currency.",
        action="Wait for the unit to restart on refresh, or force if stuck.",
        approved_critical_component=True,
    )
    UPGRADES_ACTIVE_OUTDATED = StatusObject(
        status="active",
        message=(
            "OpenSearch {workload_version} running; Snap rev {snap_revision} (outdated); "
            "Charmed operator {charm_version}"
        ),
        short_message="Snap rev outdated",
        check="Snap revision currency.",
        action="Plan a refresh when ready.",
        approved_critical_component=True,
    )
    UPGRADES_UPGRADING = StatusObject(
        status="maintenance",
        message="Upgrading.",
        check="In-place upgrade progress.",
        approved_critical_component=True,
    )
    UPGRADES_WAITING_FOR_RESUME = StatusObject(
        status="blocked",
        message="Upgrading. Verify highest unit is healthy & run `resume-upgrade` action.",
        short_message="Resume upgrade needed",
        check="User confirmation to resume rolling upgrade.",
        action="Verify the highest unit is healthy, then run resume-upgrade.",
        approved_critical_component=True,
    )
    UPGRADES_INCOMPATIBLE = StatusObject(
        status="blocked",
        message="Upgrade incompatible. Rollback to previous revision with `juju refresh`.",
        short_message="Upgrade incompatible",
        check="Version compatibility matrix.",
        action="Rollback with `juju refresh` to the previous revision.",
        approved_critical_component=True,
    )
    UPGRADES_UNHEALTHY = StatusObject(
        status="blocked",
        message="Unhealthy after upgrade. Rollback to previous revision with `juju refresh`.",
        short_message="Unhealthy after upgrade",
        check="Unit health after upgrade.",
        action="Rollback to previous revision with `juju refresh`.",
        approved_critical_component=True,
    )
    UPGRADES_PRE_UPGRADE_CHECK_FAILED = StatusObject(
        status="blocked",
        message="Pre upgrade check failed: {message}",
        short_message="Pre-upgrade check failed",
        check="Pre-upgrade health and topology checks.",
        action="Fix issues in the logs, then re-run pre-upgrade-check.",
        approved_critical_component=True,
    )
    UPGRADES_ROLLBACK_UNSUPPORTED = StatusObject(
        status="blocked",
        message=(
            "Rollback unsupported. Refresh to a newer revision or consult the recovery documentation"
        ),
        short_message="Rollback unsupported",
        check="Rollback support for current versions.",
        action="Refresh to a newer revision or follow recovery documentation.",
        approved_critical_component=True,
    )
    UPGRADES_ROLLBACK_INCOMPATIBLE = StatusObject(
        status="blocked",
        message=(
            "Rollback incompatible. Run 'juju run <unit> force-refresh-start' with "
            "`check-compatibility` set to false to override node version and attempt "
            "startup procedure"
        ),
        short_message="Rollback incompatible",
        check="Rollback compatibility.",
        action="Run force-refresh-start with check-compatibility=false if you accept risk.",
        approved_critical_component=True,
    )
    K8S_DEPLOYED_WITHOUT_TRUST = StatusObject(
        status="blocked",
        message="Run `juju trust {charm_app} --scope=cluster`. Needed for in-place refreshes",
        short_message="Missing juju trust",
        check="Kubernetes app trusted for cluster-scoped refresh ops.",
        action="Run `juju trust {charm_app} --scope=cluster`.",
        approved_critical_component=True,
    )
