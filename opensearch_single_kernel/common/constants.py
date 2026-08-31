#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Charm literals."""

from enum import Enum

from opensearch_single_kernel.utils.enum import BaseStrEnum


class ObjectStorageType(BaseStrEnum):
    """The object storage types."""

    S3 = "s3"
    AZURE = "azure"
    GCS = "gcs"
    S3_PCLUSTER = "s3-pcluster"
    AZURE_PCLUSTER = "azure-pcluster"
    GCS_PCLUSTER = "gcs-pcluster"
    CONFLICT = "conflict"


class Substrates(BaseStrEnum):
    """Possible substrates."""

    K8S = "k8s"
    VM = "vm"


class Scope(BaseStrEnum):
    """Peer relations scope."""

    APP = "app"
    UNIT = "unit"


class HealthColors(BaseStrEnum):
    """Colors the clusters or a unit may have depending on their health."""

    GREEN = "green"
    YELLOW = "yellow"
    YELLOW_TEMP = "yellow-temp"
    RED = "red"
    UNKNOWN = "unknown"
    IGNORE = "ignore"


class Directive(BaseStrEnum):
    """Directive indicating what the pending actions for the current deployments are."""

    NONE = "none"
    SHOW_STATUS = "show-status"
    WAIT_FOR_PEER_CLUSTER_RELATION = "wait-for-peer-cluster-relation"
    INHERIT_CLUSTER_NAME = "inherit-name"
    VALIDATE_CLUSTER_NAME = "validate-cluster-name"
    RECONFIGURE = "reconfigure-cluster"


class StartMode(BaseStrEnum):
    """Mode of start of units in this deployment."""

    WITH_PROVIDED_ROLES = "start-with-provided-roles"
    WITH_GENERATED_ROLES = "start-with-generated-roles"


class PerformanceType(BaseStrEnum):
    """Performance types available."""

    PRODUCTION = "production"
    TESTING = "testing"


class DeploymentType(BaseStrEnum):
    """Nature of a sub cluster deployment."""

    MAIN_ORCHESTRATOR = "main-orchestrator"
    FAILOVER_ORCHESTRATOR = "failover-orchestrator"
    OTHER = "other"


class State(BaseStrEnum):
    """State of a deployment, directly mapping to the juju statuses."""

    ACTIVE = "active"
    BLOCKED_WAITING_FOR_RELATION = "blocked-waiting-for-peer-cluster-relation"
    BLOCKED_WRONG_RELATED_CLUSTER = "blocked-wrong-related-cluster"
    BLOCKED_CANNOT_START_WITH_ROLES = "blocked-cannot-start-with-current-set-roles"
    BLOCKED_CANNOT_APPLY_NEW_ROLES = "blocked-cannot-apply-new-roles"


# TLS
class CertType(BaseStrEnum):
    """Certificate types."""

    APP_ADMIN = "app-admin"  # admin / management of cluster
    # APP_CLIENT_HTTP = "app-client-http"  # external http clients (rest layer)
    UNIT_TRANSPORT = "unit-transport"  # internal node to node communication (transport layer)
    UNIT_HTTP = "unit-http"  # http for nodes (rest layer) - units act as servers


class StoreType(BaseStrEnum):
    """Type of certificates and keys store."""

    KEYSTORE = "keystore"
    TRUSTSTORE = "truststore"


class TlsFileExt(BaseStrEnum):
    """Extensions of TLS generated files."""

    CA = ".ca"
    CERT = ".cert"
    CHAIN = ".chain"
    CSR = ".csr"
    KEY = ".key"
    KEYPASS = ".key-password"


class SmtpTransportSecurity(BaseStrEnum):
    """SMTP transport security protocol.

    Enum values match relation data (smtp-integrator). api_method() maps to
    OpenSearch Notifications API strings (start_tls, ssl).
    """

    NONE = "none"
    STARTTLS = "starttls"
    TLS = "tls"

    def api_method(self) -> str:
        """Return the OpenSearch Notifications API method string."""
        return {"none": "none", "starttls": "start_tls", "tls": "ssl"}[self.value]


class OpenSearchPaths(BaseStrEnum):
    """Base Paths for OpenSearch Snap."""

    HOME = "usr/share/opensearch"
    CONF = "etc/opensearch"
    DATA = "var/lib/opensearch"
    LOGS = "var/log/opensearch"
    JDK = "usr/lib/jvm/java-21-openjdk-amd64"
    TMP = "usr/share/tmp"
    BIN = "usr/share/opensearch/bin"


class ExtraUserRolePermissions(Enum):
    """An enum of user types and their associated permissions."""

    # Default user has CRUD in a specific index. Update index_patterns to include the index to
    # which these permissions are applied.
    DEFAULT = {
        "cluster_permissions": ["cluster_monitor"],
        "index_permissions": [
            {
                "index_patterns": [],
                "dls": "",
                "fls": [],
                "masked_fields": [],
                "allowed_actions": [
                    "indices_monitor",
                    "data_access",
                ],
            }
        ],
    }

    # Admin user has control over:
    # - creating multiple indices
    # - Removing indices they have created
    ADMIN = {
        "index_permissions": [
            {
                "index_patterns": ["*"],
                "fls": [],
                "masked_fields": [],
                "allowed_actions": [
                    "cluster_all",
                    "indices_all",
                    "crud",
                ],
            }
        ],
        "cluster_permissions": [
            "indices_all",
            "cluster_all",
            "manage",
        ],
    }


# Profiles
_1GB_IN_KB = 1024 * 1024  # 1GB in KB
MAX_HEAP_SIZE_IN_KB = 31 * _1GB_IN_KB  # 31GB in KB
PERFORMANCE_PROFILE = "profile"
# Opensearch Snap revision
# OPENSEARCH_SNAP_REVISION = "98"  # Keep in sync with `workload_version` file
# Revision 2.19.5
# OPENSEARCH_SNAP_REVISION = "108"  # Keep in sync with `workload_version` file
# Revision 3.7.0
OPENSEARCH_SNAP_REVISION = "49"  # Keep in sync with `workload_version` file

# OpenSearch Users and roles
ADMIN_USER = "admin"
KIBANA_SERVER_USER = "kibanaserver"
KIBANA_SERVER_ROLE = "kibana_server"
COS_USER = "monitor"
COS_ROLE = "readall_and_monitor"
OPENSEARCH_SYSTEM_USERS = {ADMIN_USER, KIBANA_SERVER_USER}
OPENSEARCH_USERS = OPENSEARCH_SYSTEM_USERS | {COS_USER}

# Maps an internal user to its (password, hashed_password) field names on
# OpenSearchAppPeerModel.
USER_SECRET_FIELDS: dict[str, tuple[str, str]] = {
    ADMIN_USER: ("admin_password", "admin_hashed_password"),
    KIBANA_SERVER_USER: ("kibana_server_password", "kibana_server_hashed_password"),
    COS_USER: ("monitor_password", "monitor_hashed_password"),
}

GENERATED_ROLES = ["cluster_manager", "data", "ingest", "ml"]

# OpenSearch indices
OPENSEARCH_NODE_LOCK_INDEX = ".charm_node_lock"
SYSTEM_INDICES = {
    ".opendistro_security",
    ".opensearch-sap-log-types-config",
    OPENSEARCH_NODE_LOCK_INDEX,
}
# TLS
CA_ALIAS = "ca"
CA_TRUSTSTORE_P12 = "cacerts.p12"
OLD_CA_ALIAS = f"old-{CA_ALIAS}"
OLD_CA_PREFIX = "old-"
CERTS_EXPIRATION_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# OAuth
OAUTH_CLIENT_AUDIENCE = ["opensearch"]
OAUTH_CLIENT_REDIRECT_URI = "http://opensearch.local"
OAUTH_CLIENT_SCOPE = "openid email profile"
OAUTH_CLIENT_GRANT_TYPES = ["client_credentials"]


# OpenSearch Protected Indices
PROTECTED_INDEX_NAMES = [
    ".opendistro_security",
    ".opendistro-alerting-config",
    ".opendistro-alerting-alert*",
    ".opendistro-anomaly-results*",
    ".opendistro-anomaly-detector*",
    ".opendistro-anomaly-checkpoints",
    ".opendistro-anomaly-detection-state",
    OPENSEARCH_NODE_LOCK_INDEX,
]

DEFAULT_EXTRA_USER_ROLE = "default"


# OpenSearch default port
OPENSEARCH_HTTP_PORT = 9200
COS_PORT = "9200"

# OpenSearch storage name
OPENSEARCH_DATA_STORAGE_NAME = "opensearch-data"


# Relations
PEER_RELATION = "opensearch-peers"
TLS_RELATION = "certificates"
NODE_LOCK_RELATION = "node-lock-fallback"
PEER_CLUSTER_ORCHESTRATOR_RELATION = "peer-cluster-orchestrator"
PEER_CLUSTER_RELATION = "peer-cluster"
S3_RELATION = "s3-credentials"
AZURE_RELATION = "azure-credentials"
GCS_RELATION = "gcs-credentials"
CLIENT_RELATION = "opensearch-client"
COS_RELATION = "cos-agent"
JWT_CONFIG_RELATION = "jwt-configuration"
OAUTH_RELATION = "oauth"
STATUS_PEERS_RELATION = "status-peers"
SMTP_RELATION = "smtp"
UPGRADE_RELATION = "upgrade-version-a"
PROMETHEUS_K8S_RELATION = "metrics-endpoint"
LOKI_K8S_RELATION = "logging"
GRAFANA_K8S_RELATION = "grafana-dashboard"


# Paths
BASE_SNAP_DIR = "/var/snap/opensearch-charmed"
SNAP_DATA = "current"
SNAP_COMMON = "common"
SNAP = "/snap/opensearch-charmed/current"


# Secrets
PW_POSTFIX = "password"
HASH_POSTFIX = f"{PW_POSTFIX}-hash"
ADMIN_PW = f"admin-{PW_POSTFIX}"
ADMIN_PW_HASH = f"{ADMIN_PW}-hash"
SECRETS_LABEL_SEPARATOR = "."

ADMIN_HASHED_PASSWORD_KEY = "admin-hashed-password"
KIBANA_SERVER_HASHED_PASSWORD_KEY = "kibana-server-hashed-password"

SECRET_APP_ADMIN = "app-admin"
SECRET_UNIT_TRANSPORT = "unit-transport"
SECRET_UNIT_HTTP = "unit-http"
SECRET_PLUGIN = "plugins"
SECRET_BACKUPS = "backups"

# Backup
S3_CREDENTIALS = "s3-creds"
S3_PEER_SECRET_KEYS = [
    "secret-key",
    "access-key",
    "s3-secret-key",
    "s3-access-key",
    S3_CREDENTIALS,
]
AZURE_CREDENTIALS = "azure-creds"
AZURE_PEER_SECRET_KEYS = [
    "azure-storage-account",
    "azure-secret-key",
    "secret-key",
    "storage-account",
    AZURE_CREDENTIALS,
]
GCS_CREDENTIALS = "gcs-creds"
# Secret fields to propagate per object-storage cloud, keyed by field name.
OBJECT_STORAGE_SECRET_FIELDS: dict[str, tuple[str, ...]] = {
    "s3": ("access_key", "secret_key", "tls_ca_chain"),
    "azure": ("storage_account", "secret_key"),
    "gcs": ("secret_key",),
}
S3_CA_ALIAS = "s3-snapshots-gateway"
STORE_PASSWORD = "changeit"
S3_REPOSITORY = "s3-repository"
AZURE_REPOSITORY = "azure-repository"
GCS_REPOSITORY = "gcs-repository"
OPENSEARCH_BACKUP_ID_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# SMTP
SMTP_SECRET_LABEL = "plugin-notifications"


# Messages
PEER_CLUSTER_NO_RELATION = "Cannot start. Waiting for peer cluster relation..."
PEER_CLUSTER_WRONG_RELATION = "Cluster name doesn't match with related cluster. Remove relation."
CLUSTER_MANAGER_VOTING_ROLES_PROVIDED_INVALID = (
    "cluster_manager and voting_only roles cannot be both set on the same node."
)
CLUSTER_MANAGER_ROLE_REMOVAL_FORBIDDEN = (
    "Removal of cluster_manager role from deployment not allowed."
)
DATA_ROLE_REMOVAL_FORBIDDEN = (
    "Removal of data role from current deployment not allowed - the data cannot be reallocated."
)
# Endpoints
USER_ENDPOINT = "/_plugins/_security/api/internalusers"
USER_ROLE_ENDPOINT = "/_plugins/_security/api/roles"
USER_ROLESMAPPING_ENDPOINT = "/_plugins/_security/api/rolesmapping"


# Root group id (gid 0). Used when we want root to have group-level access.
ROOT_GID = 0

# Container name for K8s deployments
CONTAINER_NAME = "opensearch"

# Service name for Pebble
OPENSEARCH_PEBBLE_SERVICE_NAME = "opensearch"

# File permissions as octal
# standard directory permissions
DIR_PERMISSIONS_READONLY = 0o750
# certificates directory permissions
# minimum permissions: daemon can write, root can list/read.
DIR_PERMISSIONS_CERTIFICATES = 0o750
# secure directory permissions
DIR_PERMISSIONS_SECURE = 0o775

# Pebble service user/group
PEBBLE_SERVICE_USER = "_daemon_"
PEBBLE_SERVICE_GROUP = "_daemon_"

# Upgrades
UPGRADES_COMPATIBILITY_MATRIX = {
    "2.19.4": {"2.18.0", "2.19.0", "2.19.1", "2.19.2", "2.19.3"},
    "2.19.5": {"2.19.1", "2.19.4"},
}
