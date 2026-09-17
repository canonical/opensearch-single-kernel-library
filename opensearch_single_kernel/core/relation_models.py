#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Relations models used by wrappers to access databag"""

from typing import Annotated, Optional

import poetry.core.constraints.version as poetry_version
from dpcharmlibs.interfaces import (
    BaseCommonModel,
    ExtraSecretStr,
    OptionalSecretStr,
    PeerModel,
    ResourceProviderModel,
    UserSecretStr,
)
from pydantic import Field, field_serializer, field_validator, model_serializer

from opensearch_single_kernel.common.constants import (
    SECRET_APP_ADMIN,
    SECRET_BACKUPS,
    SECRET_PLUGIN,
    SECRET_UNIT_HTTP,
    SECRET_UNIT_TRANSPORT,
    PerformanceType,
)
from opensearch_single_kernel.core.base_models import (
    DeploymentDescription,
    Node,
    PeerClusterApp,
    PeerClusterOrchestrators,
    PeerClusterRelErrorData,
    PluginConfigInfo,
    UnitUpgradesState,
    UpgradeVersions,
    _sort_nested_dicts,
)
from opensearch_single_kernel.core.storage import AzureRelData, GcsRelData, S3RelData

TransportSecretStr = Annotated[
    OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_TRANSPORT
]
HttpSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_HTTP]
AdminSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_APP_ADMIN]
PluginsSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_PLUGIN]
BackupSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_BACKUPS]


class JWTAuthConfiguration(ResourceProviderModel):
    """Model class for the configuration parameters of JWT authentication."""

    signing_key: ExtraSecretStr = Field(default=None)
    jwt_header: str | None = Field(default=None)
    jwt_url_parameter: str | None = Field(default=None)
    roles_key: str
    subject_key: str | None = Field(default=None)
    required_audience: str | None = Field(default=None)
    required_issuer: str | None = Field(default=None)
    jwt_clock_skew_tolerance_seconds: int | None = Field(default=None)


class LockAppStateModel(PeerModel):
    """Inert data model for the Lock application state."""

    # Juju event id during which the leader granted the lock to itself; the leader may
    # only use the lock in a next event (see LockApplication.grant_lock).
    leader_acquired_lock_after_juju_event_id: str | None = Field(default=None)
    # Name of the unit currently holding the peer lock, None when the lock is free.
    unit_with_lock: str | None = Field(default=None)


class LockServerStateModel(PeerModel):
    """Inert data model for the Lock unit state.

    Reads/writes to the databag go through the `LockServer` wrapper.
    """

    # Whether this unit is asking the leader for the peer lock.
    lock_requested: bool = Field(default=False)
    # Write-only field to force a peer relation-changed event on other units.
    trigger: str | None = Field(default=None, alias="-trigger")


class OpenSearchAppPeerModel(PeerModel):
    """Peer model mapping to the OpenSearch application state."""

    # --- Secret-group fields (internal-user credentials) ---
    admin_password: UserSecretStr = Field(default="")
    admin_hashed_password: UserSecretStr = Field(default="")
    kibana_server_password: UserSecretStr = Field(default="")
    kibana_server_hashed_password: UserSecretStr = Field(default="")
    monitor_password: UserSecretStr = Field(default="")
    monitor_hashed_password: UserSecretStr = Field(default="")

    # --- Secret-group fields (admin-TLS material) ---
    admin_truststore_password: AdminSecretStr = Field(default="")
    admin_subject: AdminSecretStr = Field(default="")
    admin_keystore_password: AdminSecretStr = Field(default="")
    admin_key: AdminSecretStr = Field(default="")
    admin_key_password: AdminSecretStr = Field(default="")
    admin_csr: AdminSecretStr = Field(default="")
    admin_chain: AdminSecretStr = Field(default="")
    admin_cert: AdminSecretStr = Field(default="")
    admin_ca_cert: AdminSecretStr = Field(default="")

    # --- Secret-group fields (plugin secrets) ---
    plugin_secrets: PluginsSecretStr = Field(default="")

    # Whether the admin user has been created in the security index.
    admin_user_initialized: bool = Field(default=False)
    # Number of units that took part in the initial cluster bootstrap.
    bootstrap_contributors_count: int = Field(default=0)
    # Whether the OpenSearch security plugin's security index has been initialized.
    security_index_initialised: bool = Field(default=False)
    # Cluster topology: unit name -> Node (roles, temperature, unit number) for every unit
    nodes_config: dict[str, Node] = Field(default_factory=dict)
    # Whether the application-level cluster bootstrap process has completed.
    bootstrapped: bool = Field(default=False)
    # Description of application's role/config within the deployment.
    deployment_description: DeploymentDescription | None = Field(default=None)
    # Peer-cluster fleet apps discovered by this application, keyed by app id.
    cluster_fleet_apps: dict[str, PeerClusterApp] = Field(default_factory=dict)
    # Peer-cluster fleet apps learned through peer-cluster relations (from other apps in the
    # fleet), keyed by relation id.
    cluster_fleet_apps_rels: dict[int, PeerClusterApp] = Field(default_factory=dict)
    # Which app in the fleet act as the main/failover orchestrator.
    orchestrators: Optional[PeerClusterOrchestrators] = Field(
        default_factory=PeerClusterOrchestrators
    )
    # Name of the first unit to take on the "data" role.
    first_data_node: Optional[str] = Field(default=None)
    # Last time application's databag was updated; used to force relation-changed hook
    update_ts: str = Field(default="")
    # Voting-exclusion entries application still needs to remove from the cluster voting config.
    delete_voting_exclusions: set[str] = Field(default_factory=set)
    # Allocation-exclusion entries application still needs to remove from the cluster
    # shard allocation exclusion settings.
    allocation_exclusions_to_delete: set[str] = Field(default_factory=set)
    # Users created for external client relations. Key is username, Value is relation id.
    client_relation_users: dict[str, str] = Field(default_factory=dict)
    # Whether the application is missing a relation it requires
    missing_relations: bool = Field(default=False)

    # Plugin configuration metadata application is responsible for, key is plugin label
    plugin_config_info: dict[str, PluginConfigInfo] = Field(default_factory=dict)

    @field_validator("allocation_exclusions_to_delete", "delete_voting_exclusions", mode="before")
    @classmethod
    def parse_comma_separated_strings(cls, v):
        """Parse the comma-separated databag string into a list, dropping empty entries."""
        if isinstance(v, str):
            return list(filter(None, v.split(",")))
        return v

    @field_serializer("allocation_exclusions_to_delete", "delete_voting_exclusions")
    def serialize_comma_separated_strings(self, v: set[str]) -> str:
        """Serialize the set to a sorted, comma-separated string for stable databag output."""
        return ",".join(sorted(v))

    @field_serializer(
        "nodes_config",
        "cluster_fleet_apps",
        "cluster_fleet_apps_rels",
        "client_relation_users",
        "plugin_config_info",
    )
    def _sort_dict_fields(self, value: dict) -> dict:
        """Sort nested dicts so serialized databag output is stable and order-independent."""
        return _sort_nested_dicts(value)

    @property
    def is_data_role_in_cluster_fleet_apps(self) -> bool:
        """Look for data-role through all the roles of all the nodes in all applications"""
        data_apps_in_fleet = [
            app for app in self.cluster_fleet_apps.values() if "data" in app.roles
        ]
        return bool(data_apps_in_fleet) and any(
            app.planned_units > 0 for app in data_apps_in_fleet
        )


class OpenSearchServerPeerModel(PeerModel):
    """Peer model to the OpenSearch unit state."""

    # --- Secret-group fields (transport-layer TLS) ---
    transport_key: TransportSecretStr = Field(default="")
    transport_key_password: TransportSecretStr = Field(default="")
    transport_csr: TransportSecretStr = Field(default="")
    transport_chain: TransportSecretStr = Field(default="")
    transport_cert: TransportSecretStr = Field(default="")
    transport_ca_cert: TransportSecretStr = Field(default="")
    transport_truststore_password: TransportSecretStr = Field(default="")
    transport_subject: TransportSecretStr = Field(default="")
    transport_keystore_password: TransportSecretStr = Field(default="")

    # --- Secret-group fields (HTTP-layer TLS) ---
    http_keystore_password: HttpSecretStr = Field(default="")
    http_key: HttpSecretStr = Field(default="")
    http_key_password: HttpSecretStr = Field(default="")
    http_csr: HttpSecretStr = Field(default="")
    http_chain: HttpSecretStr = Field(default="")
    http_cert: HttpSecretStr = Field(default="")
    http_ca_cert: HttpSecretStr = Field(default="")
    http_truststore_password: HttpSecretStr = Field(default="")
    http_subject: HttpSecretStr = Field(default="")

    # Performance profile ("testing"/"production") applied to this unit's JVM/OpenSearch config.
    # None means "not yet set" callers fall back to the profile configured via charm config.
    profile: Optional[PerformanceType] = Field(default=None)
    # Whether this unit was one of the initial seed nodes used to bootstrap the cluster.
    bootstrap_contributor: bool = Field(default=False)
    # Whether this unit has been removed from the cluster_manager-eligible role.
    cluster_manager_removed: bool = Field(default=False)
    # Timestamp set once the unit's OpenSearch service has started; unset
    # means "not started".
    started: Optional[str] = Field(default=None)
    # Whether this unit is currently mid CA-rotation
    tls_ca_renewing: bool = Field(default=False)
    # Whether this unit has finished renewing to the new CA.
    tls_ca_renewed: bool = Field(default=False)
    # Whether this unit's TLS certificates are fully configured.
    tls_configured: bool = Field(default=False)
    # Last time application's databag was updated; used to force relation-changed hook
    update_ts: str = Field(default="")
    # Timestamp of the last time this unit checked its certificates for upcoming expiry.
    certs_exp_checked_at: str = Field(default="1970-01-01 00:00:00")
    # Allocation-exclusion entries application still needs to remove from the cluster
    # shard allocation exclusion settings.
    allocation_exclusions_to_delete: set[str] = Field(default_factory=set)
    # Voting-exclusion entries application still needs to remove from the cluster voting config.
    delete_voting_exclusions: set[str] = Field(default_factory=set)
    # Last known IP address of this unit.
    last_host_ip: str = Field(default="")
    # Plugin configuration metadata unit is responsible for, key is plugin label
    plugin_config_info: dict[str, PluginConfigInfo] = Field(default_factory=dict)
    oauth_openid_connect_url: str = Field(default="")
    # Set when this unit is departing the oauth relation.
    oauth_departing: bool = Field(default=False)
    # Set when this specific unit is departing/scaling down. Used to skip relation-broken
    # triggered by the unit's own removal.
    unit_dying: bool = Field(default=False)
    # PID of this unit's running pebble-observer subprocess, or None if not started/stopped.
    pebble_observer_pid: Optional[int] = Field(default=None)

    @field_serializer("plugin_config_info")
    def _sort_plugin_config_info(self, value: dict) -> dict:
        """Sort nested dicts so serialized databag output is stable and order-independent."""
        return _sort_nested_dicts(value)

    @field_validator("allocation_exclusions_to_delete", "delete_voting_exclusions", mode="before")
    @classmethod
    def parse_comma_separated_strings(cls, v):
        """Parse the comma-separated databag string into a list, dropping empty entries."""
        if isinstance(v, str):
            return list(filter(None, v.split(",")))
        return v

    @field_serializer("allocation_exclusions_to_delete", "delete_voting_exclusions")
    def serialize_comma_separated_strings(self, v: set[str]) -> str:
        """Serialize the set to a sorted, comma-separated string for stable databag output."""
        return ",".join(sorted(v))

    @field_validator("started", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Ensure non-None values are always strings, even if the databag returns a float/int."""
        if v is None:
            return None
        return str(v)

    @field_validator("update_ts", mode="before")
    @classmethod
    def coerce_update_ts_to_str(cls, v):
        """Ensure update_ts is always a string, even if the databag returns a float/int."""
        if v is None:
            return ""
        return str(v)


class UpgradeAppModel(PeerModel):
    """Inert data model for the upgrade application-level databag.

    Reads/writes to the databag go through the `UpgradeApplication` wrapper.
    """

    # Charm/workload versions the app is upgrading to.
    versions: Optional[UpgradeVersions] = Field(default=None)
    # Whether the user has resumed the upgrade via the Juju action.
    upgrade_resumed: bool = Field(default=False)
    # Write-only timestamp bumped alongside `upgrade_resumed` so a repeated resume with
    # the same value still changes the databag and re-triggers relation-changed on peers.
    upgrade_resume_last_updated: Optional[str] = Field(
        default=None, alias="-unused-timestamp-upgrade-resume-last-updated"
    )

    @field_validator("upgrade_resume_last_updated", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Coerce numeric timestamp stored as float to str."""
        if v is None:
            return None
        return str(v)


class UpgradeServerModel(PeerModel):
    """Inert data model for the upgrade unit-level databag.

    Reads/writes to the databag go through the `UpgradeServer` wrapper.
    """

    state: Optional[str] = Field(default=None)
    snap_revision: Optional[str] = Field(default=None)
    workload_version: Optional[str] = Field(default=None)

    @field_validator("snap_revision", "workload_version", "state", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Coerce numeric values stored in the databag to str."""
        if v is None:
            return None
        return str(v)

    @property
    def unit_state(self) -> Optional["UnitUpgradesState"]:
        """Get the unit upgrade state, typed."""
        return UnitUpgradesState(self.state) if self.state else None

    @property
    def workload_version_parsed(self) -> poetry_version.Version | None:
        """Get the parsed workload version of installed OpenSearch."""
        return (
            poetry_version.Version.parse(self.workload_version) if self.workload_version else None
        )


class PeerClusterServerModel(PeerModel):
    """Data model for the peer cluster unit-level databag."""

    tls_ca_renewing: bool = Field(default=False)
    tls_ca_renewed: bool = Field(default=False)
    tls_configured: bool = Field(default=False)
    # Hash of the last snapshots (backup) credentials this unit persisted to its keystore.
    snapshots_credentials_saved: Optional[str] = Field(default=None)


class PeerClusterAppModel(BaseCommonModel):
    """Data model for the peer cluster application-level databag."""

    # Whether the requirer app offers itself as a failover-orchestrator candidate.
    is_candidate_failover_orchestrator: bool = Field(default=False)
    # Which orchestrator role ("main"/"failover") this relation was established for.
    trigger: Optional[str] = Field(default=None)
    # Whether the requirer has acknowledged/registered the main orchestrator.
    main_orchestrator_registered: Optional[bool] = Field(default=None)
    # The current peer cluster app own identity/roles/unit-count on this relation.
    app: Optional[PeerClusterApp] = Field(default=None)
    # All apps in the fleet as known by the orchestrator, keyed by app id.
    cluster_fleet_apps: dict[str, PeerClusterApp] = Field(default_factory=dict)
    # The currently elected main/failover orchestrator pair. None means this relation has
    # never had orchestrator data written to it.
    orchestrators: Optional[PeerClusterOrchestrators] = Field(default=None)
    # Hash of the last broadcast payload
    rel_data_hash: Optional[str] = Field(default=None)
    error_data: Optional[PeerClusterRelErrorData] = Field(default=None)
    security_index_initialised: bool = Field(default=False)
    first_data_node: Optional[str] = Field(default=None)
    nodes_config: dict[str, Node] = Field(default_factory=dict)
    deployment_description: Optional[DeploymentDescription] = Field(default=None)
    # Optional (not default {}) so the requirer can distinguish "no plugin data broadcast"
    # (None -> leave the subcluster's plugins untouched) from "plugins explicitly removed"
    # ({} -> remove them in the subcluster). Only the main orchestrator broadcasts a dict;
    # non-main orchestrators broadcast None. See events/peer_cluster.py guard.
    plugin_config_info: Optional[dict[str, PluginConfigInfo]] = Field(default=None)
    # Marker that the peer-cluster relation secret groups have been pre-created; see
    # initialize_empty_secrets().
    pc_secrets_initialized: bool = Field(default=False)

    # User secrets
    admin_password: UserSecretStr = Field(default="")
    admin_hashed_password: UserSecretStr = Field(default="")
    kibana_server_password: UserSecretStr = Field(default="")
    kibana_server_hashed_password: UserSecretStr = Field(default="")
    monitor_password: UserSecretStr = Field(default="")
    monitor_hashed_password: UserSecretStr = Field(default="")

    # Plugin secrets
    plugin_secrets: PluginsSecretStr = Field(default="")

    # Admin TLS secrets
    admin_truststore_password: AdminSecretStr = Field(default="")
    admin_subject: AdminSecretStr = Field(default="")
    admin_keystore_password: AdminSecretStr = Field(default="")
    admin_key: AdminSecretStr = Field(default="")
    admin_key_password: AdminSecretStr = Field(default="")
    admin_csr: AdminSecretStr = Field(default="")
    admin_chain: AdminSecretStr = Field(default="")
    admin_cert: AdminSecretStr = Field(default="")
    admin_ca_cert: AdminSecretStr = Field(default="")

    # Backup storage secrets. These must be top-level fields, the databag serializer only
    # promotes top-level secret-group fields into Juju secrets, not credential fields nested
    # inside an S3RelData/AzureRelData/GcsRelData sub-model.
    s3_access_key: BackupSecretStr = Field(default="")
    s3_secret_key: BackupSecretStr = Field(default="")
    s3_tls_ca_chain: BackupSecretStr = Field(default="")
    azure_storage_account: BackupSecretStr = Field(default="")
    azure_secret_key: BackupSecretStr = Field(default="")
    gcs_secret_key: BackupSecretStr = Field(default="")

    @field_serializer("cluster_fleet_apps", "nodes_config", "plugin_config_info")
    def _sort_dict_fields(self, value: dict) -> dict:
        """Sort nested dicts so serialized databag output is stable and order-independent."""
        return _sort_nested_dicts(value)

    @model_serializer(mode="wrap")
    def serialize_model(self, handler, info):
        """Serialize the model, skipping secret resolution on request."""
        if (info.context or {}).get("skip_secrets"):
            return handler(self)
        return BaseCommonModel.serialize_model(self, handler, info)

    def backup_reldata(self, cloud: str) -> "S3RelData | AzureRelData | GcsRelData | None":
        """Reconstruct a cloud's RelData from the backup secrets."""
        if cloud == "s3":
            if not (self.s3_access_key and self.s3_secret_key):
                return None
            return S3RelData.model_construct(
                access_key=self.s3_access_key,
                secret_key=self.s3_secret_key,
                tls_ca_chain=self.s3_tls_ca_chain or None,
            )
        if cloud == "azure":
            if not (self.azure_storage_account and self.azure_secret_key):
                return None
            return AzureRelData.model_construct(
                storage_account=self.azure_storage_account,
                secret_key=self.azure_secret_key,
            )
        if cloud == "gcs":
            if not self.gcs_secret_key:
                return None
            return GcsRelData.model_construct(secret_key=self.gcs_secret_key)
        return None
