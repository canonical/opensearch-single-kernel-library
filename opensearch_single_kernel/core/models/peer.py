#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the opensearch-peers relation (unit and application databags)."""

import json
import logging
from typing import Optional

from pydantic import Field, field_serializer, field_validator, model_serializer

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_USER,
    KIBANA_SERVER_USER,
    DeploymentType,
    PerformanceType,
)
from opensearch_single_kernel.core.models.base import (
    AdminSecretStr,
    DeploymentDescription,
    HttpSecretStr,
    Node,
    PersistentModel,
    PluginConfigInfo,
    PluginsSecretStr,
    TransportSecretStr,
    UserSecretStr,
    _sort_nested_dicts,
    stripped_or_none,
)
from opensearch_single_kernel.core.models.peer_cluster import (
    PeerClusterApp,
    PeerClusterAppModel,
    PeerClusterOrchestrators,
)
from opensearch_single_kernel.core.models.profiles import (
    OpenSearchProfile,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.core.models.storage import (
    AzureRelData,
    GcsRelData,
    S3RelData,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    PeerModel,
)

logger = logging.getLogger(__name__)


class OpenSearchServerPeerModel(PersistentModel, PeerModel):
    """Peer model mapping to the OpenSearch unit (server) state."""

    # Performance profile ("testing"/"production") applied to this unit's JVM/OpenSearch config.
    # None means "not yet set" -- callers fall back to the profile configured via charm config.
    # Stored under the databag key "profile"; the `profile` property below exposes the value
    # as a resolved OpenSearchProfile instance.
    profile_type: Optional[PerformanceType] = Field(default=None, alias="profile")
    # Whether this unit was one of the initial seed nodes used to bootstrap the cluster.
    # Alias pinned to the underscored key deployed databags use (the PeerModel alias
    # generator would otherwise hyphenate it).
    bootstrap_contributor: bool = Field(default=False, alias="bootstrap_contributor")
    # Whether this unit has been removed from the cluster_manager-eligible role (e.g. scale-down).
    cluster_manager_removed: bool = Field(default=False, alias="cluster_manager_removed")
    # Timestamp (str(time.time())) set once the unit's OpenSearch service has started; empty
    # string means "not started". Used elsewhere as a truthy started/not-started flag.
    started: str = Field(default="")
    # Whether this unit is currently mid CA-rotation (new CA generated but not yet fully rolled).
    tls_ca_renewing: bool = Field(default=False, alias="tls_ca_renewing")
    # Whether this unit has finished renewing to the new CA.
    tls_ca_renewed: bool = Field(default=False, alias="tls_ca_renewed")
    # Whether this unit's TLS certificates (transport/HTTP) are fully configured.
    tls_configured: bool = Field(default=False, alias="tls_configured")
    # Last time this unit's databag was updated; used to force relation-changed observers to
    # notice a change even when no other field differs.
    update_ts: str = Field(default="")
    # Timestamp of the last time this unit checked its certificates for upcoming expiry.
    certs_exp_checked_at: str = Field(default="1970-01-01 00:00:00", alias="certs_exp_checked_at")
    # Allocation-exclusion entries (node names/IDs) this unit still needs to remove from the
    # cluster's shard allocation exclusion settings.
    allocation_exclusions_to_delete: set[str] = Field(default_factory=set)
    # Voting-exclusion entries this unit still needs to remove from the cluster's voting config.
    delete_voting_exclusions: set[str] = Field(default_factory=set)
    # Last known IP address of this unit; used to detect IP changes across reconciliation.
    last_host_ip: str = Field(default="", alias="last_host_ip")
    # Plugin configuration/cleanup metadata this unit is responsible for, keyed by plugin label.
    plugin_config_info: dict[str, PluginConfigInfo] = Field(
        default_factory=dict, alias="plugin_config_info"
    )
    # OAuth OpenID Connect URL configured on this unit (if an oauth relation is active).
    oauth_openid_connect_url: str = Field(default="", alias="oauth_openid_connect_url")
    # Set when this specific unit is departing/scaling down (as opposed to a related app or an
    # external relation being removed). Used to skip relation-broken side effects triggered by
    # the unit's own removal.
    unit_dying: bool = Field(default=False)
    # PID of this unit's running pebble-observer subprocess, or None if not started/stopped.
    pebble_observer_pid: Optional[int] = Field(default=None)

    @field_serializer("plugin_config_info")
    def _sort_plugin_config_info(self, value: dict) -> dict:
        return _sort_nested_dicts(value)

    @field_validator("allocation_exclusions_to_delete", "delete_voting_exclusions", mode="before")
    @classmethod
    def parse_comma_separated_strings(cls, v):
        """Validator for allocation_exclusions_to_delete, delete_voting_exclusions"""
        if isinstance(v, str):
            return list(filter(None, v.split(",")))
        return v

    @field_serializer("allocation_exclusions_to_delete", "delete_voting_exclusions")
    def serialize_comma_separated_strings(self, v: set[str]) -> str:
        """Validator for allocation_exclusions_to_delete, delete_voting_exclusions"""
        return ",".join(sorted(v))

    @field_validator("started", "update_ts", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Ensure fields is always a string, even if the databag returns a float/int."""
        if v is None:
            return ""
        return str(v)

    @property
    def profile(self) -> Optional[OpenSearchProfile]:
        """Current profile of the unit, as an OpenSearchProfile instance."""
        if not self.profile_type:
            return None
        return (
            ProductionProfile()
            if self.profile_type == PerformanceType.PRODUCTION
            else TestingProfile()
        )

    @profile.setter
    def profile(self, value: OpenSearchProfile) -> None:
        """Set current profile of the unit from an OpenSearchProfile instance."""
        self.profile_type = value.type

    @property
    def is_bootstrap_contributor(self) -> bool:
        """Whether this unit was an initial seed node (alias of `bootstrap_contributor`)."""
        return self.bootstrap_contributor

    @is_bootstrap_contributor.setter
    def is_bootstrap_contributor(self, value: bool) -> None:
        self.bootstrap_contributor = value

    @is_bootstrap_contributor.deleter
    def is_bootstrap_contributor(self) -> None:
        del self.bootstrap_contributor

    @property
    def is_cluster_manager_removed(self) -> bool:
        """Whether this unit lost its cluster_manager role (alias of `cluster_manager_removed`)."""
        return self.cluster_manager_removed

    @is_cluster_manager_removed.setter
    def is_cluster_manager_removed(self, value: bool) -> None:
        self.cluster_manager_removed = value

    @is_cluster_manager_removed.deleter
    def is_cluster_manager_removed(self) -> None:
        del self.cluster_manager_removed

    @property
    def is_app_leader(self) -> bool:
        """Check if the unit this model is bound to is the leader of the application."""
        return self.component.is_leader() if self.component is not None else False

    @property
    def unit_id(self) -> int:
        """The id of the unit this model is bound to, from its unit name."""
        return int(self.component.name.split("/")[1])

    @property
    def unit(self):
        """The ops.Unit this model is bound to (alias of `component`)."""
        return self.component

    def initialize_empty_secrets(self) -> None:
        """Initialize empty unit-level secrets to prevent log spam."""
        # Use truthy placeholders only for fields whose secrets don't exist yet
        if transport_m := self.sibling_model(OpenSearchServerPeerTransportSecretsModel):
            if not transport_m.transport_key_password:
                transport_m.transport_key_password = " "
        if http_m := self.sibling_model(OpenSearchServerPeerHttpSecretsModel):
            if not http_m.http_key_password:
                http_m.http_key_password = " "


class OpenSearchServerPeerTransportSecretsModel(PersistentModel, PeerModel):
    """Peer model mapping to the OpenSearch unit's transport-layer TLS secrets.

    Split out of OpenSearchServerPeerModel so that reading/writing a plain (non-secret)
    server field doesn't also resolve the "unit-transport" Juju secret group.
    """

    # Transport TLS Secrets (node-to-node/transport layer; grouped under the "unit-transport"
    # secret group so they're stored as a single Juju secret rather than plaintext).
    transport_key: TransportSecretStr = Field(default="")  # Private key (PEM).
    transport_key_password: TransportSecretStr = Field(default="")  # Password for the key.
    transport_csr: TransportSecretStr = Field(default="")  # Certificate signing request.
    transport_chain: TransportSecretStr = Field(default="")  # Full certificate chain.
    transport_cert: TransportSecretStr = Field(default="")  # Signed leaf certificate.
    transport_ca_cert: TransportSecretStr = Field(default="")  # CA certificate.
    # Password protecting the transport truststore (holds trusted CA certs).
    transport_truststore_password: TransportSecretStr = Field(default="")
    transport_subject: TransportSecretStr = Field(default="")  # Certificate subject/DN.
    # Password protecting the transport keystore (holds the unit's private key/cert).
    transport_keystore_password: TransportSecretStr = Field(default="")


class OpenSearchServerPeerHttpSecretsModel(PersistentModel, PeerModel):
    """Peer model mapping to the OpenSearch unit's HTTP-layer TLS secrets.

    Split out of OpenSearchServerPeerModel so that reading/writing a plain (non-secret)
    server field doesn't also resolve the "unit-http" Juju secret group.
    """

    # HTTP TLS Secrets (client-facing REST layer; grouped under the "unit-http" secret group).
    # Password protecting the HTTP keystore.
    http_keystore_password: HttpSecretStr = Field(default="")
    http_key: HttpSecretStr = Field(default="")  # Private key (PEM).
    http_key_password: HttpSecretStr = Field(default="")  # Password for the key.
    http_csr: HttpSecretStr = Field(default="")  # Certificate signing request.
    http_chain: HttpSecretStr = Field(default="")  # Full certificate chain.
    http_cert: HttpSecretStr = Field(default="")  # Signed leaf certificate.
    http_ca_cert: HttpSecretStr = Field(default="")  # CA certificate.
    # Password protecting the HTTP truststore.
    http_truststore_password: HttpSecretStr = Field(default="")
    http_subject: HttpSecretStr = Field(default="")  # Certificate subject/DN.


class OpenSearchAppPeerModel(PersistentModel, PeerModel):
    """Peer model mapping to the OpenSearch application state."""

    # Whether the internal "admin" user has been created in the security index.
    # Aliases here are pinned to the underscored keys deployed databags use (the PeerModel
    # alias generator would otherwise hyphenate them).
    admin_user_initialized: bool = Field(default=False, alias="admin_user_initialized")
    # Number of units that took part in the initial cluster bootstrap (seed nodes).
    bootstrap_contributors_count: int = Field(default=0, alias="bootstrap_contributors_count")
    # Whether the OpenSearch security plugin's security index has been initialized.
    security_index_initialised: bool = Field(default=False, alias="security_index_initialised")
    # Cluster topology: unit name -> Node (roles, temperature, unit number) for every unit
    # in this application.
    nodes_config: dict[str, Node] = Field(default_factory=dict, alias="nodes_config")
    # Whether the application-level cluster bootstrap process has completed.
    bootstrapped: bool = Field(default=False)
    # Description of this application's role/config within the (possibly multi-app) deployment.
    deployment_description: DeploymentDescription | None = Field(default=None)
    # Peer-cluster fleet apps discovered locally by this application, keyed by app id.
    cluster_fleet_apps: dict[str, PeerClusterApp] = Field(
        default_factory=dict, alias="cluster_fleet_apps"
    )
    # Peer-cluster fleet apps as learned through peer-cluster relations (from other apps in the
    # fleet), keyed by app id.
    cluster_fleet_apps_rels: dict[str, PeerClusterApp] = Field(
        default_factory=dict, alias="cluster_fleet_apps_rels"
    )
    # Which app(s) in the fleet act as the main/failover orchestrator.
    orchestrators: Optional[PeerClusterOrchestrators] = Field(
        default_factory=PeerClusterOrchestrators
    )
    # Name of the first unit in this application to take on the "data" role.
    first_data_node: str = Field(default="", alias="first_data_node")
    # Last time this application's databag was updated; used to force relation-changed observers
    # to notice a change even when no other field differs.
    update_ts: str = Field(default="")
    # Voting-exclusion entries this application still needs to remove from the cluster's voting
    # config.
    delete_voting_exclusions: set[str] = Field(default_factory=set)
    # Allocation-exclusion entries this application still needs to remove from the cluster's
    # shard allocation exclusion settings.
    allocation_exclusions_to_delete: set[str] = Field(default_factory=set)
    # Users created for external client relations: username -> owning relation id.
    client_relation_users: dict[str, str] = Field(
        default_factory=dict, alias="client_relation_users"
    )
    # Whether the application is missing a relation it requires (e.g. a configured plugin or
    # backup relation that hasn't been related yet).
    missing_relations: bool = Field(default=False, alias="missing_relations")

    # Plugins
    # Plugin configuration/cleanup metadata this application is responsible for, keyed by
    # plugin label.
    plugin_config_info: dict[str, PluginConfigInfo] = Field(
        default_factory=dict, alias="plugin_config_info"
    )

    # Object Storage (cached copies of the S3/Azure/GCS relation data, propagated to the
    # peer-cluster fleet so non-orchestrator apps can reach the shared backup storage).
    s3: Optional[S3RelData] = Field(default=None)
    azure: Optional[AzureRelData] = Field(default=None)
    gcs: Optional[GcsRelData] = Field(default=None)

    @field_validator("allocation_exclusions_to_delete", "delete_voting_exclusions", mode="before")
    @classmethod
    def parse_comma_separated_strings(cls, v):
        """Validator for allocation_exclusions_to_delete, delete_voting_exclusions"""
        if isinstance(v, str):
            return list(filter(None, v.split(",")))
        return v

    @field_serializer("allocation_exclusions_to_delete", "delete_voting_exclusions")
    def serialize_comma_separated_strings(self, v: set[str]) -> str:
        """Validator for allocation_exclusions_to_delete, delete_voting_exclusions"""
        return ",".join(sorted(v))

    @field_serializer(
        "nodes_config",
        "cluster_fleet_apps",
        "cluster_fleet_apps_rels",
        "client_relation_users",
        "plugin_config_info",
    )
    def _sort_dict_fields(self, value: dict) -> dict:
        return _sort_nested_dicts(value)

    @field_validator("update_ts", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Ensure 'fields' is always a string, even if the databag returns a float/int."""
        if v is None:
            return ""
        return str(v)

    @model_serializer(mode="wrap")
    def serialize_model(self, handler, info):
        """Serializes the model, but skip empty backups data"""
        data = PeerModel.serialize_model(self, handler, info)
        for field in ("s3", "azure", "gcs"):
            if data.get(field) is None:
                data.pop(field, None)
        return data

    @property
    def app(self):
        """The ops.Application this model is bound to (alias of `component`)."""
        return self.component

    @property
    def name(self) -> str:
        """Return the name of the Application this model is bound to."""
        return self.component.name

    @property
    def is_admin_user_initialized(self) -> bool:
        """Alias of `admin_user_initialized`."""
        return self.admin_user_initialized

    @is_admin_user_initialized.setter
    def is_admin_user_initialized(self, value: bool) -> None:
        self.admin_user_initialized = value

    @is_admin_user_initialized.deleter
    def is_admin_user_initialized(self) -> None:
        del self.admin_user_initialized

    @property
    def is_security_index_initialised(self) -> bool:
        """Alias of `security_index_initialised`."""
        return self.security_index_initialised

    @is_security_index_initialised.setter
    def is_security_index_initialised(self, value: bool) -> None:
        self.security_index_initialised = value

    @is_security_index_initialised.deleter
    def is_security_index_initialised(self) -> None:
        del self.security_index_initialised

    @property
    def client_users_dict(self) -> dict[str, str]:
        """Alias of `client_relation_users`."""
        return self.client_relation_users

    @client_users_dict.setter
    def client_users_dict(self, value: dict[str, str]) -> None:
        self.client_relation_users = value

    @property
    def deployment_desc(self) -> Optional[DeploymentDescription]:
        """Alias of `deployment_description`."""
        return self.deployment_description

    @deployment_desc.setter
    def deployment_desc(self, value: Optional[DeploymentDescription]) -> None:
        self.deployment_description = value

    @property
    def apps_in_fleet(self) -> list[PeerClusterApp]:
        """Returns list of apps in cluster fleet"""
        return self.cluster_fleet_apps.values()

    @property
    def is_data_role_in_cluster_fleet_apps(self) -> bool:
        """Look for data-role through all the roles of all the nodes in all applications"""
        data_apps_in_fleet = [app for app in self.apps_in_fleet if "data" in app.roles]
        return bool(data_apps_in_fleet) and any(
            app.planned_units > 0 for app in data_apps_in_fleet
        )

    def initialize_empty_secrets(self) -> None:
        """Initialize empty app-level secrets to prevent log spam.

        The lib only creates a Juju secret when the written value is truthy.
        Writing "" silently skips creation, so the secret group never exists and
        every model read logs "Secret not found". We write a single-space placeholder
        to force creation and leave it in place -- callers strip the value before use
        so the placeholder is never mistaken for real data.
        """
        if plugin_m := self.sibling_model(OpenSearchAppPeerPluginSecretsModel):
            if not plugin_m.plugin_secrets:
                plugin_m.plugin_secrets = "{}"

        # Use truthy placeholders only for fields whose secrets don't exist yet.
        # " " is truthy so subsequent calls skip re-initialization correctly.
        if user_m := self.sibling_model(OpenSearchAppPeerUserSecretsModel):
            if not user_m.admin_password:
                user_m.admin_password = " "
        if admin_tls_m := self.sibling_model(OpenSearchAppPeerAdminTlsSecretsModel):
            if not admin_tls_m.admin_key_password:
                admin_tls_m.admin_key_password = " "

    def add_plugin_secret(self, plugin_name: str, secret_content: str) -> None:
        """Helper to safely add a secret mapping the plugin's secret_name."""
        config = self.plugin_config_info.get(plugin_name)
        if not config or not config.secret_name:
            logger.warning(f"No secret_name defined for plugin {plugin_name}")
            return
        if plugin_m := self.sibling_model(OpenSearchAppPeerPluginSecretsModel):
            current_secrets = (
                json.loads(plugin_m.plugin_secrets) if plugin_m.plugin_secrets else {}
            )
            current_secrets[config.secret_name] = secret_content
            plugin_m.plugin_secrets = json.dumps(current_secrets)

    def get_plugin_secret(self, plugin_name: str) -> str | None:
        """Retrieves the secret content for a specific plugin by its name."""
        config = self.plugin_config_info.get(plugin_name)

        if not config or not config.secret_name:
            return None

        if not (plugin_m := self.sibling_model(OpenSearchAppPeerPluginSecretsModel)):
            return None
        current_secrets = json.loads(plugin_m.plugin_secrets) if plugin_m.plugin_secrets else {}
        if not current_secrets:
            return None
        return current_secrets.get(config.secret_name)

    def delete_plugin_secret(self, plugin_name: str) -> None:
        """Deletes the secret content for a specific plugin by its name."""
        config = self.plugin_config_info.get(plugin_name)

        if not config or not config.secret_name:
            logger.warning(
                f"Cannot delete secret: no secret_name defined for plugin {plugin_name}"
            )
            return

        if not (plugin_m := self.sibling_model(OpenSearchAppPeerPluginSecretsModel)):
            return
        current_secrets = json.loads(plugin_m.plugin_secrets) if plugin_m.plugin_secrets else {}
        if not current_secrets:
            logger.debug("Plugins secrets group is empty.")
            return
        if current_secrets.pop(config.secret_name, None) is not None:
            plugin_m.plugin_secrets = json.dumps(current_secrets)
        else:
            logger.debug(f"Secret for plugin {plugin_name} was not found, nothing to delete.")

    def get_user_password(self, user: str) -> str | None:
        """Get the password for a given user from the client relation users dict."""
        user_m = self.sibling_model(OpenSearchAppPeerUserSecretsModel)
        if user == ADMIN_USER:
            return stripped_or_none(user_m.admin_password if user_m else None)
        elif user == KIBANA_SERVER_USER:
            return user_m.kibana_server_password if user_m else None
        elif user == COS_USER:
            return user_m.cos_password if user_m else None

        raise ValueError(f"User {user} is not an internal user.")

    def get_user_hashed_password(self, user: str) -> str | None:
        """Get the hashed password for a given user from the client relation users dict."""
        user_m = self.sibling_model(OpenSearchAppPeerUserSecretsModel)
        if user == ADMIN_USER:
            return user_m.admin_hashed_password if user_m else None
        elif user == KIBANA_SERVER_USER:
            return user_m.kibana_server_hashed_password if user_m else None
        elif user == COS_USER:
            return user_m.cos_hashed_password if user_m else None

        raise ValueError(f"User {user} is not an internal user.")

    def peer_cluster_rel_data_from_application_model(
        self,
        security_index_initialised: bool | None,
        first_data_node: str | None,
        cm_nodes: dict[str, Node],
    ) -> PeerClusterAppModel:
        """Marshal: Construct the peer cluster rel data from the local app peer model."""
        is_main_orchestrator = (
            self.deployment_description is not None
            and self.deployment_description.typ == DeploymentType.MAIN_ORCHESTRATOR
        )

        user_m = self.sibling_model(OpenSearchAppPeerUserSecretsModel)
        admin_tls_m = self.sibling_model(OpenSearchAppPeerAdminTlsSecretsModel)
        copied_data: dict = {
            "cluster_name": (
                self.deployment_description.config.cluster_name
                if self.deployment_description
                else ""
            ),
            "deployment_description": self.deployment_description,
        }
        copied_data["admin_password"] = stripped_or_none(user_m.admin_password)
        copied_data["admin_hashed_password"] = user_m.admin_hashed_password
        copied_data["kibana_server_password"] = user_m.kibana_server_password
        copied_data["kibana_server_hashed_password"] = user_m.kibana_server_hashed_password
        copied_data["cos_password"] = user_m.cos_password
        copied_data["cos_hashed_password"] = user_m.cos_hashed_password
        copied_data["admin_truststore_password"] = stripped_or_none(
            admin_tls_m.admin_truststore_password
        )
        copied_data["admin_keystore_password"] = stripped_or_none(
            admin_tls_m.admin_keystore_password
        )
        copied_data["admin_subject"] = stripped_or_none(admin_tls_m.admin_subject)
        copied_data["admin_key"] = stripped_or_none(admin_tls_m.admin_key)
        copied_data["admin_key_password"] = stripped_or_none(admin_tls_m.admin_key_password)
        copied_data["admin_csr"] = stripped_or_none(admin_tls_m.admin_csr)
        copied_data["admin_chain"] = stripped_or_none(admin_tls_m.admin_chain)
        copied_data["admin_cert"] = stripped_or_none(admin_tls_m.admin_cert)
        copied_data["admin_ca_cert"] = stripped_or_none(admin_tls_m.admin_ca_cert)

        copied_data["security_index_initialised"] = security_index_initialised
        copied_data["first_data_node"] = first_data_node or ""
        copied_data["nodes_config"] = cm_nodes
        copied_data["plugin_config_info"] = self.plugin_config_info if is_main_orchestrator else {}
        copied_data["plugin_secrets"] = (
            (self.sibling_model(OpenSearchAppPeerPluginSecretsModel).plugin_secrets or "")
            if is_main_orchestrator
            else ""
        )

        return PeerClusterAppModel(**copied_data)

    def update_from_peer_cluster_rel_data(self, peer_data: PeerClusterAppModel) -> None:
        """Unmarshal: Update the local app peer model using data from a peer cluster relation."""
        with self.update() as m:
            m.security_index_initialised = peer_data.security_index_initialised
            m.first_data_node = peer_data.first_data_node
            m.nodes_config = peer_data.nodes_config

        user_m = self.sibling_model(OpenSearchAppPeerUserSecretsModel)
        with user_m.update() as u:
            # Passwords
            u.admin_password = stripped_or_none(peer_data.admin_password)
            u.admin_hashed_password = peer_data.admin_hashed_password
            u.kibana_server_password = peer_data.kibana_server_password
            u.kibana_server_hashed_password = peer_data.kibana_server_hashed_password
            u.cos_password = peer_data.cos_password
            u.cos_hashed_password = peer_data.cos_hashed_password
        if stripped_or_none(peer_data.admin_password) or peer_data.admin_hashed_password:
            self.admin_user_initialized = True

        admin_tls_m = self.sibling_model(OpenSearchAppPeerAdminTlsSecretsModel)
        with admin_tls_m.update() as a:
            # Admin TLS Secrets
            a.admin_truststore_password = stripped_or_none(peer_data.admin_truststore_password)
            a.admin_keystore_password = stripped_or_none(peer_data.admin_keystore_password)
            a.admin_subject = stripped_or_none(peer_data.admin_subject)
            a.admin_key = stripped_or_none(peer_data.admin_key)
            a.admin_key_password = stripped_or_none(peer_data.admin_key_password)
            a.admin_csr = stripped_or_none(peer_data.admin_csr)
            a.admin_chain = stripped_or_none(peer_data.admin_chain)
            a.admin_cert = stripped_or_none(peer_data.admin_cert)
            a.admin_ca_cert = stripped_or_none(peer_data.admin_ca_cert)

        if peer_data.plugin_config_info:
            self.plugin_config_info = peer_data.plugin_config_info
        if peer_data.plugin_secrets and peer_data.plugin_secrets.strip():
            plugin_m = self.sibling_model(OpenSearchAppPeerPluginSecretsModel)
            plugin_m.plugin_secrets = peer_data.plugin_secrets

    def marshal_gcs_secrets(self) -> GcsRelData:
        """Return a copy of this model containing only the secret fields."""
        return GcsRelData.model_construct(secret_key=self.gcs.secret_key)

    def marshal_azure_secrets(self) -> AzureRelData:
        """Return a copy of this model containing only the secret fields."""
        return AzureRelData.model_construct(
            storage_account=self.azure.storage_account, secret_key=self.azure.secret_key
        )

    def marshal_s3_secrets(self) -> S3RelData:
        """Return a copy of this model containing only the secret fields."""
        return S3RelData.model_construct(
            access_key=self.s3.access_key,
            secret_key=self.s3.secret_key,
            tls_ca_chain=self.s3.tls_ca_chain,
        )


class OpenSearchAppPeerUserSecretsModel(PersistentModel, PeerModel):
    """Peer model mapping to the OpenSearch application's internal-user credentials.

    Split out of OpenSearchAppPeerModel so that reading/writing a plain (non-secret)
    application field doesn't also resolve the "user" Juju secret group.
    """

    # Users (internal-user credentials, grouped under the "user" secret group).
    admin_password: UserSecretStr = Field(default="")
    admin_hashed_password: UserSecretStr = Field(default="")
    kibana_server_password: UserSecretStr = Field(default="")
    kibana_server_hashed_password: UserSecretStr = Field(default="")
    cos_password: UserSecretStr = Field(default="")
    cos_hashed_password: UserSecretStr = Field(default="")


class OpenSearchAppPeerAdminTlsSecretsModel(PersistentModel, PeerModel):
    """Peer model mapping to the OpenSearch application's admin-TLS secrets.

    Split out of OpenSearchAppPeerModel so that reading/writing a plain (non-secret)
    application field doesn't also resolve the "app-admin" Juju secret group.
    """

    # Admin TLS Secrets (used for admin/inter-cluster authentication to the security plugin;
    # grouped under the "app-admin" secret group).
    admin_truststore_password: AdminSecretStr = Field(default="")  # Truststore password.
    admin_subject: AdminSecretStr = Field(default="")  # Certificate subject/DN.
    admin_keystore_password: AdminSecretStr = Field(default="")  # Keystore password.
    admin_key: AdminSecretStr = Field(default="")  # Private key (PEM).
    admin_key_password: AdminSecretStr = Field(default="")  # Password for the key.
    admin_csr: AdminSecretStr = Field(default="")  # Certificate signing request.
    admin_chain: AdminSecretStr = Field(default="")  # Full certificate chain.
    admin_cert: AdminSecretStr = Field(default="")  # Signed leaf certificate.
    admin_ca_cert: AdminSecretStr = Field(default="")  # CA certificate.


class OpenSearchAppPeerPluginSecretsModel(PersistentModel, PeerModel):
    """Peer model mapping to the OpenSearch application's plugin secrets.

    Split out of OpenSearchAppPeerModel so that reading/writing a plain (non-secret)
    application field doesn't also resolve the "plugins" Juju secret group.
    """

    # JSON blob of per-plugin secrets (e.g. API keys) for plugins configured on this application.
    plugin_secrets: PluginsSecretStr = Field(default="")


# Wire up transparent proxying of secret-group fields (see PersistentModel._secret_group_fields):
# reading/writing e.g. `server.transport_key` or `application.admin_ca_cert` delegates to the
# dedicated sibling secret model, so callers never need to build the secret models themselves.
OpenSearchServerPeerModel._secret_group_fields = {
    **dict.fromkeys(
        OpenSearchServerPeerTransportSecretsModel.__pydantic_fields__,
        OpenSearchServerPeerTransportSecretsModel,
    ),
    **dict.fromkeys(
        OpenSearchServerPeerHttpSecretsModel.__pydantic_fields__,
        OpenSearchServerPeerHttpSecretsModel,
    ),
}

OpenSearchAppPeerModel._secret_group_fields = {
    **dict.fromkeys(
        OpenSearchAppPeerUserSecretsModel.__pydantic_fields__, OpenSearchAppPeerUserSecretsModel
    ),
    **dict.fromkeys(
        OpenSearchAppPeerAdminTlsSecretsModel.__pydantic_fields__,
        OpenSearchAppPeerAdminTlsSecretsModel,
    ),
    **dict.fromkeys(
        OpenSearchAppPeerPluginSecretsModel.__pydantic_fields__,
        OpenSearchAppPeerPluginSecretsModel,
    ),
}
