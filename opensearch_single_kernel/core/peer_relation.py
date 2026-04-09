#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for opensearch-peers relation."""

import json
import logging

from ops.model import Application, Relation, Unit

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_USER,
    KIBANA_SERVER_USER,
    DeploymentType,
)
from opensearch_single_kernel.core.models import (
    AzureRelData,
    GcsRelData,
    ModelProperty,
    Node,
    OpenSearchAppPeerModel,
    OpenSearchProfile,
    OpenSearchServerPeerModel,
    PeerClusterApp,
    PeerClusterAppModel,
    PeerClusterOrchestrators,
    PerformanceType,
    ProductionProfile,
    S3RelData,
    TestingProfile,
)
from opensearch_single_kernel.core.peer_cluster_relation import PeerCluster
from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    OpsOtherPeerUnitRepositoryInterface,
    OpsPeerRepositoryInterface,
    OpsPeerUnitRepositoryInterface,
)

logger = logging.getLogger(__name__)


class OpenSearchServer(RelationState):
    """State/Relation data collection for an opensearch unit"""

    # State flags
    is_bootstrap_contributor = ModelProperty("bootstrap_contributor", default=False)
    is_cluster_manager_removed = ModelProperty("cluster_manager_removed", default=False)
    started = ModelProperty("started", default="")
    unit_dying = ModelProperty("unit_dying", default=False)
    pebble_observer_pid = ModelProperty("pebble_observer_pid", default=None)

    # TLS Status & Timestamps
    tls_ca_renewing = ModelProperty("tls_ca_renewing", default=False)
    tls_ca_renewed = ModelProperty("tls_ca_renewed", default=False)
    tls_configured = ModelProperty("tls_configured", default=False)
    certs_exp_checked_at = ModelProperty("certs_exp_checked_at", default="1970-01-01 00:00:00")

    # Networking & Auth
    last_host_ip = ModelProperty("last_host_ip", default="")
    oauth_openid_connect_url = ModelProperty("oauth_openid_connect_url", default="")
    plugin_config_info = ModelProperty("plugin_config_info", default_factory=dict)

    # Passwords
    transport_keystore_password = ModelProperty("transport_keystore_password", default="")
    http_keystore_password = ModelProperty("http_keystore_password", default="")
    transport_truststore_password = ModelProperty("transport_truststore_password", default="")
    http_truststore_password = ModelProperty("http_truststore_password", default="")

    # Transport TLS Properties
    transport_key = ModelProperty("transport_key", default="")
    transport_key_password = ModelProperty("transport_key_password", default="")
    transport_csr = ModelProperty("transport_csr", default="")
    transport_chain = ModelProperty("transport_chain", default="")
    transport_cert = ModelProperty("transport_cert", default="")
    transport_ca_cert = ModelProperty("transport_ca_cert", default="")
    transport_subject = ModelProperty("transport_subject", default="")

    # HTTP TLS Properties
    http_key = ModelProperty("http_key", default="")
    http_key_password = ModelProperty("http_key_password", default="")
    http_csr = ModelProperty("http_csr", default="")
    http_chain = ModelProperty("http_chain", default="")
    http_cert = ModelProperty("http_cert", default="")
    http_ca_cert = ModelProperty("http_ca_cert", default="")
    http_subject = ModelProperty("http_subject", default="")

    def __init__(
        self,
        relation: Relation | None,
        repository: (
            OpsPeerUnitRepositoryInterface[OpenSearchServerPeerModel]
            | OpsOtherPeerUnitRepositoryInterface[OpenSearchServerPeerModel]
        ),
        component: Unit,
    ):
        super().__init__(relation, repository, component)
        self.unit = component

    @property
    def model(self) -> OpenSearchServerPeerModel | None:
        """Internal helper to retrieve the peer model state."""
        if not self.relation:
            return None
        return self.repository.build_model(self.relation.id, component=self.unit)

    def write(self, model: OpenSearchServerPeerModel):
        """Internal helper to write the modified peer model back to the databag."""
        if self.relation:
            self.repository.write_model(self.relation.id, model)

    @property
    def unit_id(self) -> int:
        """The id of the unit from the unit name."""
        return int(self.unit.name.split("/")[1])

    @property
    def is_app_leader(self) -> bool:
        """Check if the current unit is the leader of the application."""
        return self.unit.is_leader()

    @property
    def profile(self) -> OpenSearchProfile | None:
        """Current profile of the unit"""
        if not (m := self.model) or not m.profile:
            return None
        return ProductionProfile() if m.profile == PerformanceType.PRODUCTION else TestingProfile()

    @profile.setter
    def profile(self, profile_value: OpenSearchProfile):
        """Set current profile of the unit."""
        if m := self.model:
            m.profile = profile_value.type
            self.write(m)

    @property
    def allocation_exclusions_to_delete(self) -> set[str]:
        """Return the value of 'allocation_exclusion_to_delete' from databag."""
        if m := self.model:
            return (
                set(m.allocation_exclusions_to_delete)
                if m.allocation_exclusions_to_delete
                else set()
            )
        return set()

    @allocation_exclusions_to_delete.setter
    def allocation_exclusions_to_delete(self, value: set[str]):
        """Set the value of 'allocation_exclusion_to_delete' in databag."""
        if m := self.model:
            m.allocation_exclusions_to_delete = list(value)
            self.write(m)

    @property
    def delete_voting_exclusions(self) -> set[str]:
        """Return the value of 'delete_voting_exclusions' from databag."""
        if m := self.model:
            return set(m.delete_voting_exclusions) if m.delete_voting_exclusions else set()
        return set()

    @delete_voting_exclusions.setter
    def delete_voting_exclusions(self, value: set[str]):
        """Set the value of 'delete_voting_exclusions' in databag."""
        if m := self.model:
            m.delete_voting_exclusions = list(value)
            self.write(m)

    @property
    def update_ts(self) -> str:
        """Get the value of 'update-ts' from the application databag."""
        return m.update_ts if (m := self.model) else ""

    @update_ts.setter
    def update_ts(self, timestamp: int):
        """Update the value of 'update-ts' in the application databag (casts int to str)."""
        if m := self.model:
            m.update_ts = str(timestamp)
            self.write(m)

    def initialize_empty_secrets(self) -> None:
        """Initialize empty unit-level secrets to prevent log spam."""
        if m := self.model:
            # Use truthy placeholders only for fields whose secrets don't exist yet
            if not m.transport_key_password:
                m.transport_key_password = " "
            if not m.http_key_password:
                m.http_key_password = " "
            self.write(m)


class OpenSearchApplication(RelationState):
    """An OpenSearch Application is a charm application with a given role."""

    # State flags
    is_admin_user_initialized = ModelProperty("admin_user_initialized", default=False)
    is_security_index_initialised = ModelProperty("security_index_initialised", default=False)
    bootstrapped = ModelProperty("bootstrapped", default=False)

    # Counters & Configs
    bootstrap_contributors_count = ModelProperty("bootstrap_contributors_count", default=0)
    nodes_config = ModelProperty("nodes_config", default_factory=dict)
    deployment_desc = ModelProperty("deployment_description", default=None)
    cluster_fleet_apps = ModelProperty("cluster_fleet_apps", default_factory=dict)
    cluster_fleet_apps_rels = ModelProperty("cluster_fleet_apps_rels", default_factory=dict)
    orchestrators = ModelProperty("orchestrators", default_factory=PeerClusterOrchestrators)
    first_data_node = ModelProperty("first_data_node", default="")
    client_users_dict = ModelProperty("client_relation_users", default_factory=dict)
    plugin_config_info = ModelProperty("plugin_config_info", default_factory=dict)
    plugin_secrets = ModelProperty("plugin_secrets", default=None)
    missing_relations = ModelProperty("missing_relations", default=False)

    # Object Storage
    s3 = ModelProperty("s3", default=None)
    azure = ModelProperty("azure", default=None)
    gcs = ModelProperty("gcs", default=None)

    # Passwords & Secrets
    admin_truststore_password = ModelProperty("admin_truststore_password", default="")
    admin_keystore_password = ModelProperty("admin_keystore_password", default="")
    admin_password = ModelProperty("admin_password", default="")
    admin_hashed_password = ModelProperty("admin_hashed_password", default="")
    kibana_server_password = ModelProperty("kibana_server_password", default="")
    kibana_server_hashed_password = ModelProperty("kibana_server_hashed_password", default="")
    cos_password = ModelProperty("cos_password", default="")
    cos_hashed_password = ModelProperty("cos_hashed_password", default="")

    # TLS Certificates & Keys
    admin_key = ModelProperty("admin_key", default="")
    admin_key_password = ModelProperty("admin_key_password", default="")
    admin_csr = ModelProperty("admin_csr", default="")
    admin_chain = ModelProperty("admin_chain", default="")
    admin_cert = ModelProperty("admin_cert", default="")
    admin_ca_cert = ModelProperty("admin_ca_cert", default="")
    admin_subject = ModelProperty("admin_subject", default="")

    def __init__(
        self,
        relation: Relation | None,
        repository: OpsPeerRepositoryInterface[OpenSearchAppPeerModel],
        component: Application,
    ):
        super().__init__(relation, repository, component)
        self.app = component

    @property
    def model(self) -> OpenSearchAppPeerModel | None:
        """Internal helper to retrieve the peer model state."""
        if not self.relation:
            return None
        return self.repository.build_model(self.relation.id)

    def write(self, model: OpenSearchAppPeerModel):
        """Internal helper to write the modified peer model back to the databag."""
        if self.relation:
            self.repository.write_model(self.relation.id, model)

    @property
    def name(self) -> str:
        """Return the name of the Application."""
        return self.app.name

    @property
    def update_ts(self) -> str:
        """Get the value of 'update-ts' from the application databag."""
        return m.update_ts if (m := self.model) else ""

    @update_ts.setter
    def update_ts(self, timestamp: int):
        """Update the value of 'update-ts' in the application databag (casts int to str)."""
        if m := self.model:
            m.update_ts = str(timestamp)
            self.write(m)

    @property
    def delete_voting_exclusions(self) -> set[str]:
        """Return the value of 'delete_voting_exclusions' from application databag."""
        if m := self.model:
            return set(m.delete_voting_exclusions) if m.delete_voting_exclusions else set()
        return set()

    @delete_voting_exclusions.setter
    def delete_voting_exclusions(self, value: set[str]):
        """Set the value of 'delete_voting_exclusions' in application databag."""
        if m := self.model:
            m.delete_voting_exclusions = list(value)
            self.write(m)

    @property
    def allocation_exclusions_to_delete(self) -> set[str]:
        """Return the value of 'allocation_exclusion_to_delete' from application databag."""
        if m := self.model:
            return (
                set(m.allocation_exclusions_to_delete)
                if m.allocation_exclusions_to_delete
                else set()
            )
        return set()

    @allocation_exclusions_to_delete.setter
    def allocation_exclusions_to_delete(self, value: set[str]):
        """Set the value of 'allocation_exclusion_to_delete' in application databag."""
        if m := self.model:
            m.allocation_exclusions_to_delete = list(value)
            self.write(m)

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
        to force creation and leave it in place — callers strip the value before use
        so the placeholder is never mistaken for real data.
        """
        if m := self.model:
            m.plugin_secrets = m.plugin_secrets or "{}"

            # Use truthy placeholders only for fields whose secrets don't exist yet.
            # " " is truthy so subsequent calls skip re-initialization correctly.
            if not m.admin_password:
                m.admin_password = " "
            if not m.admin_key_password:
                m.admin_key_password = " "
            self.write(m)

    def add_plugin_secret(self, plugin_name: str, secret_content: str) -> None:
        """Helper to safely add a secret mapping the plugin's secret_name."""
        if m := self.model:
            config = m.plugin_config_info.get(plugin_name)
            if not config or not config.secret_name:
                logger.warning(f"No secret_name defined for plugin {plugin_name}")
                return
            current_secrets = json.loads(m.plugin_secrets) if m.plugin_secrets else {}
            current_secrets[config.secret_name] = secret_content
            m.plugin_secrets = json.dumps(current_secrets)
            self.write(m)

    def get_plugin_secret(self, plugin_name: str) -> str | None:
        """Retrieves the secret content for a specific plugin by its name."""
        if m := self.model:
            config = m.plugin_config_info.get(plugin_name)

            if not config or not config.secret_name:
                return None

            current_secrets = json.loads(m.plugin_secrets) if m.plugin_secrets else {}
            if not current_secrets:
                return None
            return current_secrets.get(config.secret_name)
        return None

    def delete_plugin_secret(self, plugin_name: str) -> None:
        """Deletes the secret content for a specific plugin by its name."""
        if m := self.model:
            config = m.plugin_config_info.get(plugin_name)

            if not config or not config.secret_name:
                logger.warning(
                    f"Cannot delete secret: no secret_name defined for plugin {plugin_name}"
                )
                return

            current_secrets = json.loads(m.plugin_secrets) if m.plugin_secrets else {}
            if not current_secrets:
                logger.debug("Plugins secrets group is empty.")
                return
            if current_secrets.pop(config.secret_name, None) is not None:
                m.plugin_secrets = json.dumps(current_secrets)
                self.write(m)
            else:
                logger.debug(f"Secret for plugin {plugin_name} was not found, nothing to delete.")

    def get_user_password(self, user: str) -> str | None:
        """Get the password for a given user from the client relation users dict."""
        if user == ADMIN_USER:
            return (self.admin_password or "").strip() or None
        elif user == KIBANA_SERVER_USER:
            return self.kibana_server_password
        elif user == COS_USER:
            return self.cos_password

        raise ValueError(f"User {user} is not an internal user.")

    def get_user_hashed_password(self, user: str) -> str | None:
        """Get the hashed password for a given user from the client relation users dict."""
        if user == ADMIN_USER:
            return self.admin_hashed_password
        elif user == KIBANA_SERVER_USER:
            return self.kibana_server_hashed_password
        elif user == COS_USER:
            return self.cos_hashed_password

        raise ValueError(f"User {user} is not an internal user.")

    def peer_cluster_rel_data_from_application_model(
        self,
        security_index_initialised: bool | None,
        first_data_node: str | None,
        cm_nodes: dict[str, Node],
    ) -> PeerClusterAppModel:
        """Marshal: Construct the peer cluster rel data from the local app peer model."""
        is_main_orchestrator = (
            self.deployment_desc is not None
            and self.deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
        )

        m = self.model
        copied_data: dict = {
            "cluster_name": (
                m.deployment_description.config.cluster_name if m.deployment_description else ""
            ),
            "deployment_description": m.deployment_description,
        }
        copied_data["admin_password"] = (m.admin_password or "").strip() or None
        copied_data["admin_hashed_password"] = m.admin_hashed_password
        copied_data["kibana_server_password"] = m.kibana_server_password
        copied_data["kibana_server_hashed_password"] = m.kibana_server_hashed_password
        copied_data["cos_password"] = m.cos_password
        copied_data["cos_hashed_password"] = m.cos_hashed_password
        copied_data["admin_truststore_password"] = (
            m.admin_truststore_password or ""
        ).strip() or None
        copied_data["admin_keystore_password"] = (m.admin_keystore_password or "").strip() or None
        copied_data["admin_subject"] = (m.admin_subject or "").strip() or None
        copied_data["admin_key"] = (m.admin_key or "").strip() or None
        copied_data["admin_key_password"] = (m.admin_key_password or "").strip() or None
        copied_data["admin_csr"] = (m.admin_csr or "").strip() or None
        copied_data["admin_chain"] = (m.admin_chain or "").strip() or None
        copied_data["admin_cert"] = (m.admin_cert or "").strip() or None
        copied_data["admin_ca_cert"] = (m.admin_ca_cert or "").strip() or None

        copied_data["security_index_initialised"] = security_index_initialised
        copied_data["first_data_node"] = first_data_node or ""
        copied_data["nodes_config"] = cm_nodes
        copied_data["plugin_config_info"] = self.plugin_config_info if is_main_orchestrator else {}
        copied_data["plugin_secrets"] = self.plugin_secrets if is_main_orchestrator else ""

        return PeerClusterAppModel(**copied_data)

    def update_from_peer_cluster_rel_data(self, peer_data: PeerCluster) -> None:
        """Unmarshal: Update the local app peer model using data from a peer cluster relation."""
        self.is_security_index_initialised = peer_data.security_index_initialised
        self.first_data_node = peer_data.first_data_node
        self.nodes_config = peer_data.nodes_config

        # Passwords
        self.admin_password = (peer_data.admin_password or "").strip() or None
        self.admin_hashed_password = peer_data.admin_hashed_password
        if (
            peer_data.admin_password and peer_data.admin_password.strip()
        ) or peer_data.admin_hashed_password:
            self.is_admin_user_initialized = True
        self.kibana_server_password = peer_data.kibana_server_password
        self.kibana_server_hashed_password = peer_data.kibana_server_hashed_password
        self.cos_password = peer_data.cos_password
        self.cos_hashed_password = peer_data.cos_hashed_password

        # Admin TLS Secrets
        self.admin_truststore_password = (
            peer_data.admin_truststore_password or ""
        ).strip() or None
        self.admin_keystore_password = (peer_data.admin_keystore_password or "").strip() or None
        self.admin_subject = (peer_data.admin_subject or "").strip() or None
        self.admin_key = (peer_data.admin_key or "").strip() or None
        self.admin_key_password = (peer_data.admin_key_password or "").strip() or None
        self.admin_csr = (peer_data.admin_csr or "").strip() or None
        self.admin_chain = (peer_data.admin_chain or "").strip() or None
        self.admin_cert = (peer_data.admin_cert or "").strip() or None
        self.admin_ca_cert = (peer_data.admin_ca_cert or "").strip() or None

        if peer_data.plugin_config_info:
            self.plugin_config_info = peer_data.plugin_config_info
        if peer_data.plugin_secrets and peer_data.plugin_secrets.strip():
            self.plugin_secrets = peer_data.plugin_secrets

    def marshal_gcs_secrets(self) -> GcsRelData:
        """Return a copy of this model containing only the secret fields."""
        return GcsRelData.model_construct(secret_key=self.gcs.secret_key)

    def unmarshal_gcs_secrets(self, source: GcsRelData) -> None:
        """Copy secret fields from source into this instance."""
        current = self.gcs or GcsRelData.model_construct()
        self.gcs = current.model_copy(update={"secret_key": source.secret_key})

    def marshal_azure_secrets(self) -> AzureRelData:
        """Return a copy of this model containing only the secret fields."""
        return AzureRelData.model_construct(
            storage_account=self.azure.storage_account, secret_key=self.azure.secret_key
        )

    def unmarshal_azure_secrets(self, source: AzureRelData) -> None:
        """Copy secret fields from source into this instance."""
        current = self.azure or AzureRelData.model_construct()
        self.azure = current.model_copy(
            update={"storage_account": source.storage_account, "secret_key": source.secret_key}
        )

    def marshal_s3_secrets(self) -> S3RelData:
        """Return a copy of this model containing only the secret fields."""
        return S3RelData.model_construct(
            access_key=self.s3.access_key,
            secret_key=self.s3.secret_key,
            tls_ca_chain=self.s3.tls_ca_chain,
        )

    def unmarshal_s3_secrets(self, source: S3RelData) -> None:
        """Copy secret fields from source into this instance."""
        current = self.s3 or S3RelData.model_construct()
        self.s3 = current.model_copy(
            update={
                "access_key": source.access_key,
                "secret_key": source.secret_key,
                "tls_ca_chain": source.tls_ca_chain,
            }
        )
