#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the opensearch-peers relation (application databags)."""

import logging
from typing import Optional

from dpcharmlibs.interfaces import PeerModel, UserSecretStr
from pydantic import Field, field_serializer, field_validator

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    USER_SECRET_FIELDS,
    DeploymentType,
)
from opensearch_single_kernel.core.base_models import (
    DeploymentDescription,
    Node,
    PluginConfigInfo,
    _sort_nested_dicts,
    stripped_or_none,
)
from opensearch_single_kernel.core.peer_cluster import (
    PeerClusterApp,
    PeerClusterAppModel,
    PeerClusterOrchestrators,
)
from opensearch_single_kernel.core.relation_base import (
    AdminSecretStr,
    PluginsSecretStr,
    RelationModel,
)

logger = logging.getLogger(__name__)


class OpenSearchAppPeerModel(RelationModel, PeerModel):
    """Peer model mapping to the OpenSearch application state.

    Plain databag fields and the application's Juju secret-group fields (internal-user
    credentials, admin-TLS material and plugin secrets) all live on this single model.
    """

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
    cluster_fleet_apps_rels: dict[str, PeerClusterApp] = Field(default_factory=dict)
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
    def name(self) -> str:
        """Return the name of the Application this model is bound to."""
        return self.component.name

    @property
    def is_data_role_in_cluster_fleet_apps(self) -> bool:
        """Look for data-role through all the roles of all the nodes in all applications"""
        data_apps_in_fleet = [
            app for app in self.cluster_fleet_apps.values() if "data" in app.roles
        ]
        return bool(data_apps_in_fleet) and any(
            app.planned_units > 0 for app in data_apps_in_fleet
        )

    def initialize_empty_secrets(self) -> None:
        """Initialize empty app-level secrets to prevent log spam.

        The v1 lib only creates a Juju secret when the written value is truthy.
        We write a single-space placeholder to force creation and leave it in place
        callers strip the value before use so the placeholder is never
        mistaken for real data.
        """
        with self.update() as m:
            if not m.plugin_secrets:
                m.plugin_secrets = "{}"
            if not m.admin_password:
                m.admin_password = " "
            if not m.admin_key_password:
                m.admin_key_password = " "

    def get_user_secret(self, user: str, hashed: bool = False) -> str | None:
        """Read a user's password (or hashed password) off the model's user secrets."""
        fields = USER_SECRET_FIELDS.get(user)
        if fields is None:
            raise ValueError(f"User {user} is not an internal user.")

        field_name = fields[1] if hashed else fields[0]
        value = getattr(self, field_name)
        # admin_password may hold a single-space placeholder to force secret
        # creation (see initialize_empty_secrets)
        if user == ADMIN_USER and not hashed:
            return stripped_or_none(value)
        return value

    def to_peer_cluster_rel_data(
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
        copied_data: dict = {
            "deployment_description": self.deployment_description,
            "admin_password": stripped_or_none(self.admin_password),
            "admin_hashed_password": self.admin_hashed_password,
            "kibana_server_password": self.kibana_server_password,
            "kibana_server_hashed_password": self.kibana_server_hashed_password,
            "monitor_password": self.monitor_password,
            "monitor_hashed_password": self.monitor_hashed_password,
            "admin_truststore_password": stripped_or_none(self.admin_truststore_password),
            "admin_keystore_password": stripped_or_none(self.admin_keystore_password),
            "admin_subject": stripped_or_none(self.admin_subject),
            "admin_key": stripped_or_none(self.admin_key),
            "admin_key_password": stripped_or_none(self.admin_key_password),
            "admin_csr": stripped_or_none(self.admin_csr),
            "admin_chain": stripped_or_none(self.admin_chain),
            "admin_cert": stripped_or_none(self.admin_cert),
            "admin_ca_cert": stripped_or_none(self.admin_ca_cert),
            "security_index_initialised": security_index_initialised,
            "first_data_node": first_data_node or "",
            "nodes_config": cm_nodes,
            "plugin_config_info": self.plugin_config_info if is_main_orchestrator else None,
            "plugin_secrets": (self.plugin_secrets or "") if is_main_orchestrator else "",
        }

        return PeerClusterAppModel(**copied_data)

    def update_from_peer_cluster_rel_data(self, peer_data: PeerClusterAppModel) -> None:
        """Unmarshal: Update the local app peer model using data from a peer cluster relation."""
        with self.update() as m:
            m.security_index_initialised = peer_data.security_index_initialised
            m.first_data_node = peer_data.first_data_node
            m.nodes_config = peer_data.nodes_config

            m.admin_password = stripped_or_none(peer_data.admin_password)
            m.admin_hashed_password = peer_data.admin_hashed_password
            m.kibana_server_password = peer_data.kibana_server_password
            m.kibana_server_hashed_password = peer_data.kibana_server_hashed_password
            m.monitor_password = peer_data.monitor_password
            m.monitor_hashed_password = peer_data.monitor_hashed_password

            m.admin_truststore_password = stripped_or_none(peer_data.admin_truststore_password)
            m.admin_keystore_password = stripped_or_none(peer_data.admin_keystore_password)
            m.admin_subject = stripped_or_none(peer_data.admin_subject)
            m.admin_key = stripped_or_none(peer_data.admin_key)
            m.admin_key_password = stripped_or_none(peer_data.admin_key_password)
            m.admin_csr = stripped_or_none(peer_data.admin_csr)
            m.admin_chain = stripped_or_none(peer_data.admin_chain)
            m.admin_cert = stripped_or_none(peer_data.admin_cert)
            m.admin_ca_cert = stripped_or_none(peer_data.admin_ca_cert)

            if stripped_or_none(peer_data.admin_password) or peer_data.admin_hashed_password:
                m.admin_user_initialized = True

            if peer_data.plugin_config_info:
                m.plugin_config_info = peer_data.plugin_config_info
            if peer_data.plugin_secrets and peer_data.plugin_secrets.strip():
                m.plugin_secrets = peer_data.plugin_secrets
