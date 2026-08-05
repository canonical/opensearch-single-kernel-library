#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the opensearch-peers relation (application databags)."""

import logging
from typing import ClassVar, Optional

from pydantic import Field, field_serializer, field_validator

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    USER_SECRET_FIELDS,
    DeploymentType,
)
from opensearch_single_kernel.core.models.peer_cluster import (
    PeerClusterApp,
    PeerClusterAppModel,
    PeerClusterOrchestrators,
)
from opensearch_single_kernel.core.models.peer_secrets import (
    OpenSearchAppPeerAdminTlsSecretsModel,
    OpenSearchAppPeerPluginSecretsModel,
    OpenSearchAppPeerUserSecretsModel,
)
from opensearch_single_kernel.core.models.plain_base import (
    DeploymentDescription,
    Node,
    PluginConfigInfo,
    _sort_nested_dicts,
    stripped_or_none,
)
from opensearch_single_kernel.core.models.relation_base import RelationModel
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    PeerModel,
)

logger = logging.getLogger(__name__)


class OpenSearchAppPeerModel(RelationModel, PeerModel):
    """Peer model mapping to the OpenSearch application state. Contains only plain values"""

    # Proxy of secret-group fields (see RelationModel._secret_group_fields)
    # so callers never need to build the secret models themselves.
    _secret_group_fields: ClassVar[dict[str, type]] = {
        **dict.fromkeys(
            OpenSearchAppPeerUserSecretsModel.__pydantic_fields__,
            OpenSearchAppPeerUserSecretsModel,
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

    # Aliases here are pinned to the underscored keys deployed databags use,
    # so upgrade works correctly

    # Whether the admin user has been created in the security index.
    admin_user_initialized: bool = Field(default=False, alias="admin_user_initialized")
    # Number of units that took part in the initial cluster bootstrap.
    bootstrap_contributors_count: int = Field(default=0, alias="bootstrap_contributors_count")
    # Whether the OpenSearch security plugin's security index has been initialized.
    security_index_initialised: bool = Field(default=False, alias="security_index_initialised")
    # Cluster topology: unit name -> Node (roles, temperature, unit number) for every unit
    nodes_config: dict[str, Node] = Field(default_factory=dict, alias="nodes_config")
    # Whether the application-level cluster bootstrap process has completed.
    bootstrapped: bool = Field(default=False)
    # Description of application's role/config within the deployment.
    deployment_description: DeploymentDescription | None = Field(default=None)
    # Peer-cluster fleet apps discovered by this application, keyed by app id.
    cluster_fleet_apps: dict[str, PeerClusterApp] = Field(
        default_factory=dict, alias="cluster_fleet_apps"
    )
    # Peer-cluster fleet apps learned through peer-cluster relations (from other apps in the
    # fleet), keyed by app id.
    cluster_fleet_apps_rels: dict[str, PeerClusterApp] = Field(
        default_factory=dict, alias="cluster_fleet_apps_rels"
    )
    # Which app in the fleet act as the main/failover orchestrator.
    orchestrators: Optional[PeerClusterOrchestrators] = Field(
        default_factory=PeerClusterOrchestrators
    )
    # Name of the first unit to take on the "data" role.
    first_data_node: Optional[str] = Field(default=None, alias="first_data_node")
    # Last time application's databag was updated; used to force relation-changed hook
    update_ts: str = Field(default="")
    # Voting-exclusion entries application still needs to remove from the cluster voting config.
    delete_voting_exclusions: set[str] = Field(default_factory=set)
    # Allocation-exclusion entries application still needs to remove from the cluster
    # shard allocation exclusion settings.
    allocation_exclusions_to_delete: set[str] = Field(default_factory=set)
    # Users created for external client relations. Key is username, Value is relation id.
    client_relation_users: dict[str, str] = Field(
        default_factory=dict, alias="client_relation_users"
    )
    # Whether the application is missing a relation it requires
    missing_relations: bool = Field(default=False, alias="missing_relations")

    # Plugin configuration metadata application is responsible for, key is plugin label
    plugin_config_info: dict[str, PluginConfigInfo] = Field(
        default_factory=dict, alias="plugin_config_info"
    )

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
        if plugin_m := self.build_sibling_model(OpenSearchAppPeerPluginSecretsModel):
            if not plugin_m.plugin_secrets:
                plugin_m.plugin_secrets = "{}"
        if user_m := self.build_sibling_model(OpenSearchAppPeerUserSecretsModel):
            if not user_m.admin_password:
                user_m.admin_password = " "
        if admin_tls_m := self.build_sibling_model(OpenSearchAppPeerAdminTlsSecretsModel):
            if not admin_tls_m.admin_key_password:
                admin_tls_m.admin_key_password = " "

    def get_user_secret(self, user: str, hashed: bool = False) -> str | None:
        """Read a user's password (or hashed password) off the user secrets sibling model."""
        fields = USER_SECRET_FIELDS.get(user)
        if fields is None:
            raise ValueError(f"User {user} is not an internal user.")

        field_name = fields[1] if hashed else fields[0]
        user_m = self.build_sibling_model(OpenSearchAppPeerUserSecretsModel)
        value = getattr(user_m, field_name) if user_m else None
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
        user_m = self.build_sibling_model(OpenSearchAppPeerUserSecretsModel)
        admin_tls_m = self.build_sibling_model(OpenSearchAppPeerAdminTlsSecretsModel)
        copied_data: dict = {
            "cluster_name": (
                self.deployment_description.config.cluster_name
                if self.deployment_description
                else ""
            ),
            "deployment_description": self.deployment_description,
            "admin_password": stripped_or_none(user_m.admin_password),
            "admin_hashed_password": user_m.admin_hashed_password,
            "kibana_server_password": user_m.kibana_server_password,
            "kibana_server_hashed_password": user_m.kibana_server_hashed_password,
            "cos_password": user_m.cos_password,
            "cos_hashed_password": user_m.cos_hashed_password,
            "admin_truststore_password": stripped_or_none(admin_tls_m.admin_truststore_password),
            "admin_keystore_password": stripped_or_none(admin_tls_m.admin_keystore_password),
            "admin_subject": stripped_or_none(admin_tls_m.admin_subject),
            "admin_key": stripped_or_none(admin_tls_m.admin_key),
            "admin_key_password": stripped_or_none(admin_tls_m.admin_key_password),
            "admin_csr": stripped_or_none(admin_tls_m.admin_csr),
            "admin_chain": stripped_or_none(admin_tls_m.admin_chain),
            "admin_cert": stripped_or_none(admin_tls_m.admin_cert),
            "admin_ca_cert": stripped_or_none(admin_tls_m.admin_ca_cert),
            "security_index_initialised": security_index_initialised,
            "first_data_node": first_data_node or "",
            "nodes_config": cm_nodes,
            "plugin_config_info": self.plugin_config_info if is_main_orchestrator else {},
            "plugin_secrets": (
                (
                    self.build_sibling_model(OpenSearchAppPeerPluginSecretsModel).plugin_secrets
                    or ""
                )
                if is_main_orchestrator
                else ""
            ),
        }

        return PeerClusterAppModel(**copied_data)

    def update_from_peer_cluster_rel_data(self, peer_data: PeerClusterAppModel) -> None:
        """Unmarshal: Update the local app peer model using data from a peer cluster relation."""
        with self.update() as m:
            m.security_index_initialised = peer_data.security_index_initialised
            m.first_data_node = peer_data.first_data_node
            m.nodes_config = peer_data.nodes_config

        user_m = self.build_sibling_model(OpenSearchAppPeerUserSecretsModel)
        with user_m.update() as u:
            u.admin_password = stripped_or_none(peer_data.admin_password)
            u.admin_hashed_password = peer_data.admin_hashed_password
            u.kibana_server_password = peer_data.kibana_server_password
            u.kibana_server_hashed_password = peer_data.kibana_server_hashed_password
            u.cos_password = peer_data.cos_password
            u.cos_hashed_password = peer_data.cos_hashed_password
        if stripped_or_none(peer_data.admin_password) or peer_data.admin_hashed_password:
            self.admin_user_initialized = True

        admin_tls_m = self.build_sibling_model(OpenSearchAppPeerAdminTlsSecretsModel)
        with admin_tls_m.update() as a:
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
            plugin_m = self.build_sibling_model(OpenSearchAppPeerPluginSecretsModel)
            plugin_m.plugin_secrets = peer_data.plugin_secrets
