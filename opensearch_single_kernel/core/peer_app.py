#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the opensearch-peers relation (application databags)."""

import logging
from typing import Optional

from dpcharmlibs.interfaces import PeerModel, UserSecretStr
from pydantic import Field, field_serializer, field_validator

from opensearch_single_kernel.core.base_models import (
    DeploymentDescription,
    Node,
    PluginConfigInfo,
    _sort_nested_dicts,
)
from opensearch_single_kernel.core.peer_cluster import (
    PeerClusterApp,
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
