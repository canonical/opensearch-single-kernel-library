#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the peer-cluster / peer-cluster-orchestrator relations."""

import logging
import re
from typing import Literal, Optional

from data_platform_helpers.advanced_statuses import StatusObject
from pydantic import (
    Field,
    field_serializer,
    field_validator,
    model_serializer,
)

from opensearch_single_kernel.common.statuses import PeerClusterErrorDataStatuses
from opensearch_single_kernel.core.models.base import (
    AdminSecretStr,
    App,
    DeploymentDescription,
    Model,
    Node,
    PersistentModel,
    PluginConfigInfo,
    PluginsSecretStr,
    UserSecretStr,
    _sort_nested_dicts,
    stripped_or_none,
)
from opensearch_single_kernel.core.models.storage import (
    AzureRelData,
    GcsRelData,
    S3RelData,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    BaseCommonModel,
    PeerModel,
)

logger = logging.getLogger(__name__)


class PeerClusterRelErrorData(Model):
    """Error state an orchestrator broadcasts over a peer-cluster relation."""

    cluster_name: str | None
    # Whether the receiving side should break the relation (unrecoverable mismatch).
    should_sever_relation: bool
    # Whether the receiving side should keep waiting (transient condition).
    should_wait: bool
    # Human-readable message describing why the relation is blocked/waiting.
    blocked_message: str
    deployment_desc: DeploymentDescription | None

    def get_status(self) -> StatusObject | None:
        """Get the status matching this error's blocked_message."""
        return self.get_status_from_message(self.blocked_message)

    @staticmethod
    def get_status_from_message(message: str) -> StatusObject | None:
        """Find the known PeerClusterErrorDataStatuses entry matching `message`.

        Status templates contain "{...}" placeholders for dynamic parts; each template
        is turned into a regex (placeholders become non-greedy wildcards) and matched
        against the concrete message. The returned status carries the concrete message.
        """
        for status in PeerClusterErrorDataStatuses:
            escaped_message = re.escape(status.value.message)
            # Replace the (escaped) "{...}" placeholder blocks with non-greedy wildcards.
            regex_pattern = "^" + re.sub(r"\\\{.*?\\\}", r"(?s:.*?)", escaped_message) + "$"
            if re.match(regex_pattern, message):
                return status.value.model_copy(update={"message": message})
        return None


class PeerClusterOrchestrators(Model):
    """Model class for the PClusters registered main/failover clusters."""

    _TYPES = Literal["main", "failover"]

    main_rel_id: int = -1
    main_app: App | None = None
    failover_rel_id: int = -1
    failover_app: App | None = None

    def delete(self, typ: _TYPES) -> None:
        """Delete an orchestrator from the current pair."""
        if typ == "main":
            self.main_rel_id = -1
            self.main_app = None
        else:
            self.failover_rel_id = -1
            self.failover_app = None

    def promote_failover(self) -> None:
        """Delete previous main orchestrator and promote failover if any."""
        self.main_app = self.failover_app
        self.main_rel_id = self.failover_rel_id
        self.delete("failover")

    def check_relation_conflict(self, trigger: str, relation_id: int) -> bool:
        """Return whether the relation conflicts with an already connected orchestrator."""
        data = self.to_dict()
        return data.get(f"{trigger}_app") is not None and data.get(
            f"{trigger}_rel_id", -1
        ) not in [-1, relation_id]


class PeerClusterApp(Model):
    """Model class for representing an application part of a large deployment."""

    app: App
    planned_units: int
    units: list[str]
    roles: list[str]

    @field_validator("units", "roles")
    @classmethod
    def sort_list(cls, v):
        """Returns deduplicated sorted list."""
        return sorted(set(v))


class PeerClusterServerModel(PersistentModel, PeerModel):
    """Pydantic model for peer cluster unit-level databag."""

    # Mirror of the unit's CA-rotation flags from the opensearch-peers databag, published
    # on the peer-cluster relation so other fleet apps can track rotation progress.
    tls_ca_renewing: bool = Field(default=False)
    tls_ca_renewed: bool = Field(default=False)
    tls_configured: bool = Field(default=False)
    # Hash of the last snapshots (backup) credentials this unit persisted to its keystore.
    snapshots_credentials_saved: str = Field(default="")

    @property
    def unit(self):
        """The ops.Unit this model is bound to (alias of `component`)."""
        return self.component


class PeerClusterAppModel(PersistentModel, BaseCommonModel):
    """Pydantic model for peer cluster application-level databag.

    Inherits from BaseCommonModel so that secret fields are stored as Juju Secret URIs
    in the relation databag and automatically granted to remote applications, enabling
    cross-cluster (cross-application) sharing.
    """

    # Orchestration fields
    # Whether the requirer app offers itself as a failover-orchestrator candidate.
    is_candidate_failover_orchestrator: bool = Field(default=False)
    # Which orchestrator role ("main"/"failover") this relation was established for.
    trigger: str = Field(default="")
    # Whether the requirer has acknowledged/registered the main orchestrator.
    main_orchestrator_registered: Optional[bool] = Field(default=None)
    # All apps in the fleet as known by the orchestrator, keyed by app id.
    cluster_fleet_apps: dict[str, PeerClusterApp] = Field(default_factory=dict)
    # The currently elected main/failover orchestrator pair. None means this relation has
    # never had orchestrator data written to it; once written, callers overwrite it wholesale
    # (see peer_cluster_orchestrator.py), so it stays populated (though possibly with both
    # main_app/failover_app unset) for the life of the relation.
    orchestrators: Optional[PeerClusterOrchestrators] = Field(default=None)
    # Object-storage (backup) connection data propagated by the orchestrator so
    # non-orchestrator apps can reach the shared backup storage.
    s3: Optional[S3RelData] = Field(default=None)
    azure: Optional[AzureRelData] = Field(default=None)
    gcs: Optional[GcsRelData] = Field(default=None)
    # Hash of the last broadcast payload; lets the orchestrator skip rewriting
    # unchanged relation data.
    rel_data_hash: str = Field(default="")
    # Set instead of the regular payload when the orchestrator cannot serve this
    # relation (misconfiguration, pending bootstrap, ...).
    error_data: Optional[PeerClusterRelErrorData] = Field(default=None)
    security_index_initialised: bool = Field(default=False)
    first_data_node: str = Field(default="")

    # App-state fields from OpenSearchAppPeerModel, shared cross-cluster
    cluster_name: str = Field(default="")
    nodes_config: dict[str, Node] = Field(default_factory=dict)
    deployment_description: Optional[DeploymentDescription] = Field(default=None)
    plugin_config_info: dict[str, PluginConfigInfo] = Field(default_factory=dict)

    # User secrets
    admin_password: UserSecretStr = Field(default="")
    admin_hashed_password: UserSecretStr = Field(default="")
    kibana_server_password: UserSecretStr = Field(default="")
    kibana_server_hashed_password: UserSecretStr = Field(default="")
    cos_password: UserSecretStr = Field(default="")
    cos_hashed_password: UserSecretStr = Field(default="")

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

    @field_serializer("cluster_fleet_apps", "nodes_config", "plugin_config_info")
    def _sort_dict_fields(self, value: dict) -> dict:
        return _sort_nested_dicts(value)

    @field_validator(
        "main_orchestrator_registered",
        "trigger",
        "rel_data_hash",
        "first_data_node",
        mode="before",
    )
    @classmethod
    def coerce_to_str(cls, v):
        """Ensure fields are always strings, even if the databag parses them as bool/float/int."""
        if v is None:
            return ""
        return str(v)

    @model_serializer(mode="wrap")
    def serialize_model(self, handler, info):
        """Serializes the model, but skip empty backups data"""
        if info.context and info.context.get("skip_secrets"):
            data = handler(self)
        else:
            data = BaseCommonModel.serialize_model(self, handler, info)
        for field in ("s3", "azure", "gcs"):
            if data.get(field) is None:
                data.pop(field, None)
        return data

    @property
    def deployment_desc(self) -> Optional[DeploymentDescription]:
        """Alias of `deployment_description`."""
        return self.deployment_description

    @deployment_desc.setter
    def deployment_desc(self, value: Optional[DeploymentDescription]) -> None:
        self.deployment_description = value

    def apply_rel_data(self, source: "PeerClusterAppModel") -> None:
        """Copy orchestrator-broadcast fields from source into this relation's databag."""
        with self.update() as m:
            m.cluster_name = source.cluster_name
            m.deployment_description = source.deployment_description
            m.security_index_initialised = source.security_index_initialised
            m.first_data_node = source.first_data_node or ""
            m.nodes_config = source.nodes_config
            m.plugin_config_info = source.plugin_config_info
            # Passwords
            m.admin_password = source.admin_password
            m.admin_hashed_password = source.admin_hashed_password
            m.kibana_server_password = source.kibana_server_password
            m.kibana_server_hashed_password = source.kibana_server_hashed_password
            m.cos_password = source.cos_password
            m.cos_hashed_password = source.cos_hashed_password
            # Plugin secrets
            m.plugin_secrets = source.plugin_secrets
            # Admin TLS secrets
            m.admin_truststore_password = stripped_or_none(source.admin_truststore_password)
            m.admin_keystore_password = stripped_or_none(source.admin_keystore_password)
            m.admin_subject = stripped_or_none(source.admin_subject)
            m.admin_key = stripped_or_none(source.admin_key)
            m.admin_key_password = stripped_or_none(source.admin_key_password)
            m.admin_csr = stripped_or_none(source.admin_csr)
            m.admin_chain = stripped_or_none(source.admin_chain)
            m.admin_cert = stripped_or_none(source.admin_cert)
            m.admin_ca_cert = stripped_or_none(source.admin_ca_cert)

    def clear_rel_data(self) -> None:
        """Reset all orchestrator-broadcast fields to their defaults."""
        with self.update() as m:
            m.cluster_name = ""
            m.deployment_description = None
            m.security_index_initialised = False
            m.first_data_node = ""
            m.nodes_config = {}
            m.plugin_config_info = {}
            m.admin_password = None
            m.admin_hashed_password = None
            m.kibana_server_password = None
            m.kibana_server_hashed_password = None
            m.cos_password = None
            m.cos_hashed_password = None
            m.plugin_secrets = None
            m.admin_truststore_password = None
            m.admin_keystore_password = None
            m.admin_subject = None
            m.admin_key = None
            m.admin_key_password = None
            m.admin_csr = None
            m.admin_chain = None
            m.admin_cert = None
            m.admin_ca_cert = None
            # emptying the secret fields above deletes the backing group secrets, so
            # drop the marker to let initialize_empty_secrets() re-create them later
            m.model_extra["pc_secrets_initialized"] = None

    def initialize_empty_secrets(self) -> None:
        """Pre-create peer cluster relation secret groups to prevent log spam.

        PeerClusterAppModel has user, app-admin, and plugins secret groups. If those
        groups don't exist in the Juju store when build_model() runs, extract_secrets
        logs "No secret for group X" for every field in those groups on every hook. We
        write a placeholder truthy value to one field per group to force creation, only
        if the group is not already populated.
        """
        if self.model_extra.get("pc_secrets_initialized"):
            return

        with self.update() as m:
            m.admin_password = m.admin_password or " "
            m.admin_cert = m.admin_cert or " "
            m.plugin_secrets = m.plugin_secrets or " "
            m.model_extra["pc_secrets_initialized"] = "true"
