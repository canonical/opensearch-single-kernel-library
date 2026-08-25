#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the peer-cluster relations."""

import json
import logging
import re
from hashlib import sha1
from typing import Literal, Optional

from data_platform_helpers.advanced_statuses import StatusObject
from dpcharmlibs.interfaces import BaseCommonModel, PeerModel, UserSecretStr
from pydantic import (
    Field,
    field_serializer,
    field_validator,
    model_serializer,
)

from opensearch_single_kernel.common.statuses import PeerClusterErrorDataStatuses
from opensearch_single_kernel.core.base_models import (
    App,
    DeploymentDescription,
    Node,
    PlainModel,
    PluginConfigInfo,
    _sort_nested_dicts,
    stripped_or_none,
)
from opensearch_single_kernel.core.relation_base import (
    AdminSecretStr,
    BackupSecretStr,
    PluginsSecretStr,
    RelationModel,
)
from opensearch_single_kernel.core.storage import (
    AzureRelData,
    GcsRelData,
    S3RelData,
)

logger = logging.getLogger(__name__)


class PeerClusterRelErrorData(PlainModel):
    """Error state model an orchestrator broadcasts over a peer-cluster relation."""

    should_sever_relation: bool
    should_wait: bool
    blocked_message: str

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
            status_value: StatusObject = status.value
            escaped_message = re.escape(status_value.message)
            # Replace the (escaped) "{...}" placeholder blocks with non-greedy wildcards.
            regex_pattern = "^" + re.sub(r"\\\{.*?\\}", r"(?s:.*?)", escaped_message) + "$"
            if re.match(regex_pattern, message):
                return status_value.model_copy(update={"message": message})
        return None


class PeerClusterOrchestrators(PlainModel):
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


class PeerClusterApp(PlainModel):
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


class PeerClusterServerModel(RelationModel, PeerModel):
    """Model for peer cluster unit-level databag."""

    tls_ca_renewing: bool = Field(default=False)
    tls_ca_renewed: bool = Field(default=False)
    tls_configured: bool = Field(default=False)
    # Hash of the last snapshots (backup) credentials this unit persisted to its keystore.
    snapshots_credentials_saved: Optional[str] = Field(default=None)

    @property
    def unit(self):
        """The ops.Unit this model is bound to."""
        return self.component


class PeerClusterAppModel(RelationModel, BaseCommonModel):
    """Model for peer cluster application-level databag.

    Inherits from BaseCommonModel so that secret fields are stored as Juju Secret URIs
    in the relation databag and automatically granted to remote applications, enabling
    cross-cluster sharing.
    """

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

    def apply_rel_data(self, source: "PeerClusterAppModel") -> None:
        """Copy orchestrator-broadcast fields from source into this relation's databag."""
        with self.update() as m:
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
            m.monitor_password = source.monitor_password
            m.monitor_hashed_password = source.monitor_hashed_password
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

            digest_source = source.model_dump(mode="json", context={"skip_secrets": True})
            m.rel_data_hash = sha1(json.dumps(digest_source, sort_keys=True).encode()).hexdigest()

    def set_backup_secrets(
        self, cloud: str, reldata: "S3RelData | AzureRelData | GcsRelData | None"
    ) -> None:
        """Store a cloud's secret credentials in the top-level backup-secret fields.

        Passing `reldata=None` clears the fields (e.g. the backup relation went away).
        Call inside an `update()`
        """
        if cloud == "s3":
            self.s3_access_key = getattr(reldata, "access_key", None)
            self.s3_secret_key = getattr(reldata, "secret_key", None)
            self.s3_tls_ca_chain = getattr(reldata, "tls_ca_chain", None)
        elif cloud == "azure":
            self.azure_storage_account = getattr(reldata, "storage_account", None)
            self.azure_secret_key = getattr(reldata, "secret_key", None)
        elif cloud == "gcs":
            self.gcs_secret_key = getattr(reldata, "secret_key", None)

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

    def clear_rel_data(self) -> None:
        """Reset all orchestrator-broadcast fields to their defaults."""
        with self.update() as m:
            m.deployment_description = None
            m.security_index_initialised = False
            m.first_data_node = ""
            m.nodes_config = {}
            m.plugin_config_info = {}
            m.admin_password = None
            m.admin_hashed_password = None
            m.kibana_server_password = None
            m.kibana_server_hashed_password = None
            m.monitor_password = None
            m.monitor_hashed_password = None
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
            # Backup storage secrets
            m.s3_access_key = None
            m.s3_secret_key = None
            m.s3_tls_ca_chain = None
            m.azure_storage_account = None
            m.azure_secret_key = None
            m.gcs_secret_key = None
            # emptying the secret fields above deletes the backing group secrets, so
            # drop the marker to let initialize_empty_secrets() re-create them later
            m.pc_secrets_initialized = False

    def initialize_empty_secrets(self) -> None:
        """Pre-create peer cluster relation secret groups to prevent log spam.

        PeerClusterAppModel has user, app-admin, and plugins secret groups. If those
        groups don't exist in the Juju store when build_model() runs, extract_secrets
        logs "No secret for group X" for every field in those groups on every hook. We
        write a placeholder truthy value to one field per group to force creation, only
        if the group is not already populated.
        """
        if self.pc_secrets_initialized:
            return

        with self.update() as m:
            m.admin_password = m.admin_password or " "
            m.admin_cert = m.admin_cert or " "
            m.plugin_secrets = m.plugin_secrets or " "
            m.pc_secrets_initialized = True
