#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for peer cluster relation."""

import logging

from ops.model import Application, Relation, SecretNotFoundError, Unit
from pydantic_core import PydanticSerializationError

from opensearch_single_kernel.core.models import (
    ModelProperty,
    PeerClusterAppModel,
    PeerClusterOrchestrators,
    PeerClusterServerModel,
)
from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    OpsRelationRepositoryInterface,
)

logger = logging.getLogger(__name__)


class PeerCluster(RelationState):
    """State collection metadata for a peer-cluster application."""

    is_candidate_failover_orchestrator = ModelProperty(
        "is_candidate_failover_orchestrator", default=False
    )
    trigger = ModelProperty("trigger", default="")
    main_orchestrator_registered = ModelProperty("main_orchestrator_registered", default=None)
    cluster_fleet_apps = ModelProperty("cluster_fleet_apps", default_factory=dict)
    orchestrators = ModelProperty("orchestrators", default_factory=PeerClusterOrchestrators)
    rel_data_hash = ModelProperty("rel_data_hash", default="")
    error_data = ModelProperty("error_data", default=None)
    security_index_initialised = ModelProperty("security_index_initialised", default=False)
    first_data_node = ModelProperty("first_data_node", default="")

    # Backup credentials
    s3 = ModelProperty("s3", default=None)
    azure = ModelProperty("azure", default=None)
    gcs = ModelProperty("gcs", default=None)

    # App-state fields broadcast by the orchestrator to peer clusters
    cluster_name = ModelProperty("cluster_name", default="")
    nodes_config = ModelProperty("nodes_config", default_factory=dict)
    deployment_desc = ModelProperty("deployment_description", default=None)
    plugin_config_info = ModelProperty("plugin_config_info", default_factory=dict)

    # User secrets
    admin_password = ModelProperty("admin_password", default="")
    admin_hashed_password = ModelProperty("admin_hashed_password", default="")
    kibana_server_password = ModelProperty("kibana_server_password", default="")
    kibana_server_hashed_password = ModelProperty("kibana_server_hashed_password", default="")
    cos_password = ModelProperty("cos_password", default="")
    cos_hashed_password = ModelProperty("cos_hashed_password", default="")

    # Plugin secrets
    plugin_secrets = ModelProperty("plugin_secrets", default="")

    # Admin TLS secrets
    admin_truststore_password = ModelProperty("admin_truststore_password", default="")
    admin_subject = ModelProperty("admin_subject", default="")
    admin_keystore_password = ModelProperty("admin_keystore_password", default="")
    admin_key = ModelProperty("admin_key", default="")
    admin_key_password = ModelProperty("admin_key_password", default="")
    admin_csr = ModelProperty("admin_csr", default="")
    admin_chain = ModelProperty("admin_chain", default="")
    admin_cert = ModelProperty("admin_cert", default="")
    admin_ca_cert = ModelProperty("admin_ca_cert", default="")

    def __init__(
        self,
        relation: Relation | None,
        repository: OpsRelationRepositoryInterface[PeerClusterAppModel],
        component: Application,
        is_provider: bool = True,
    ):
        super().__init__(relation, repository, component)
        self.component = component
        self.is_provider = is_provider

    @property
    def model(self) -> PeerClusterAppModel | None:
        """Internal helper to retrieve the peer model state."""
        if not self.relation:
            return None
        try:
            return self.repository.build_model(self.relation.id, component=self.component)
        except SecretNotFoundError:
            logger.warning(
                "Secret not found when reading relation %s model — relation may be departing.",
                self.relation.id,
            )
            return None

    def write(self, model: PeerClusterAppModel) -> None:
        """Internal helper to write the modified peer model back to the databag."""
        if not self.relation or not self.relation.active:
            return

        try:
            if self.is_provider:
                self.repository.write_model(self.relation.id, model)
            else:
                self.repository.write_model(
                    self.relation.id, model, context={"skip_secrets": True}
                )
        except (SecretNotFoundError, PydanticSerializationError) as e:
            # Secrets for this relation may have been deleted before the relation itself
            # So we skip the write
            # the data will be gone when the relation departs anyway
            logger.warning(
                "Skipping write to relation %s — secret unavailable: %s", self.relation.id, e
            )

    def apply_rel_data(self, source: PeerClusterAppModel) -> None:
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
            m.admin_truststore_password = (source.admin_truststore_password or "").strip() or None
            m.admin_keystore_password = (source.admin_keystore_password or "").strip() or None
            m.admin_subject = (source.admin_subject or "").strip() or None
            m.admin_key = (source.admin_key or "").strip() or None
            m.admin_key_password = (source.admin_key_password or "").strip() or None
            m.admin_csr = (source.admin_csr or "").strip() or None
            m.admin_chain = (source.admin_chain or "").strip() or None
            m.admin_cert = (source.admin_cert or "").strip() or None
            m.admin_ca_cert = (source.admin_ca_cert or "").strip() or None

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

    def initialize_empty_secrets(self) -> None:
        """Pre-create peer cluster relation secret groups to prevent log spam.

        PeerClusterAppModel has user, app-admin, and plugins secret groups. If those
        groups don't exist in the Juju store when build_model() runs, extract_secrets
        logs "No secret for group X" for every field in those groups on every hook. We
        write a placeholder truthy value to one field per group to force creation, only
        if the group is not already populated.
        """
        if not self.relation:
            return
        m = self.model
        if m is None:
            return
        if m.model_extra.get("pc_secrets_initialized"):
            return

        m.admin_password = m.admin_password or " "
        m.admin_cert = m.admin_cert or " "
        m.plugin_secrets = m.plugin_secrets or " "
        m.model_extra["pc_secrets_initialized"] = "true"
        self.write(m)


class PeerClusterServer(RelationState):
    """State collection metadata for a peer-cluster unit."""

    tls_ca_renewing = ModelProperty("tls_ca_renewing", default=False)
    tls_ca_renewed = ModelProperty("tls_ca_renewed", default=False)
    tls_configured = ModelProperty("tls_configured", default=False)
    snapshots_credentials_saved = ModelProperty("snapshots_credentials_saved", default="")

    def __init__(
        self,
        relation: Relation | None,
        repository: OpsRelationRepositoryInterface[PeerClusterServerModel],
        component: Unit,
    ):
        super().__init__(relation, repository, component)
        self.unit = component

    @property
    def model(self) -> PeerClusterServerModel | None:
        """Internal helper to retrieve the peer model state."""
        if not self.relation:
            return None
        return self.repository.build_model(self.relation.id)

    def write(self, model: PeerClusterServerModel) -> None:
        """Internal helper to write the modified peer model back to the databag."""
        if self.relation and self.relation.active:
            self.repository.write_model(self.relation.id, model)
