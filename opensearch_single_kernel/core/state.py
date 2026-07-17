#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object representing the global state of OpenSearch Charm."""

import json
import logging
import re
import socket
from json import JSONDecodeError
from typing import TYPE_CHECKING, Any, Literal

from data_platform_helpers.advanced_statuses import StatusesState, StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from ops import JujuVersion, Object, Relation, Unit

from opensearch_single_kernel.common.constants import (
    AZURE_RELATION,
    CLIENT_RELATION,
    GCS_RELATION,
    GENERATED_ROLES,
    JWT_CONFIG_RELATION,
    KIBANA_SERVER_ROLE,
    NODE_LOCK_RELATION,
    OAUTH_RELATION,
    OPENSEARCH_HTTP_PORT,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    S3_RELATION,
    SMTP_RELATION,
    STATUS_PEERS_RELATION,
    TLS_RELATION,
    UPGRADE_RELATION,
    ObjectStorageType,
    Scope,
    StartMode,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchInvalidStorageTypeError,
    OpenSearchObjectStorageConfigValidationError,
)
from opensearch_single_kernel.core.external_clients_relation import (
    ExternalOpenSearchClient,
)
from opensearch_single_kernel.core.jwt_relation import JwtState
from opensearch_single_kernel.core.lock_relation import LockAppState, LockServerState
from opensearch_single_kernel.core.models import (
    AzureRelDataCredentials,
    DeploymentType,
    GcsRelDataCredentials,
    Node,
    ObjectStorageConfig,
    PeerClusterApp,
    PeerClusterRelData,
    S3RelDataCredentials,
)
from opensearch_single_kernel.core.peer_cluster_relation import (
    PeerCluster,
    PeerClusterServer,
)
from opensearch_single_kernel.core.peer_relation import (
    OpenSearchApplication,
    OpenSearchServer,
)
from opensearch_single_kernel.core.relations import (
    JwtData,
    PeerClusterData,
    PeerClusterOrchestratorData,
)
from opensearch_single_kernel.core.secrets import OpenSearchSecrets
from opensearch_single_kernel.core.upgrade_relation import (
    UpgradeAppState,
    UpgradeServerState,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.azure_storage import (
    AzureStorageRequires,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerUnitData,
    OpenSearchProvidesData,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.gcs_storage import (
    GcsStorageRequires,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.s3 import S3Requirer
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import SmtpRequires
from opensearch_single_kernel.utils.helpers import (
    format_unit_name,
    get_k8s_fqdn,
    k8s_fqdn,
    lock_unit_name,
)
from opensearch_single_kernel.utils.object_storage import (
    storage_config_from_connection_info,
)
from opensearch_single_kernel.utils.status import format_status

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


logger = logging.getLogger(__name__)


class ClusterState(Object):
    """The global OpenSearch Cluster State ."""

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
        substrate: Substrates,
        smtp_requires: SmtpRequires,
        s3_requirer: S3Requirer,
        azure_requires: AzureStorageRequires,
        gcs_requires: GcsStorageRequires,
    ) -> None:
        super().__init__(charm, "cluster_state")
        self.config = charm.config
        self.substrate = substrate
        logger.error("ClusterState initialized with substrate: %s", self.substrate)

        # Secrets  FIXME: Handle this separately.
        self.secrets = OpenSearchSecrets(charm, peer_relation=PEER_RELATION)

        self.statuses = StatusesState(self, STATUS_PEERS_RELATION)
        # TODO: Add secrets
        self.peer_app_interface = DataPeerData(model=charm.model, relation_name=PEER_RELATION)
        self.peer_unit_interface = DataPeerUnitData(model=charm.model, relation_name=PEER_RELATION)
        self.client_data_interface = OpenSearchProvidesData(
            model=charm.model, relation_name=CLIENT_RELATION
        )

        self.peer_cluster_data_interface = PeerClusterData(
            model=charm.model, relation_name=PEER_CLUSTER_RELATION
        )
        self.peer_cluster_orchestrator_data_interface = PeerClusterOrchestratorData(
            model=charm.model, relation_name=PEER_CLUSTER_ORCHESTRATOR_RELATION
        )
        self.smtp_requires = smtp_requires
        self.s3_requirer = s3_requirer
        self.azure_requires = azure_requires
        self.gcs_requires = gcs_requires

    # -- Relations

    @property
    def peer_relation(self) -> Relation | None:
        """Get charm peer relation."""
        return self.model.get_relation(PEER_RELATION)

    @property
    def lock_relation(self) -> Relation | None:
        """Get Node Lock Peer Relation."""
        return self.model.get_relation(NODE_LOCK_RELATION)

    @property
    def tls_relation(self) -> Relation | None:
        """Get TLS relation."""
        return self.model.get_relation(TLS_RELATION)

    @property
    def peer_cluster_relations(self) -> list[Relation]:
        """The 'peer-cluster' relation that the charm is requiring."""
        return self.model.relations.get(PEER_CLUSTER_RELATION, [])

    @property
    def peer_cluster_orchestrator_relations(self) -> list[Relation]:
        """The 'peer-cluster-orchestrator' relations that the charm is providing."""
        return self.model.relations.get(PEER_CLUSTER_ORCHESTRATOR_RELATION, [])

    @property
    def s3_relation(self) -> Relation | None:
        """Get S3 relation."""
        return self.model.get_relation(S3_RELATION)

    @property
    def azure_relation(self) -> Relation | None:
        """Get Azure relation."""
        return self.model.get_relation(AZURE_RELATION)

    @property
    def gcs_relation(self) -> Relation | None:
        """Get GCS relation."""
        return self.model.get_relation(GCS_RELATION)

    @property
    def external_client_relations(self) -> list[Relation]:
        """Get OpenSearch client relation."""
        return self.model.relations.get(CLIENT_RELATION, [])

    @property
    def jwt_relation(self) -> Relation | None:
        """Get JWT relation."""
        return self.model.get_relation(JWT_CONFIG_RELATION)

    @property
    def oauth_relation(self) -> Relation | None:
        """Get OAuth relation."""
        return self.model.get_relation(OAUTH_RELATION)

    @property
    def smtp_relations(self) -> list[Relation]:
        """Get SMTP relations."""
        return self.model.relations.get(SMTP_RELATION, [])

    def relation_exists(self, relation_name) -> bool:
        """Check if the relation exists"""
        return bool(self.model.get_relation(relation_name))

    @property
    def upgrade_relation(self) -> Relation | None:
        """Get peer upgrade relation."""
        return self.model.get_relation(UPGRADE_RELATION)

    def peer_cluster_orchestrator_relation_exists(self, relation_id: int) -> bool:
        """Check if the relation with id exists"""
        relation = self.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, relation_id)
        return bool(relation)

    # --- Upgrade Relation State Properties ---

    @property
    def server_upgrade(self) -> UpgradeServerState:
        """Get state of lock relation for current unit."""
        return UpgradeServerState(
            relation=self.upgrade_relation,
            data_interface=DataPeerUnitData(model=self.model, relation_name=UPGRADE_RELATION),
            component=self.model.unit,
        )

    @property
    def application_upgrade(self) -> UpgradeAppState:
        """Get application state of upgrade relation."""
        return UpgradeAppState(
            relation=self.upgrade_relation,
            data_interface=DataPeerData(model=self.model, relation_name=UPGRADE_RELATION),
            component=self.model.app,
        )

    @property
    def sorted_upgrades_units(self) -> list[UpgradeServerState]:
        """Get state of upgrade relation for all units in it sorted by highest unit number."""
        return (
            [
                UpgradeServerState(
                    relation=self.upgrade_relation,
                    data_interface=DataPeerUnitData(
                        model=self.model, relation_name=UPGRADE_RELATION
                    ),
                    component=unit,
                )
                for unit in sorted(
                    (self.server.unit, *self.upgrade_relation.units),
                    key=lambda unit: int(unit.name.split("/")[1]),
                    reverse=True,
                )
            ]
            if self.upgrade_relation
            else []
        )

    @property
    def pod_name(self) -> str:
        """K8S only: The pod name."""
        return self.model.unit.name.replace("/", "-")

    @property
    def namespace(self) -> str:
        """K8S only: The namespace."""
        return self.model.name

    # -- Peer Cluster / Peer Cluster Orchestrator

    def peer_cluster_by_relation_id(
        self, is_provider: bool, relation_id: int, remote: bool = False
    ) -> PeerCluster | None:
        """Return the current related peer cluster if any.

        Args:
            is_provider: whether the current cluster is provider or requirer in the relation.
            relation_id: the relation id of the peer cluster relation to look for.
            remote: whether to return the remote databag (related to current)
              or the local one (current cluster as part of the relation).
        """
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        data_interface = (
            self.peer_cluster_orchestrator_data_interface
            if is_provider
            else self.peer_cluster_data_interface
        )

        def get_component(relation):
            """Get the component for the relation based on the remote flag."""
            return relation.app if remote else self.model.app

        if relation := self.model.get_relation(relation_name, relation_id):
            return PeerCluster(
                relation=relation,
                data_interface=data_interface,
                component=get_component(relation),
                secrets=self.secrets,
            )
        return None

    def peer_clusters(
        self, is_provider: bool, must_have_units: bool = True, remote: bool = False
    ) -> list[PeerCluster]:
        """Return the list of peer clusters for each relations."""
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        data_interface = (
            self.peer_cluster_orchestrator_data_interface
            if is_provider
            else self.peer_cluster_data_interface
        )

        def get_component(relation):
            """Get the component for the relation based on the remote flag."""
            return relation.app if remote else self.model.app

        return [
            PeerCluster(
                relation=rel,
                data_interface=data_interface,
                component=get_component(rel),
                secrets=self.secrets,
            )
            for rel in self.model.relations[relation_name]
            if not must_have_units or len(rel.units) > 0
        ]

    def _peer_clusters_servers(
        self, is_provider: bool, remote: bool = False
    ) -> list[PeerClusterServer]:
        """Return the list of peer cluster servers for each relations.

        Args:
            is_provider: whether the current cluster is provider or requirer in the relation.
            remote: whether to return the remote units databags related to current application
                or the local one which returns only the current unit.
        """
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        data_interface = (
            self.peer_cluster_orchestrator_data_interface
            if is_provider
            else self.peer_cluster_data_interface
        )

        def get_units(relation):
            """Get the units for the relation based on the remote flag."""
            return relation.units if remote else [self.model.unit]

        return [
            PeerClusterServer(relation=rel, data_interface=data_interface, component=unit)
            for rel in self.model.relations[relation_name]
            for unit in get_units(rel)
        ]

    def local_peer_cluster_server_by_relation_id(
        self,
        is_provider: bool,
        relation_id: int,
    ) -> PeerClusterServer | None:
        """Return the peer cluster server for the given relation id."""
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        if relation := self.model.get_relation(relation_name, relation_id):
            return PeerClusterServer(
                relation=relation,
                data_interface=(
                    self.peer_cluster_data_interface
                    if not is_provider
                    else self.peer_cluster_orchestrator_data_interface
                ),
                component=self.model.unit,
            )
        return None

    def all_peer_clusters_servers(self, remote: bool = False) -> list[PeerClusterServer]:
        """Return the list of all peer cluster servers for each relations."""
        return self._peer_clusters_servers(
            is_provider=False, remote=remote
        ) + self._peer_clusters_servers(is_provider=True, remote=remote)

    def peer_clusters_relations_ids(
        self, is_provider: bool, must_have_units: bool = True
    ) -> list[int]:
        """Return the list of related peer cluster relation ids."""
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        return [
            rel.id
            for rel in self.model.relations[relation_name]
            if not must_have_units or len(rel.units) > 0
        ]

    # -- Core Components

    @property
    def server(self) -> OpenSearchServer:
        """Get the opensearch unit state."""
        return OpenSearchServer(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
            secrets=self.secrets,
        )

    @property
    def application_servers(self) -> list[OpenSearchServer]:
        """Return all opensearch servers using peer relation."""
        return [
            OpenSearchServer(
                relation=self.peer_relation,
                data_interface=self.peer_unit_interface,
                component=unit,
                secrets=self.secrets,
            )
            for unit in self.all_units
        ]

    @property
    def application(self) -> OpenSearchApplication:
        """Get the opensearch application state."""
        return OpenSearchApplication(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
            secrets=self.secrets,
        )

    @property
    def external_clients(self) -> set[ExternalOpenSearchClient]:
        """Get all related external opensearch clients."""
        clients = set()
        for relation in self.external_client_relations:
            if not relation.app:
                continue

            clients.add(
                ExternalOpenSearchClient(
                    relation=relation,
                    data_interface=self.client_data_interface,
                    component=relation.app,
                    relation_name=CLIENT_RELATION,
                )
            )

        return clients

    def external_client_by_relation(self, relation: Relation) -> ExternalOpenSearchClient | None:
        """Get external opensearch client by relation."""
        if relation not in self.external_client_relations:
            return None
        if not relation.app:
            return None

        return ExternalOpenSearchClient(
            relation=relation,
            data_interface=self.client_data_interface,
            component=relation.app,
            relation_name=CLIENT_RELATION,
        )

    @property
    def dashboards_clients(self) -> list[ExternalOpenSearchClient]:
        """Return the dashboard relations out of all."""
        result = []
        for external_client in self.external_clients:
            if (roles := external_client.extra_user_roles) and KIBANA_SERVER_ROLE in roles:
                # if any(key.name == "opensearch-dashboards" for key in relation.data.keys()):
                result.append(external_client)
        return result

    @property
    def jwt(self) -> JwtState:
        """Get JWT state."""
        return JwtState(
            relation=self.jwt_relation,
            data_interface=JwtData(self.model, JWT_CONFIG_RELATION),
            component=self.model.app,
        )

    @property
    def server_lock(self) -> LockServerState:
        """Get state of lock relation for current unit."""
        return LockServerState(
            relation=self.lock_relation,
            data_interface=DataPeerUnitData(model=self.model, relation_name=NODE_LOCK_RELATION),
            component=self.model.unit,
        )

    @property
    def lock_granted_server(self) -> LockServerState | None:
        """Get state of lock relation for unit granted with lock."""
        return (
            LockServerState(
                relation=self.lock_relation,
                data_interface=DataPeerUnitData(
                    model=self.model, relation_name=NODE_LOCK_RELATION
                ),
                component=self.get_unit(lock_unit_name(granted_unit_name)),
            )
            if (granted_unit_name := self.application_lock.unit_with_lock)
            else None
        )

    @property
    def server_locks(self) -> list[LockServerState]:
        """Get state of lock relation for all units in it."""
        return (
            [
                LockServerState(
                    relation=self.lock_relation,
                    data_interface=DataPeerUnitData(
                        model=self.model, relation_name=NODE_LOCK_RELATION
                    ),
                    component=unit,
                )
                for unit in (self.server.unit, *self.lock_relation.units)
            ]
            if self.lock_relation
            else []
        )

    @property
    def application_lock(self) -> LockAppState:
        """Get application state of lock relation."""
        return LockAppState(
            relation=self.lock_relation,
            data_interface=DataPeerData(model=self.model, relation_name=NODE_LOCK_RELATION),
            component=self.model.app,
            unit_name=self.unit_name,
        )

    # -- Cluster State Properties

    @property
    def unit_name(self):
        """Name of the current unit."""
        return format_unit_name(self.model.unit, app=self.application.deployment_desc.app)

    @property
    def node_config(self) -> Node | None:
        """Return the current node from 'nodes_config' in application state."""
        return (
            new_node_conf
            if (nodes_config := self.application.nodes_config)
            and (new_node_conf := nodes_config.get(self.unit_name))
            else None
        )

    @property
    def node_host(self) -> str:
        """Return a connectable host for the current unit.

        On K8s this is the unit DNS name. On VM this is the unit IP address.
        """
        if self.substrate == Substrates.K8S:
            return self.fqdn
        return self.host_ip

    @property
    def planned_units(self) -> int:
        """Return the planned units for the charm."""
        return self.model.app.planned_units()

    @property
    def host_ip(self) -> str:
        """Fetches the IP address of the current unit."""
        address = self.model.get_binding(PEER_RELATION).network.bind_address
        return str(address)

    @property
    def fqdn(self) -> str:
        """Return a stable FQDN for the current unit.

        - VM: local host FQDN from the runtime environment.
        - K8s: canonical endpoint FQDN for this unit service name.
        """
        if self.substrate == Substrates.K8S:
            unit_prefix = self.unit_name.split(".")[0]
            service_name = f"{unit_prefix}.{self.application.name}-endpoints"
            return get_k8s_fqdn(service_name)
        return socket.getfqdn()

    @property
    def network_hosts(self) -> list[str]:
        """All HTTP/Transport hosts for the current node."""
        hosts = ["_site_", self.fqdn]
        if self.substrate == Substrates.VM:
            hosts.append(self.host_ip)
        return hosts

    @property
    def port(self) -> int:
        """Return Port of OpenSearch unit."""
        return OPENSEARCH_HTTP_PORT

    def unit_ip(self, unit: Unit) -> str | None:
        """Returns the ip address of a given unit."""
        # check if host is current host
        if unit == self.model.unit:
            return self.host_ip

        if self.peer_relation:
            private_address = self.peer_relation.data[unit].get("private-address")
            if private_address:
                return str(private_address)

    def get_unit(self, name: str):
        """Get unit by name"""
        return self.model.get_unit(name)

    @property
    def is_tls_full_configured_in_cluster(self) -> bool:
        """Check if TLS is configured in all the units of the current cluster."""
        if not self.peer_relation:
            return False
        for unit in self.all_units:
            if self.peer_relation.data[unit].get("tls_configured", "").lower() != "true":
                return False
        return True

    @property
    def ca_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        # Use related_peer_cluster_servers since we are reading remote data.
        all_units_in_fleet = self.application_servers + self.all_peer_clusters_servers(remote=True)

        # check peer units and current unit
        rotation_in_progress = any([server.tls_ca_renewing for server in all_units_in_fleet])
        rotation_complete = all([server.tls_ca_renewed for server in all_units_in_fleet])

        logger.debug(
            "CA rotation state CA rotation happening in cluster: %s | \
                rotation complete in cluster: %s |",
            rotation_in_progress,
            rotation_complete,
        )
        # if no unit is renewing the CA, or all of them renewed it, the rotation is complete
        return not rotation_in_progress or rotation_complete

    @property
    def ca_and_certs_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        # Use related_peer_cluster_servers since we are reading remote data.
        all_units_in_fleet = self.application_servers + self.all_peer_clusters_servers(remote=True)
        logger.debug(
            "CA and certs rotation state Units in fleet: %s | \
                CA rotation complete in fleet: %s | \
                TLS configured in fleet: %s",
            [server.unit.name for server in all_units_in_fleet],
            [server.tls_ca_renewed for server in all_units_in_fleet],
            [server.tls_configured for server in all_units_in_fleet],
        )

        logger.debug(
            "CA and certs rotation complete in cluster: %s",
            all(
                [
                    server.tls_configured and (not server.tls_ca_renewing or server.tls_ca_renewed)
                    for server in all_units_in_fleet
                ]
            ),
        )
        # if the current unit is not in the relation.units list
        # or if tls is not configured or in the middle of rotation, return False
        return all(
            [
                server.tls_configured and (not server.tls_ca_renewing or server.tls_ca_renewed)
                for server in all_units_in_fleet
            ]
        )

    def reset_ca_rotation_state(self) -> None:
        """Handle internal flags during CA rotation routine."""
        if not self.server.tls_ca_renewing:
            # if the CA is not being renewed we don't have to do anything here
            return

        peer_cluster_servers = self.all_peer_clusters_servers(remote=False)
        # if this flag is set, the CA rotation routine is complete for this unit
        if self.server.tls_ca_renewed and self.ca_and_certs_rotation_complete_in_cluster:
            # both CA rotation and certs rotation completed in the cluster
            del self.server.tls_ca_renewing
            del self.server.tls_ca_renewed
            for peer_cluster_server in peer_cluster_servers:
                del peer_cluster_server.tls_ca_renewing
                del peer_cluster_server.tls_ca_renewed
            return

        # this means only the CA rotation completed, still need to create certificates
        self.server.tls_ca_renewed = True
        for peer_cluster_server in peer_cluster_servers:
            peer_cluster_server.tls_ca_renewed = True

    @property
    def network_ingress_address(self) -> str:
        """Get the public ip address of the unit."""
        return str(self.model.get_binding(PEER_RELATION).network.ingress_address)

    @property
    def peer_unit_hosts(self) -> set[str]:
        """Fetch the list of hosts for the current juju app."""
        hosts = set()

        if not (all_units := self.all_units):
            return hosts

        for unit in all_units:
            if self.substrate == Substrates.K8S:
                hosts.add(
                    k8s_fqdn(format_unit_name(unit, app=self.application.deployment_desc.app))
                )
            else:
                hosts.add(self.unit_ip(unit))

        return hosts

    @property
    def all_units(self) -> list[Unit]:
        """Fetch the list of units for the current app."""
        if not self.peer_relation:
            return []
        return list(self.peer_relation.units.union({self.server.unit}))

    @property
    def all_unit_names(self) -> list[str]:
        """Fetch the list of unit names for the current app."""
        return [
            format_unit_name(unit, app=self.application.deployment_desc.app)
            for unit in self.all_units
        ]

    @property
    def implements_secrets(self):
        """Property to cache results from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    @property
    def model_uuid(self):
        """UUID of the Charm Model."""
        return self.model.uuid

    @property
    def current_peer_cluster_app(self) -> PeerClusterApp | None:
        """Return the current peer cluster App."""
        deployment_desc = self.application.deployment_desc
        if not deployment_desc:
            return None
        logger.info("Current deployment desc %s", deployment_desc)
        return PeerClusterApp(
            app=deployment_desc.app,
            planned_units=self.planned_units,
            units=[format_unit_name(u, app=deployment_desc.app) for u in self.all_units],
            roles=(
                deployment_desc.config.roles
                if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES
                else GENERATED_ROLES
            ),
        )

    def get_relation_mapped_users(self, role: str) -> list[str]:
        """Get the list of users mapped to a specific role from config roles_mapping."""
        config_roles_mapping = self.config.get("roles_mapping")
        if not config_roles_mapping:
            return []
        try:
            roles_mapping = json.loads(config_roles_mapping)
            if not isinstance(roles_mapping, dict):
                logger.error("Bad roles_mapping config value")
                return []
        except JSONDecodeError:
            logger.error("Bad roles_mapping config value")
            return []

        return [
            mapped_user
            for mapped_user, mapped_role in roles_mapping.items()
            if mapped_role == role
        ]

    def computed_roles(self) -> list[str]:
        """Return computed_roles"""
        if (
            deployment_desc := self.application.deployment_desc
        ).start == StartMode.WITH_PROVIDED_ROLES:
            computed_roles = deployment_desc.config.roles.copy()
        else:
            computed_roles = GENERATED_ROLES.copy()

        # If the failover orchestrator is the only data node in the cluster, remove the
        # cluster-manager role from it to avoid it bootstrapping the cluster
        # which is the responsibility of the main orchestrator
        # who then broadcasts `security_index_initialized` to the peer clusters.
        if (
            self.model.unit.is_leader()
            and self.is_failover_and_sole_data_app
            and not self.application.is_security_index_initialised
        ):
            self.server.is_cluster_manager_removed = True
            if "cluster_manager" in computed_roles:
                computed_roles.remove("cluster_manager")

        if computed_roles == ["coordinating"]:
            computed_roles = []  # to mark a node as dedicated coordinating only, we clear the list
        return computed_roles

    @property
    def is_failover_and_sole_data_app(self) -> bool:
        """Check if the current node is a failover and the only data node in the cluster."""
        deployment_desc = self.application.deployment_desc
        cluster_fleet_apps = self.application.cluster_fleet_apps or {}
        return (
            # data node in a failover orchestrator deployment
            deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR
            and (
                "data" in deployment_desc.config.roles
                or deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            )
            # No pure data nodes in the cluster
            and not any(
                self.application.name != cluster_fleet_app.app.name
                and "data" in cluster_fleet_app.roles
                and "cluster_manager" not in cluster_fleet_app.roles
                for cluster_fleet_app in cluster_fleet_apps.values()
            )
        )

    def get_local_first_data_node(self) -> str | None:
        """Get first data node from the local app relation data."""
        orchestrators = self.application.orchestrators

        if orchestrators.main_app is None:
            return None
        local_peer_cluster = self.peer_cluster_by_relation_id(
            is_provider=False, relation_id=orchestrators.main_rel_id, remote=False
        )
        if not local_peer_cluster:
            return None

        return local_peer_cluster.first_data_node

    def add_status_if_not_present(
        self,
        status: StatusObject,
        scope: AdvancedStatusesScope,
        component: str,
        dynamic_params: dict[str, Any] | None = None,
        search_parameters: dict[str, Any] | None = None,
    ) -> None:
        """Add charm status if not present already.

        Args:
            status: charm status to be added.
            scope: scope of the added charm status.
            component: name of the responsible component of the added status.
            dynamic_params: params to format added status message with.
            search_parameters: params to format searched status message with prior to interpolated
                search. Helps to differentiate between statuses with multiple dynamic parameters.
                For example, if one of the parameters is a relation id, you want for search to be
                performed only through specific relation, while other parameters should be loosen
                by search regex. E.g. if you have a two parameters `relation_id` and `exception`,
                you may want to add a status with {"relation_id": 1, "exception": "err"} but with
                search parameters {"relation_id": 1, "exception": "{}"} in order to not override
                the same statuses from different relations. Note: "{}" placeholder makes
                parameter loosen.
        """
        if scope == "app" and not self.server.is_app_leader:
            return

        present_statuses = self.statuses.get(scope, component)

        if not dynamic_params and status not in present_statuses:
            self.statuses.add(status, scope, component)

        if dynamic_params and (
            not (
                present_status := self._search_interpolated_status(
                    status, scope, component, search_parameters
                )
            )
            or present_status.message != format_status(status, dynamic_params).message
        ):
            # Updates dynamic params if status already present.
            self.remove_status_if_present(status, scope, component, interpolated=True)
            self.statuses.add(format_status(status, dynamic_params), scope, component)

    def remove_status_if_present(
        self,
        status: StatusObject,
        scope: AdvancedStatusesScope,
        component: str,
        interpolated: bool = False,
        search_parameters: dict[str, Any] | None = None,
    ) -> None:
        """Remove charm status if it is present.

        Args:
            status: charm status to be removed.
            scope: scope of the removed charm status.
            component: name of the responsible component of the removed status.
            interpolated: perform a regex search by the status message to find
                statuses formatted with dynamic parameters.
            search_parameters: params to format searched status message with prior to interpolated
                search. Helps to differentiate between statuses with multiple dynamic parameters.
                Note: "{}" placeholder makes parameter loosen.
        """
        if scope == "app" and not self.server.is_app_leader:
            return

        present_statuses = self.statuses.get(scope, component)

        if not interpolated and status in present_statuses:
            self.statuses.delete(status, scope, component)

        if interpolated and (
            present_status := self._search_interpolated_status(
                status, scope, component, search_parameters
            )
        ):
            self.statuses.delete(present_status, scope, component)

    def _search_interpolated_status(
        self,
        status: StatusObject,
        scope: AdvancedStatusesScope,
        component: str,
        interpolated_parameters: dict[str, Any] | None = None,
    ) -> StatusObject | None:
        """Remove charm status if it is present.

        Args:
            status: charm status to be removed.
            scope: scope of the removed charm status.
            component: name of the responsible component of the removed status.
            interpolated_parameters: params to format searched status message with prior to
                interpolated search. Helps to differentiate between statuses with multiple
                dynamic parameters. Note: "{}" placeholder makes parameter loosen.

        Returns:
            status if it was found.
        """
        regex_pattern = re.sub(
            r"\{.*?\}",
            r"(?s:.*?)",
            format_status(status, interpolated_parameters).message,
        )
        for present_status in self.statuses.get(scope, component):
            if re.fullmatch(regex_pattern, present_status.message) is not None:
                return present_status
        return None

    def is_peer_cluster_provider(self, typ: Literal["main", "failover"] | None = None) -> bool:
        """Return whether the current app is a related to provider / orchestrator."""
        if not (deployment_desc := self.application.deployment_desc):
            return False

        if deployment_desc.typ == DeploymentType.OTHER:
            return False

        # the current app is not related as an orchestrator to any app
        if not self.peer_cluster_orchestrator_relations:
            return False

        # check if the current app is elected orchestrator
        if not (orchestrators := self.application.orchestrators):
            # not populated yet
            return False

        current_app_id = deployment_desc.app.id

        is_main = orchestrators.main_app and orchestrators.main_app.id == current_app_id
        is_failover = (
            orchestrators.failover_app and orchestrators.failover_app.id == current_app_id
        )

        if typ == "main":
            return is_main
        elif typ == "failover":
            return is_failover
        else:
            return is_main or is_failover

    def is_peer_cluster_consumer(self, of: Literal["main", "failover"] | None = None) -> bool:
        """Check if the current app is a consumer of the peer-cluster-relation."""
        if not (deployment_desc := self.application.deployment_desc):
            return False

        # the current app is not related to any orchestrator app
        if not self.peer_cluster_relations:
            return False

        # check if the current app is elected orchestrator
        if not (orchestrators := self.application.orchestrators):
            # not populated yet
            return False

        if orchestrators.main_app and orchestrators.main_app.id == deployment_desc.app.id:
            # there is a wrong relation happening - where current is the main orchestrator
            # yet related to another "orchestrator"
            return False

        of_main = (
            orchestrators.main_app
            and self.peer_cluster_by_relation_id(
                relation_id=orchestrators.main_rel_id,
                is_provider=False,
                remote=True,
            )
            is not None
        )
        of_failover = (
            orchestrators.failover_app
            and self.peer_cluster_by_relation_id(
                is_provider=False, relation_id=orchestrators.failover_rel_id, remote=True
            )
            is not None
        )
        if of == "main":
            return of_main
        elif of == "failover":
            return of_failover
        else:
            return of_main or of_failover

    def get_rel_data_from_main_orchestrator(
        self, peek_secrets: bool = False
    ) -> PeerClusterRelData | None:
        """Get the data from the main orchestrator relation.

        Returns:
            data: peer cluster rel data if any.

        """
        if not self.is_peer_cluster_consumer(of="main"):
            return None

        if not (orchestrators := self.application.orchestrators) or not orchestrators.main_rel_id:
            logger.info("no orchestrators found")
            return None

        if not self.peer_cluster_orchestrator_relation_exists(orchestrators.main_rel_id):
            logger.info(
                "relation with id %s not found for main orchestrator", orchestrators.main_rel_id
            )
            return None

        if not (
            remote_peer_cluster := self.peer_cluster_by_relation_id(
                is_provider=True,
                relation_id=orchestrators.main_rel_id,
                remote=True,
            )
        ):
            logger.info(
                "related peer cluster not found for relation id %s of main orchestrator",
                orchestrators.main_rel_id,
            )
            return None

        return remote_peer_cluster.data(peek_secrets=peek_secrets)

    @property
    def storage_type(self) -> ObjectStorageType | None:  # noqa: C901
        """Get the active object storage type from relations/peer-cluster.

        Returns:
            Optional[ObjectStorageType]: the active object storage type.
        """
        if not (deployment_desc := self.application.deployment_desc):
            logger.debug("Deployment description missing; storage type unknown.")
            return None

        if deployment_desc.typ in {DeploymentType.MAIN_ORCHESTRATOR}:
            active = [
                r
                for r in [
                    self.s3_relation,
                    self.azure_relation,
                    self.gcs_relation,
                ]
                if r
            ]
            if len(active) == 0:
                return None
            if len(active) > 1:
                return ObjectStorageType.CONFLICT
            if self.s3_relation:
                return ObjectStorageType.S3
            if self.azure_relation:
                return ObjectStorageType.AZURE
            if self.gcs_relation:
                return ObjectStorageType.GCS

        # non-main orchestrator
        peer_data = self.get_rel_data_from_main_orchestrator(peek_secrets=True)
        if not peer_data or not peer_data.credentials:
            return None
        if peer_data.credentials.s3:
            return ObjectStorageType.S3_PCLUSTER
        if peer_data.credentials.azure:
            return ObjectStorageType.AZURE_PCLUSTER
        if peer_data.credentials.gcs:
            return ObjectStorageType.GCS_PCLUSTER

    def get_storage_connection_info_from_relation(
        self, object_storage_type: ObjectStorageType
    ) -> dict[str, str]:
        """Returns the storage connection info from the active relation.."""
        match object_storage_type:
            case ObjectStorageType.S3:
                return self.s3_requirer.get_s3_connection_info() or {}
            case ObjectStorageType.AZURE:
                return self.azure_requires.get_azure_storage_connection_info() or {}
            case ObjectStorageType.GCS:
                if not self.gcs_relation:
                    return {}
                return self.gcs_requires.get_storage_connection_info(self.gcs_relation) or {}
            case _:
                raise OpenSearchInvalidStorageTypeError(
                    "Unsupported object storage type: %s" % object_storage_type
                )

    def gcs_credentials(self, connection_info: dict[str, str]) -> GcsRelDataCredentials | None:
        """Retrieve GCS storage credentials."""
        deployment_desc = self.application.deployment_desc
        if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            if not self.gcs_relation:
                return None

            try:
                object_storage_config = (
                    storage_config_from_connection_info(ObjectStorageType.GCS, connection_info)
                    or ObjectStorageConfig()
                )
            except OpenSearchObjectStorageConfigValidationError as e:
                logger.warning(
                    "Invalid %s object storage configuration: %s",
                    ObjectStorageType.GCS,
                    e.error,
                )
                return None
            gcs = object_storage_config.gcs
            if not (gcs and gcs.credentials and gcs.credentials.secret_key):
                return None

            # As the main orchestrator, this application must set the gcs information.
            secret_key = gcs.credentials.secret_key

            # set the secrets in the charm
            self.secrets.put(Scope.APP, "gcs-secret-key", secret_key)

            return GcsRelDataCredentials(secret_key=secret_key)

        # Non-main orchestrators: only return creds if we already have them
        if not self.secrets.get(Scope.APP, "gcs-secret-key"):
            return None

        # Return what we have received from the peer relation
        return GcsRelDataCredentials(
            secret_key=self.secrets.get(Scope.APP, "gcs-secret-key"),
        )

    def azure_credentials(self, connection_info: dict[str, str]) -> AzureRelDataCredentials | None:
        """Retrieve Azure storage credentials."""
        deployment_desc = self.application.deployment_desc
        if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            if not self.azure_relation:
                return None

            try:
                object_storage_config = (
                    storage_config_from_connection_info(ObjectStorageType.AZURE, connection_info)
                    or ObjectStorageConfig()
                )
            except OpenSearchObjectStorageConfigValidationError as e:
                logger.warning(
                    "Invalid %s object storage configuration: %s",
                    ObjectStorageType.AZURE,
                    e.error,
                )
                return None
            azure = object_storage_config.azure
            if not (azure and azure.credentials and azure.credentials.storage_account):
                return None

            # As the main orchestrator, this application must set the azure information.
            storage_account = azure.credentials.storage_account
            secret_key = azure.credentials.secret_key

            # set the secrets in the charm
            # TODO Move this to azure relation and include both in one secret
            self.secrets.put(Scope.APP, "azure-storage-account", storage_account)
            self.secrets.put(Scope.APP, "azure-secret-key", secret_key)

            return AzureRelDataCredentials(storage_account=storage_account, secret_key=secret_key)

        if not self.secrets.get(Scope.APP, "azure-storage-account"):
            return None

        # Return what we have received from the peer relation
        return AzureRelDataCredentials(
            storage_account=self.secrets.get(Scope.APP, "azure-storage-account"),
            secret_key=self.secrets.get(Scope.APP, "azure-secret-key"),
        )

    def s3_credentials(self, connection_info: dict[str, str]) -> S3RelDataCredentials | None:
        """Retrieve S3 storage credentials."""
        deployment_desc = self.application.deployment_desc
        if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            if not self.s3_relation:
                return None
            try:
                object_storage_config = (
                    storage_config_from_connection_info(ObjectStorageType.S3, connection_info)
                    or ObjectStorageConfig()
                )
            except OpenSearchObjectStorageConfigValidationError as e:
                logger.warning(
                    "Invalid %s object storage configuration: %s",
                    ObjectStorageType.S3,
                    e.error,
                )
                return None
            s3_cfg = object_storage_config.s3
            if not (
                s3_cfg
                and s3_cfg.credentials
                and s3_cfg.credentials.access_key
                and s3_cfg.credentials.secret_key
            ):
                return None

            # As the main orchestrator, this application must set the S3 information.
            access_key = s3_cfg.credentials.access_key
            secret_key = s3_cfg.credentials.secret_key
            s3_tls_ca_chain = s3_cfg.tls_ca_chain

            # set the secrets in the charm
            # TODO Move this to s3 relation and include both in one secret
            self.secrets.put(Scope.APP, "s3-access-key", access_key)
            self.secrets.put(Scope.APP, "s3-secret-key", secret_key)
            if s3_tls_ca_chain:
                self.secrets.put(Scope.APP, "s3-tls-ca-chain", s3_tls_ca_chain)

            return S3RelDataCredentials(
                access_key=access_key, secret_key=secret_key, s3_tls_ca_chain=s3_tls_ca_chain
            )

        if not self.secrets.get(Scope.APP, "s3-access-key"):
            return None

        # Return what we have received from the peer relation
        return S3RelDataCredentials(
            access_key=self.secrets.get(Scope.APP, "s3-access-key"),
            secret_key=self.secrets.get(Scope.APP, "s3-secret-key"),
            s3_tls_ca_chain=self.secrets.get(Scope.APP, "s3-tls-ca-chain"),
        )

    def is_highest_ordinal_unit(self) -> bool:
        """Check if the current unit is the highest ordinal unit in the application."""
        return self.server_upgrade.unit.name == self.sorted_upgrades_units[0].unit.name
