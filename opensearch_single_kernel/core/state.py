#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object representing the global state of OpenSearch Charm."""
import json
import logging
import socket
from json import JSONDecodeError
from typing import TYPE_CHECKING

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
    TLS_RELATION,
    StartMode,
    Substrates,
)
from opensearch_single_kernel.core.external_clients_relation import (
    ExternalOpenSearchClient,
)
from opensearch_single_kernel.core.jwt_relation import JwtState
from opensearch_single_kernel.core.lock_relation import LockAppState, LockServerState
from opensearch_single_kernel.core.models import (
    DeploymentType,
    Node,
    PeerClusterApp,
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
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerUnitData,
    OpenSearchProvidesData,
)
from opensearch_single_kernel.utils.helpers import (
    format_unit_name,
    lock_unit_name,
)

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


logger = logging.getLogger(__name__)


class ClusterState(Object):
    """The global OpenSearch Cluster State ."""

    def __init__(self, charm: "OpenSearchBaseCharm", substrate: Substrates):
        super().__init__(charm, "cluster_state")
        self.config = charm.config
        self.substrate = substrate

        # Secrets  FIXME: Handle this separately.
        self.secrets = OpenSearchSecrets(charm, peer_relation=PEER_RELATION)

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

    def relation_exists(self, relation_name) -> bool:
        """Check if the relation exists"""
        return bool(self.model.get_relation(relation_name))

    def peer_cluster_relation_exists(self, relation_id: int) -> bool:
        """Check if the relation with id exists"""
        relation = self.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, relation_id)
        return bool(relation)

    def peer_cluster_by_relation_id(
        self, is_provider: bool, relation_id: int
    ) -> PeerCluster | None:
        """Return the current related peer cluster if any."""
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        if relation := self.model.get_relation(relation_name, relation_id):
            return PeerCluster(
                relation=relation,
                data_interface=(
                    self.peer_cluster_data_interface
                    if not is_provider
                    else self.peer_cluster_orchestrator_data_interface
                ),
                component=self.model.app,
                secrets=self.secrets,
            )
        return None

    def related_peer_cluster_by_relation_id(
        self, is_provider: bool, relation_id: int
    ) -> PeerCluster | None:
        """Return the related peer cluster for the given relation id.

        This returns the remote peer cluster related to the current peer-cluster
        for the given relation id.
        """
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        if relation := self.model.get_relation(relation_name, relation_id):
            return PeerCluster(
                relation=relation,
                data_interface=(
                    self.peer_cluster_data_interface
                    if not is_provider
                    else self.peer_cluster_orchestrator_data_interface
                ),
                component=relation.app,
                secrets=self.secrets,
            )
        return None

    def peer_clusters(self, is_provider: bool, must_have_units: bool = True) -> list[PeerCluster]:
        """Return the list of peer clusters for each relations."""
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        return [
            PeerCluster(
                relation=rel,
                data_interface=(
                    self.peer_cluster_data_interface
                    if not is_provider
                    else self.peer_cluster_orchestrator_data_interface
                ),
                component=self.model.app,
                secrets=self.secrets,
            )
            for rel in self.model.relations[relation_name]
            if not must_have_units or len(rel.units) > 0
        ]

    def peer_clusters_servers(self, is_provider: bool) -> list[PeerClusterServer]:
        """Return the list of peer cluster servers for each relations."""
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        return [
            PeerClusterServer(
                relation=rel,
                data_interface=(
                    self.peer_cluster_data_interface
                    if not is_provider
                    else self.peer_cluster_orchestrator_data_interface
                ),
                component=unit,
            )
            for rel in self.model.relations[relation_name]
            for unit in rel.units
        ]

    def peer_cluster_server_by_relation_id(
        self, is_provider: bool, relation_id: int
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

    def related_peer_cluster_servers(self, is_provider: bool) -> list[PeerClusterServer]:
        """Return the list of related peer cluster servers for each relations.

        This returns the remote peer cluster servers related to the current peer-cluster.
        """
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        return [
            PeerClusterServer(
                relation=rel,
                data_interface=(
                    self.peer_cluster_data_interface
                    if not is_provider
                    else self.peer_cluster_orchestrator_data_interface
                ),
                component=unit,
            )
            for rel in self.model.relations[relation_name]
            for unit in rel.units
        ]

    def related_peer_clusters(
        self, is_provider: bool, must_have_units: bool = True
    ) -> list[PeerCluster]:
        """Return the list of related peer clusters.

        This returns the remote peer clusters related to the current peer-cluster.
        """
        relation_name = (
            PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
        )
        return [
            PeerCluster(
                relation=rel,
                data_interface=(
                    self.peer_cluster_data_interface
                    if not is_provider
                    else self.peer_cluster_orchestrator_data_interface
                ),
                component=rel.app,
                secrets=self.secrets,
            )
            for rel in self.model.relations[relation_name]
            if not must_have_units or len(rel.units) > 0
        ]

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
    def servers(self) -> list[OpenSearchServer]:
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
    def planned_units(self) -> int:
        """Return the planned units for the charm."""
        return self.model.app.planned_units()

    @property
    def host_ip(self) -> str:
        """Fetches the IP address of the current unit."""
        address = self.model.get_binding(PEER_RELATION).network.bind_address
        return str(address)

    @property
    def network_hosts(self) -> list[str]:
        """All HTTP/Transport hosts for the current node."""
        return [socket.getfqdn(), self.host_ip]

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
            if (
                self.peer_relation.data[unit].get("tls_configured", "").lower() != "true"
                or "tls_ca_renewing" in self.peer_relation.data[unit]
                or "tls_ca_renewed" in self.peer_relation.data[unit]
            ):
                return False
        return True

    @property
    def ca_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        # Use related_peer_cluster_servers since we are reading remote data.
        all_units_in_fleet = (
            self.servers
            + self.related_peer_cluster_servers(is_provider=False)
            + self.related_peer_cluster_servers(is_provider=True)
        )

        # check peer units and current unit
        rotation_in_progress = any([server.tls_ca_renewing for server in all_units_in_fleet])
        rotation_complete = all([server.tls_ca_renewed for server in all_units_in_fleet])

        logger.debug(
            "CA rotation state"
            "CA rotation happening in cluster: %s | \
                rotation complete in cluster: %s |",
            rotation_in_progress,
            rotation_complete,
        )
        # if no unit is renewing the CA, or all of them renewed it, the rotation is complete
        return not rotation_in_progress or rotation_complete

    def ca_and_certs_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        all_units_in_fleet = (
            self.servers
            + self.related_peer_cluster_servers(is_provider=False)
            + self.related_peer_cluster_servers(is_provider=True)
        )

        # if the current unit is not in the relation.units list
        # or if tls is not configured or in the middle of rotation, return False
        return all([server.tls_configured for server in all_units_in_fleet]) and all(
            [server.tls_ca_renewing and not server.tls_ca_renewed for server in all_units_in_fleet]
        )

    def reset_ca_rotation_state(self) -> None:
        """Handle internal flags during CA rotation routine."""
        if not self.server.tls_ca_renewing:
            # if the CA is not being renewed we don't have to do anything here
            return

        peer_cluster_servers = self.peer_clusters_servers(
            is_provider=False
        ) + self.peer_clusters_servers(is_provider=True)
        # if this flag is set, the CA rotation routine is complete for this unit
        if self.server.tls_ca_renewed and self.ca_and_certs_rotation_complete_in_cluster():
            # both CA rotation and certs rotation completed in the cluster
            self.server.update({"tls_ca_renewing": ""})
            self.server.update({"tls_ca_renewed": ""})
            for peer_cluster_server in peer_cluster_servers:
                peer_cluster_server.update({"tls_ca_renewing": ""})
                peer_cluster_server.update({"tls_ca_renewed": ""})
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
    def units_ips(self) -> dict[str, str]:
        """Returns the mapping "unit id / ip address" of all units."""
        unit_ip_map = {}
        if not self.peer_relation:
            return unit_ip_map

        for unit in self.peer_relation.units:
            unit_id = unit.name.split("/")[1]
            unit_ip_map[unit_id] = self.unit_ip(unit)

        # Sometimes the above command doesn't get the current node,
        # so ensure we get this unit's ip.
        unit_ip_map[self.model.unit.name.split("/")[1]] = self.host_ip

        return unit_ip_map

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
    def current_peer_cluster_app(self) -> PeerClusterApp:
        """Return the current peer cluster App."""
        deployment_desc = self.application.deployment_desc
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
            and self.is_failover_and_sole_data_app()
            and not self.application.is_security_index_initialised
        ):
            self.server.is_cluster_manager_removed = True
            computed_roles.remove("cluster_manager")

        if computed_roles == ["coordinating"]:
            computed_roles = []  # to mark a node as dedicated coordinating only, we clear the list
        return computed_roles

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
        peer_cluster = self.peer_cluster_by_relation_id(
            is_provider=False, relation_id=orchestrators.main_rel_id
        )
        if not peer_cluster:
            return None

        return peer_cluster.first_data_node

    @property
    def jwt_relation(self) -> Relation | None:
        """Get JWT relation."""
        return self.model.get_relation(JWT_CONFIG_RELATION)

    @property
    def jwt(self) -> JwtState:
        """Get JWT state."""
        return JwtState(
            relation=self.jwt_relation,
            data_interface=JwtData(self.model, JWT_CONFIG_RELATION),
            component=self.model.app,
        )

    @property
    def oauth_relation(self) -> Relation | None:
        """Get OAuth relation."""
        return self.model.get_relation(OAUTH_RELATION)

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
