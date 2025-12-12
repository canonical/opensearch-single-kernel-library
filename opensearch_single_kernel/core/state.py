#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object representing the global state of OpenSearch Charm."""

import random
import socket
from typing import TYPE_CHECKING, Dict, List, Optional

from ops import JujuVersion, Object, Relation, Unit

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    NODE_LOCK_RELATION,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    TLS_RELATION,
    Scope,
    Substrates,
)
from opensearch_single_kernel.core.models import (
    Node,
    OpenSearchApplication,
    OpenSearchServer,
    PeerCluster,
    PeerClusterData,
    PeerClusterOrchestratorData,
)
from opensearch_single_kernel.core.secrets import OpenSearchSecrets
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerUnitData,
)
from opensearch_single_kernel.utils.logging import WithLogging

if TYPE_CHECKING:
    from opensearch_single_kernel.events.base_charm import OpenSearchBaseCharm


class ClusterState(Object, WithLogging):
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

    # -- Relations

    @property
    def peer_relation(self) -> Relation | None:
        """Get charm peer relation."""
        return self.model.get_relation(PEER_RELATION)

    @property
    def node_lock_relation(self) -> Relation | None:
        """Get Node Lock Peer Relation."""
        return self.model.get_relation(NODE_LOCK_RELATION)

    @property
    def tls_relation(self) -> Relation | None:
        """Get TLS relation."""
        return self.model.get_relation(TLS_RELATION)

    @property
    def peer_cluster_relation(self) -> Relation | None:
        """The 'peer-cluster' relation that the charm is requiring."""
        return self.model.get_relation(PEER_CLUSTER_RELATION)

    @property
    def peer_cluster_orchestrator_relation(self) -> Relation | None:
        """The 'peer-cluster-orchestrator' relation that the charm is requiring."""
        return self.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION)

    @property
    def peer_cluster_orchestrator(self) -> PeerCluster:
        """The state for the related 'peer-cluster-orchestrator' application requiring."""
        return PeerCluster(
            relation=self.peer_cluster_relation,
            data_interface=PeerClusterData(self.model, PEER_CLUSTER_RELATION),
        )

    @property
    def peer_cluster(self) -> PeerCluster:
        """The state for the related 'peer-cluster-orchestrator' related application"""
        return PeerCluster(
            relation=self.peer_cluster_orchestrator_relation,
            data_interface=PeerClusterOrchestratorData(
                self.model, PEER_CLUSTER_ORCHESTRATOR_RELATION
            ),
        )

    # -- Core Components

    @property
    def unit(self) -> OpenSearchServer:
        """Get the opensearch unit state."""
        return OpenSearchServer(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
        )

    @property
    def application(self) -> OpenSearchApplication:
        """Get the opensearch application state."""
        return OpenSearchApplication(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
        )

    # -- Cluster State Properties

    @property
    def planned_units(self) -> int:
        """Return the planned units for the charm."""
        return self.model.app.planned_units()

    @property
    def host_ip(self) -> str:
        """Fetches the IP address of the current unit."""
        address = self.charm.model.get_binding(PEER_RELATION).network.bind_address
        return str(address)

    @property
    def network_hosts(self) -> List[str]:
        """All HTTP/Transport hosts for the current node."""
        return [socket.getfqdn(), self.host_ip]

    @property
    def port(self) -> int:
        """Return Port of OpenSearch unit."""
        return 9200

    def unit_ip(self, unit: Unit) -> str:
        """Returns the ip address of a given unit."""
        # check if host is current host
        if unit == self.charm.unit:
            return self.host_ip

        private_address = (
            self.charm.model.get_relation(PEER_RELATION).data[unit].get("private-address")
        )
        return str(private_address)

    @property
    def units_ips(self) -> Dict[str, str]:
        """Returns the mapping "unit id / ip address" of all units."""
        unit_ip_map = {}
        if not self.charm.model.get_relation(PEER_RELATION):
            return unit_ip_map

        for unit in self.charm.model.get_relation(PEER_RELATION).units:
            unit_id = unit.name.split("/")[1]
            unit_ip_map[unit_id] = self.unit_ip(unit)

        # Sometimes the above command doesn't get the current node,
        # so ensure we get this unit's ip.
        unit_ip_map[self.charm.unit.name.split("/")[1]] = self.host_ip

        return unit_ip_map

    @property
    def alt_hosts(self) -> Optional[List[str]]:
        """Return an alternative host (of another node)in case the current is offline."""
        all_units_ips = self.units_ips
        all_hosts = list(all_units_ips.values())

        if nodes_conf := self.opensearch_application.nodes_config:
            all_hosts.extend([Node.from_dict(node).ip for node in nodes_conf.values()])

        # TODO: Handle Peer CM
        # if peer_cm_rel_data := self.opensearch_peer_cm.rel_data():
        # all_hosts.extend([node.ip for node in peer_cm_rel_data.cm_nodes])

        random.shuffle(all_hosts)

        if not all_hosts:
            return None

        admin_field = self.secrets.password_key("admin")
        admin_secret = self.secrets.get(Scope.APP, admin_field)
        opensearch_client = OpenSearchClient(
            self.charm.workload, self.host, self.port, admin_secret
        )

        return [
            host
            for host in all_hosts
            if host != self.unit_ip and opensearch_client.is_node_up(host)
        ]

    @property
    def all_units(self) -> List[Unit]:
        """Fetch the list of units for the current app."""
        return list(self.peer_relation.units.union({self.opensearch_unit.unit}))

    @property
    def implements_secrets(self):
        """Property to cache results from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    def get_unit(self, name: str):
        """Get unit by name"""
        return self.charm.model.get_unit(name)
