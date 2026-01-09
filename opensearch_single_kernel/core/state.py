#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object representing the global state of OpenSearch Charm."""

import socket
from typing import TYPE_CHECKING, Dict, List

from ops import JujuVersion, Object, Relation, Unit

from opensearch_single_kernel.common.constants import (
    NODE_LOCK_RELATION,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    TLS_RELATION,
    Substrates,
)
from opensearch_single_kernel.core.models import (
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
from opensearch_single_kernel.utils.helpers import format_unit_name
from opensearch_single_kernel.utils.logging import WithLogging

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


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
            component=self.model.app,
        )

    @property
    def peer_cluster(self) -> PeerCluster:
        """The state for the related 'peer-cluster-orchestrator' related application"""
        return PeerCluster(
            relation=self.peer_cluster_orchestrator_relation,
            data_interface=PeerClusterOrchestratorData(
                self.model, PEER_CLUSTER_ORCHESTRATOR_RELATION
            ),
            component=self.model.app,
        )

    # -- Core Components

    @property
    def server(self) -> OpenSearchServer:
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
        address = self.model.get_binding(PEER_RELATION).network.bind_address
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
        if unit == self.model.unit:
            return self.host_ip

        private_address = self.peer_relation.data[unit].get("private-address")
        return str(private_address)

    def get_unit(self, name: str):
        """Get unit by name"""
        return self.model.get_unit(name)

    @property
    def ca_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        rotation_happening = False
        rotation_complete = True

        # check current unit
        self.logger.debug(
            "current unit tls_ca_renewing:%s | tls_ca_renewed:%s",
            self.server.tls_ca_renewing,
            self.server.tls_ca_renewed,
        )
        if self.server.tls_ca_renewing:
            rotation_happening = True
        if not self.server.tls_ca_renewed:
            self.logger.debug(
                f"TLS CA rotation ongoing in unit: {self.server.unit_name}, will not update tls certificates."
            )
            rotation_complete = False
        # TODO: Support peer cluster and peer cluster orchestrator
        for relation_type in [
            PEER_RELATION,
            # PeerClusterRelationName,
            # PeerClusterOrchestratorRelationName,
        ]:
            for relation in self.model.relations[relation_type]:
                for unit in relation.units:
                    self.logger.debug(
                        f"Checking unit {unit} in relation {relation}: \
                            tls_ca_renewing: {relation.data[unit].get('tls_ca_renewing')} \
                            | tls_ca_renewed: {relation.data[unit].get('tls_ca_renewed')}"
                    )
                    if relation.data[unit].get("tls_ca_renewing"):
                        rotation_happening = True

                    if not relation.data[unit].get("tls_ca_renewed"):
                        self.logger.debug(
                            f"TLS CA rotation ongoing in unit {unit}, will not update tls certificates."
                        )
                        rotation_complete = False
        self.logger.debug(
            "CA rotation happening in cluster: %s | \
                rotation complete in cluster: %s | return value: %s \
                ",
            rotation_happening,
            rotation_complete,
            not rotation_happening or rotation_complete,
        )
        # if no unit is renewing the CA, or all of them renewed it, the rotation is complete
        return not rotation_happening or rotation_complete

    def ca_and_certs_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        rotation_complete = True

        # the current unit is not in the relation.units list
        # if tls is not configured or in the middle of rotation, return False
        if not self.server.tls_configured or (
            self.server.tls_ca_renewing and not self.server.tls_ca_renewed
        ):
            self.logger.debug("TLS CA and/or Cert rotation ongoing on this unit.")
            return False

        for relation_type in [
            PEER_RELATION
            # PeerClusterRelationName,
            # PeerClusterOrchestratorRelationName,
        ]:
            for relation in self.model.relations[relation_type]:
                self.logger.debug(f"Checking relation {relation}: units: {relation.units}")
                for unit in relation.units:

                    if relation.data[unit].get("tls_configured") != "True" or (
                        relation.data[unit].get("tls_ca_renewing", False)
                        and not relation.data[unit].get("tls_ca_renewed", False)
                    ):
                        self.logger.debug(
                            f"TLS CA and or Cert rotation not complete for unit {unit}: {relation} \
                                | tls_ca_renewing: {relation.data[unit].get('tls_ca_renewing')} \
                                | tls_ca_renewed: {relation.data[unit].get('tls_ca_renewed')} \
                                | tls_configured: {relation.data[unit].get('tls_configured')}"
                        )
                        rotation_complete = False
                        break
        return rotation_complete

    def reset_ca_rotation_state(self) -> None:
        """Handle internal flags during CA rotation routine."""
        if not self.server.tls_ca_renewing:
            # if the CA is not being renewed we don't have to do anything here
            return

        # if this flag is set, the CA rotation routine is complete for this unit
        if self.server.tls_ca_renewed and self.ca_and_certs_rotation_complete_in_cluster():
            # both CA rotation and certs rotation completed in the cluster
            self.server.update({"tls_ca_renewing": None})
            self.server.update({"tls_ca_renewed": None})
            # TODO: Handle large deployment
            # self.update_tls_flag_to_peer_cluster_relation(
            # flag="tls_ca_renewing", operation="remove"
            # )
            # self.update_tls_flag_to_peer_cluster_relation(
            #    flag="tls_ca_renewed", operation="remove"
            # )
            return

        # this means only the CA rotation completed, still need to create certificates
        self.server.tls_ca_renewed = True
        # TODO: Handle large deployment
        # self.update_tls_flag_to_peer_cluster_relation(flag="tls_ca_renewed", operation="add")

    @property
    def network_ingress_address(self) -> str:
        """Get the public ip address of the unit."""
        return str(self.model.get_binding(PEER_RELATION).network.ingress_address)

    @property
    def units_ips(self) -> Dict[str, str]:
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
    def all_units(self) -> List[Unit]:
        """Fetch the list of units for the current app."""
        return list(self.peer_relation.units.union({self.server.unit}))

    @property
    def implements_secrets(self):
        """Property to cache results from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    @property
    def unit_name(self):
        """Name of the current unit."""
        return format_unit_name(self.model.unit, app=self.application.deployment_desc.app)

    @property
    def app_name(self):
        """Name of the charm application."""
        return self.model.app.name

    @property
    def model_uuid(self):
        """UUID of the Charm Model."""
        return self.model.uuid
