#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object representing the global state of OpenSearch Charm."""

import json
import socket
from typing import TYPE_CHECKING, Any

from ops import Application, JujuVersion, Object, Relation, Unit

from opensearch_single_kernel.common.constants import (
    NODE_LOCK_RELATION,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    PERFORMANCE_PROFILE,
    TLS_RELATION,
    Substrates,
)
from opensearch_single_kernel.core.models import (
    DeploymentDescription,
    Model,
    OpenSearchProfile,
    PeerClusterApp,
    PerformanceType,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.core.relations import (
    PeerCluster,
    PeerClusterData,
    PeerClusterOrchestratorData,
    RelationDataStore,
    RelationState,
)
from opensearch_single_kernel.core.secrets import OpenSearchSecrets
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerUnitData,
)
from opensearch_single_kernel.utils.helpers import format_unit_name

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


class OpenSearchServer(RelationState):
    """State/Relation data collection for an opensearch unit"""

    def __init__(
        self, relation: Relation | None, data_interface: DataPeerUnitData, component: Unit
    ):
        super().__init__(relation, data_interface, component)
        self.unit = component

    @property
    def unit_id(self) -> int:
        """The id of the unit from the unit name."""
        return int(self.unit.name.split("/")[1])

    @property
    def profile(self) -> OpenSearchProfile | None:
        """Current profile of the unit"""
        if profile_str := self.relation_data.get(PERFORMANCE_PROFILE, None):
            return (
                ProductionProfile()
                if PerformanceType(profile_str) == PerformanceType.PRODUCTION
                else TestingProfile()
            )
        return None

    @property
    def is_app_leader(self) -> bool:
        """Check if the current unit is the leader of the application."""
        return self.unit.is_leader()

    @property
    def bootstrap_contributor(self) -> bool:
        """Get value of 'bootstrap_contributor'"""
        return self.relation.data.get("bootstrap_contributor", "") == "True"

    @bootstrap_contributor.setter
    def bootstrap_contributor(self, value: bool):
        """Set the value of 'bootstrap_contributor' in application state."""
        self.update({"bootstrap_contributor": str(value)})

    @property
    def cluster_manager_removed(self) -> bool:
        """Get value of 'cluster_manager_removed'"""
        return self.relation_data.get("cluster_manager_removed", "") == "True"

    @cluster_manager_removed.setter
    def cluster_manager_removed(self, value: bool):
        """Set value of 'cluster_manager_removed'"""
        self.update({"cluster_manager_removed": str(value)})

    @property
    def started(self) -> bool:
        """Get the value of 'started' key from unit data bag"""
        return bool(self.relation_data.get("started", ""))


class OpenSearchApplication(RelationState):
    """An OpenSearch Application is a charm application with a given role.

    In OpenSearch a cluster can be formed using one or more applications.
    This class defines state/relation data for a single opensearch application.
    """

    def __init__(
        self, relation: Relation | None, data_interface: DataPeerData, component: Application
    ):
        super().__init__(relation, data_interface, component)
        self.app = component

    def get_object(self, key: str) -> dict[str, Any] | None:
        """Get dict / json object from the relation data store."""
        data = self.relation_data.get(key)
        if data is None:
            return None

        return json.loads(data)

    def put_object(self, key: str, value: dict[str, Any], merge: bool = False) -> None:
        """Put dict / json object into relation data store."""
        if merge:
            stored = self.get_object(key)

            if stored is not None:
                stored.update(value)
                value = stored

        sorted_value = Model.sort_payload(value)

        payload_str = None
        if value is not None:
            payload_str = json.dumps(
                sorted_value, default=RelationDataStore._default_encoder, sort_keys=True
            )

        self.update({key: payload_str})

    @property
    def name(self) -> str:
        """Return the name of the Application."""
        return self.app.name

    @property
    def is_admin_user_initialized(self) -> bool:
        """Return the value of 'admin_user_initialized' in application state."""
        return self.relation_data.get("admin_user_initialized", "") == "True"

    @property
    def bootstrap_contributors_count(self) -> int:
        """Get the value of 'bootstrap_contributors_count'"""
        return int(self.relation_data.get("bootstrap_contributors_count", 0))

    @bootstrap_contributors_count.setter
    def bootstrap_contributors_count(self, value: int):
        """Set value of bootstrap contributors count in application state."""
        self.update({"bootstrap_contributors_count": str(value)})

    @is_admin_user_initialized.setter
    def is_admin_user_initialized(self, value: bool):
        """Update the value of 'admin_user_initialized' in application state."""
        self.update({"admin_user_initialized": str(value)})

    @property
    def security_index_initialised(self) -> bool:
        """Return the value of 'security_index_initialised' in application state."""
        return self.relation_data.get("security_index_initialised", "") == "True"

    @security_index_initialised.setter
    def security_index_initialised(self, value: bool):
        """Update the value of 'security_index_initialised' in application state."""
        self.update({"security_index_initialised": str(value)})

    @property
    def nodes_config(self) -> str:
        """Return the value of 'nodes_config' in application state"""
        return self.relation_data.get("nodes_config", "")

    @property
    def bootstrapped(self) -> bool:
        """Return the value of 'bootstrapped' in application state"""
        return bool(self.relation_data.get("bootstrapped", ""))

    @property
    def deployment_desc(self) -> DeploymentDescription | None:
        """Return the deployment description object if any."""
        current_deployment_desc = self.get_object("deployment-description")
        if not current_deployment_desc:
            return None
        return DeploymentDescription.from_dict(current_deployment_desc)

    @property
    def cluster_fleet_apps(self) -> dict[str, PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = self.relation_data.get("cluster_fleet_apps", "")
        if not cluster_fleet_apps:
            cluster_fleet_apps = {}
        elif not json.loads(cluster_fleet_apps):
            cluster_fleet_apps = {}
        else:
            cluster_fleet_apps = json.loads(cluster_fleet_apps)
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps.items()}

    def apps_in_fleet(self) -> list[PeerClusterApp]:
        """Returns list of apps in cluster fleet"""
        cluster_fleet_apps = self.get_object("cluster_fleet_apps")
        if not cluster_fleet_apps:
            cluster_fleet_apps = {}
        elif not json.loads(cluster_fleet_apps):
            cluster_fleet_apps = json.loads(cluster_fleet_apps)
        return [PeerClusterApp.from_dict(app) for app in cluster_fleet_apps.values()]


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
    def unit_name(self):
        """Name of the current unit."""
        return format_unit_name(self.model.unit, app=self.application.deployment_desc.app)

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
        return 9200

    def unit_ip(self, unit: Unit) -> str | None:
        """Returns the ip address of a given unit."""
        # check if host is current host
        if unit == self.model.unit:
            return self.host_ip

        if self.peer_relation:
            private_address = self.peer_relation.data[unit].get("private-address")
            return str(private_address)

    def get_unit(self, name: str):
        """Get unit by name"""
        return self.model.get_unit(name)

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
    def implements_secrets(self):
        """Property to cache results from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    @property
    def model_uuid(self):
        """UUID of the Charm Model."""
        return self.model.uuid
