#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Topology Manager."""

from typing import List, Optional

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    GENERATED_ROLES,
    DeploymentType,
    StartMode,
)
from opensearch_single_kernel.core.models import App, Node, Scope
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.logging import WithLogging
from opensearch_single_kernel.workload.base import BaseWorkload


class TopologyManager(WithLogging):
    """OpenSearch Topology Manager.

    This manager is responsible for managing the topology of the opensearch cluster.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        self.name = "topology_manager"
        self.state = state
        self.workload = workload

    @property
    def opensearch_client(self):
        """Initialize an opensearch client"""
        admin_field = self.state.secrets.password_key("admin")
        admin_secret = self.state.secrets.get(Scope.APP, admin_field)
        return OpenSearchClient(self.workload, self.state.host, self.state.port, admin_secret)

    @staticmethod
    def generated_roles() -> List[str]:
        """Get generated roles for a Node."""
        return GENERATED_ROLES

    @staticmethod
    def nodes(
        opensearch_client: OpenSearchClient,
        use_localhost: bool,
        hosts: Optional[List[str]] = None,
    ) -> List[Node]:
        """Get the list of nodes in a cluster."""
        host: Optional[str] = None  # defaults to current unit ip
        alt_hosts: Optional[List[str]] = hosts
        if not use_localhost and hosts:
            host = hosts[0]
            if len(hosts) >= 2:
                alt_hosts = hosts[1:]

        nodes: List[Node] = []
        if use_localhost or host:
            response = opensearch_client.get_nodes(host, alt_hosts)
            if "nodes" in response:
                for obj in response["nodes"].values():
                    node = Node(
                        name=obj["name"],
                        roles=obj["roles"],
                        ip=obj["ip"],
                        app=App(id=obj["attributes"]["app_id"]),
                        unit_number=int(obj["name"].split(".")[0].split("-")[-1]),
                        temperature=obj.get("attributes", {}).get("temp"),
                    )
                    nodes.append(node)
        return nodes

    def _set_node_conf(self, nodes: List[Node]) -> None:
        """Set the configuration of the current node / unit."""
        # set user provided roles if any, else generate base roles
        if (
            deployment_desc := self.opensearch_peer_cm.deployment_desc()
        ).start == StartMode.WITH_PROVIDED_ROLES:
            computed_roles = deployment_desc.config.roles
        else:
            computed_roles = TopologyManager.generated_roles()

        # If the failover orchestrator is the only data node in the cluster, remove the
        # cluster-manager role from it to avoid it bootstrapping the cluster
        # which is the responsibility of the main orchestrator
        # who then broadcasts `security_index_initialized` to the peer clusters.
        if (
            self.state.opensearch_unit.is_app_leader
            and self._is_failover_and_sole_data_app()
            and not self.state.opensearch_application.security_index_initialised
        ):
            self.peers_data.put(Scope.UNIT, "cluster_manager_removed", True)
            computed_roles.remove("cluster_manager")

        cm_names = TopologyManager.get_cluster_managers_names(nodes)
        cm_ips = TopologyManager.get_cluster_managers_ips(nodes)

        contribute_to_bootstrap = False
        if computed_roles == ["coordinating"]:
            computed_roles = []  # to mark a node as dedicated coordinating only, we clear the list
        elif "cluster_manager" in computed_roles:
            cm_names.append(self.unit_name)
            cm_ips.append(self.unit_ip)

            if (
                self.opensearch_peer_cm.deployment_desc().typ == DeploymentType.MAIN_ORCHESTRATOR
                and not self.peers_data.get(Scope.APP, "bootstrapped", False)
            ):
                cms_in_bootstrap = self.peers_data.get(
                    Scope.APP, "bootstrap_contributors_count", 0
                )
                if cms_in_bootstrap < self.app.planned_units():
                    contribute_to_bootstrap = True

                    if self.unit.is_leader():
                        self.peers_data.put(
                            Scope.APP, "bootstrap_contributors_count", cms_in_bootstrap + 1
                        )

                    # indicates that this unit is part of the "initial cm nodes"
                    self.peers_data.put(Scope.UNIT, "bootstrap_contributor", True)

        deployment_desc = self.opensearch_peer_cm.deployment_desc()
        self.opensearch_config.set_node(
            app=deployment_desc.app,
            cluster_name=deployment_desc.config.cluster_name,
            unit_name=self.unit_name,
            roles=computed_roles,
            cm_names=list(set(cm_names)),
            cm_ips=list(set(cm_ips)),
            contribute_to_bootstrap=contribute_to_bootstrap,
            node_temperature=deployment_desc.config.data_temperature,
        )

    @staticmethod
    def get_cluster_managers_ips(nodes: List[Node]) -> List[str]:
        """Get the nodes of cluster manager eligible nodes."""
        result = []
        for node in nodes:
            if node.is_cm_eligible():
                result.append(node.ip)

        return result

    @staticmethod
    def get_cluster_managers_names(nodes: List[Node]) -> List[str]:
        """Get the nodes of cluster manager eligible nodes."""
        result = []
        for node in nodes:
            if node.is_cm_eligible():
                result.append(node.name)

        return result
