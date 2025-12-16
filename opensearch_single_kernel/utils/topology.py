#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Topology Manager."""

from logging import Logger
from typing import Dict, List, Optional

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    GENERATED_ROLES,
)
from opensearch_single_kernel.core.models import App, Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.logging import WithLogging


class ClusterTopology(WithLogging):
    """OpenSearch Cluster Topology.

    Provides functions to manage cluster topology.
    """

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

    @staticmethod
    def is_data_role_in_cluster_fleet_apps(state: ClusterState) -> bool:
        """Look for data-role through all the roles of all the nodes in all applications"""
        data_apps_in_fleet = [
            app for app in state.application.apps_in_fleet() if "data" in app.roles
        ]
        return data_apps_in_fleet and any(app.planned_units > 0 for app in data_apps_in_fleet)

    @staticmethod
    def recompute_nodes_conf(logger: Logger, app_id: str, nodes: List[Node]) -> Dict[str, Node]:
        """Recompute the configuration of all the nodes (cluster set to auto-generate roles)."""
        if not nodes:
            return {}
        logger.debug(f"Roles before re-balancing {({node.name: node.roles for node in nodes})=}")
        nodes_by_name = {}
        current_cluster_nodes = []
        for node in nodes:
            if node.app.id == app_id:
                current_cluster_nodes.append(node)
            else:
                # Leave node unchanged
                nodes_by_name[node.name] = node
        for node in current_cluster_nodes:
            nodes_by_name[node.name] = Node(
                name=node.name,
                # we do this in order to remove any non-default role / add any missing default role
                roles=ClusterTopology.generated_roles(),
                ip=node.ip,
                app=node.app,
                unit_number=node.unit_number,
                temperature=node.temperature,
            )
        logger.debug(
            f"Roles after re-balancing {({name: node.roles for name, node in nodes_by_name.items()})=}"
        )
        return nodes_by_name
