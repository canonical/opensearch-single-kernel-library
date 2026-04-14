#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base OpenSearch manager."""

import logging
import random
from typing import Literal

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    OPENSEARCH_HTTP_PORT,
    DeploymentType,
)
from opensearch_single_kernel.core.models import App, Node, PeerClusterRelData
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class BaseManager:
    """Base OpenSearch Manager.

    Include a set of functions and properties useful to other managers.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        self.state: ClusterState = state
        self.workload = workload

    @property
    def opensearch_client(self) -> OpenSearchClient:
        """Initialize an opensearch client"""
        return OpenSearchClient(
            self.workload,
            self.state.host_ip,
            OPENSEARCH_HTTP_PORT,
            self.state.application.admin_password,
        )

    @property
    def alt_hosts(self) -> list[str] | None:
        """Return an alternative host (of another node)in case the current is offline."""
        all_units_ips = self.state.units_ips
        all_hosts = list(all_units_ips.values())

        if nodes_conf := self.state.application.nodes_config:
            all_hosts.extend([node.ip for node in nodes_conf.values()])

        if peer_cm_rel_data := self.get_rel_data_from_main_orchestrator():
            all_hosts.extend([node.ip for node in peer_cm_rel_data.cm_nodes])

        random.shuffle(all_hosts)

        if not all_hosts:
            return None

        client = self.opensearch_client

        return [
            host for host in all_hosts if host != self.state.host_ip and client.is_node_up(host)
        ]

    def get_cluster_managers_ips(self, nodes: list[Node]) -> list[str]:
        """Get the nodes of cluster manager eligible nodes."""
        result = []
        for node in nodes:
            if node.is_cm_eligible():
                result.append(node.ip)

        return result

    def get_cluster_managers_names(self, nodes: list[Node]) -> list[str]:
        """Get the nodes of cluster manager eligible nodes."""
        result = []
        for node in nodes:
            if node.is_cm_eligible():
                result.append(node.name)

        return result

    def _nodes(
        self,
        use_localhost: bool,
        hosts: list[str] | None = None,
    ) -> list[Node]:
        """Get the list of nodes in a cluster."""
        host: str | None = None  # defaults to current unit ip
        alt_hosts: list[str] | None = hosts
        if not use_localhost and hosts:
            host = hosts[0]
            if len(hosts) >= 2:
                alt_hosts = hosts[1:]

        nodes: list[Node] = []
        if use_localhost or host:
            response = self.opensearch_client.get_nodes(host, alt_hosts)
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

    def get_rel_data_from_main_orchestrator(
        self, peek_secrets: bool = False
    ) -> PeerClusterRelData | None:
        """Get the data from the main orchestrator relation.

        Returns:
            data: peer cluster rel data if any.

        """
        if not self.is_peer_cluster_consumer(of="main"):
            return None

        if (
            not (orchestrators := self.state.application.orchestrators)
            or not orchestrators.main_rel_id
        ):
            logger.info("no orchestrators found")
            return None

        if not self.state.peer_cluster_relation_exists(orchestrators.main_rel_id):
            logger.info(
                "relation with id %s not found for main orchestrator", orchestrators.main_rel_id
            )
            return None

        if not (
            related_peer_cluster := self.state.related_peer_cluster_by_relation_id(
                is_provider=True, relation_id=orchestrators.main_rel_id
            )
        ):
            logger.info(
                "related peer cluster not found for relation id %s of main orchestrator",
                orchestrators.main_rel_id,
            )
            return None

        data = related_peer_cluster.get_data(peek_secrets=peek_secrets)
        return data

    def is_peer_cluster_provider(self, typ: Literal["main", "failover"] | None = None) -> bool:
        """Return whether the current app is a related to provider / orchestrator."""
        if not (deployment_desc := self.state.application.deployment_desc):
            return False

        if deployment_desc.typ == DeploymentType.OTHER:
            return False

        # the current app is not related as an orchestrator to any app
        if not self.state.peer_cluster_orchestrator_relations:
            return False

        # check if the current app is elected orchestrator
        if not (orchestrators := self.state.application.orchestrators):
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
        if not (deployment_desc := self.state.application.deployment_desc):
            return False

        # the current app is not related to any orchestrator app
        if not self.state.peer_cluster_relations:
            return False

        # check if the current app is elected orchestrator
        if not (orchestrators := self.state.application.orchestrators):
            # not populated yet
            return False

        if orchestrators.main_app and orchestrators.main_app.id == deployment_desc.app.id:
            # there is a wrong relation happening - where current is the main orchestrator
            # yet related to another "orchestrator"
            return False

        of_main = (
            orchestrators.main_app
            and self.state.related_peer_cluster_by_relation_id(
                relation_id=orchestrators.main_rel_id, is_provider=True
            )
            is not None
        )
        of_failover = (
            orchestrators.failover_app
            and self.state.related_peer_cluster_by_relation_id(
                is_provider=True, relation_id=orchestrators.failover_rel_id
            )
            is not None
        )
        if of == "main":
            return of_main
        elif of == "failover":
            return of_failover
        else:
            return of_main or of_failover
