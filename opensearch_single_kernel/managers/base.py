#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base OpenSearch manager."""

import logging
import random

from data_platform_helpers.advanced_statuses import ManagerStatusProtocol, StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import OPENSEARCH_HTTP_PORT, Substrates
from opensearch_single_kernel.common.k8s import K8sClient
from opensearch_single_kernel.common.statuses import GeneralStatuses
from opensearch_single_kernel.core.models import App, Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class BaseManager(ManagerStatusProtocol):
    """Base OpenSearch Manager.

    Include a set of functions and properties useful to other managers.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload, name: str):
        self.state: ClusterState = state  # type: ignore[override]
        self.workload = workload
        self.name = name

    @property
    def opensearch_client(self) -> OpenSearchClient:
        """Initialize an opensearch client"""
        return OpenSearchClient(
            self.workload,
            self.state.node_host,
            OPENSEARCH_HTTP_PORT,
            self.state.application.admin_password,
        )

    @property
    def k8s_client(self) -> K8sClient:
        """Initialize a k8s client."""
        if self.state.substrate != Substrates.K8S:
            raise NotImplementedError("K8s client is only available on K8s substrate.")
        return K8sClient(self.state.pod_name, self.state.namespace)

    @property
    def alt_hosts(self) -> list[str] | None:
        """Return an alternative host (of another node)in case the current is offline."""
        all_hosts = self.state.peer_unit_hosts

        if nodes_conf := self.state.application.nodes_config:
            all_hosts.update([node.ip for node in nodes_conf.values()])

        if peer_cm_rel_data := self.state.get_rel_data_from_main_orchestrator():
            all_hosts.update([node.ip for node in peer_cm_rel_data.cm_nodes])

        if not all_hosts:
            return None

        client = self.opensearch_client

        active_hosts = [
            host for host in all_hosts if host != self.state.node_host and client.is_node_up(host)
        ]

        random.shuffle(active_hosts)

        return active_hosts

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
                    # For k8s we need to use the host instead of IP
                    host = obj["ip"] if self.state.substrate == Substrates.VM else obj["host"]
                    node = Node(
                        name=obj["name"],
                        roles=obj["roles"],
                        ip=host,
                        app=App(id=obj["attributes"]["app_id"]),
                        unit_number=int(obj["name"].split(".")[0].split("-")[-1]),
                        temperature=obj.get("attributes", {}).get("temp"),
                    )
                    nodes.append(node)
        return nodes

    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute the manager's statuses."""
        if not recompute:
            return self.state.statuses.get(scope, self.name).root or [
                GeneralStatuses.ACTIVE_IDLE.value
            ]

        return [GeneralStatuses.ACTIVE_IDLE.value]
