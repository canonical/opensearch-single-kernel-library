#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base OpenSearch manager."""
import random
from typing import List, Optional

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.core.models import Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.logging import WithLogging
from opensearch_single_kernel.workload.base import BaseWorkload


class BaseManager(WithLogging):
    """Base OpenSearch Manager.

    Include a set of functions and properties useful to other managers.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        self.state = state
        self.workload = workload

    @property
    def opensearch_client(self):
        """Initialize an opensearch client"""
        admin_field = self.state.secrets.password_key("admin")
        admin_secret = self.state.secrets.get(Scope.APP, admin_field)
        return OpenSearchClient(self.workload, self.state.host_ip, self.state.port, admin_secret)

    @property
    def alt_hosts(self) -> Optional[List[str]]:
        """Return an alternative host (of another node)in case the current is offline."""
        all_units_ips = self.state.units_ips
        all_hosts = list(all_units_ips.values())

        if nodes_conf := self.state.application.nodes_config:
            all_hosts.extend([Node.from_dict(node).ip for node in nodes_conf.values()])

        # TODO: Add getting relation data form state
        # if peer_cm_rel_data := self.state.peer_cluster_orchestrator.rel_data():
        #    all_hosts.extend([node.ip for node in peer_cm_rel_data.cm_nodes])

        random.shuffle(all_hosts)

        if not all_hosts:
            return None

        client = self.opensearch_client

        return [
            host for host in all_hosts if host != self.state.host_ip and client.is_node_up(host)
        ]
