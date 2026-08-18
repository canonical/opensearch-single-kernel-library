#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base OpenSearch manager."""

import logging
import random

import ops
from data_platform_helpers.advanced_statuses import ManagerStatusProtocol, StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import OPENSEARCH_HTTP_PORT, Substrates
from opensearch_single_kernel.common.k8s import K8sClient
from opensearch_single_kernel.common.statuses import GeneralStatuses
from opensearch_single_kernel.core.plain_base import (
    App,
    Node,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.status import running_statuses
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

    def _admin_tls_secret_with_v0_fallback(self, field: str, v0_key: str) -> str:
        """Resolve an app-level admin TLS secret, with a v0-secret fallback during upgrade.

        The v1 app-admin TLS secret is migrated only by the leader
        (`_migrate_v0_secrets`), which sometimes upgrades LAST. During a rolling v0->v1 upgrade a
        non-leader unit restarts first and reads the v1 field empty; it would then write
        opensearch.yml without a truststore password and fail to
        open the existing v0-created stores, blocking its OpenSearch start and wedging the
        whole upgrade. When the v1 field is empty, read the still-present v0
        `<app>:app:app-admin` secret locally. This is read-only.
        """
        if value := getattr(self.state.application, field):
            return value
        try:
            label = f"{self.state.model.app.name}:app:app-admin"
            secret = self.state.model.get_secret(label=label)
            return secret.get_content().get(v0_key) or ""
        except ops.SecretNotFoundError:
            return ""

    @property
    def admin_truststore_password(self) -> str:
        """App-level admin truststore password (with v0-secret fallback during upgrade)."""
        return self._admin_tls_secret_with_v0_fallback(
            "admin_truststore_password", "truststore-password"
        )

    @property
    def admin_keystore_password(self) -> str:
        """App-level admin keystore password (with v0-secret fallback during upgrade)."""
        return self._admin_tls_secret_with_v0_fallback(
            "admin_keystore_password", "keystore-password"
        )

    @property
    def opensearch_client(self) -> OpenSearchClient:
        """Initialize an opensearch client"""
        return OpenSearchClient(
            self.workload,
            self.state.node_host,
            OPENSEARCH_HTTP_PORT,
            (self.state.application.admin_password or "").strip() or None,
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

        if peer_cm_rel_data := self.state.main_orchestrator_app:
            all_hosts.update([node.ip for node in peer_cm_rel_data.nodes_config.values()])

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
                    node = Node(
                        name=obj["name"],
                        roles=obj["roles"],
                        ip=obj["ip"] if self.state.substrate == Substrates.VM else obj["host"],
                        app=App(id=obj["attributes"]["app_id"]),
                        unit_number=int(obj["name"].split(".")[0].split("-")[-1]),
                        temperature=obj.get("attributes", {}).get("temp"),
                    )
                    nodes.append(node)
        return nodes

    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Return this manager's statuses.

        Non-running statuses should come from state (read-only). Merge cached
        running statuses and apply-path failures via
        :func:`~opensearch_single_kernel.utils.status.running_statuses` and
        :func:`~opensearch_single_kernel.utils.status.cached_non_running_statuses`.
        Don't write to OpenSearch/relations/databags here.

        ``recompute=False`` returns the full cache. ``recompute=True`` clears the
        component cache first — recompute non-running statuses, keep running ones,
        else return ``ACTIVE_IDLE``.
        """
        if not recompute:
            return self.state.statuses.get(scope, self.name).root or [
                GeneralStatuses.ACTIVE_IDLE.value
            ]

        status_list = running_statuses(self.state.statuses, scope, self.name)
        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
