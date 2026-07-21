#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch COS manager."""

import logging

from data_platform_helpers.advanced_statuses import StatusObject

from opensearch_single_kernel.common.constants import Scope, Substrates
from opensearch_single_kernel.common.statuses import CosStatuses, GeneralStatuses
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ClusterManager(BaseManager):
    """OpenSearch COS Manager."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "cos_manager")

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Compute the cos manager's statuses."""
        status_list: list[StatusObject] = []

        if self.state.substrate == Substrates.VM and (
            self.state.loki_relation
            or self.state.grafana_relation
            or self.state.prometheus_relation
        ):
            status_list.append(CosStatuses.COS_RELATION_IN_VM.value)
        elif self.state.substrate == Substrates.K8S and self.state.cos_agent_relation:
            status_list.append(CosStatuses.COS_RELATION_IN_K8s.value)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
