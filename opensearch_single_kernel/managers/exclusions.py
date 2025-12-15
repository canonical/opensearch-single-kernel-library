#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Nodes Exclusions manager."""


from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.workload.base import BaseWorkload


class NodesExclusionsManager(BaseManager):
    """OpenSearch Nodes Exclusions Manager."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        self.name = "exclusions_manager"
        self.state = state
        self.workload = workload

    def delete_current(
        self, voting: bool = True, allocation: bool = True, raise_error: bool = False
    ) -> None:
        """Delete voting and alloc exclusions."""
        # TODO: Refactor
