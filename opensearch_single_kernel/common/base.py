#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base classes for Manager."""

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import Scope
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
        return OpenSearchClient(self.workload, self.state.host, self.state.port, admin_secret)
