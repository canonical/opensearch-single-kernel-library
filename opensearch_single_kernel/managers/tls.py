#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch TLS manager."""
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.workload.base import BaseWorkload


class TlsManager(BaseManager):
    """OpenSearch TLS Manager."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "tls_manager"

    def is_fully_configured(self) -> bool:
        """Check if all TLS secrets and resources exist and are stored."""
        # TODO: Will be updated once we start working on TLS
        return True

    def get_tls_status(self) -> bool:
        """Get TLS Status."""
        pass
