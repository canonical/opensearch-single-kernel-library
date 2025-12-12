#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch TLS manager."""

from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.logging import WithLogging


class TlsManager(WithLogging):
    """OpenSearch TLS Manager."""

    def __init__(self, state: ClusterState):
        self.name = "tls_manager"
        self.state = state

    def is_fully_configured(self) -> bool:
        """Check if all TLS secrets and resources exist and are stored."""
        # TODO: Will be updated once we start working on TLS
        return True

    def get_tls_status(self) -> bool:
        """Get TLS Status."""
        pass
