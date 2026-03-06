#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Kubernetes Charm."""

import logging

from ops.model import ModelError

from opensearch_single_kernel.charms.base import OpenSearchBaseCharm
from opensearch_single_kernel.common.constants import (
    CONTAINER_NAME,
    Substrates,
)
from opensearch_single_kernel.workload.base import BaseWorkload
from opensearch_single_kernel.workload.k8s import K8sWorkload

logger = logging.getLogger(__name__)


class OpenSearchK8sCharm(OpenSearchBaseCharm):
    """OpenSearch Kubernetes Charm"""

    def __init__(self, *args):
        """Initialize the OpenSearch Kubernetes Charm."""
        super().__init__(*args)

    def _get_container(self):
        """Return the workload container if available, else None."""
        try:
            return self.unit.get_container(CONTAINER_NAME)
        except ModelError:
            return None

    @property
    def workload(self) -> BaseWorkload:
        """Access current workload instance.

        Returns the workload object.

        Returns:
            BaseWorkload: The K8sWorkload instance for this charm
        """
        if not hasattr(self, "_workload") or self._workload is None:
            # Workload can be created even if the container isn't ready yet.
            # Managers will check workload.workload_present when they actually need to use it.
            self._workload = K8sWorkload(container_getter=self._get_container)
        return self._workload

    @property
    def substrate(self) -> Substrates:
        """Access current substrate type.

        Returns:
            Substrates: always Substrates.K8S for this charm
        """
        return Substrates.K8S
