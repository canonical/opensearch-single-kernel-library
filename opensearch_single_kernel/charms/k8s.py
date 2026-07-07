#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Kubernetes Charm."""

import logging

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

    @property
    def workload(self) -> BaseWorkload:
        """Access current workload instance.

        Returns the workload object.

        Returns:
            BaseWorkload: The K8sWorkload instance for this charm
        """
        return K8sWorkload(
            charm_root=self.charm_dir, container=self.unit.get_container(CONTAINER_NAME)
        )

    @property
    def substrate(self) -> Substrates:
        """Access current substrate type.

        Returns:
            Substrates: always Substrates.K8S for this charm
        """
        return Substrates.K8S
