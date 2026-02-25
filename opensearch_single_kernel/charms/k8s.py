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
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.status import Status
from opensearch_single_kernel.workload.base import BaseWorkload
from opensearch_single_kernel.workload.k8s import K8sWorkload

logger = logging.getLogger(__name__)


class OpenSearchK8sCharm(OpenSearchBaseCharm):
    """OpenSearch Kubernetes Charm"""

    def __init__(self, *args):
        """Initialize the OpenSearch Kubernetes Charm.

        This calls the __init__ of the class that comes after OpenSearchBaseCharm in the MRO,
        which is ops.CharmBase. This skips OpenSearchBaseCharm.__init__().
        We need self.unit initialized first (from ops.CharmBase.__init__())
        Then, we need to create the workload with the container before initializing managers.
        This ensures the container is available before creating
        the workload and initializing manager.

        Args:
            *args: variable length argument list passed to ops.CharmBase.__init__().

        """
        super(OpenSearchBaseCharm, self).__init__(*args)

        self.status = Status(self)
        self.state = ClusterState(self, self.substrate)

        # Get container may return None if not ready yet
        try:
            container = self.unit.get_container(CONTAINER_NAME)
        except ModelError:
            container = None

        # Workload can be created even if container is None
        # it will check readiness when needed
        if container is None:

            def get_container():
                try:
                    return self.unit.get_container(CONTAINER_NAME)
                except ModelError:
                    return None

            self._workload = K8sWorkload(container_getter=get_container)
        else:
            self._workload = K8sWorkload(container_getter=lambda: container)

        # Now, we can initialize managers
        # The managers will check workload.workload_present when they need to use it
        self._initialize_managers()

    @property
    def workload(self) -> BaseWorkload:
        """Access current workload instance.

        Returns the workload object.

        Returns:
            BaseWorkload: The K8sWorkload instance for this charm
        """
        return self._workload

    @property
    def substrate(self) -> Substrates:
        """Access current substrate type.

        Returns:
            Substrates: always Substrates.K8S for this charm
        """
        return Substrates.K8S
