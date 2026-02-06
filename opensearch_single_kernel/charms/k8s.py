#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Kubernetes Charm."""

import logging

from opensearch_single_kernel.charms.base import OpenSearchBaseCharm
from opensearch_single_kernel.common.constants import Substrates
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.status import Status
from opensearch_single_kernel.workload.base import BaseWorkload
from opensearch_single_kernel.workload.k8s import CONTAINER_NAME, K8sWorkload
from ops.model import ModelError

logger = logging.getLogger(__name__)


class OpenSearchK8sCharm(OpenSearchBaseCharm):
    """OpenSearch Kubernetes Charm"""

    def __init__(self, *args):
        # Initialize ops.CharmBase first to get self.unit
        super(OpenSearchBaseCharm, self).__init__(*args)

        # Initialize status and state
        # The base class does this, but we bypassed its __init__
        self.status = Status(self)
        self.state = ClusterState(self, self.substrate)

        # Get container may return None if not ready yet
        try:
            container = self.unit.get_container(CONTAINER_NAME)
        except ModelError:
            container = None

        # Create workload before managers are initialized
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

        # Now initialize managers using base class method
        # Managers will check workload.workload_present when they need to use it
        self._initialize_managers()

    @property
    def workload(self) -> BaseWorkload:
        """Access current workload instance.
        
        Returns the workload object. Container readiness should be checked via
        workload.workload_present when needed. Methods that require container
        should check workload_present and raise ContainerNotReadyError if not ready.
        
        Returns:
            BaseWorkload: The K8sWorkload instance for this charm
        """
        return self._workload

    @property
    def substrate(self) -> Substrates:
        """Access current substrate type.
        
        Returns the substrate type for this charm instance. For OpenSearchK8sCharm,
        this always returns Substrates.K8S to indicate this is a Kubernetes deployment.
        
        The substrate type is used to determine:
        - Which workload implementation to use (K8sWorkload or VMWorkload)
        - How to handle file operations (container API or filesystem)
        - Network configuration (DNS names or IP addresses)
        - TLS certificate handling (container paths or filesystem paths)
        
        Returns:
            Substrates: The substrate type (always Substrates.K8S for this charm)
        """
        return Substrates.K8S
