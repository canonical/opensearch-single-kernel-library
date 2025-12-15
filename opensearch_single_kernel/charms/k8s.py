#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Kubernetes Charm."""

from opensearch_single_kernel.charms.base import OpenSearchBaseCharm
from opensearch_single_kernel.common.constants import Substrates
from opensearch_single_kernel.workload.base import BaseWorkload
from opensearch_single_kernel.workload.k8s import K8sWorkload


class OpenSearchK8sCharm(OpenSearchBaseCharm):
    """OpenSearch Machine Charm"""

    def __init__(self, *args):
        super().__init__(*args)

    @property
    def workload(self) -> BaseWorkload:
        """Access current workload."""
        return K8sWorkload()

    @property
    def substrate(self) -> Substrates:
        """Access current substrate."""
        return Substrates.K8S
