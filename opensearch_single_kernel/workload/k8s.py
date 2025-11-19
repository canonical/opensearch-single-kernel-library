#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes Workload."""


from opensearch_single_kernel.workload.base import BaseWorkload


class K8sWorkload(BaseWorkload):
    """Kubernetes OpenSearch Workload."""

    def __init__(self):
        super().__init__()
