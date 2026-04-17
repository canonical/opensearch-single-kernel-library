#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Machine Charm."""

from opensearch_single_kernel.charms.base import OpenSearchBaseCharm
from opensearch_single_kernel.common.constants import Substrates
from opensearch_single_kernel.workload.base import BaseWorkload
from opensearch_single_kernel.workload.vm import VMWorkload


class OpenSearchVMCharm(OpenSearchBaseCharm):
    """OpenSearch Machine Charm"""

    def __init__(self, *args):
        super().__init__(*args)

    @property
    def workload(self) -> BaseWorkload:
        """Access current workload."""
        return VMWorkload()

    @property
    def substrate(self) -> Substrates:
        """Access current substrate."""
        return Substrates.VM
