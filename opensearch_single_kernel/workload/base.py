#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base interface for workload operations across different substrates."""

from abc import ABC, abstractmethod

from opensearch_single_kernel.utils.logging import WithLogging


class BaseWorkload(ABC, WithLogging):
    """Base interface for common workload operations."""

    @abstractmethod
    def install(self) -> None:
        """Install the workload."""
        pass
