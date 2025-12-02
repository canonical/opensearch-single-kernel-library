#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base OpenSearch Charm, this will include base structure for both machine and k8s charms."""


from abc import ABC, abstractmethod

import ops

from opensearch_single_kernel.common.literals import Substrates
from opensearch_single_kernel.core.state import GlobalState
from opensearch_single_kernel.events.opensearch import OpenSearchEventsHandler
from opensearch_single_kernel.managers.example_manager import ExampleManager
from opensearch_single_kernel.utils.helpers import Status
from opensearch_single_kernel.utils.logging import WithLogging
from opensearch_single_kernel.workload import BaseWorkload


class OpenSearchBaseCharm(ops.CharmBase, ABC, WithLogging):
    """Base OpenSearch Charm"""

    def __init__(self, *args):
        super().__init__(*args)

        # Status
        self.status = Status(self)

        # Context
        self.state = GlobalState(self)

        # Managers
        self.example_manager = ExampleManager(self.state)

        # Event Handlers
        self.opensearch_events = OpenSearchEventsHandler(self, self.state)

    @property
    @abstractmethod
    def workload(self) -> BaseWorkload:
        """Access current workload."""
        pass

    @property
    @abstractmethod
    def substrate(self) -> Substrates:
        """Access current substrate."""
        pass
