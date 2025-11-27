#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base OpenSearch Charm, this will include base structure for both machine and k8s charms."""

import logging
import ops
from opensearch_single_kernel.core.state import GlobalState
from opensearch_single_kernel.events.general import GeneralEventsHandler
from opensearch_single_kernel.managers.example_manager import ExampleManager


logger = logging.getLogger(__name__)


class OpenSearchBaseCharm(ops.CharmBase):
    """Base OpenSearch Charm"""

    def __init__(self, *args):
        super().__init__(*args)

        # Context
        self.state = GlobalState(self)

        # Managers
        self.example_manager = ExampleManager(self.state)

        # Event Handlers
        self.general_events = GeneralEventsHandler(self, self.state)
