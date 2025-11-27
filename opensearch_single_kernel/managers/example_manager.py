#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Example Manager."""

from opensearch_single_kernel.utils.logging import WithLogging
from opensearch_single_kernel.core.state import GlobalState


class ExampleManager(WithLogging):
    """Example Manager."""

    def __init__(self, state: GlobalState):
        self.name = "example_manager"
        self.state = state

    def print_hello_world(self):
        """
        Print Hello World
        """
        self.logger.debug("Hello World ! ")
        return "Hello World !"
