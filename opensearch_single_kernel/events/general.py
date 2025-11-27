#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for General OpenSearch charm events."""

from typing import TYPE_CHECKING
from ops import Object
from ops.charm import ConfigChangedEvent
from ops.model import ActiveStatus
from opensearch_single_kernel.utils.logging import WithLogging
from opensearch_single_kernel.core.state import GlobalState


if TYPE_CHECKING:
    from base_charm import OpenSearchBaseCharm


class GeneralEventsHandler(Object, WithLogging):
    """Class implementing OpenSearch Charm events handling."""

    def __init__(self, charm: "OpenSearchBaseCharm", state: GlobalState):
        super().__init__(charm, key="general")
        self.charm = charm

        self.framework.observe(self.charm.on.config_changed, self._on_config_changed)

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Event handler for configuration changed events."""
        if not self.charm.unit.is_leader():
            return

        message = self.charm.example_manager.print_hello_world()
        self.charm.unit.status = ActiveStatus(message)
