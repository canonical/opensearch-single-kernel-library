# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""

import logging
from typing import TYPE_CHECKING
from ops import EventSource, Object

from opensearch_single_kernel.events.custom_events import ReloadKeystoreEvent

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class KeystoreEventsHandler(Object):
    """Keystore events."""

    reload_event = EventSource(ReloadKeystoreEvent)

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ) -> None:
        """Initialize keystore events."""
        super().__init__(charm, key="opensearch_keystore_events")
        self.charm = charm

        self.framework.observe(self.reload_event, self._on_reload)

    def _on_reload(self, event: ReloadKeystoreEvent) -> None:
        """Handle keystore reload event."""
        if not self.charm.keystore_manager.reload():
            logger.error("Keystore reload failed.")
            event.defer()
