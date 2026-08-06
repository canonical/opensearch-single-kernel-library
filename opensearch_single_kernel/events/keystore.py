# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""

import logging
from typing import TYPE_CHECKING

from ops import Object

from opensearch_single_kernel.events.custom_events import ReloadKeystoreEvent
from opensearch_single_kernel.managers.keystore import KeystoreReloadResult

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class KeystoreEventsHandler(Object):
    """Keystore events."""

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ) -> None:
        """Initialize keystore events."""
        super().__init__(charm, key="keystore_events")
        self.charm = charm

        self.framework.observe(self.charm.reload_keystore_event, self._on_reload)

    def _on_reload(self, event: ReloadKeystoreEvent) -> None:
        """Handle keystore reload event."""
        result = self.charm.keystore_manager.reload()
        if result is KeystoreReloadResult.SUCCESS:
            return

        if result is KeystoreReloadResult.RELOAD_FAILED:
            logger.warning(
                "Keystore secure-settings reload failed; "
                "restarting OpenSearch to apply settings."
            )
            self.charm.restart_opensearch_event.emit()
            return

        logger.error("Keystore reload failed.")
        event.defer()
