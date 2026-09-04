#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for plugins events."""

import logging
from typing import TYPE_CHECKING

from ops import (
    Object,
)

from opensearch_single_kernel.common.constants import (
    PEER_RELATION,
    Scope,
)
from opensearch_single_kernel.utils.helpers import (
    diff,
)

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class PluginEventsHandler(Object):
    """Events handler for OpenSearch plugin events"""

    def __init__(self, charm: OpenSearchBaseCharm):
        super().__init__(charm, "plugin_events")
        self.charm = charm
        self.framework.observe(
            self.charm.on[PEER_RELATION].relation_changed,
            self._on_peer_relation_changed,
        )

    def _on_peer_relation_changed(self, event):  # noqa: C901
        """Handle plugin secret-related peer relation changes."""
        # if this is a subcluster, all units must add plugin keys from secrets to their keystores
        if not self.charm.state.is_peer_cluster_consumer(of="main"):
            return
        app_plugins = self.charm.state.application.plugin_config_info
        unit_plugins = self.charm.state.server.plugin_config_info
        added, removed = diff(app_plugins.keys(), unit_plugins.keys())
        for label in added:
            plugin = app_plugins[label]
            if not plugin.secret_name:
                continue

            # start locally tracking secret and write transferred keys to keystore
            content = self.charm.plugin_manager.get_plugin_secret(label)
            keys_to_add = content.get("keys")

            self.charm.keystore_manager.put_entries(keys_to_add)
            cleanup = {"keys": list(keys_to_add.keys())}
            # store on unit for later removal (only keys needed and not values)
            self.charm.plugin_manager.put_plugin_config(
                scope=Scope.UNIT, label=label, cleanup=cleanup
            )

        for label in removed:
            # this unit should delete the keys it wrote as the app secret has been removed
            cleanup = unit_plugins[label].cleanup
            for key, items in cleanup.items():
                if key == "keys":
                    if not self.charm.keystore_manager.remove_entries(items):
                        logger.error("Failed to remove plugin keystore entries.")

        # reload keystore
        self.charm.reload_keystore_event.emit()

        for label in removed:
            self.charm.plugin_manager.remove_plugin_config(scope=Scope.UNIT, label=label)
