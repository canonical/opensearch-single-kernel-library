#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for General OpenSearch charm events."""

from typing import TYPE_CHECKING

from ops import InstallEvent, Object

from opensearch_single_kernel.common.exceptions import OpenSearchInstallError
from opensearch_single_kernel.common.literals import Substrates
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.core.state import GlobalState
from opensearch_single_kernel.utils.logging import WithLogging

if TYPE_CHECKING:
    from opensearch_single_kernel.core.base_charm import OpenSearchBaseCharm


class OpenSearchEventsHandler(Object, WithLogging):
    """Class implementing OpenSearch Charm events handling."""

    def __init__(self, charm: "OpenSearchBaseCharm", state: GlobalState):
        super().__init__(charm, key="opensearch_events")
        self.charm = charm

        # --- OpenSearch charm events ---
        self.framework.observe(self.charm.on.install, self._on_install)

    def _on_install(self, event: InstallEvent):
        """Event handler for install event."""
        if self.charm.substrate == Substrates.VM:
            self.charm.unit.status = CharmStatuses.INSTALL_IN_PROGRESS.value
        try:
            self.charm.workload.install()
            self.charm.status.clear(CharmStatuses.INSTALL_IN_PROGRESS.value)
        except OpenSearchInstallError:
            self.charm.unit.status = CharmStatuses.INSTALL_ERROR.value
