# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""

import logging

from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class KeystoreManager(BaseManager):
    """Manages keystore."""

    KEYSTORE = "opensearch.keystore"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        """Creates the keystore manager class."""
        super().__init__(state, workload)
        self.name = "keystore_manager"

    def _create_if_needed(self) -> None:
        """Creates the keystore if not already present."""
        if self.workload.paths.opensearch_keystore.exists():
            return

        self.workload.run_cmd(self.KEYSTORE, "create")

    def put_entries(self, entries: dict[str, str]) -> None:
        """Add new key/val entries on the keystore."""
        for key, val in entries.items():
            # adding the '--force' flag will create the keystore if not present
            self.workload.run_cmd(self.KEYSTORE, f"add {key} --force", stdin=val)

    def put_file_entry(self, key: str, filename: str) -> None:
        """Add a new file entry in the keystore."""
        self.workload.run_cmd(self.KEYSTORE, f"add-file {key} {filename} --force")

    def remove_entries(self, keys: list[str]) -> None:
        """Remove entries from the keystore."""
        self._create_if_needed()

        for key in keys:
            if key == "keystore.seed":
                continue

            try:
                self.workload.run_cmd(self.KEYSTORE, f"remove {key}")
            except OpenSearchCmdError as e:
                err_text = e.err or ""
                if "does not exist in the keystore" in err_text:
                    continue
                raise

    def list_keys(self) -> list[str]:
        """List all keys in the keystore."""
        self._create_if_needed()
        return self.workload.run_cmd(self.KEYSTORE, "list").splitlines()

    def reload(self) -> bool:
        """Reload the keystore."""
        self._create_if_needed()
        self.workload.run_cmd(self.KEYSTORE, "upgrade")

        if not self.workload.is_service_started():
            # service not running, settings will be picked up at startup
            logger.debug("Opensearch not running. Keystore settings will be loaded at start time.")
            return True

        try:
            response = self.opensearch_client.request("POST", "_nodes/reload_secure_settings")
        except OpenSearchHttpError as e:
            logger.error("Could not reload secure settings: %s", e)
            return False

        success = response.get("_nodes", {}).get("failed", -1) == 0
        logger.debug("keystore reloaded: %s", success)
        return success
