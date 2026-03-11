# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""

import logging

from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
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

    def put_notifications_plugin_smtp_credentials(
        self, account_id: str, user: str | None, password: str | None
    ) -> dict[str, str]:
        """Build a smtp credential entries and put them in the keystore.

        Returns:
            built smtp credentials entries.
        """
        entries = {
            f"opensearch.notifications.core.email.{account_id}.username": user or "",
            f"opensearch.notifications.core.email.{account_id}.password": password or "",
        }
        self.put_entries(entries)
        return entries

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
        """Reload the keystore.

        Returns:
            whether a reload was successful.
        """
        self._create_if_needed()
        self.workload.run_cmd(self.KEYSTORE, "upgrade")

        if not self.workload.is_service_started():
            # service not running, settings will be picked up at startup
            logger.debug("Opensearch not running. Keystore settings will be loaded at start time.")
            return True

        if not self.opensearch_client.reload_secure_settings():
            return False

        logger.debug("Keystore reload successful")
        return True
