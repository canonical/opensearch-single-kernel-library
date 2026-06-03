# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""

import logging

from tenacity import retry, stop_after_attempt, wait_fixed

from opensearch_single_kernel.common.constants import ObjectStorageType
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
)
from opensearch_single_kernel.core.models import (
    AzureRelDataCredentials,
    GcsRelDataCredentials,
    ObjectStorageCredentials,
    S3RelDataCredentials,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class KeystoreManager(BaseManager):
    """Manages keystore."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        """Creates the keystore manager class."""
        super().__init__(state, workload, "keystore_manager")

    @property
    def keystore(self) -> str:
        """Return the path to the keystore."""
        return self.workload.opensearch_keystore_binary

    def _create_if_needed(self) -> None:
        """Creates the keystore if not already present."""
        if self.workload.paths.opensearch_keystore.exists():
            return

        self.workload.run_cmd(self.keystore, "create")

    def put_object_storage_credentials(
        self,
        object_storage_type: ObjectStorageType,
        object_storage_credentials: ObjectStorageCredentials,
        gcs_file_path: str | None = None,
    ) -> None:
        """Put S3 credentials in the keystore."""
        if object_storage_type == ObjectStorageType.S3 and isinstance(
            object_storage_credentials, S3RelDataCredentials
        ):
            self.put_entries(
                {
                    "s3.client.default.access_key": object_storage_credentials.access_key,
                    "s3.client.default.secret_key": object_storage_credentials.secret_key,
                }
            )
        elif object_storage_type == ObjectStorageType.AZURE and isinstance(
            object_storage_credentials, AzureRelDataCredentials
        ):
            self.put_entries(
                {
                    "azure.client.default.account": object_storage_credentials.storage_account,
                    "azure.client.default.key": object_storage_credentials.secret_key,
                }
            )
        elif object_storage_type == ObjectStorageType.GCS and isinstance(
            object_storage_credentials, GcsRelDataCredentials
        ):
            if gcs_file_path is None:
                raise ValueError(
                    "GCS credentials file path must be provided for GCS object storage."
                )
            self.put_file_entry(key="gcs.client.default.credentials_file", filename=gcs_file_path)
        else:
            raise ValueError(f"Unknown object storage type: {object_storage_type}")

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def cleanup_storage_credentials(self, object_storage_type) -> None:
        """Remove keystore entries for the given object storage type with retries.

        Args:
            object_storage_type: Object storage type to use
            keystore_entries: Keystore entries to remove

        Retries on OpenSearchCmdError unless the error indicates the entries
        do not exist.
        """
        keystore_entries = []
        if object_storage_type == ObjectStorageType.S3:
            keystore_entries = ["s3.client.default.access_key", "s3.client.default.secret_key"]
        elif object_storage_type == ObjectStorageType.AZURE:
            keystore_entries = ["azure.client.default.account", "azure.client.default.key"]
        else:
            keystore_entries = ["gcs.client.default.credentials_file"]

        if not keystore_entries:
            logger.warning(
                "No keystore entries defined for object storage type %s. Skipping cleanup.",
                object_storage_type,
            )
            return None
        try:
            self.remove_entries(keystore_entries)
            logger.info("Removed keystore entries for %s", object_storage_type)
        except OpenSearchCmdError as e:
            parts = [
                getattr(e, "stdout", "") or "",
                getattr(e, "stderr", "") or "",
                str(e) or "",
            ]
            msg = " ".join(parts).lower()
            if "does not exist" in msg and "keystore" in msg:
                # treat as successful cleanup
                logger.info(
                    "Keystore entries already absent for %s (message: %s).",
                    object_storage_type,
                    msg,
                )
                return None

            logger.warning(
                "Keystore cleanup attempt failed for %s: %s",
                object_storage_type,
                msg or repr(e),
            )
            raise

    def put_entries(self, entries: dict[str, str]) -> None:
        """Add new key/val entries on the keystore."""
        for key, val in entries.items():
            # adding the '--force' flag will create the keystore if not present
            self.workload.run_cmd(self.keystore, f"add {key} --force", stdin=val)

    def put_file_entry(self, key: str, filename: str) -> None:
        """Add a new file entry in the keystore."""
        self.workload.run_cmd(self.keystore, f"add-file {key} {filename} --force")

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
                self.workload.run_cmd(self.keystore, f"remove {key}")
            except OpenSearchCmdError as e:
                err_text = e.err or ""
                if "does not exist in the keystore" in err_text:
                    continue
                raise

    def reload(self) -> bool:
        """Reload the keystore.

        Returns:
            whether a reload was successful.
        """
        try:
            self._create_if_needed()
            self.workload.run_cmd(self.keystore, "upgrade")
        except OpenSearchCmdError as e:
            logger.error("Keystore operation failed: %s", e)
            return False

        if not self.workload.is_service_started():
            # service not running, settings will be picked up at startup
            logger.debug("Opensearch not running. Keystore settings will be loaded at start time.")
            return True

        if not self.opensearch_client.reload_secure_settings():
            return False

        logger.debug("Keystore reload successful")
        return True
