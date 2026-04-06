#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Backup manager."""
import json
import logging
from typing import Any

from charmlibs.pathops import PathProtocol
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import (
    S3_CA_ALIAS,
    STORE_PASSWORD,
    ObjectStorageType,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchBackupCredentialsIncorrectError,
    OpenSearchBackupRelationDataIncompleteError,
    OpenSearchCreateBackupError,
    OpenSearchHttpError,
    OpenSearchListBackupsError,
    OpenSearchObjectStorageConfigValidationError,
    OpenSearchRestoreBackupError,
)
from opensearch_single_kernel.core.models import (
    AzureRelData,
    GcsRelData,
    ObjectStorageConfig,
    S3RelData,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.certificates import (
    list_cas,
    normalize_certificate_chain_unordered,
    remove_ca,
    store_ca_chain,
)
from opensearch_single_kernel.utils.cloud_storage import (
    verify_azure_credentials,
    verify_gcs_credentials,
    verify_s3_credentials,
)
from opensearch_single_kernel.utils.helpers import hash_credentials
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class BackupManager(BaseManager):
    """OpenSearch Backup Manager.

    This manager will handle backup and restore operations, as well as backup
    credentials management.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "backup_manager"

    def storage_config_from_connection_info(  # noqa: C901
        self, object_storage_type: ObjectStorageType, connection_info: dict[str, str]
    ) -> ObjectStorageConfig | None:
        """Get the active object storage config from relations/peer-cluster.

        Args:
            object_storage_type (ObjectStorageType): the type of the object storage
            to get the config for.
            connection_info (dict[str, str]): the raw connection info to build the config from.

        Returns:
            ObjectStorageConfig | None: the active object storage config.
        """
        match object_storage_type:
            case ObjectStorageType.S3:
                data_model = S3RelData
            case ObjectStorageType.AZURE:
                data_model = AzureRelData
            case ObjectStorageType.GCS:
                data_model = GcsRelData
            case _:
                return
        try:
            rel_data = data_model.from_relation(connection_info) if connection_info else None
        except ValidationError as e:
            raise OpenSearchObjectStorageConfigValidationError(e) from e
        return ObjectStorageConfig(**{object_storage_type.value: rel_data}) if rel_data else None

    def validate_storage_config(
        self, config: ObjectStorageConfig, storage_type: ObjectStorageType
    ) -> None:
        """Validate the given object storage config.

        Args:
            config (ObjectStorageConfig): the object storage config to validate.

        Raises:
            OpenSearchBackupRelationDataIncompleteError: if the config is missing required
            fields.
            OpenSearchBackupCredentialsIncorrectError: if the credentials provided in the
            config are incorrect.
        """
        if (
            not config
            or (
                storage_type == ObjectStorageType.S3
                and (not config.s3 or not config.s3.credentials)
            )
            or (
                storage_type == ObjectStorageType.AZURE
                and (not config.azure or not config.azure.credentials)
            )
            or (
                storage_type == ObjectStorageType.GCS
                and (not config.gcs or not config.gcs.credentials)
            )
        ):
            raise OpenSearchBackupRelationDataIncompleteError()

        if (
            (storage_type == ObjectStorageType.AZURE and not verify_azure_credentials(config))
            or (storage_type == ObjectStorageType.S3 and not verify_s3_credentials(config))
            or (storage_type == ObjectStorageType.GCS and not verify_gcs_credentials(config))
        ):
            raise OpenSearchBackupCredentialsIncorrectError()

    def is_custom_s3_ca_stored(self, s3_ca_chain: str | None = None) -> bool:
        """Check if a custom CA for the object storage is stored in the cacerts trust store.

        Args:
            s3_ca_chain: CA chain which will be detected in the stored cacerts

        Returns:
            True if the given CA chain is stored in the stored cacerts, else False
        """
        if not (current_chain := self.get_s3_chain_from_cacerts()):
            # Nothing stored at all: definitely no custom S3 CA
            return False

        if not s3_ca_chain:
            # There is existing S3 CA stored, but no new one, we need to remove the old one.
            return True

        # Compare as unordered sets of normalized cert blocks
        stored_blocks = normalize_certificate_chain_unordered(current_chain)
        new_blocks = normalize_certificate_chain_unordered(s3_ca_chain)

        return stored_blocks == new_blocks

    def get_s3_chain_from_cacerts(self) -> str:
        """Return the currently stored S3 CA chain from cacerts, or ''.

        Returns:
            Stored CA chain if found, else ''.
        """
        stored_cacerts = list_cas(
            self.workload,
            store_pwd=STORE_PASSWORD,
            store_path=self.workload.paths.certs / "cacerts.p12",
        )

        if not stored_cacerts:
            return ""
        # list_cas consolidates per base alias, so we just look up the root alias
        chain = stored_cacerts.get(S3_CA_ALIAS, "")
        return chain or ""

    def remove_s3_ca(self) -> None:
        """Remove an S3 TLS CA chain on the cacerts trust store.

        Args:
            s3_tls_ca_chain: S3 TLS CA chain to remove
        """
        store_path = self.workload.paths.certs / "cacerts.p12"
        # Drop the CA entirely
        remove_ca(
            workload=self.workload,
            alias=S3_CA_ALIAS,
            store_pwd=STORE_PASSWORD,
            store_path=store_path,
        )

    def store_s3_ca(self, s3_tls_ca_chain: str | None) -> None:
        """Store or remove an S3 TLS CA chain on the cacerts trust store.

        Args:
            s3_tls_ca_chain: S3 TLS CA chain to store

        If there is s3_tls_ca_chain, the old CA will be removed.
        """
        store_path = self.workload.paths.certs / "cacerts.p12"

        # If we already have the same CA, skip re-import
        if self.is_custom_s3_ca_stored(s3_tls_ca_chain):
            logger.info("S3 CA unchanged; skipping re-import.")
            return

        # Chain changed: ensure we remove the old alias family first
        # to avoid keytool already exists error
        remove_ca(
            workload=self.workload,
            alias=S3_CA_ALIAS,
            store_pwd=STORE_PASSWORD,
            store_path=store_path,
        )

        # Import fresh CA
        store_ca_chain(
            workload=self.workload,
            store_pwd=STORE_PASSWORD,
            store_path=store_path,
            alias=S3_CA_ALIAS,
            ca=s3_tls_ca_chain,
            keep_previous=False,
            snap_user_with_write_permission=True,
        )

    def write_gcs_service_account_json(
        self,
        secret_key: str,
    ) -> PathProtocol:
        """Write GCS service account JSON (from relation secret_key) to a file.

        Args:
            secret_key: JSON string content of the service account.

        Returns:
            Path to the written file.

        Raises:
            ValueError: if secret_key is empty or not valid JSON.
            OSError: if writing fails.
        """
        if not secret_key:
            raise ValueError("Missing GCS secret_key (service account JSON).")

        try:
            # validate JSON and normalize formatting
            obj = json.loads(secret_key)
            content = json.dumps(obj)
        except json.JSONDecodeError as e:
            raise ValueError("GCS secret_key is not valid JSON.") from e

        self.workload.write_text(content, self.workload.paths.gcs_service_account_json)
        return self.workload.paths.gcs_service_account_json

    def remove_gcs_service_account_json(
        self,
    ) -> None:
        """Remove the GCS service account JSON file.

        Raises:
            OSError: if deletion fails for other reasons.
        """
        self.workload.unlink(self.workload.paths.gcs_service_account_json, missing_ok=True)

    def ensure_repository(
        self, storage_type: ObjectStorageType, storage_cfg: ObjectStorageConfig
    ) -> bool:
        """Create the repository if we have a storage type/config and it doesn't exist yet.

        Args:
            storage_type (ObjectStorageType): Object storage type
            storage_cfg (ObjectStorageConfig): Object storage config

        Raises:
            OpenSearchHttpError: repository does not exist
        """
        if not storage_type or not storage_cfg or storage_type == ObjectStorageType.CONFLICT:
            return False

        if storage_type not in {
            ObjectStorageType.S3,
            ObjectStorageType.AZURE,
            ObjectStorageType.GCS,
        }:
            logger.error("Repository should be created by main orchestrator.")
            return False

        logger.info("Creating/Updating snapshot repository for %s", storage_type)
        self.opensearch_client.create_repository(
            object_storage_type=storage_type,
            object_storage_config=storage_cfg,
            alt_hosts=self.alt_hosts,
        )
        logger.info("Created/Updated snapshot repository for %s", storage_type)
        return self.opensearch_client.is_repository_created(storage_type, alt_hosts=self.alt_hosts)

    def remove_repository(self, storage_type: ObjectStorageType) -> bool:
        """Remove the snapshot repository for the given storage type.

        Args:
            storage_type (ObjectStorageType): Object storage type

        Returns:
            bool: True if repository was removed or did not exist, False if removal failed.
        """
        try:
            self.opensearch_client.remove_repository(
                object_storage_type=storage_type,
                alt_hosts=self.alt_hosts,
            )
            return True
        except OpenSearchHttpError as e:
            logger.error(
                "Repository cleanup for %s failed after 3 attempts: %s",
                storage_type,
                e,
            )
            return False

    def create_snapshot(self) -> str:
        """Create a snapshot in the repository for the given storage type.

        Returns:
            str: The ID of the created snapshot.
        """
        object_storage_type = self.state.storage_type
        # Create a new snapshot
        snapshot_id = self.opensearch_client.create_snapshot(
            object_storage_type=object_storage_type,
            alt_hosts=self.alt_hosts,
        )
        return snapshot_id

    def get_snapshot_status(self, snapshot_id: str) -> str:
        """Get the status of a snapshot by its ID.

        Args:
            snapshot_id (str): The ID of the snapshot to check.

        Returns:
            str: The status of the snapshot.
        Raises:
            OpenSearchCreateBackupError: If the snapshot status cannot be determined.
        """
        object_storage_type = self.state.storage_type
        # Fetch the new snapshot for sanity check
        snapshot = self.opensearch_client.get_snapshot(
            object_storage_type=object_storage_type,
            snapshot_id=snapshot_id,
            alt_hosts=self.alt_hosts,
        )
        status = str(snapshot.get("state", "unknown")).lower()
        return status

    def list_snapshots(self) -> dict[Any, dict[str, Any]]:
        """List snapshots in the repository for the given storage type.

        Args:
            output_format (str): The format to return the snapshot list in supported formats.

        Returns:
            dict: A dictionary of snapshots with their details.

        Raises:
            OpenSearchListBackupsError: If the snapshot listing fails.
        """
        object_storage_type = self.state.storage_type
        return self.opensearch_client.list_snapshots(
            object_storage_type=object_storage_type, alt_hosts=self.alt_hosts
        )

    def restore_snapshot(self, snapshot_id: str) -> None:
        """Restore a snapshot from the repository for the given storage type.

        This method will first get the snapshot details using the snapshot_id,
        then it will attempt to close any indices that are still open from the snapshot,
        and finally it will start the restore process.
        After running this method, the caller should monitor the cluster health

        Args:
            snapshot_id (str): The ID of the snapshot to restore.

        Raises:
            OpenSearchRestoreBackupError: If the restore operation fails.

        """
        object_storage_type = self.state.storage_type
        # Fetch the snapshot with the corresponding ID
        try:
            if not (
                snapshot := self.opensearch_client.get_snapshot(
                    object_storage_type, snapshot_id, alt_hosts=self.alt_hosts
                )
            ):
                logger.error("Backup %s not found", snapshot_id)
                raise OpenSearchRestoreBackupError("Backup %s not found." % snapshot_id)
        except OpenSearchHttpError as e:
            logger.error("Backup %s could not be fetched. Error: \n%s", snapshot_id, e)
            raise OpenSearchRestoreBackupError(
                "Backup %s could not be fetched. Error: %s." % (snapshot_id, str(e))
            )

        # close indices that were snapshotted if they still exist, so they can be restored
        self.close_snapshot_indices(snapshot_id)
        # start the restore
        logger.info("Starting restore of snapshot %s.", snapshot_id)
        try:
            non_restored_indices = self.opensearch_client.restore_snapshot(
                object_storage_type=object_storage_type,
                snapshot=snapshot,
                alt_hosts=self.alt_hosts,
            )
            if not non_restored_indices:
                return

            logger.error(
                "Failed to restore the following indices in snapshot %s: %s.",
                snapshot_id,
                non_restored_indices,
            )
            raise OpenSearchRestoreBackupError(
                f"Failed to restore {len(non_restored_indices)} indices. Check logs for details."
            )
        except OpenSearchHttpError as e:
            logger.error("Failed to restore snapshot %s. Error: %s.", snapshot_id, str(e))
            raise OpenSearchRestoreBackupError(
                f"Failed to restore snapshot {snapshot_id}. Error: {str(e)}."
            )

    def close_snapshot_indices(self, snapshot: str) -> None:
        """Close the given indices.

        Args:
            snapshot (str): The snapshot containing the indices to close.

        Raises:
            OpenSearchRestoreBackupError: If closing the indices fails.
        """
        try:
            closed_indices, indices_failed_to_close = (
                self.opensearch_client.close_snapshot_indices_open_in_cluster(
                    snapshot, alt_hosts=self.alt_hosts
                )
            )
            if indices_failed_to_close:
                raise OpenSearchRestoreBackupError(
                    "Failed to close %d open indices. Check logs for details."
                    % len(indices_failed_to_close)
                )
        except OpenSearchHttpError as e:
            raise OpenSearchRestoreBackupError("Failed to close open indices. Error: %s." % str(e))

    def verify_stored_credentials(
        self, object_storage_type: ObjectStorageType, object_storage_config: ObjectStorageConfig
    ) -> None:
        """Verify that the stored credentials are valid."""
        credential_dict = {}
        if object_storage_config.s3:
            credential_dict = {
                "access_key": object_storage_config.s3.credentials.access_key,
                "secret_key": object_storage_config.s3.credentials.secret_key,
                "s3_tls_ca_chain": object_storage_config.s3.tls_ca_chain,
            }
        elif object_storage_config.azure:
            credential_dict = {
                "storage_account": object_storage_config.azure.credentials.storage_account,
                "secret_key": object_storage_config.azure.credentials.secret_key,
            }
        elif object_storage_config.gcs:
            credential_dict = {
                "secret_key": object_storage_config.gcs.credentials.secret_key,
            }

        credentials_hash = hash_credentials(credential_dict)
        logger.info(
            "Verifying credentials for %s with hash %s", object_storage_type, credentials_hash
        )

        # TODO: Handle large deployments
        # check all other clusters if they have saved the credentials

        # all units have saved the latest credentials
        logger.info("All peer-cluster units have saved the latest backup credentials.")
        self.opensearch_client.verify_repository(object_storage_type, alt_hosts=self.alt_hosts)

    @property
    def is_operation_in_progress(self) -> bool:
        """Check if a backup or restore operation is currently in progress.

        Returns:
            bool: True if an operation is in progress, False otherwise.
        """
        return self.opensearch_client.is_snapshot_in_progress(
            self.alt_hosts
        ) or self.opensearch_client.is_restore_in_progress(self.alt_hosts)
