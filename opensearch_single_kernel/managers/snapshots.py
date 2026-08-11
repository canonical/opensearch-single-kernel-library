#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Snapshots manager."""

import json
import logging
from typing import Any

from charmlibs.pathops import PathProtocol
from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.constants import (
    AZURE_RELATION,
    GCS_RELATION,
    S3_CA_ALIAS,
    S3_RELATION,
    STORE_PASSWORD,
    ObjectStorageType,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchBackupCredentialsIncorrectError,
    OpenSearchBackupRelationDataIncompleteError,
    OpenSearchHttpError,
    OpenSearchInvalidStorageTypeError,
    OpenSearchObjectStorageConfigValidationError,
    OpenSearchPeerClusterDidntSaveCredentialsYetError,
    OpenSearchRestoreBackupError,
    OpenSearchSnapshotsPeerClusterDataConflictError,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    PeerClusterStatuses,
    SnapshotsStatuses,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.core.storage import (
    AzureRelData,
    GcsRelData,
    ObjectStorageConfig,
    S3RelData,
)
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.certificates import (
    list_cas,
    normalize_certificate_chain_unordered,
    remove_ca,
    store_ca_chain,
)
from opensearch_single_kernel.utils.helpers import hash_credentials
from opensearch_single_kernel.utils.object_storage import (
    storage_config_from_connection_info,
    verify_azure_credentials,
    verify_gcs_credentials,
    verify_s3_credentials,
)
from opensearch_single_kernel.utils.status import format_status
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class SnapshotsManager(BaseManager):
    """OpenSearch Snapshots Manager.

    This manager will handle backup and restore operations, as well as backup
    credentials management.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "snapshots_manager")

    def read_snapshots_data_from_peer_cluster(
        self,
    ) -> tuple[S3RelData | AzureRelData | GcsRelData | None, list[ObjectStorageType]]:
        """Read snapshots configuration data from peer cluster relation.

        Raises:
            OpenSearchSnapshotsPeerClusterDataConflictError: if there is conflicting
              data for multiple storage backends.

        Returns:
            Tuple of (snapshots config dict if found, list of object storage types to clean).
        """
        # Read peer data
        s3_info = self.storage_relation_data_from_peer_cluster(
            object_storage_type=ObjectStorageType.S3
        )
        azure_info = self.storage_relation_data_from_peer_cluster(
            object_storage_type=ObjectStorageType.AZURE
        )
        gcs_info = self.storage_relation_data_from_peer_cluster(
            object_storage_type=ObjectStorageType.GCS
        )
        backends_enabled = [
            bool(s3_info),
            bool(azure_info),
            bool(gcs_info),
        ]
        # check conflict
        if sum(backends_enabled) >= 2:
            logger.error(
                "Received conflicting snapshot credentials over peer-clusters "
                "(S3=%s, Azure=%s, GCS=%s). "
                "Only one backend may be configured; not applying any object-storage config.",
                bool(s3_info),
                bool(azure_info),
                bool(gcs_info),
            )
            raise OpenSearchSnapshotsPeerClusterDataConflictError(
                "Conflicting snapshot credentials received over peer-clusters."
                "Only one backend may be configured."
            )
        if s3_info:
            info_to_save = s3_info
            object_storage_types_to_clean = [ObjectStorageType.AZURE, ObjectStorageType.GCS]
        elif azure_info:
            info_to_save = azure_info
            object_storage_types_to_clean = [ObjectStorageType.S3, ObjectStorageType.GCS]
        elif gcs_info:
            info_to_save = gcs_info
            object_storage_types_to_clean = [ObjectStorageType.S3, ObjectStorageType.AZURE]
        else:
            info_to_save = None
            object_storage_types_to_clean = []

        return info_to_save, object_storage_types_to_clean

    def set_credentials_saved(
        self, credentials: S3RelData | AzureRelData | GcsRelData | None
    ) -> None:
        """Set in the peer relation data that credentials have been saved."""
        orchestrators = self.state.application.orchestrators

        if not orchestrators or orchestrators.main_app is None:
            return

        # set the credentials_saved in the unit data bag with the main orchestrator
        peer_cluster_server = self.state.local_peer_cluster_server_by_relation_id(
            is_provider=True, relation_id=orchestrators.main_rel_id
        )

        if not peer_cluster_server:
            logger.warning("No peer-cluster relation found to set credentials_saved.")
            return

        if credentials is None:
            del peer_cluster_server.snapshots_credentials_saved
            return

        peer_cluster_server.snapshots_credentials_saved = hash_credentials(
            credentials.model_dump(exclude_none=True)
        )

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
            or (storage_type == ObjectStorageType.S3 and not config.s3)
            or (storage_type == ObjectStorageType.AZURE and not config.azure)
            or (storage_type == ObjectStorageType.GCS and not config.gcs)
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
            use_sudo=self.state.substrate == Substrates.VM,
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
            use_sudo=self.state.substrate == Substrates.VM,
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
            use_sudo=self.state.substrate == Substrates.VM,
        )

    def write_gcs_service_account_json(
        self,
        secret_key: str,
        path: PathProtocol,
    ) -> PathProtocol:
        """Write GCS service account JSON (from relation secret_key) to a file.

        Args:
            secret_key: JSON string content of the service account.
            path: Path to write the service account JSON file to.

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

        self.workload.write_text(content, path)

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
            OpenSearchHttpError: If the snapshot status cannot be fetched.
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
        self.close_snapshot_indices(snapshot)
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

    def close_snapshot_indices(self, snapshot: dict) -> None:
        """Close the given indices.

        Args:
            snapshot (dict): The snapshot containing the indices to close.

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
        self,
        object_storage_type: ObjectStorageType,
        object_storage_config: ObjectStorageConfig,
    ) -> None:
        """Verify that the stored credentials are valid."""
        credential_dict = {}
        if object_storage_config.s3:
            credential_dict = {
                "access_key": object_storage_config.s3.access_key,
                "secret_key": object_storage_config.s3.secret_key,
                "s3_tls_ca_chain": object_storage_config.s3.tls_ca_chain,
            }
        elif object_storage_config.azure:
            credential_dict = {
                "storage_account": object_storage_config.azure.storage_account,
                "secret_key": object_storage_config.azure.secret_key,
            }
        elif object_storage_config.gcs:
            credential_dict = {
                "secret_key": object_storage_config.gcs.secret_key,
            }

        credentials_hash = hash_credentials(credential_dict)
        logger.info(
            "Verifying credentials for %s with hash %s",
            object_storage_type,
            credentials_hash,
        )

        # check all other clusters if they have saved the credentials
        peer_clusters_servers = self.state.all_peer_clusters_servers(remote=True)
        for peer_cluster_server in peer_clusters_servers:
            if peer_cluster_server.snapshots_credentials_saved != credentials_hash:
                logger.warning(
                    "Peer cluster %s has not saved the latest backup credentials yet.",
                    peer_cluster_server.relation.id,
                )
                raise OpenSearchPeerClusterDidntSaveCredentialsYetError(
                    f"Peer cluster {peer_cluster_server.relation.id} has not saved the latest backup credentials yet."
                )

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

    def missing_backup_relations(self) -> list[str]:
        """Get backup relations that are integrated but missing valid credentials."""
        missing = []

        if self.state.s3_relation:
            s3_info = self.state.get_storage_connection_info_from_relation(ObjectStorageType.S3)
            if not s3_info:
                missing.append(S3_RELATION)

        if self.state.azure_relation:
            azure_info = self.state.get_storage_connection_info_from_relation(
                ObjectStorageType.AZURE
            )
            if not azure_info:
                missing.append(AZURE_RELATION)

        if self.state.gcs_relation:
            gcs_info = self.state.get_storage_connection_info_from_relation(ObjectStorageType.GCS)
            if not gcs_info:
                missing.append(GCS_RELATION)

        return missing

    def storage_relation_data_from_peer_cluster(
        self, object_storage_type: ObjectStorageType
    ) -> S3RelData | AzureRelData | GcsRelData | None:
        """Returns storage credentials broadcast by the main orchestrator."""
        data = self.state.main_orchestrator_app
        if not data:
            logger.warning("no relation data from orchestrator found.")
            return None

        cloud = {
            ObjectStorageType.S3: "s3",
            ObjectStorageType.S3_PCLUSTER: "s3",
            ObjectStorageType.AZURE: "azure",
            ObjectStorageType.AZURE_PCLUSTER: "azure",
            ObjectStorageType.GCS: "gcs",
            ObjectStorageType.GCS_PCLUSTER: "gcs",
        }.get(object_storage_type)
        if cloud is None:
            return None

        reldata = data.backup_reldata(cloud)
        if reldata is None:
            logger.warning("no %s credentials found in peer-cluster data.", cloud)
        return reldata

    @override
    def get_statuses(  # noqa: C901
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute the manager's statuses."""
        if not recompute:
            return self.state.statuses.get(scope, self.name).root or [
                GeneralStatuses.ACTIVE_IDLE.value
            ]

        pcluster_types = {
            ObjectStorageType.S3_PCLUSTER,
            ObjectStorageType.AZURE_PCLUSTER,
            ObjectStorageType.GCS_PCLUSTER,
        }
        if (
            scope == "app"
            and self.state.application.deployment_description
            and (object_storage_type := self.state.storage_type)
            and object_storage_type not in pcluster_types
        ):
            if object_storage_type == ObjectStorageType.CONFLICT:
                return [SnapshotsStatuses.BACKUP_RELATION_CONFLICT.value]
            try:
                connection_info = self.state.get_storage_connection_info_from_relation(
                    object_storage_type
                )

                if not (
                    object_storage_config := (
                        storage_config_from_connection_info(object_storage_type, connection_info)
                    )
                ):
                    return [SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value]

                self.validate_storage_config(object_storage_config, object_storage_type)
            except OpenSearchInvalidStorageTypeError:
                return [SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value]
            except OpenSearchObjectStorageConfigValidationError:
                return [SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value]
            except OpenSearchBackupRelationDataIncompleteError:
                return [SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value]
            except OpenSearchBackupCredentialsIncorrectError:
                return [SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value]
        if scope == "app" and self.state.application.missing_relations:
            missing_relations = self.missing_backup_relations()
            if missing_relations:
                return [
                    format_status(
                        PeerClusterStatuses.PEER_CLUSTER_MISSING_RELATIONS.value,
                        {"relation": missing_relations[0]},
                    )
                ]

        return [GeneralStatuses.ACTIVE_IDLE.value]
