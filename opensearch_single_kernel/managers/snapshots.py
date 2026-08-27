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
    AZURE_CREDENTIALS,
    AZURE_RELATION,
    GCS_CREDENTIALS,
    GCS_RELATION,
    S3_CA_ALIAS,
    S3_CREDENTIALS,
    S3_RELATION,
    STORE_PASSWORD,
    DeploymentType,
    ObjectStorageType,
    Scope,
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
from opensearch_single_kernel.core.models import (
    AzureRelDataCredentials,
    GcsRelDataCredentials,
    ObjectStorageConfig,
    PeerClusterRelData,
    S3RelDataCredentials,
)
from opensearch_single_kernel.core.state import ClusterState
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
from opensearch_single_kernel.utils.status import (
    cached_non_running_statuses,
    format_status,
    running_statuses,
)
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
    ) -> tuple[dict[str, str] | None, list[ObjectStorageType]]:
        """Read snapshots configuration data from peer cluster relation.

        Raises:
            OpenSearchSnapshotsPeerClusterDataConflictError: if there is conflicting
              data for multiple storage backends.

        Returns:
            Tuple of (snapshots config dict if found, list of object storage types to clean).
        """
        # Read peer data
        s3_info = self.s3_info_from_peer_cluster
        azure_info = self.azure_info_from_peer_cluster
        gcs_info = self.gcs_info_from_peer_cluster
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

    def set_credentials_saved(self, credentials: dict[str, str] | None) -> None:
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

        peer_cluster_server.snapshots_credentials_saved = hash_credentials(credentials)

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
        self.opensearch_client.reload_secure_settings()
        object_storage_type = self.state.storage_type
        alt_hosts = self.alt_hosts
        # Create a new snapshot
        self.opensearch_client.verify_repository(object_storage_type, alt_hosts)
        snapshot_id = self.opensearch_client.create_snapshot(
            object_storage_type=object_storage_type,
            alt_hosts=alt_hosts,
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
        self.opensearch_client.check_repository(object_storage_type, alt_hosts=self.alt_hosts)

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
        """Get the current backup missing relations."""
        backup_relations = [
            rel_name
            for rel_name, label in [
                (S3_RELATION, S3_CREDENTIALS),
                (AZURE_RELATION, AZURE_CREDENTIALS),
                (GCS_RELATION, GCS_CREDENTIALS),
            ]
            if self.state.secrets.has(Scope.APP, label)
        ]
        return [
            relation_name
            for relation_name in backup_relations
            if not self.state.relation_exists(relation_name)
        ]

    def update_backup_credentials_from_peer_relation(self, data: PeerClusterRelData) -> None:
        """Update backup credentials based on data from peer relation."""
        if s3_creds := data.credentials.s3:
            self.state.secrets.put_object(
                Scope.APP, S3_CREDENTIALS, s3_creds.to_dict(by_alias=True)
            )
        else:
            # Set the S3 credentials to empty
            self.state.secrets.put_object(
                Scope.APP,
                S3_CREDENTIALS,
                S3RelDataCredentials().to_dict(by_alias=True),
            )

        if azure_creds := data.credentials.azure:
            self.state.secrets.put_object(
                Scope.APP, AZURE_CREDENTIALS, azure_creds.to_dict(by_alias=True)
            )
        else:
            # Set Azure credentials to empty
            self.state.secrets.put_object(
                Scope.APP,
                AZURE_CREDENTIALS,
                AzureRelDataCredentials().to_dict(by_alias=True),
            )

        if gcs_creds := data.credentials.gcs:
            self.state.secrets.put_object(
                Scope.APP, GCS_CREDENTIALS, gcs_creds.to_dict(by_alias=True)
            )
        else:
            # Set GCS credentials to empty
            self.state.secrets.put_object(
                Scope.APP,
                GCS_CREDENTIALS,
                GcsRelDataCredentials().to_dict(by_alias=True),
            )

    @property
    def s3_info_from_peer_cluster(self) -> dict[str, str] | None:
        """Read S3 credentials from peer cluster relation."""
        data = self.state.get_rel_data_from_main_orchestrator()
        if not data or not data.credentials or not data.credentials.s3:
            logger.warning("no S3 credentials found.")
            return None

        if not (data.credentials.s3.access_key and data.credentials.s3.secret_key):
            logger.warning("no access key or secret key found.")
            return None

        # CA chain may be published separately
        logger.debug("S3 CA secret: %s", data.credentials.s3.s3_tls_ca_chain)
        return {
            "access_key": data.credentials.s3.access_key,
            "secret_key": data.credentials.s3.secret_key,
            "s3_tls_ca_chain": data.credentials.s3.s3_tls_ca_chain,
        }

    @property
    def azure_info_from_peer_cluster(self) -> dict[str, str] | None:
        """Read Azure credentials from peer cluster relation."""
        data = self.state.get_rel_data_from_main_orchestrator()
        if not data or not data.credentials or not data.credentials.azure:
            logger.warning("no azure credentials found.")
            return None

        if not (data.credentials.azure.storage_account and data.credentials.azure.secret_key):
            logger.debug("Azure storage credentials are incomplete.")
            return None

        return {
            "storage_account": data.credentials.azure.storage_account,
            "secret_key": data.credentials.azure.secret_key,
        }

    @property
    def gcs_info_from_peer_cluster(self) -> dict[str, str] | None:
        """Read GCS credentials from peer cluster relation."""
        data = self.state.get_rel_data_from_main_orchestrator()

        if not data or not data.credentials or not data.credentials.gcs:
            logger.warning("no gcs credentials found.")
            return None

        if not data.credentials.gcs.secret_key:
            logger.debug("GCS storage credentials are incomplete.")
            return None

        return {
            "secret_key": data.credentials.gcs.secret_key,
        }

    @override
    def get_statuses(  # noqa: C901
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute snapshot statuses from relation / config state."""
        status_list = running_statuses(self.state.statuses, scope, self.name)

        if scope != "app":
            return status_list or [GeneralStatuses.ACTIVE_IDLE.value]

        status_list.extend(
            cached_non_running_statuses(
                self.state.statuses,
                scope,
                self.name,
                matches=[SnapshotsStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED.value],
                message_contains=["repository setup failed"],
            )
        )

        deployment_desc = self.state.application.deployment_desc
        if not deployment_desc:
            return status_list or [GeneralStatuses.ACTIVE_IDLE.value]

        # Non-main apps shouldn't take direct backup relations.
        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR and (
            self.state.is_peer_cluster_consumer() or self.state.is_peer_cluster_provider()
        ):
            if self.state.s3_relation or self.state.azure_relation or self.state.gcs_relation:
                status_list.append(SnapshotsStatuses.BACKUP_RELATION_SHOULD_NOT_EXIST.value)
                return status_list

            return status_list or [GeneralStatuses.ACTIVE_IDLE.value]

        # Main orchestrator: validate backup relation and data.
        if object_storage_type := self.state.storage_type:
            if object_storage_type == ObjectStorageType.CONFLICT:
                status_list.append(SnapshotsStatuses.BACKUP_RELATION_CONFLICT.value)
                return status_list
            try:
                connection_info = self.state.get_storage_connection_info_from_relation(
                    object_storage_type
                )

                if not (
                    object_storage_config := (
                        storage_config_from_connection_info(object_storage_type, connection_info)
                    )
                ):
                    status_list.append(SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value)
                    return status_list

                self.validate_storage_config(object_storage_config, object_storage_type)
            except OpenSearchInvalidStorageTypeError:
                status_list.append(SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value)
                return status_list
            except OpenSearchObjectStorageConfigValidationError:
                status_list.append(SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value)
                return status_list
            except OpenSearchBackupRelationDataIncompleteError:
                status_list.append(SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value)
                return status_list
            except OpenSearchBackupCredentialsIncorrectError:
                status_list.append(SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value)
                return status_list

        if missing_relations := self.missing_backup_relations():
            status_list.append(
                format_status(
                    PeerClusterStatuses.PEER_CLUSTER_MISSING_RELATIONS.value,
                    {"relation": missing_relations[0]},
                )
            )
            return status_list

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
