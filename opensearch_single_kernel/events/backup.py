#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for OpenSearch Backup and Restore events."""

import logging
from typing import TYPE_CHECKING

from ops import ActionEvent, Object

from opensearch_single_kernel.common.constants import (
    AZURE_RELATION,
    GCS_RELATION,
    S3_RELATION,
    HealthColors,
    ObjectStorageType,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchBackupCredentialsIncorrectError,
    OpenSearchBackupRelationDataIncompleteError,
    OpenSearchCmdError,
    OpenSearchCreateBackupError,
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchListBackupsError,
    OpenSearchObjectStorageConfigValidationError,
    OpenSearchRestoreBackupError,
)
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.core.models import ObjectStorageConfig
from opensearch_single_kernel.events.custom_events import VerifyBackupCredentialsEvent
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.azure_storage import (
    AzureStorageRequires,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.gcs_storage import (
    GcsStorageRequires,
    StorageConnectionInfoChangedEvent,
    StorageConnectionInfoGoneEvent,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.s3 import (
    CredentialsChangedEvent,
    CredentialsGoneEvent,
    S3Requirer,
)
from opensearch_single_kernel.utils.cloud_storage import repository_name
from opensearch_single_kernel.utils.status import Status

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class BackupEventsHandler(Object):
    """Class implementing OpenSearch Backup/Restore events handling."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, key="backups_events")
        self.charm = charm

        # requirers
        self.s3_requirer = S3Requirer(charm, S3_RELATION)
        self.azure_requirer = AzureStorageRequires(charm, AZURE_RELATION)
        self.gcs_requirer = GcsStorageRequires(charm, GCS_RELATION)

        # simple deployments or main orchestrator
        for event in [
            self.s3_requirer.on.credentials_changed,
            self.azure_requirer.on.storage_connection_info_changed,
            self.gcs_requirer.on.storage_connection_info_changed,
        ]:
            self.framework.observe(event, self._on_backup_credentials_changed)

        for event in [
            self.s3_requirer.on.credentials_gone,
            self.azure_requirer.on.storage_connection_info_gone,
            self.gcs_requirer.on.storage_connection_info_gone,
        ]:
            self.framework.observe(event, self._on_backup_credentials_gone)

        # TODO: Handle large deployments
        # large deployments with non-main orchestrator
        # self.framework.observe(
        #    charm.on[PeerClusterRelationName].relation_changed,
        #    self._on_peer_clusters_relation_changed_for_snapshots,
        # )
        # self.framework.observe(
        #    charm.on[PeerClusterRelationName].relation_departed,
        #    self._on_peer_clusters_relation_departed_for_snapshots,
        # )
        # self.framework.observe(
        #    self.verify_backup_credentials_event, self._on_verify_backup_credentials
        # )

        # Custom events
        self.framework.observe(
            self.charm.verify_backup_credentials_event, self._on_verify_backup_credentials
        )

        # actions
        self.framework.observe(charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(charm.on.restore_action, self._on_restore_action)

    def _on_backup_credentials_changed(  # noqa C901
        self, event: CredentialsChangedEvent | StorageConnectionInfoChangedEvent
    ) -> None:
        """Handler for backup credentials changed event."""
        if not (self.charm.state.application.deployment_desc):
            logger.debug("Deployment description not ready; deferring %s", event)
            event.defer()
            return

        # block non-main orchestrators only when they are in a multi-app topology.
        # TODO: Handle once large deployments are implemented

        object_storage_type = self.charm.state.storage_type

        if not object_storage_type:
            logger.warning("No object storage type could be determined.")
            return

        if object_storage_type == ObjectStorageType.CONFLICT:
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.BACKUP_RELATION_CONFLICT, app=True)
            event.defer()
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.BACKUP_RELATION_CONFLICT, app=True)

        # Get connection info
        connection_info = self.get_storage_connection_info_from_relation(object_storage_type)
        if not connection_info:
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE, app=True)
            return
        # Get config using the connection info
        try:
            object_storage_config = self.charm.backup_manager.storage_config_from_connection_info(
                object_storage_type, connection_info
            )
        except OpenSearchObjectStorageConfigValidationError as e:
            logger.warning(
                "%s object storage configuration is invalid: %s",
                object_storage_type,
                e.error,
            )
            if self.charm.unit.is_leader():
                self.charm.status.clear(CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE, app=True)
                self.charm.status.set(CharmStatuses.BACKUP_CREDENTIALS_INCORRECT, app=True)
            return

        # Validate storage config
        try:
            self.charm.backup_manager.validate_storage_config(
                object_storage_type, object_storage_config
            )
        except OpenSearchBackupRelationDataIncompleteError:
            logger.warning("No %s object storage configuration.", object_storage_type)
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE, app=True)
            return

        except OpenSearchBackupCredentialsIncorrectError:
            logger.warning("%s object storage credentials not verified.", object_storage_type)
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.BACKUP_CREDENTIALS_INCORRECT, app=True)
            return

        # Clear backup related statuses if validation passes
        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE, app=True)
            self.charm.status.clear(CharmStatuses.BACKUP_CREDENTIALS_INCORRECT, app=True)

        # Update backup credentials
        # Catch file operation exceptions
        try:
            self.update_stored_credentials(object_storage_type, object_storage_config)

        except OpenSearchFileOperationError:
            logger.error("Failed to update stored backup credentials.")
            return

        # Reload keystore
        self.charm.reload_keystore_event.emit()

        if not self.charm.unit.is_leader():
            return

        try:
            if self.charm.backup_manager.ensure_repository(
                object_storage_type, object_storage_config
            ):
                self.charm.verify_backup_credentials_event.emit()
        except OpenSearchHttpError as e:
            logger.error(
                "Failed to create/verify snapshot repository for %s. "
                "Error: %s, response_body=%r",
                object_storage_type,
                e,
                getattr(e, "response_body", None),
            )
            self.charm.status.set(
                CharmStatuses.BACKUP_REPOSITORY_MISCONFIGURED,
                dynamic_params={
                    "object_storage_type": object_storage_type.value,
                    "integrator": f"{object_storage_type.value} integrator",
                },
                app=True,
            )
            event.defer()
            return

        self.charm.status.clear(
            CharmStatuses.BACKUP_REPOSITORY_MISCONFIGURED,
            pattern=Status.CheckPattern.Interpolated,
        )
        # TODO: Handle large deployments
        # Refresh peer relations

    def _on_backup_credentials_gone(
        self, event: CredentialsGoneEvent | StorageConnectionInfoGoneEvent
    ) -> None:
        """Handler for backup credentials gone event."""
        if isinstance(event, CredentialsGoneEvent):
            object_storage_type = ObjectStorageType.S3
        elif event.relation.name == GCS_RELATION:
            object_storage_type = ObjectStorageType.GCS
        elif event.relation.name == AZURE_RELATION:
            object_storage_type = ObjectStorageType.AZURE
        else:
            logger.debug("The object storage type could not be determined.")
            return

        # Clear backup related statuses
        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.BACKUP_RELATION_SHOULD_NOT_EXIST, app=True)
            self.charm.status.clear(CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE, app=True)
            self.charm.status.clear(
                CharmStatuses.BACKUP_REPOSITORY_MISCONFIGURED,
                pattern=Status.CheckPattern.Interpolated,
            )

        if not self.charm.backup_manager.cleanup(
            object_storage_type=object_storage_type,
            remove_repository=True,
        ):
            logger.warning("Cleanup for %s credentials are failed.", object_storage_type)
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED,
                    app=True,
                )
            event.defer()
            return
        if (
            object_storage_type == ObjectStorageType.S3
            and self.charm.backup_manager.is_custom_s3_ca_stored()
        ):
            self.charm.backup_manager.remove_s3_ca()

        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED, app=True)
            self.charm.status.clear(CharmStatuses.BACKUP_CREDENTIALS_INCORRECT, app=True)

        self.charm.reload_keystore_event.emit()

        # TODO: Handle large deployments
        # Refresh peer relations

    def _on_verify_backup_credentials(  # noqa C901
        self, event: VerifyBackupCredentialsEvent
    ) -> None:
        """Verify that stored backup credentials are still valid."""
        object_storage_type = self.charm.state.storage_type
        # Get connection info
        connection_info = self.get_storage_connection_info_from_relation(object_storage_type)
        # Get config using the connection info
        object_storage_config = self.charm.backup_manager.storage_config_from_connection_info(
            object_storage_type, connection_info
        )
        if not object_storage_type or not object_storage_config:
            return

        try:
            self.charm.backup_manager.verify_credentials(
                object_storage_type, object_storage_config
            )
        except OpenSearchHttpError as e:
            self.charm.status.set(
                CharmStatuses.BACKUP_REPOSITORY_MISCONFIGURED,
                dynamic_params={
                    "object_storage_type": object_storage_type.value,
                    "integrator": f"{object_storage_type.value} integrator",
                },
                app=True,
            )
            logger.error(
                "Failed to verify snapshot repository after credentials verification. "
                "Error: %s, response_body=%r",
                e,
                getattr(e, "response_body", None),
            )
            event.defer()
            return
        self.charm.status.clear(
            CharmStatuses.BACKUP_REPOSITORY_MISCONFIGURED,
            pattern=Status.CheckPattern.Interpolated,
            app=True,
        )
        logger.info("Backup credentials verified successfully.")

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handler for create backup action event."""
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        self.charm.status.set(CharmStatuses.BACKUP_IN_PROGRESS)
        try:
            try:
                result = self.charm.backup_manager.create_snapshot()
                event.set_results(result)
            except OpenSearchCreateBackupError as e:
                event.fail(str(e))
                return
        finally:
            self.charm.status.clear(CharmStatuses.BACKUP_IN_PROGRESS)

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Handler for list backups changes."""
        if error_message := self._action_missing_pre_requisites(report_running_operations=False):
            event.fail(error_message)
            return

        if (output_format := event.params.get("output", "").lower()) not in {"json", "table"}:
            event.fail("Failed: invalid output format, must be either 'json' or 'table'.")
            return

        try:
            result = self.charm.backup_manager.list_snapshots(output_format)
            event.set_results(result)
        except OpenSearchListBackupsError as e:
            event.fail(str(e))

    def _on_restore_action(self, event: ActionEvent) -> None:  # noqa C901
        """Handler for the restore action."""
        snapshot_id = event.params.get("backup-id")
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        self.charm.status.set(CharmStatuses.RESTORE_IN_PROGRESS)
        try:
            try:
                self.restore_snapshot(snapshot_id)
            except OpenSearchRestoreBackupError as e:
                event.fail(str(e))
                return
            # Once restore finishes successfully , we wait for cluster health
            final_status = self.charm.status.apply_health(
                wait_for_green_first=True, app=self.charm.unit.is_leader()
            )
            if final_status == "green":
                event.set_results({"restored-backup-id": snapshot_id, "status": "success"})
            else:
                event.set_results(
                    {
                        "restored-backup-id": snapshot_id,
                        "status": "success_with_warning",
                        "note": "restore completed; cluster didn't reach GREEN within 30s",
                    }
                )
            return
        finally:
            self.charm.status.clear(CharmStatuses.RESTORE_IN_PROGRESS)

    def _action_missing_pre_requisites(  # noqa C901
        self, report_running_operations: bool = True
    ) -> str | None:
        """Compute the missing prerequisites for running a snapshot/restore action.

        Args:
            report_running_operations (bool): Whether to report running operations.

        Returns:
            A string representing the missing prerequisites.
        """
        if not self.charm.unit.is_leader():
            return "Backup/Restore related actions must be run on the juju leader unit."

        if not self.state.application.deployment_desc:
            return "Deployment not ready."
        # TODO: Handle upgrades
        # if self.charm.upgrade_in_progress:
        #    return "Backup/Restore operations not supported while upgrade in-progress."

        object_storage_type = self.charm.state.storage_type

        if not object_storage_type:
            if self.charm.unit.is_leader():
                for status in (
                    CharmStatuses.BACKUP_CREDENTIALS_INCORRECT,
                    CharmStatuses.BACKUP_RELATION_CONFLICT,
                    CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE,
                ):
                    self.charm.status.set(status, app=True)
            return "Missing relation with an object storage integrator."

        if object_storage_type == ObjectStorageType.CONFLICT:
            return "Conflict: more than one object storage integrators integrated."

        if (
            not self.charm.backup_manager.opensearch_client.is_node_up()
            and not self.charm.backup_manager.alt_hosts
        ):
            return "Connectivity issue: the opensearch service is not reachable."

        repo_name = repository_name(object_storage_type)
        logger.debug(
            f"[snapshots] precheck: type={object_storage_type} repo={repo_name} alt_hosts={self.charm.backup_manager.alt_hosts}"
        )

        # TODO: Handle large deployments
        if not report_running_operations:
            return

        match self.charm.health_manager.get(wait_for_green_first=True):
            case HealthColors.RED:
                return "Cluster health red, current state must be resolved before."
            case HealthColors.YELLOW_TEMP:
                return "Shards are still relocating or initializing."
            case HealthColors.UNKNOWN:
                return "Cluster health unknown."

        try:
            if self.charm.backup_manager.is_operation_in_progress:
                return "Backup / Restore operation in progress."
        except OpenSearchHttpError as e:
            return f"Action failed with: {str(e)}."

        return

    def get_storage_connection_info_from_relation(
        self, object_storage_type: ObjectStorageType
    ) -> dict[str, str]:
        """Returns the storage connection info from the active relation.."""
        if object_storage_type == ObjectStorageType.S3:
            return self.s3_requirer.get_s3_connection_info() or {}

        if object_storage_type == ObjectStorageType.AZURE:
            return self.azure_requirer.get_azure_storage_connection_info() or {}

        if object_storage_type == ObjectStorageType.GCS:
            return (
                self.gcs_requirer.get_storage_connection_info(self.charm.state.gcs_relation) or {}
            )

    def update_stored_credentials(
        self, object_storage_type: ObjectStorageType, object_storage_config: ObjectStorageConfig
    ) -> None:
        """Update the stored credentials."""
        service_account_path = None
        if object_storage_type == ObjectStorageType.GCS:
            service_account_path = self.charm.backup_manager.write_gcs_service_account_json(
                secret_key=object_storage_config.gcs.credentials.secret_key
            )
        self.charm.keystore_manager.put_object_storage_credentials(
            object_storage_type, object_storage_config, service_account_path
        )
        if object_storage_type == ObjectStorageType.S3:
            if object_storage_config.s3.tls_ca_chain:
                if not self.charm.backup_manager.is_custom_s3_ca_stored(
                    object_storage_config.s3.tls_ca_chain
                ):
                    # Content differs: rotate / store new chain
                    self.charm.backup_manager.store_s3_ca(object_storage_config.s3.tls_ca_chain)
                    logger.info("S3 CA stored/updated.")
            else:
                self.charm.backup_manager.remove_s3_ca()

    def cleanup(
        self, object_storage_type: ObjectStorageType, remove_repository: bool = False
    ) -> bool:
        """Cleanup stored credentials and related config for a given object storage type."""
        try:
            self.charm.keystore_manager.cleanup_storage_credentials(object_storage_type)
            # Reload keystore after cleanup
            self.charm.reload_keystore_event.emit()
        except OpenSearchCmdError as e:
            logger.warning(
                "Keystore cleanup for %s failed after retries: %s",
                object_storage_type,
                e,
            )
            return False
        try:
            # If the storage type is gcs, also remove the service account json file
            if object_storage_type == ObjectStorageType.GCS or str(object_storage_type) == "gcs":
                self.remove_gcs_service_account_json()
        except OpenSearchFileOperationError as e:
            logger.warning("Failed to remove GCS service account JSON file during cleanup: %s", e)
            # Not critical, continue with cleanup

        if remove_repository:
            if not self.charm.unit.is_leader():
                return True
            return self.charm.backup_manager.remove_repository(object_storage_type)

        return True
