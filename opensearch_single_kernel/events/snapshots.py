#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for OpenSearch Backup and Restore events."""

import json
import logging
from typing import TYPE_CHECKING

from ops import ActionEvent, Object

from opensearch_single_kernel.common.constants import (
    AZURE_RELATION,
    GCS_RELATION,
    PEER_CLUSTER_RELATION,
    S3_RELATION,
    DeploymentType,
    HealthColors,
    ObjectStorageType,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchBackupCredentialsIncorrectError,
    OpenSearchBackupRelationDataIncompleteError,
    OpenSearchCmdError,
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchInvalidStorageTypeError,
    OpenSearchObjectStorageConfigValidationError,
    OpenSearchPeerClusterDidntSaveCredentialsYetError,
    OpenSearchRestoreBackupError,
)
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.core.models import (
    AzureRelData,
    AzureRelDataCredentials,
    GcsRelData,
    GcsRelDataCredentials,
    ObjectStorageConfig,
    S3RelData,
    S3RelDataCredentials,
)
from opensearch_single_kernel.events.custom_events import (
    VerifySnapshotsCredentialsEvent,
)
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
from opensearch_single_kernel.utils.object_storage import repository_name
from opensearch_single_kernel.utils.status import Status

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class SnapshotsEventsHandler(Object):
    """Class implementing OpenSearch Backup/Restore events handling."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, key="snapshots_events")
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
            self.framework.observe(event, self._on_snapshots_credentials_changed)

        for event in [
            self.s3_requirer.on.credentials_gone,
            self.azure_requirer.on.storage_connection_info_gone,
            self.gcs_requirer.on.storage_connection_info_gone,
        ]:
            self.framework.observe(event, self._on_snapshots_credentials_gone)

        self.framework.observe(
            charm.on[PEER_CLUSTER_RELATION].relation_changed,
            self._on_peer_clusters_relation_changed_for_snapshots,
        )
        self.framework.observe(
            charm.on[PEER_CLUSTER_RELATION].relation_departed,
            self._on_peer_clusters_relation_departed_for_snapshots,
        )

        # Custom events
        self.framework.observe(
            self.charm.verify_snapshots_credentials_event, self._on_verify_snapshots_credentials
        )

        # actions
        self.framework.observe(charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(charm.on.restore_action, self._on_restore_action)

    def _on_snapshots_credentials_changed(  # noqa C901
        self, event: CredentialsChangedEvent | StorageConnectionInfoChangedEvent
    ) -> None:
        """Handler for backup credentials changed event."""
        if not (deployment_desc := self.charm.state.application.deployment_desc):
            logger.debug("Deployment description not ready; deferring %s", event)
            event.defer()
            return

        # block non-main orchestrators only when they are in a multi-app topology.
        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR and (
            self.charm.snapshots_manager.is_peer_cluster_consumer()
            or self.charm.snapshots_manager.is_peer_cluster_provider()
        ):
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.BACKUP_RELATION_SHOULD_NOT_EXIST, app=True)
            return

        if not (object_storage_type := self.charm.snapshots_manager.storage_type):
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
        try:
            connection_info = self.get_storage_connection_info_from_relation(object_storage_type)
        except OpenSearchInvalidStorageTypeError as e:
            logger.error(str(e))
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE, app=True)
            return

        # Get config using the connection info
        try:
            object_storage_config = (
                self.charm.snapshots_manager.storage_config_from_connection_info(
                    object_storage_type, connection_info
                )
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
            self.charm.snapshots_manager.validate_storage_config(
                object_storage_config, object_storage_type
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

        if (
            not self.charm.snapshots_manager.opensearch_client.is_node_up()
            and not self.charm.snapshots_manager.alt_hosts
        ):
            logger.warning("OpenSearch service is not reachable.")
            event.defer()
            return

        try:
            if self.charm.snapshots_manager.ensure_repository(
                object_storage_type, object_storage_config
            ):
                self.charm.verify_snapshots_credentials_event.emit()
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
                    "storage_type": object_storage_type.value,
                    "integrator": f"{object_storage_type.value} integrator",
                },
                app=True,
            )
            event.defer()
            return

        self.charm.status.clear(
            CharmStatuses.BACKUP_REPOSITORY_MISCONFIGURED,
            pattern=Status.CheckPattern.Interpolated,
            app=True,
        )
        # Refresh peer relations
        self.charm.peer_cluster_events.reconcile_peer_relation_data(event)

    def _on_snapshots_credentials_gone(  # noqa C901
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

        if not self._remove_credentials(
            object_storage_type=object_storage_type,
        ):
            logger.warning("Cleanup for %s credentials are failed.", object_storage_type)
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED,
                    app=True,
                )
            event.defer()
            return None

        if self.charm.unit.is_leader() and not self.charm.snapshots_manager.remove_repository(
            object_storage_type
        ):
            logger.warning(
                "Failed to remove snapshot repository for %s during credentials cleanup.",
                object_storage_type,
            )
            self.charm.status.set(
                CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED,
                app=True,
            )
            event.defer()
            return None

        if (
            object_storage_type == ObjectStorageType.S3
            and self.charm.snapshots_manager.is_custom_s3_ca_stored()
        ):
            self.charm.snapshots_manager.remove_s3_ca()

        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED, app=True)
            self.charm.status.clear(CharmStatuses.BACKUP_CREDENTIALS_INCORRECT, app=True)

        self.charm.reload_keystore_event.emit()
        if self.charm.unit.is_leader():
            # Refresh peer relations
            self.charm.peer_cluster_events.reconcile_peer_relation_data(event)

    def _on_verify_snapshots_credentials(  # noqa C901
        self, event: VerifySnapshotsCredentialsEvent
    ) -> None:
        """Verify that stored backup credentials are still valid."""
        if not (object_storage_type := self.charm.snapshots_manager.storage_type):
            logger.warning(
                "No object storage type could be determined for backup credentials verification."
            )
            return

        # Get connection info
        try:
            connection_info = self.get_storage_connection_info_from_relation(object_storage_type)
        except OpenSearchInvalidStorageTypeError as e:
            logger.error(str(e))
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE, app=True)
            return

        # Get config using the connection info
        if not (
            object_storage_config := self.charm.snapshots_manager.storage_config_from_connection_info(
                object_storage_type, connection_info
            )
        ):
            logger.warning(
                "Object storage configuration not ready for backup credentials verification."
            )
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.BACKUP_RELATION_DATA_INCOMPLETE, app=True)
            return

        try:
            self.charm.snapshots_manager.verify_stored_credentials(
                object_storage_type, object_storage_config
            )
        except OpenSearchHttpError as e:
            self.charm.status.set(
                CharmStatuses.BACKUP_REPOSITORY_MISCONFIGURED,
                dynamic_params={
                    "storage_type": object_storage_type.value,
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
        except OpenSearchPeerClusterDidntSaveCredentialsYetError as e:
            logger.warning(
                "Not all peer clusters have saved the latest backup credentials yet: %s", e
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
            logger.warning("Pre-requisites not met for creating backup: %s", error_message)
            event.fail(error_message)
            return

        self.charm.status.set(CharmStatuses.BACKUP_IN_PROGRESS)
        try:
            snapshot_id = self.charm.snapshots_manager.create_snapshot()
        except OpenSearchHttpError as e:
            logger.error("Failed to create backup: %s", e)
            event.fail(f"Backup request failed with: {str(e)}")
            return

        # Fetch the new snapshot for sanity check
        try:
            status = self.charm.snapshots_manager.get_snapshot_status(snapshot_id)
            event.set_results({"backup-id": snapshot_id, "status": status})
        except OpenSearchHttpError as e:
            logger.error("Unknown state for snapshot %s: %s", snapshot_id, e)
            event.fail(f"Unknown state for backup {snapshot_id}: {str(e)}")
        finally:
            self.charm.status.clear(CharmStatuses.BACKUP_IN_PROGRESS)

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Handler for list backups changes."""
        if error_message := self._action_missing_pre_requisites(report_running_operations=False):
            logger.warning("Pre-requisites not met for listing backups: %s", error_message)
            event.fail(error_message)
            return

        if (output_format := event.params.get("output", "").lower()) not in {"json", "table"}:
            logger.error("Invalid output format for listing backups: %s", output_format)
            event.fail("Failed: invalid output format, must be either 'json' or 'table'.")
            return
        try:
            snapshots = self.charm.snapshots_manager.list_snapshots()
            if output_format == "json":
                event.set_results({"backups": json.dumps(snapshots)})
                return

            # Format table output
            table_output = []

            header = "{:<20s} | {:s}".format("backup-id", "backup-status")
            table_output.append(header)
            table_output.append("-" * len(header))

            for _id, _snapshot in snapshots.items():
                line = "{:<20s} | {:s}".format(_id, _snapshot["state"])
                table_output.append(line)

            event.set_results({"backups": "\n".join(table_output)})
        except OpenSearchHttpError as e:
            logger.error("Could not fetch the list of snapshots: %s", e)
            event.fail(f"Backup request failed with: {str(e)}")

    def _on_restore_action(self, event: ActionEvent) -> None:  # noqa C901
        """Handler for the restore action."""
        snapshot_id = event.params.get("backup-id")

        if error_message := self._action_missing_pre_requisites(report_running_operations=False):
            logger.warning("Pre-requisites not met for restoring backup: %s", error_message)
            event.fail(error_message)
            return

        self.charm.status.set(CharmStatuses.RESTORE_IN_PROGRESS)
        try:
            try:
                self.charm.snapshots_manager.restore_snapshot(snapshot_id)
            except OpenSearchRestoreBackupError as e:
                logger.error("Failed to restore backup %s: %s", snapshot_id, e)
                event.fail(str(e))
                return
            # Once restore finishes successfully , we wait for cluster health
            if (
                self.charm.status.apply_health(
                    wait_for_green_first=True,
                    app=True,
                )
                == "green"
            ):
                event.set_results({"restored-backup-id": snapshot_id, "status": "success"})
            else:
                event.set_results(
                    {
                        "restored-backup-id": snapshot_id,
                        "status": "success_with_warning",
                        "note": "restore completed; cluster didn't reach GREEN within 30s",
                    }
                )
        finally:
            self.charm.status.clear(CharmStatuses.RESTORE_IN_PROGRESS)

    def _on_peer_clusters_relation_changed_for_snapshots(self, event) -> None:  # noqa C901
        """Apply snapshots config when the orchestrator broadcasts over peer-clusters."""
        if not self.charm.state.application.deployment_desc:
            logger.debug("Deployment description not ready; deferring %s", event)
            event.defer()
            return None

        info_to_save, object_storage_type_to_cleanup = (
            self.charm.snapshots_manager.read_snapshots_data_from_peer_cluster()
        )
        if info_to_save:
            for object_storage_type in object_storage_type_to_cleanup:
                if not self._remove_credentials(object_storage_type):
                    logger.warning(
                        "Cleanup for %s credentials are failed during peer cluster relation change.",
                        object_storage_type,
                    )
                    if self.charm.unit.is_leader():
                        self.charm.status.set(
                            CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED,
                            app=True,
                        )
                    event.defer()
                    return None
            if self.charm.unit.is_leader():
                self.charm.status.clear(CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED, app=True)

            if self.charm.snapshots_manager.s3_info_from_peer_cluster:
                object_storage_type = ObjectStorageType.S3
                s3_credentials = self.charm.snapshots_manager.s3_info_from_peer_cluster
                s3_rel_data = S3RelData(credentials=S3RelDataCredentials(**s3_credentials.dict()))
                object_storage_config = ObjectStorageConfig(s3=s3_rel_data)
            elif self.charm.snapshots_manager.azure_info_from_peer_cluster:
                object_storage_type = ObjectStorageType.AZURE
                azure_credentials = self.charm.snapshots_manager.azure_info_from_peer_cluster
                azure_rel_data = AzureRelData(
                    credentials=AzureRelDataCredentials(**azure_credentials.dict())
                )
                object_storage_config = ObjectStorageConfig(azure=azure_rel_data)
            elif self.charm.snapshots_manager.gcs_info_from_peer_cluster:
                object_storage_type = ObjectStorageType.GCS
                gcs_credentials = self.charm.snapshots_manager.gcs_info_from_peer_cluster
                gcs_rel_data = GcsRelData(
                    credentials=GcsRelDataCredentials(**gcs_credentials.dict())
                )
                object_storage_config = ObjectStorageConfig(gcs=gcs_rel_data)

            try:
                self.update_stored_credentials(
                    object_storage_type, object_storage_config=object_storage_config
                )
            except OpenSearchFileOperationError:
                logger.error("Failed to update stored backup credentials.")
                return

            # Reload keystore
            self.charm.reload_keystore_event.emit()
            self.charm.snapshots_manager.set_credentials_saved(info_to_save)
            return

        for object_storage_type in [
            ObjectStorageType.S3,
            ObjectStorageType.AZURE,
            ObjectStorageType.GCS,
        ]:
            self.charm.keystore_manager.cleanup_storage_credentials(object_storage_type)

        # clean S3 CA
        if self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.remove_s3_ca()

        self.charm.reload_keystore_event.emit()

        self.charm.snapshots_manager.set_credentials_saved(None)

    def _on_peer_clusters_relation_departed_for_snapshots(self, event) -> None:  # noqa C901
        """Cleanup snapshot config if the orchestrator we depended on is gone."""
        if not self.charm.state.application.deployment_desc:
            logger.debug("Deployment description not ready; deferring %s", event)
            event.defer()
            return

        if (
            self.charm.state.application.orchestrators
            and self.charm.state.application.orchestrators.main_app
            and self.charm.state.application.orchestrators.main_app.name == event.relation.app.name
            and len(event.relation.units) > 0
        ):
            logger.debug(
                "Main orchestrator still accessible; do not cleanup as it can be scale down"
            )
            return

        logger.info(
            "peer-clusters relation for snapshots departed; "
            "cleaning all object-storage snapshot configuration."
        )
        # clean S3-related config
        for object_storage_type in [
            ObjectStorageType.S3,
            ObjectStorageType.AZURE,
            ObjectStorageType.GCS,
        ]:
            if not self._remove_credentials(object_storage_type):
                logger.warning(
                    "Cleanup for %s credentials are failed during peer cluster relation departure.",
                    object_storage_type,
                )
                if self.charm.unit.is_leader():
                    self.charm.status.set(
                        CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED,
                        app=True,
                    )
                event.defer()
                return

        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED, app=True)

        # clean S3 CA
        if self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.remove_s3_ca()

        self.charm.reload_keystore_event.emit()

    def _action_missing_pre_requisites(  # noqa C901
        self,
        report_running_operations: bool = True,
    ) -> str | None:
        """Compute the missing prerequisites for running a snapshot/restore action.

        Args:
            report_running_operations (bool): Whether to report running operations.

        Returns:
            A string representing the missing prerequisites.
        """
        if not (object_storage_type := self.charm.snapshots_manager.storage_type):
            logger.warning("Missing object storage type for create backup action.")
            return "Missing relation with an object storage integrator."

        if not self.charm.unit.is_leader():
            return "Backup/Restore related actions must be run on the juju leader unit."

        if not self.charm.state.application.deployment_desc:
            return "Deployment not ready."
        # TODO: Handle upgrades
        # if self.charm.upgrade_in_progress:
        #    return "Backup/Restore operations not supported while upgrade in-progress."

        if object_storage_type == ObjectStorageType.CONFLICT:
            return "Conflict: more than one object storage integrators integrated."

        if (
            not self.charm.snapshots_manager.opensearch_client.is_node_up()
            and not self.charm.snapshots_manager.alt_hosts
        ):
            return "Connectivity issue: the opensearch service is not reachable."

        repo_name = repository_name(object_storage_type)
        logger.debug(
            f"[snapshots] precheck: type={object_storage_type} repo={repo_name} alt_hosts={self.charm.snapshots_manager.alt_hosts}"
        )

        pcluster_types = {
            ObjectStorageType.S3_PCLUSTER,
            ObjectStorageType.AZURE_PCLUSTER,
            ObjectStorageType.GCS_PCLUSTER,
        }
        if object_storage_type not in pcluster_types:
            try:
                if (
                    not (storage_type := self.charm.snapshots_manager.storage_type)
                    or not (
                        conn_inf := self.get_storage_connection_info_from_relation(storage_type)
                    )
                    or not self.charm.snapshots_manager.storage_config_from_connection_info(
                        storage_type, conn_inf
                    )
                ):
                    return "Object storage configuration not ready."
                if not self.charm.snapshots_manager.opensearch_client.is_repository_created(
                    object_storage_type
                ):
                    return "The opensearch repository could not be created yet."
            except OpenSearchInvalidStorageTypeError as e:
                logger.error(str(e))
                return "Object storage credentials are invalid."
            except OpenSearchObjectStorageConfigValidationError:
                return "Object storage credentials are invalid."
            except OpenSearchHttpError as e:
                return f"Action failed with: {str(e)}."

        if not report_running_operations:
            return None

        match self.charm.health_manager.get(wait_for_green_first=True):
            case HealthColors.RED:
                return "Cluster health red, current state must be resolved before."
            case HealthColors.YELLOW_TEMP:
                return "Shards are still relocating or initializing."
            case HealthColors.UNKNOWN:
                return "Cluster health unknown."

        try:
            if self.charm.snapshots_manager.is_operation_in_progress:
                return "Backup / Restore operation in progress."
        except OpenSearchHttpError as e:
            return f"Action failed with: {str(e)}."

        return None

    def get_storage_connection_info_from_relation(
        self, object_storage_type: ObjectStorageType
    ) -> dict[str, str]:
        """Returns the storage connection info from the active relation.."""
        match object_storage_type:
            case ObjectStorageType.S3:
                return self.s3_requirer.get_s3_connection_info() or {}
            case ObjectStorageType.AZURE:
                return self.azure_requirer.get_azure_storage_connection_info() or {}
            case ObjectStorageType.GCS:
                return (
                    self.gcs_requirer.get_storage_connection_info(self.charm.state.gcs_relation)
                    or {}
                )
            case _:
                raise OpenSearchInvalidStorageTypeError(
                    "Unsupported object storage type: %s" % object_storage_type
                )

    def update_stored_credentials(
        self, object_storage_type: ObjectStorageType, object_storage_config: ObjectStorageConfig
    ) -> None:
        """Update the stored credentials."""
        if object_storage_type == ObjectStorageType.GCS:
            with self.charm.workload.temp_file(
                chown="snap_daemon:root", dir=self.charm.workload.paths.conf
            ) as temp_path:
                self.charm.snapshots_manager.write_gcs_service_account_json(
                    secret_key=object_storage_config.gcs.credentials.secret_key, path=temp_path
                )
                self.charm.keystore_manager.put_object_storage_credentials(
                    object_storage_type, object_storage_config, gcs_file_path=temp_path
                )
            return

        if object_storage_type == ObjectStorageType.S3:
            if object_storage_config.s3.tls_ca_chain:
                if not self.charm.snapshots_manager.is_custom_s3_ca_stored(
                    object_storage_config.s3.tls_ca_chain
                ):
                    # Content differs: rotate / store new chain
                    self.charm.snapshots_manager.store_s3_ca(object_storage_config.s3.tls_ca_chain)
                    logger.info("S3 CA stored/updated.")
            else:
                self.charm.snapshots_manager.remove_s3_ca()
        self.charm.keystore_manager.put_object_storage_credentials(
            object_storage_type, object_storage_config
        )

    def _remove_credentials(self, object_storage_type: ObjectStorageType) -> bool:
        """Cleanup stored credentials and related config for a given object storage type."""
        try:
            self.charm.keystore_manager.cleanup_storage_credentials(object_storage_type)
        except OpenSearchCmdError as e:
            logger.warning(
                "Keystore cleanup for %s failed after retries: %s",
                object_storage_type,
                e,
            )
            return False
        return True
