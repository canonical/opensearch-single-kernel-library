#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Peer Cluster Orchestrator manager."""

import logging

from opensearch_single_kernel.common.constants import (
    COS_USER,
    GENERATED_ROLES,
    DeploymentType,
    Directive,
    ObjectStorageType,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchInvalidStorageTypeError,
    OpenSearchObjectStorageConfigValidationError,
)
from opensearch_single_kernel.common.statuses import PeerClusterErrorDataStatuses
from opensearch_single_kernel.core.peer_cluster import (
    PeerClusterApp,
    PeerClusterAppModel,
    PeerClusterOrchestrators,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.core.plain_base import (
    DeploymentDescription,
    Node,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.object_storage import (
    storage_config_from_connection_info,
)
from opensearch_single_kernel.utils.peer_cluster import (
    update_cluster_fleet,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PeerClusterOrchestratorManager(BaseManager):
    """OpenSearch Peer Cluster Orchestrator manager class.

    This class is responsible for managing the peer cluster relation,
    which is used for communication between different OpenSearch clusters.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "peer_cluster_orchestrator_manager")

    def refresh_relation_data(  # noqa: C901
        self,
        event_rel_id: int | None = None,
    ) -> bool:
        """Refresh the peer cluster rel data (new cm node, admin password change etc.).

        Returns:
            whether the operation was completed. In case of negative result retry is preferred.
        """
        # get deployment descriptor of current app
        deployment_description = self.state.application.deployment_description

        # compute the data that needs to be broadcast to all related clusters (success or error)
        remote_peer_cluster = self.build_peer_cluster_rel_data()
        orchestrators = self.state.application.orchestrators
        rel_err_data = self.build_peer_cluster_rel_err_data(
            deployment_description, orchestrators, remote_peer_cluster
        )

        # exit if current cluster should not have been considered a provider
        if (
            self.set_peer_cluster_err_data_if_wrong_integration(event_rel_id, rel_err_data)
            and event_rel_id
        ):
            return True

        # store the main/failover-cm planned units count
        self.save_cluster_fleet_apps(deployment_description)

        cluster_type = (
            "main"
            if deployment_description.typ == DeploymentType.MAIN_ORCHESTRATOR
            else "failover"
        )

        # flag the trigger of the rel changed update on the consumer side
        if event_rel_id:
            local_peer_cluster = self.state.peer_cluster_by_relation_id(
                relation_id=event_rel_id, is_provider=True, remote=False
            )
            if local_peer_cluster:
                local_peer_cluster.trigger = cluster_type

        # update reported orchestrators on local orchestrator
        if cluster_type == "main":
            orchestrators.main_app = deployment_description.app
        else:
            orchestrators.failover_app = deployment_description.app
        self.state.application.orchestrators = orchestrators

        should_wait = rel_err_data and rel_err_data.should_wait

        # save the orchestrators of this fleet
        has_units = self.state.planned_units > 0
        for local_peer_cluster in self.state.peer_clusters(is_provider=True, remote=False):
            with local_peer_cluster.update():
                local_peer_cluster.initialize_empty_secrets()
                orchestrators = local_peer_cluster.orchestrators or PeerClusterOrchestrators()
                logger.debug(
                    "Provider Updating orchestrators for requirer %s previous orchestrators %s. Updating with cluster type %s with %s",
                    local_peer_cluster.relation.app.name,
                    orchestrators,
                    cluster_type,
                    deployment_description.app.to_dict(),
                )

                if cluster_type == "main":
                    orchestrators.main_app = deployment_description.app if has_units else None
                    orchestrators.main_rel_id = local_peer_cluster.relation.id if has_units else -1
                else:
                    orchestrators.failover_app = deployment_description.app if has_units else None
                    orchestrators.failover_rel_id = (
                        local_peer_cluster.relation.id if has_units else -1
                    )

                # in case of demotion update the trigger
                local_peer_cluster.trigger = cluster_type
                local_peer_cluster.orchestrators = orchestrators
                if remote_peer_cluster:
                    local_peer_cluster.apply_rel_data(remote_peer_cluster)
                logger.debug(
                    f"Current rel error data for {local_peer_cluster.relation.app.name} is {local_peer_cluster.error_data}"
                )

                # share object-storage backup credentials with the requirer sub-cluster
                self.broadcast_backup_secrets(local_peer_cluster)

                # there is no error to broadcast - we clear any previously broadcasted error
                if not rel_err_data:
                    logger.debug(
                        f"No rel error data to set for {local_peer_cluster.relation.app.name}. Deleting any existing error data."
                    )
                    del local_peer_cluster.error_data
                else:
                    logger.debug(
                        f"Setting rel error data for {local_peer_cluster.relation.app.name} with blocked message: {rel_err_data.blocked_message}"
                    )
                    local_peer_cluster.error_data = rel_err_data

                # if no planned units, delete relation data as it won't get updated
                if not has_units:
                    del local_peer_cluster.error_data
        return not should_wait

    def broadcast_backup_secrets(self, local_peer_cluster: PeerClusterAppModel) -> None:
        """Share this orchestrator's object-storage credentials with a requirer sub-cluster."""
        for cloud, storage_type in (
            ("s3", ObjectStorageType.S3),
            ("azure", ObjectStorageType.AZURE),
            ("gcs", ObjectStorageType.GCS),
        ):
            if not getattr(self.state, f"{cloud}_relation"):
                local_peer_cluster.set_backup_secrets(cloud, None)
                continue
            try:
                connection_info = self.state.get_storage_connection_info_from_relation(
                    storage_type
                )
                config = storage_config_from_connection_info(storage_type, connection_info)
            except (
                OpenSearchInvalidStorageTypeError,
                OpenSearchObjectStorageConfigValidationError,
            ) as e:
                # credentials not yet published/complete; leave any previous value untouched
                # and let a later refresh broadcast them.
                logger.warning("Backup credentials for %s not ready to broadcast: %s", cloud, e)
                continue
            reldata = getattr(config, cloud, None) if config else None
            if reldata is not None:
                local_peer_cluster.set_backup_secrets(cloud, reldata)

    def build_peer_cluster_rel_data(self) -> PeerClusterAppModel | None:
        """Build and return the peer cluster rel data to be shared with requirer sub-clusters."""
        # returns None if this cluster is not fully ready, or if the admin user
        # is not initialized

        deployment_description = self.state.application.deployment_description
        if not deployment_description:
            logger.debug("Cluster not ready to populate relation data")
            return None

        if not self.state.application.admin_user_initialized:
            logger.debug("Admin user not initialized. Relation data not ready")
            return None

        cm_nodes = {}
        try:
            cm_nodes = self.fetch_current_app_cm_nodes(deployment_description)
        except OpenSearchHttpError:
            logger.warning(
                f"Could not fetch nodes in related {deployment_description.typ} sub-cluster"
            )

        return self.state.application.to_peer_cluster_rel_data(
            cm_nodes=cm_nodes,
            security_index_initialised=self.is_security_index_initialised_in_all_clusters,
            first_data_node=self.first_data_node_in_all_clusters,
        )

    def fetch_current_app_cm_nodes(
        self, deployment_desc: DeploymentDescription
    ) -> dict[str, Node]:
        """Fetch the cluster_manager eligible node IPs in the current application."""
        nodes = self._nodes(
            use_localhost=self.opensearch_client.is_node_up(),
            hosts=self.alt_hosts,
        )

        if not nodes and self.state.planned_units != 0:
            # create a node from the deployment desc or generated roles and unit data only
            if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES:
                computed_roles = deployment_desc.config.roles
            else:
                computed_roles = GENERATED_ROLES

            return {
                self.state.unit_name: Node(
                    name=self.state.unit_name,
                    roles=computed_roles,
                    ip=self.state.node_host,
                    app=deployment_desc.app,
                    unit_number=self.state.server.unit_id,
                )
            }

        if cluster_fleet_apps := self.state.application.cluster_fleet_apps:
            # only report nodes from apps with planned units
            has_planned_units = (
                lambda app_id: app_id in cluster_fleet_apps
                and cluster_fleet_apps[app_id].planned_units > 0
            )
            nodes = [node for node in nodes if has_planned_units(node.app.id)]

        return {
            node.name: node
            for node in nodes
            if node.is_cm_eligible() and node.app.id == deployment_desc.app.id
        }

    @property
    def is_security_index_initialised_in_all_clusters(self) -> bool:
        """Check if the security index is initialised."""
        if self.state.application.security_index_initialised:
            return True

        # check all other clusters if they have initialised the security index
        for remote_peer_cluster in self.state.peer_clusters(is_provider=True, remote=True):
            if remote_peer_cluster.security_index_initialised:
                return True
        return False

    @property
    def first_data_node_in_all_clusters(self) -> str | None:
        """Check if the first data node is up in any of the related clusters."""
        if first_data_node := self.state.application.first_data_node:
            return first_data_node

        for remote_peer_cluster in self.state.peer_clusters(is_provider=True, remote=True):
            if remote_peer_cluster.first_data_node:
                return remote_peer_cluster.first_data_node
        return None

    @property
    def is_every_unit_marked_as_started(self) -> bool:
        """Check if every unit in the cluster is marked as started."""
        all_started = True
        for server in self.state.application_servers:
            if not server.started:
                all_started = False
                break

        if all_started:
            return True

        try:
            current_app_nodes = [
                node
                for node in self._nodes(self.opensearch_client.is_node_up())
                if node.app.id == self.state.application.deployment_description.app.id
            ]
            return len(current_app_nodes) == self.state.planned_units
        except OpenSearchHttpError:
            return False

    def build_peer_cluster_rel_err_data(  # noqa: C901
        self,
        deployment_desc: DeploymentDescription | None,
        orchestrators: PeerClusterOrchestrators,
        rel_data: PeerClusterAppModel | None,
    ) -> PeerClusterRelErrorData | None:
        """Build error peer relation data object."""
        should_sever_relation, should_retry, blocked_msg = False, True, None
        message_suffix = f"in related '{deployment_desc.typ}'"

        if not deployment_desc:
            blocked_msg = (
                PeerClusterErrorDataStatuses.MAIN_OR_FAILOVER_NOT_CONFIGURED.value.message
            )
        elif deployment_desc.typ == DeploymentType.OTHER:
            should_sever_relation, should_retry = True, False
            blocked_msg = (
                PeerClusterErrorDataStatuses.RELATED_TO_NON_MAIN_OR_FAILOVER.value.message
            )
        elif Directive.WAIT_FOR_PEER_CLUSTER_RELATION in deployment_desc.pending_directives:
            blocked_msg = PeerClusterErrorDataStatuses.WAITING_FOR_PEER_RELATION_CREATED.value.message.format(
                message_suffix=message_suffix
            )
        elif (
            orchestrators.main_app
            and orchestrators.main_app.id != deployment_desc.app.id
            and orchestrators.failover_app
            and orchestrators.failover_app.id != deployment_desc.app.id
        ):
            should_sever_relation, should_retry = True, False
            blocked_msg = PeerClusterErrorDataStatuses.CANNOT_HAVE_TWO_FAILOVERS.value.message
        elif not self.state.application.admin_user_initialized:
            blocked_msg = (
                PeerClusterErrorDataStatuses.ADMIN_USER_NOT_FULLY_CONFIGURED.value.message.format(
                    message_suffix=message_suffix
                )
            )
        elif not self.state.is_tls_full_configured_in_cluster:
            blocked_msg = (
                PeerClusterErrorDataStatuses.TLS_NOT_FULLY_CONFIGURED.value.message.format(
                    message_suffix=message_suffix
                )
            )
            should_retry = False
        elif (
            "data" in deployment_desc.config.roles
            or deployment_desc.start == StartMode.WITH_GENERATED_ROLES
        ):
            if not self.state.application.security_index_initialised:
                blocked_msg = PeerClusterErrorDataStatuses.SECURITY_INDEX_NOT_INITIALIZED.value.message.format(
                    message_suffix=message_suffix
                )
        elif (
            self.state.application.is_data_role_in_cluster_fleet_apps
            and self.state.application.security_index_initialised
        ):
            # Requirer units should start after all provider units have started,
            # and only if the security index has already been initialized by a data node.
            # This avoids a potential deadlock where both orchestrator and data units
            # wait on each other to proceed.
            if not self.is_every_unit_marked_as_started:
                blocked_msg = PeerClusterErrorDataStatuses.WAITING_FOR_EVERY_UNIT_TO_START.value.message.format(
                    message_suffix=message_suffix
                )
            elif not self.state.application.cos_password:
                blocked_msg = PeerClusterErrorDataStatuses.COS_USER_PASSWORD_NOT_AVAILABLE.value.message.format(
                    COS_USER=COS_USER
                )
            else:
                try:
                    if not self.fetch_current_app_cm_nodes(deployment_desc):
                        blocked_msg = PeerClusterErrorDataStatuses.NO_CLUSTER_MANAGER_ELIGIBLE_NODES.value.message.format(
                            message_suffix=message_suffix
                        )
                except OpenSearchHttpError as e:
                    logger.error(e)
                    blocked_msg = (
                        PeerClusterErrorDataStatuses.COULD_NOT_FETCH_NODES.value.message.format(
                            message_suffix=message_suffix
                        )
                    )
        elif rel_data and not rel_data.nodes_config:
            blocked_msg = PeerClusterErrorDataStatuses.COULD_NOT_FETCH_NODES_IN_RELATED_CLUSTER.value.message.format(
                deployment_desc=deployment_desc
            )
        if not blocked_msg:
            return None

        return PeerClusterRelErrorData(
            should_sever_relation=should_sever_relation,
            should_wait=should_retry,
            blocked_message=blocked_msg,
        )

    def set_peer_cluster_err_data_if_wrong_integration(
        self,
        event_rel_id: int,
        rel_err_data: PeerClusterRelErrorData | None,
    ) -> bool:
        """Check if relation is invalid and notify related sub-clusters."""
        if not rel_err_data or not rel_err_data.should_sever_relation:
            return False

        for local_peer_cluster in self.state.peer_clusters(is_provider=True, remote=False):
            local_peer_cluster.error_data = rel_err_data

        # delete trigger
        if local_peer_cluster := self.state.peer_cluster_by_relation_id(
            relation_id=event_rel_id, is_provider=True, remote=False
        ):
            logger.warning(
                "Relation with %s severed due to wrong integration: %s",
                local_peer_cluster.relation.app.name,
                rel_err_data.blocked_message,
            )
            del local_peer_cluster.trigger
        return True

    def save_cluster_fleet_apps(
        self,
        deployment_desc: DeploymentDescription,
        p_cluster_app: PeerClusterApp | None = None,
        trigger_rel_id: int | None = None,
    ) -> None:
        """Save in the peer cluster rel data the current app's descriptions."""
        cluster_fleet_apps = self.state.application.cluster_fleet_apps

        current_app = PeerClusterApp(
            app=deployment_desc.app,
            planned_units=self.state.planned_units,
            units=self.state.all_unit_names,
            roles=(
                deployment_desc.config.roles
                if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES
                else GENERATED_ROLES
            ),
        )
        update_cluster_fleet(cluster_fleet_apps, current_app)
        # In case we want to add another app
        if p_cluster_app:
            update_cluster_fleet(cluster_fleet_apps, p_cluster_app)
        for local_peer_cluster in self.state.peer_clusters(is_provider=True, remote=False):
            local_peer_cluster.cluster_fleet_apps = cluster_fleet_apps

        self.state.application.cluster_fleet_apps = cluster_fleet_apps

        # store the trigger app (not current) with relation id, useful for departed rel event
        if trigger_rel_id and p_cluster_app:
            cluster_fleet_apps_rels = self.state.application.cluster_fleet_apps_rels
            update_cluster_fleet(cluster_fleet_apps_rels, p_cluster_app, key=str(trigger_rel_id))
            self.state.application.cluster_fleet_apps_rels = cluster_fleet_apps_rels

    def should_promote_failover_to_main(self) -> bool:
        """Check if majority of related apps are disconnected from main orchestrator.

        This runs on the failover application.
        """
        # check how many related apps are disconnected from main orchestrator
        remote_peer_clusters = self.state.peer_clusters(is_provider=True, remote=True)
        n_disconnected = sum(
            1
            for p_cluster in remote_peer_clusters
            if p_cluster.main_orchestrator_registered is False
        )

        # check if failover is disconnected from main orchestrator
        orchestrators = self.state.application.orchestrators
        if not orchestrators.main_app:
            n_disconnected += 1

        # if majority are disconnected, promote failover
        return n_disconnected > (len(remote_peer_clusters) + 1) // 2

    def promote_failover(self) -> None:
        """Handle failover promotion to main orchestrator."""
        logger.debug("Promoting unit %s from failover to main", self.state.unit_name)
        # remove old main and promote new failover
        orchestrators = self.state.application.orchestrators
        orchestrators.promote_failover()
        self.state.application.orchestrators = orchestrators
        for p_cluster in self.state.peer_clusters(is_provider=True, remote=False):
            p_cluster.trigger = "main"

    def reconcile_security_index_initialised(self) -> None:
        """Check if security index is initialised in any cluster and update state."""
        if self.is_security_index_initialised_in_all_clusters:
            self.state.application.security_index_initialised = True
            # clean up the first data node attribute when security index is initialised
            del self.state.application.first_data_node

    def broadcast_new_failover_app(self, peer_cluster_app: PeerClusterApp) -> None:
        """Broadcasts the new failover in all the cluster fleet"""
        candidate_failover_app = peer_cluster_app.app
        for local_p_cluster in self.state.peer_clusters(is_provider=True, remote=False):
            logger.debug(
                "Broadcasting failover: %s to relation id: %s",
                peer_cluster_app.app.name,
                local_p_cluster.relation.id,
            )
            # Update the orchestrators
            orchestrators = local_p_cluster.orchestrators or PeerClusterOrchestrators()
            orchestrators.failover_app = candidate_failover_app
            local_p_cluster.orchestrators = orchestrators

    def clean_all_provider_relation_data(self):
        """Clean all relation data on provider."""
        for local_peer_cluster in self.state.peer_clusters(is_provider=True, remote=False):
            self._delete_rel_data(local_peer_cluster.relation.id)

    def _delete_rel_data(self, rel_id: int) -> None:
        """Deletes relation data"""
        local_peer_cluster = self.state.peer_cluster_by_relation_id(
            is_provider=True, relation_id=rel_id, remote=False
        )
        if local_peer_cluster:
            local_peer_cluster.clear_rel_data()
            del local_peer_cluster.rel_data_hash
            del local_peer_cluster.error_data
            del local_peer_cluster.cluster_fleet_apps
            del local_peer_cluster.orchestrators
            del local_peer_cluster.trigger
            for cloud in ("gcs", "azure", "s3"):
                delattr(local_peer_cluster, cloud)
