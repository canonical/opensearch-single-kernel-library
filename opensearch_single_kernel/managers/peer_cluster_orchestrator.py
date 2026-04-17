#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Peer Cluster Orchestrator manager."""

import logging

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_USER,
    GENERATED_ROLES,
    KIBANA_SERVER_USER,
    CertType,
    DeploymentType,
    Directive,
    Scope,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.core.models import (
    AzureRelDataCredentials,
    DeploymentDescription,
    GcsRelDataCredentials,
    Node,
    PeerClusterApp,
    PeerClusterOrchestrators,
    PeerClusterRelData,
    PeerClusterRelDataCredentials,
    PeerClusterRelErrorData,
    PluginConfigInfo,
    S3RelDataCredentials,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.peer_cluster import (
    update_cluster_fleet,
)
from opensearch_single_kernel.utils.secrets import hash_key, password_key
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PeerClusterOrchestratorManager(BaseManager):
    """OpenSearch Peer Cluster Orchestrator manager class.

    This class is responsible for managing the peer cluster relation,
    which is used for communication between different OpenSearch clusters.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "peer_cluster_orchestrator_manager"

    def refresh_relation_data(  # noqa: C901
        self,
        event_rel_id: int | None = None,
        s3_credentials: S3RelDataCredentials | None = None,
        azure_credentials: AzureRelDataCredentials | None = None,
        gcs_credentials: GcsRelDataCredentials | None = None,
    ) -> None:
        """Refresh the peer cluster rel data (new cm node, admin password change etc.).

        This function is only called on leader unit. it returns whether
        a defer is needed.
        """
        # get deployment descriptor of current app
        deployment_desc = self.state.application.deployment_desc

        # compute the data that needs to be broadcast to all related clusters (success or error)
        rel_data = self.build_peer_cluster_rel_data(
            deployment_desc=deployment_desc,
            s3_credentials=s3_credentials,
            azure_credentials=azure_credentials,
            gcs_credentials=gcs_credentials,
        )

        orchestrators = self.state.application.orchestrators
        rel_err_data = self.build_peer_cluster_rel_err_data(
            deployment_desc, orchestrators, rel_data
        )

        # exit if current cluster should not have been considered a provider
        if (
            self.set_peer_cluster_err_data_if_wrong_integration(event_rel_id, rel_err_data)
            and event_rel_id
        ):
            return

        # store the main/failover-cm planned units count
        self.save_cluster_fleet_apps(deployment_desc)

        cluster_type = (
            "main" if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR else "failover"
        )

        # flag the trigger of the rel changed update on the consumer side
        if event_rel_id:
            peer_cluster = self.state.peer_cluster_by_relation_id(
                relation_id=event_rel_id, is_provider=True
            )
            if peer_cluster:
                peer_cluster.trigger = cluster_type

        # update reported orchestrators on local orchestrator
        # fetch stored orchestrators
        orchestrators_dict = orchestrators.to_dict()
        orchestrators_dict[f"{cluster_type}_app"] = deployment_desc.app.to_dict()
        self.state.application.orchestrators = PeerClusterOrchestrators.from_dict(
            orchestrators_dict
        )

        should_defer = rel_err_data and rel_err_data.should_wait

        # save the orchestrators of this fleet
        has_units = self.state.planned_units > 0
        for peer_cluster in self.state.peer_clusters(is_provider=True):
            orchestrators = peer_cluster.orchestrators
            logger.debug(
                "Provider Updating orchestrators for requirer %s previous orchestrators %s. Updating with cluster type %s with %s",
                peer_cluster.relation.app.name,
                orchestrators,
                cluster_type,
                deployment_desc.app.to_dict(),
            )
            orchestrators.update(
                {
                    f"{cluster_type}_app": deployment_desc.app.to_dict() if has_units else None,
                    f"{cluster_type}_rel_id": peer_cluster.relation.id if has_units else -1,
                }
            )
            # in case of demotion update the trigger
            peer_cluster.trigger = cluster_type
            peer_cluster.orchestrators = orchestrators

            # we add the hash of the rel_data to only emit a change event
            # if the data has actually changed
            if rel_data:
                peer_cluster.set_data(rel_data, is_provider=True)
            # there is no error to broadcast - we clear any previously broadcasted error
            if not rel_err_data:
                del peer_cluster.error_data
            else:
                peer_cluster.error_data = rel_err_data

            # if no planned units, delete relation data as it won't get updated
            if not has_units:
                del peer_cluster.error_data
        return should_defer

    def build_peer_cluster_rel_data(
        self,
        deployment_desc: DeploymentDescription | None,
        s3_credentials: S3RelDataCredentials | None,
        azure_credentials: AzureRelDataCredentials | None,
        gcs_credentials: GcsRelDataCredentials | None,
    ) -> PeerClusterRelData | None:
        """Build and return the peer cluster rel data to be shared with requirer sub-clusters."""
        # returns None if this cluster is not fully ready, or if the admin user
        # is not initialized
        if not deployment_desc:
            logger.debug("Cluster not ready to populate relation data")
            return None

        credentials = self.build_peer_cluster_rel_data_credentials(
            s3_creds=s3_credentials,
            azure_creds=azure_credentials,
            gcs_creds=gcs_credentials,
        )
        if not credentials:
            logger.debug("Admin user not initialized. Relation data not ready")
            return None

        cm_nodes = []
        try:
            cm_nodes = self.fetch_current_app_cm_nodes(deployment_desc)
        except OpenSearchHttpError:
            logger.warning(f"Could not fetch nodes in related {deployment_desc.typ} sub-cluster")

        return PeerClusterRelData(
            cluster_name=deployment_desc.config.cluster_name,
            cm_nodes=cm_nodes,
            credentials=credentials,
            deployment_desc=deployment_desc,
            security_index_initialised=self.is_security_index_initialised_in_all_clusters,
            first_data_node=self.first_data_node_in_all_clusters,
            plugins=(
                self.plugin_config_info
                if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
                else None
            ),
        )

    def fetch_current_app_cm_nodes(self, deployment_desc: DeploymentDescription) -> list[Node]:
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

            return [
                Node(
                    name=self.state.unit_name,
                    roles=computed_roles,
                    ip=self.state.host_ip,
                    app=deployment_desc.app,
                    unit_number=self.state.server.unit_id,
                )
            ]

        if cluster_fleet_apps := self.state.application.cluster_fleet_apps:
            # only report nodes from apps with planned units
            has_planned_units = (
                lambda app_id: app_id in cluster_fleet_apps
                and cluster_fleet_apps[app_id].planned_units > 0
            )
            nodes = [node for node in nodes if has_planned_units(node.app.id)]

        return [
            node
            for node in nodes
            if node.is_cm_eligible() and node.app.id == deployment_desc.app.id
        ]

    def build_peer_cluster_rel_data_credentials(
        self,
        s3_creds: S3RelDataCredentials | None,
        azure_creds: AzureRelDataCredentials | None,
        gcs_creds: GcsRelDataCredentials | None,
    ) -> PeerClusterRelDataCredentials | None:
        """Build and return the rel data credentials to be shared with requirer sub-clusters."""
        if self.state.application.is_admin_user_initialized:
            return PeerClusterRelDataCredentials(
                admin_username=ADMIN_USER,
                admin_password=self.state.secrets.get(Scope.APP, password_key(ADMIN_USER)),
                admin_password_hash=self.state.secrets.get(Scope.APP, hash_key(ADMIN_USER)),
                kibana_password=self.state.secrets.get(
                    Scope.APP, password_key(KIBANA_SERVER_USER)
                ),
                kibana_password_hash=self.state.secrets.get(
                    Scope.APP, hash_key(KIBANA_SERVER_USER)
                ),
                monitor_password=self.state.secrets.get(Scope.APP, password_key(COS_USER)),
                admin_tls=self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val),
                s3=s3_creds,
                azure=azure_creds,
                gcs=gcs_creds,
            )
        return None

    @property
    def is_security_index_initialised_in_all_clusters(self) -> bool:
        """Check if the security index is initialised."""
        if self.state.application.is_security_index_initialised:
            return True

        # check all other clusters if they have initialised the security index
        for related_peer_cluster in self.state.related_peer_clusters(is_provider=True):
            if related_peer_cluster.security_index_initialised:
                return True
        return False

    @property
    def first_data_node_in_all_clusters(self) -> str | None:
        """Check if the first data node is up in any of the related clusters."""
        if first_data_node := self.state.application.first_data_node:
            return first_data_node

        for related_peer_cluster in self.state.related_peer_clusters(is_provider=True):
            if related_peer_cluster.first_data_node:
                return related_peer_cluster.first_data_node
        return None

    @property
    def plugin_config_info(self) -> dict[str, PluginConfigInfo]:
        """Returns managed plugin configurations and grants related secrets to subclusters"""
        plugins = self.state.application.plugin_config_info
        return {
            label: plugin
            for label, plugin in plugins.items()
            if plugin.secret_id
            and self.state.secrets.grant_secret_to_subclusters(plugin.secret_id, is_provider=True)
        }

    @property
    def is_every_unit_marked_as_started(self) -> bool:
        """Check if every unit in the cluster is marked as started."""
        all_started = True
        for server in self.state.servers:
            if not server.started:
                all_started = False
                break

        if all_started:
            return True

        try:
            current_app_nodes = [
                node
                for node in self._nodes(self.opensearch_client.is_node_up())
                if node.app.id == self.state.application.deployment_desc.app.id
            ]
            return len(current_app_nodes) == self.state.planned_units
        except OpenSearchHttpError:
            return False

    def build_peer_cluster_rel_err_data(  # noqa: C901
        self,
        deployment_desc: DeploymentDescription | None,
        orchestrators: PeerClusterOrchestrators,
        rel_data: PeerClusterRelData | None,
    ) -> PeerClusterRelErrorData | None:
        """Build error peer relation data object."""
        should_sever_relation, should_retry, blocked_msg = False, True, None
        message_suffix = f"in related '{deployment_desc.typ}'"

        if not deployment_desc:
            blocked_msg = "'main/failover'-orchestrators not configured yet."
        elif deployment_desc.typ == DeploymentType.OTHER:
            should_sever_relation, should_retry = True, False
            blocked_msg = "Related to non 'main/failover'-orchestrator cluster."
        elif Directive.WAIT_FOR_PEER_CLUSTER_RELATION in deployment_desc.pending_directives:
            blocked_msg = f"Waiting for peer cluster relation to be created {message_suffix}."
        elif (
            orchestrators.main_app
            and orchestrators.main_app.id != deployment_desc.app.id
            and orchestrators.failover_app
            and orchestrators.failover_app.id != deployment_desc.app.id
        ):
            should_sever_relation, should_retry = True, False
            blocked_msg = (
                "Cannot have 2 'failover'-orchestrators. Relate to the existing failover."
            )
        elif not self.state.application.is_admin_user_initialized:
            blocked_msg = f"Admin user not fully configured {message_suffix}."
        elif not self.state.is_tls_full_configured_in_cluster:
            blocked_msg = f"TLS not fully configured {message_suffix}."
            should_retry = False
        elif (
            "data" in deployment_desc.config.roles
            or deployment_desc.start == StartMode.WITH_GENERATED_ROLES
        ):
            if not self.state.application.is_security_index_initialised:
                blocked_msg = f"Security index not initialized {message_suffix}."
        elif (
            self.state.application.is_data_role_in_cluster_fleet_apps
            and self.state.application.is_security_index_initialised
        ):
            # Requirer units should start after all provider units have started,
            # and only if the security index has already been initialized by a data node.
            # This avoids a potential deadlock where both orchestrator and data units
            # wait on each other to proceed.
            if not self.is_every_unit_marked_as_started:
                blocked_msg = f"Waiting for every unit {message_suffix} to start."
            elif not self.state.secrets.get(Scope.APP, password_key(COS_USER)):
                blocked_msg = f"'{COS_USER}' user not created yet."
            else:
                try:
                    if not self.fetch_current_app_cm_nodes(deployment_desc):
                        blocked_msg = f"No 'cluster_manager' eligible nodes found {message_suffix}"
                except OpenSearchHttpError as e:
                    logger.error(e)
                    blocked_msg = f"Could not fetch nodes {message_suffix}"
        elif rel_data and not rel_data.cm_nodes:
            blocked_msg = f"Could not fetch nodes in related {deployment_desc.typ} sub-cluster."

        if not blocked_msg:
            return None

        return PeerClusterRelErrorData(
            cluster_name=deployment_desc.config.cluster_name if deployment_desc else None,
            should_sever_relation=should_sever_relation,
            should_wait=should_retry,
            blocked_message=blocked_msg,
            deployment_desc=deployment_desc,
        )

    def set_peer_cluster_err_data_if_wrong_integration(
        self,
        event_rel_id: int,
        rel_err_data: PeerClusterRelErrorData | None,
    ) -> bool:
        """Check if relation is invalid and notify related sub-clusters."""
        if not rel_err_data or not rel_err_data.should_sever_relation:
            return False

        for peer_cluster in self.state.peer_clusters(is_provider=True):
            peer_cluster.error_data = rel_err_data

        # delete trigger
        if peer_cluster := self.state.peer_cluster_by_relation_id(
            relation_id=event_rel_id, is_provider=True
        ):
            logger.warning(
                "Relation with %s severed due to wrong integration: %s",
                peer_cluster.relation.app.name,
                rel_err_data.blocked_message,
            )
            del peer_cluster.trigger
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
        for peer_cluster in self.state.peer_clusters(is_provider=True):
            peer_cluster.cluster_fleet_apps = cluster_fleet_apps

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
        related_peer_clusters = self.state.related_peer_clusters(is_provider=True)
        n_disconnected = sum(
            1
            for p_cluster in related_peer_clusters
            if (p_cluster.main_orchestrator_registered.lower() == "false")
        )

        # check if failover is disconnected from main orchestrator
        orchestrators = self.state.application.orchestrators
        if not orchestrators.main_app:
            n_disconnected += 1

        # if majority are disconnected, promote failover
        return n_disconnected > (len(related_peer_clusters) + 1) // 2

    def promote_failover(self) -> None:
        """Handle failover promotion to main orchestrator."""
        logger.debug("Promoting unit %s from failover to main", self.state.unit_name)
        # remove old main and promote new failover
        orchestrators = self.state.application.orchestrators
        orchestrators.promote_failover()
        self.state.application.orchestrators = orchestrators

        related_peer_clusters = self.state.peer_clusters(is_provider=True)
        for p_cluster in related_peer_clusters:
            p_cluster.trigger = "main"

    def reconcile_security_index_initialised(self) -> None:
        """Check if security index is initialised in any cluster and update state."""
        if self.is_security_index_initialised_in_all_clusters:
            self.state.application.is_security_index_initialised = True
            # clean up the first data node attribute when security index is initialised
            del self.state.application.first_data_node

    def broadcast_new_failover_app(self, peer_cluster_app: PeerClusterApp) -> None:
        """Broadcasts the new failover in all the cluster fleet"""
        candidate_failover_app = peer_cluster_app.app
        for p_cluster in self.state.peer_clusters(is_provider=True):
            logger.debug(
                "Broadcasting failover: %s to relation id: %s",
                peer_cluster_app.app.name,
                p_cluster.relation.id,
            )
            # Update the orchestrators
            orchestrators = PeerClusterOrchestrators.from_dict(p_cluster.orchestrators)
            orchestrators.failover_app = candidate_failover_app
            p_cluster.orchestrators = orchestrators.to_dict()

    def clean_all_provider_relation_data(self):
        """Clean all relation data on provider."""
        for peer_cluster in self.state.peer_clusters(is_provider=True):
            self._delete_rel_data(peer_cluster.relation.id)

    def _delete_rel_data(self, rel_id: int) -> None:
        """Deletes relation data"""
        peer_cluster = self.state.peer_cluster_by_relation_id(is_provider=True, relation_id=rel_id)
        if peer_cluster:
            peer_cluster.delete_data()
            del peer_cluster.rel_data_hash
            del peer_cluster.error_data
            del peer_cluster.cluster_fleet_apps
            del peer_cluster.orchestrators
            del peer_cluster.trigger
