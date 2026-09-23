#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Peer Cluster manager."""

import logging

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

from opensearch_single_kernel.common.constants import (
    DeploymentType,
    Directive,
    State,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchPeerClusterRelationDataIncompleteError,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    PeerClusterErrorDataStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.core.base_models import (
    DeploymentDescription,
    Node,
    PeerClusterOrchestrators,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.core.relation_models import (
    PeerClusterAppModel,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.peer_cluster import peer_cluster_credentials
from opensearch_single_kernel.utils.status import running_statuses
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PeerClusterManager(BaseManager):
    """OpenSearch Peer Cluster manager class.

    This class is responsible for managing the peer cluster relation,
    which is used for communication between different OpenSearch clusters.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "peer_cluster_manager")

    def set_current_app_in_cluster_fleet(
        self, rel_id: int, deployment_desc: DeploymentDescription, is_provider: bool
    ) -> None:
        """Report the current app on the peer cluster rel data to be broadcast to all apps."""
        current_app = self.state.current_peer_cluster_app
        if local_peer_cluster := self.state.peer_cluster_by_relation_id(
            is_provider=is_provider, relation_id=rel_id, remote=False
        ):
            local_peer_cluster.app = current_app

        # update content of fleet in the current app's peer databag
        remote_peer_cluster = self.state.peer_cluster_by_relation_id(
            relation_id=rel_id,
            is_provider=is_provider,
            remote=True,
        )
        related_cluster_fleet_apps = (
            remote_peer_cluster.cluster_fleet_apps if remote_peer_cluster else {}
        )
        related_cluster_fleet_apps[deployment_desc.app.id] = current_app

        # Update the application peer databag
        cluster_fleet_apps = self.state.application.cluster_fleet_apps
        cluster_fleet_apps.update(related_cluster_fleet_apps)
        self.state.application.cluster_fleet_apps = cluster_fleet_apps

    def update_local_app_from_peer_cluster_rel_data(self, peer_data: PeerClusterAppModel) -> None:
        """Unmarshal: update the local app peer model using peer cluster relation data."""
        items: dict = {
            "first_data_node": peer_data.first_data_node,
            "nodes_config": peer_data.nodes_config,
            **peer_cluster_credentials(peer_data),
        }

        if items["admin_password"] or peer_data.admin_hashed_password:
            items["admin_user_initialized"] = True

        if peer_data.plugin_config_info:
            items["plugin_config_info"] = peer_data.plugin_config_info
        if peer_data.plugin_secrets and peer_data.plugin_secrets.strip():
            items["plugin_secrets"] = peer_data.plugin_secrets

        self.state.application.update(items)

    def update_main_orchestrator_registered(self, rel_id: int, value: bool | None) -> None:
        """Update whether the main orchestrator is registered in the relation data.

        A ``None`` value removes the key from the relation data.
        """
        if rel_id == -1:
            return
        local_peer_cluster_data = self.state.peer_cluster_by_relation_id(
            is_provider=False, relation_id=rel_id, remote=False
        )

        if local_peer_cluster_data:
            local_peer_cluster_data.main_orchestrator_registered = value
        else:
            logger.debug(
                "No local peer cluster data found for relation id %s to update main_orchestrator_registered",
                rel_id,
            )

    def reconcile_orchestrators_from_provider_data(
        self,
        remote_peer_cluster: PeerClusterAppModel,
        trigger: str | None,
        relation_id: int,
        relation_app_name: str,
        relation_units: int,
    ) -> PeerClusterOrchestrators:
        """Register the orchestrator announced by the provider of ``relation_id``."""
        orchestrators = self.state.application.orchestrators.model_copy()
        if trigger not in {"main", "failover"} or relation_units == 0:
            return orchestrators

        logger.debug(
            "Updating local orchestrator from provider %s with relation id %s. trigger %s. "
            "The provider orchestrators are %s",
            relation_app_name,
            relation_id,
            trigger,
            remote_peer_cluster.orchestrators,
        )
        # If this relation previously held the opposite role, clear that stale entry.
        # Without this, a relation switching from trigger=main to trigger=failover
        # (or vice versa) leaves both main_* and failover_* pointing to the same app,
        # causing is_failover_promoted() to fire a false positive and wipe failover state.
        # The app is only taken from the event relation: other peer cluster relations
        # may carry a stale value for it.
        remote_orchestrators = remote_peer_cluster.orchestrators
        if trigger == "main":
            if orchestrators.failover_rel_id == relation_id:
                orchestrators.delete("failover")
            orchestrators.main_rel_id = relation_id
            orchestrators.main_app = remote_orchestrators.main_app
        else:
            if orchestrators.main_rel_id == relation_id:
                orchestrators.delete("main")
            orchestrators.failover_rel_id = relation_id
            orchestrators.failover_app = remote_orchestrators.failover_app
        self.state.application.orchestrators = orchestrators.model_copy()
        return orchestrators

    def error_set_from_providers(
        self,
        orchestrators: PeerClusterOrchestrators,
        event_rel_id: int,
    ) -> PeerClusterRelErrorData | None:
        """Check if the providers are ready and return their error if not."""
        orchestrator_rel_ids = [
            rel_id
            for rel_id in [orchestrators.main_rel_id, orchestrators.failover_rel_id]
            if rel_id != -1
        ]

        for rel_id in orchestrator_rel_ids:
            remote_peer_cluster = self.state.peer_cluster_by_relation_id(
                relation_id=rel_id,
                is_provider=False,
                remote=True,
            )
            has_data = (
                remote_peer_cluster and remote_peer_cluster.deployment_description is not None
            )
            error_data = remote_peer_cluster.error_data if remote_peer_cluster else None
            if not has_data and not error_data:  # relation data still incomplete
                raise OpenSearchPeerClusterRelationDataIncompleteError(
                    f"Peer cluster relation data is incomplete for relation id {rel_id}"
                )

            if not error_data:
                continue

            # A failover orchestrator that is not-ready-yet must not block a requirer from
            # bootstrapping off an already-ready main orchestrator. Otherwise, the whole fleet
            # blocks waiting for failover. Only the main
            # orchestrator's errors, or a failover error that requires
            # severing the relation, should block here.
            if (
                rel_id == orchestrators.failover_rel_id
                and orchestrators.main_rel_id != -1
                and not error_data.should_sever_relation
            ):
                continue

            return error_data

        # handle the case where the error came from the provider of a wrong relation
        if event_rel_id not in orchestrator_rel_ids and (
            wrong_rel_peer_cluster := self.state.peer_cluster_by_relation_id(
                relation_id=event_rel_id,
                is_provider=False,
                remote=True,
            )
        ):
            return wrong_rel_peer_cluster.error_data

        return None

    def requirer_errors(  # noqa: C901
        self,
        orchestrators: PeerClusterOrchestrators,
        deployment_desc: DeploymentDescription,
        peer_cluster_rel_data: PeerClusterAppModel,
        event_rel_id: int | None,
    ) -> PeerClusterRelErrorData | None:
        """Fetch error when relation is wrong and can only be computed on the requirer side."""
        blocked_msg = None
        provider_deployment_desc = peer_cluster_rel_data.deployment_description
        if (
            provider_deployment_desc
            and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
            and (
                provider_deployment_desc.promotion_time is None
                or deployment_desc.promotion_time > provider_deployment_desc.promotion_time
            )
        ):
            cluster_fleet_apps = self.state.application.cluster_fleet_apps
            provider_app_id = provider_deployment_desc.app.id
            if (
                provider_app_id in cluster_fleet_apps
                and cluster_fleet_apps[provider_app_id].planned_units > 0
            ):
                blocked_msg = (
                    PeerClusterErrorDataStatuses.PEER_CLUSTER_MAIN_IS_REQUIRER.value.message
                )
        elif event_rel_id and (
            event_rel_id
            not in [
                orchestrators.main_rel_id,
                orchestrators.failover_rel_id,
            ]
        ):
            blocked_msg = PeerClusterErrorDataStatuses.CLUSTER_CAN_ONLY_HAVE_ONE_MAIN_OR_FAILOVER.value.message
        elif (
            provider_deployment_desc
            and provider_deployment_desc.config.cluster_name != deployment_desc.config.cluster_name
        ):
            contains_inherit_directive = (
                Directive.INHERIT_CLUSTER_NAME in deployment_desc.pending_directives
            )
            if not contains_inherit_directive or (
                contains_inherit_directive
                and not provider_deployment_desc.cluster_name_autogenerated
            ):
                blocked_msg = PeerClusterErrorDataStatuses.CANNOT_RELATE_TO_CLUSTER_WITH_DIFFERENT_NAME.value.message

        provider_cluster_name = (
            provider_deployment_desc.config.cluster_name if provider_deployment_desc else None
        )
        logger.debug(
            f"This is cluster_name from provider: {provider_cluster_name}, "
            f"and this is cluster_name from requirer: {deployment_desc.config.cluster_name}"
        )

        if blocked_msg:
            return PeerClusterRelErrorData(
                should_sever_relation=True,
                should_wait=False,
                blocked_message=blocked_msg,
            )
        else:
            return None

    def set_security_index_initialised(self) -> None:
        """Set the security index as initialised."""
        # get the MAIN orchestrator
        orchestrators = self.state.application.orchestrators
        if orchestrators.main_app is None:
            return None

        local_peer_cluster = self.state.peer_cluster_by_relation_id(
            is_provider=False,
            relation_id=orchestrators.main_rel_id,
            remote=False,
        )
        if not local_peer_cluster:
            return None

        local_peer_cluster.security_index_initialised = True

    def cm_nodes(self, orchestrators: PeerClusterOrchestrators) -> list[Node]:
        """Fetch the cm nodes passed from the peer cluster relation not api call."""
        cm_nodes = {}
        for rel_id in [orchestrators.main_rel_id, orchestrators.failover_rel_id]:
            if rel_id == -1:
                continue

            remote_peer_cluster = self.state.peer_cluster_by_relation_id(
                relation_id=rel_id,
                is_provider=False,
                remote=True,
            )
            if not remote_peer_cluster:  # not ready yet
                continue

            cm_nodes = {
                **cm_nodes,
                **{node.name: node for node in remote_peer_cluster.nodes_config.values()},
            }

        # attempt to have an opensearch reported list of CMs - the response
        # may be smaller or greater than previous list.
        try:
            for attempt in Retrying(stop=stop_after_attempt(3), wait=wait_fixed(0.5)):
                with attempt:
                    all_nodes = self._nodes(
                        self.opensearch_client.is_node_up(),
                        hosts=self.alt_hosts + [node.ip for node in cm_nodes],
                    )
                    cm_nodes = {
                        **cm_nodes,
                        **{node.name: node for node in all_nodes if node.is_cm_eligible()},
                    }
        except RetryError:
            pass

        return list(cm_nodes.values())

    def is_any_cm_up(self) -> bool:
        """Check if there is at least one cluster manager node up."""
        cm_nodes = self.cm_nodes(self.state.application.orchestrators)
        for node in cm_nodes:
            # 503 security index not initialised is a valid response,
            # we just need to check if the node is up
            if self.opensearch_client.is_node_up(node.ip, any_resp_code=True):
                return True
        return False

    def reconcile_is_candidate_failover_orchestrator(self, relation_id: int) -> None:
        """Reconcile the is_candidate_failover_orchestrator key in relation data"""
        deployment_desc = self.state.application.deployment_description
        if not deployment_desc:
            return

        local_peer_cluster = self.state.peer_cluster_by_relation_id(
            relation_id=relation_id,
            is_provider=False,
            remote=False,
        )

        if not local_peer_cluster:
            return
        if deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR:
            local_peer_cluster.is_candidate_failover_orchestrator = True
        else:
            del local_peer_cluster.is_candidate_failover_orchestrator

    def delete_departed_orchestrator(
        self, event_src_cluster_type: str, orchestrators: PeerClusterOrchestrators
    ) -> None:
        """Delete the orchestrator that left the relation from the state and cluster fleet."""
        # delete the orchestrator that triggered this event
        if event_src_cluster_type == "main" and orchestrators.main_app:
            orchestrator_app_id = orchestrators.main_app.id
        elif event_src_cluster_type == "failover" and orchestrators.failover_app:
            orchestrator_app_id = orchestrators.failover_app.id
        else:
            return

        cluster_fleet_apps = self.state.application.cluster_fleet_apps
        cluster_fleet_apps.pop(orchestrator_app_id, None)
        self.state.application.cluster_fleet_apps = cluster_fleet_apps

        orchestrators.delete(event_src_cluster_type)
        self.state.application.orchestrators = orchestrators

    def refresh_requirer_relation_data(self) -> None:
        """Refresh the peer cluster rel data (planned units).

        Only call this method on leader. This will update the planned units.
        """
        deployment_desc = self.state.application.deployment_description
        all_relations = [rel for rel in self.state.peer_cluster_relations if len(rel.units) > 0]
        for rel in all_relations:
            self.set_current_app_in_cluster_fleet(
                rel_id=rel.id, deployment_desc=deployment_desc, is_provider=False
            )

    def should_promote_failover_to_main(self) -> bool:
        """Check if majority of related apps are disconnected from main orchestrator.

        This runs on the failover application.
        """
        # Count related apps that have lost the main orchestrator.
        remote_peer_clusters = self.state.peer_clusters(is_provider=True, remote=True)
        n_disconnected = sum(
            1
            for p_cluster in remote_peer_clusters
            if p_cluster.main_orchestrator_registered is False
        )

        # The failover app itself may also be disconnected.
        orchestrators = self.state.application.orchestrators
        if not orchestrators.main_app:
            n_disconnected += 1

        # Promote only once a majority is cut off.
        return n_disconnected > (len(remote_peer_clusters) + 1) // 2

    @override
    def get_statuses(  # noqa: C901
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute peer-cluster statuses from orchestrator and relation state."""
        status_list = running_statuses(self.state.statuses, scope, self.name)

        if not self.state.application.deployment_description:
            return status_list

        if scope == "app":
            requirer_peer_clusters = self.state.peer_clusters(is_provider=False, remote=True)
            orchestrators = self.state.application.orchestrators
            has_no_orchestrators = (
                orchestrators and not orchestrators.main_app and not orchestrators.failover_app
            )
            if (
                orchestrators
                and not orchestrators.main_app
                and orchestrators.failover_app
                # On scale-up from 0, cluster manager owns these statuses.
                and Directive.WAIT_FOR_PEER_CLUSTER_RELATION
                not in self.state.application.deployment_description.pending_directives
            ):
                if self.should_promote_failover_to_main():
                    status_list.append(
                        PeerClusterStatuses.PEER_CLUSTER_WAITING_FOR_FAILOVER_PROMOTION.value
                    )
                else:
                    status_list.append(
                        PeerClusterStatuses.PEER_CLUSTER_MAIN_ORCHESTRATOR_REMOVED_WITHOUT_MAJORITY.value
                    )
            elif has_no_orchestrators and (
                (self.state.is_peer_cluster_consumer() and requirer_peer_clusters)
                or (
                    self.state.application.deployment_description.typ == DeploymentType.OTHER
                    and self.state.application.deployment_description.state.value == State.ACTIVE
                    and not requirer_peer_clusters
                )
            ):
                status_list.append(PeerClusterStatuses.PEER_CLUSTER_ORCHESTRATORS_REMOVED.value)
            for peer_cluster in requirer_peer_clusters:
                # check if there is an error reported directly by the provider
                if (error_data := peer_cluster.error_data) and (status := error_data.get_status()):
                    status_list.append(status)

                if peer_cluster.deployment_description is not None:
                    requirer_errors = self.requirer_errors(
                        orchestrators=orchestrators,
                        deployment_desc=self.state.application.deployment_description,
                        peer_cluster_rel_data=peer_cluster,
                        # only check if we have orchestrators in the data bag
                        event_rel_id=peer_cluster.relation.id if orchestrators.main_app else None,
                    )
                    if requirer_errors and (status := requirer_errors.get_status()):
                        status_list.append(status)
        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
