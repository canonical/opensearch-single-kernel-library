#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Peer Cluster manager."""

import json
import logging
from typing import Any, MutableMapping

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

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
from opensearch_single_kernel.common.exceptions import (
    OpenSearchPeerClusterRelationDataIncompleteError,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    PeerClusterErrorDataStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.core.models import (
    DeploymentDescription,
    Node,
    PeerClusterApp,
    PeerClusterOrchestrators,
    PeerClusterRelData,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.core.peer_cluster_relation import PeerCluster
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import (
    format_unit_name,
)
from opensearch_single_kernel.utils.secrets import hash_key, password_key
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
        current_app = PeerClusterApp(
            app=deployment_desc.app,
            planned_units=self.state.planned_units,
            units=[
                format_unit_name(unit, app=deployment_desc.app) for unit in self.state.all_units
            ],
            roles=(
                deployment_desc.config.roles
                if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES
                else GENERATED_ROLES
            ),
        )
        local_peer_cluster = self.state.peer_cluster_by_relation_id(
            is_provider=is_provider, relation_id=rel_id, remote=False
        )
        local_peer_cluster.update({"app": current_app.to_str()})

        # update content of fleet in the current app's peer databag
        remote_peer_cluster = self.state.peer_cluster_by_relation_id(
            relation_id=rel_id,
            is_provider=is_provider,
            remote=True,
        )
        related_cluster_fleet_apps = remote_peer_cluster.cluster_fleet_apps
        related_cluster_fleet_apps.update({deployment_desc.app.id: current_app})

        # Update peer application databag
        cluster_fleet_apps = self.state.application.cluster_fleet_apps
        cluster_fleet_apps.update(related_cluster_fleet_apps)
        self.state.application.cluster_fleet_apps = cluster_fleet_apps

    def update_main_orchestrator_registered(self, rel_id: int, value: bool) -> None:
        """Update whether the main orchestrator is registered in the relation data."""
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

    def remove_main_orchestrator_registered(self, rel_id: int) -> None:
        """Remove the main_orchestrator_registered key form relation data."""
        if local_peer_cluster_data := self.state.peer_cluster_by_relation_id(
            is_provider=False, relation_id=rel_id, remote=False
        ):
            del local_peer_cluster_data.main_orchestrator_registered

    def reconcile_orchestrators_from_provider_data(
        self,
        remote_peer_cluster: PeerCluster,
        data: MutableMapping[str, str],
        trigger: str | None,
        relation_id: str,
        relation_app_name: str,
        relation_units: int,
    ) -> PeerClusterOrchestrators:
        """Fetch related orchestrator IDs and App names."""
        if not (remote_orchestrators := remote_peer_cluster.orchestrators):
            remote_orchestrators = json.loads(data["orchestrators"])
        logger.debug(
            "Fetched orchestrators from provider %s with relation id %s are %s",
            relation_app_name,
            relation_id,
            remote_orchestrators,
        )

        # fetch the (main/failover)-cluster-orchestrator relations
        for remote_peer_cluster in self.state.peer_clusters(is_provider=False, remote=True):
            remote_orchestrators.update(remote_peer_cluster.orchestrators)

        local_orchestrators = self.state.application.orchestrators_dict

        if (trigger in {"main", "failover"}) and (relation_units > 0):
            logger.debug(
                "Updating local orchestrator from provider %s. trigger %s The orchestrators are %s",
                relation_app_name,
                trigger,
                remote_orchestrators,
            )
            # If this relation previously held the opposite role, clear that stale entry.
            # Without this, a relation switching from trigger=main to trigger=failover
            # (or vice versa) leaves both main_* and failover_* pointing to the same app,
            # causing is_failover_promoted() to fire a false positive and wipe failover state.
            opposite = "failover" if trigger == "main" else "main"
            if local_orchestrators.get(f"{opposite}_rel_id") == relation_id:
                local_orchestrators[f"{opposite}_rel_id"] = -1
                local_orchestrators[f"{opposite}_app"] = None
            local_orchestrators.update(
                {
                    f"{trigger}_rel_id": relation_id,
                    f"{trigger}_app": remote_orchestrators[f"{trigger}_app"],
                }
            )
            self.state.application.orchestrators = PeerClusterOrchestrators.from_dict(
                local_orchestrators
            )

        return PeerClusterOrchestrators.from_dict(local_orchestrators)

    def error_set_from_providers(
        self,
        orchestrators: PeerClusterOrchestrators,
        event_data: MutableMapping[str, Any] | None,
        event_rel_id: int,
    ) -> tuple[PeerClusterRelErrorData | None, int]:
        """Check if the providers are ready and set error if not."""
        orchestrator_rel_ids = [
            rel_id
            for rel_id in [orchestrators.main_rel_id, orchestrators.failover_rel_id]
            if rel_id != -1
        ]

        error = None
        # We need to know from where the error comes from to set the correct relation data key
        rel_error_id = -1
        for rel_id in orchestrator_rel_ids:
            remote_peer_cluster = self.state.peer_cluster_by_relation_id(
                relation_id=rel_id,
                is_provider=False,
                remote=True,
            )
            data = remote_peer_cluster.relation_data.get("data", {}) if remote_peer_cluster else {}
            error_data = (
                remote_peer_cluster.get_object("error_data") if remote_peer_cluster else {}
            )
            if not data and not error_data:  # relation data still incomplete
                raise OpenSearchPeerClusterRelationDataIncompleteError(
                    f"Peer cluster relation data is incomplete for relation id {rel_id}"
                )

            if error_data:
                error = error_data
                rel_error_id = rel_id
                break

        # we handle the case where the error came from the provider of a wrong relation
        if not error and "error_data" in (event_data or {}):
            error = json.loads(event_data["error_data"])
            rel_error_id = event_rel_id

        if rel_error_id == -1:
            rel_error_id = event_rel_id

        return (PeerClusterRelErrorData.from_dict(error) if error else None, rel_error_id)

    def requirer_errors(  # noqa: C901
        self,
        orchestrators: PeerClusterOrchestrators,
        deployment_desc: DeploymentDescription,
        peer_cluster_rel_data: PeerClusterRelData,
        event_rel_id: int | None,
    ) -> PeerClusterRelErrorData | None:
        """Fetch error when relation is wrong and can only be computed on the requirer side."""
        blocked_msg = None
        provider_deployment_desc = peer_cluster_rel_data.deployment_desc
        if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR and (
            provider_deployment_desc.promotion_time is None
            or deployment_desc.promotion_time > provider_deployment_desc.promotion_time
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
            blocked_msg = (
                PeerClusterErrorDataStatuses.CLUSTER_CAN_ONLY_HAVE_ONE_MAIN_OR_FAILOVER.value.message
            )
        elif peer_cluster_rel_data.cluster_name != deployment_desc.config.cluster_name:
            contains_inherit_directive = (
                Directive.INHERIT_CLUSTER_NAME in deployment_desc.pending_directives
            )
            if not contains_inherit_directive or (
                contains_inherit_directive
                and not provider_deployment_desc.cluster_name_autogenerated
            ):
                blocked_msg = (
                    PeerClusterErrorDataStatuses.CANNOT_RELATE_TO_CLUSTER_WITH_DIFFERENT_NAME.value.message
                )

        logger.debug(
            f"This is cluster_name from provider: {peer_cluster_rel_data.cluster_name}, "
            f"and this is cluster_name from requirer: {deployment_desc.config.cluster_name}"
        )

        if blocked_msg:
            return PeerClusterRelErrorData(
                cluster_name=peer_cluster_rel_data.cluster_name,
                should_sever_relation=True,
                should_wait=False,
                blocked_message=blocked_msg,
                deployment_desc=deployment_desc,
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

    def update_admin_secrets_from_relation(
        self, peer_cluster_rel_data: PeerClusterRelData
    ) -> None:
        """Update secrets based on the peer cluster relation data."""
        # set admin secrets
        self.state.secrets.put(
            Scope.APP,
            password_key(ADMIN_USER),
            peer_cluster_rel_data.credentials.admin_password,
        )
        self.state.secrets.put(
            Scope.APP,
            hash_key(ADMIN_USER),
            peer_cluster_rel_data.credentials.admin_password_hash,
        )
        self.state.secrets.put(
            Scope.APP,
            password_key(KIBANA_SERVER_USER),
            peer_cluster_rel_data.credentials.kibana_password,
        )
        self.state.secrets.put(
            Scope.APP,
            hash_key(KIBANA_SERVER_USER),
            peer_cluster_rel_data.credentials.kibana_password_hash,
        )
        self.state.secrets.put(
            Scope.APP,
            password_key(COS_USER),
            peer_cluster_rel_data.credentials.monitor_password,
        )

        self.state.secrets.put_object(
            Scope.APP, CertType.APP_ADMIN.val, peer_cluster_rel_data.credentials.admin_tls
        )

        self.state.application.is_admin_user_initialized = True

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
            if not (data := remote_peer_cluster.data()):  # not ready yet
                continue

            cm_nodes = {**cm_nodes, **{node.name: node for node in data.cm_nodes}}

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
        deployment_desc = self.state.application.deployment_desc
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

    def delete_departed_orchestrator(self, event_src_cluster_type: str) -> None:
        """Delete the orchestrator that left the relation from the state and cluster fleet."""
        orchestrators = self.state.application.orchestrators
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

    def cleanup_error_in_relation_data(self) -> None:
        """Clean up the error data in relation data when the error is resolved."""
        for key, _ in self.state.application.relation_data.items():
            if key.startswith("error_from_provider") or key.startswith("error_from_requirer"):
                # get the relation id from key
                rel_id = int(key.split("-")[-1])
                relation_ids = [rel.id for rel in self.state.peer_cluster_relations]
                if rel_id not in relation_ids:
                    self.state.application.relation_data.pop(key)

    def refresh_requirer_relation_data(self) -> None:
        """Refresh the peer cluster rel data (planned units).

        Only call this method on leader. This will update the planned units.
        """
        deployment_desc = self.state.application.deployment_desc
        all_relations = [rel for rel in self.state.peer_cluster_relations if len(rel.units) > 0]
        for rel in all_relations:
            self.set_current_app_in_cluster_fleet(
                rel_id=rel.id, deployment_desc=deployment_desc, is_provider=False
            )

    @override
    def get_statuses(  # noqa: C901
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute peer-cluster statuses pure from orchestrator and relation state.

        Orchestrator-removed / failover-waiting statuses are plain blocked/waiting
        (not running). ``recompute`` is accepted for protocol compatibility.
        """
        status_list = running_statuses(self.state.statuses, scope, self.name)

        if not self.state.application.deployment_desc:
            return status_list

        if scope == "app":
            orchestrators = self.state.application.orchestrators
            # Empty dict means orchestrators were never related
            # dict with empty ids means orchestrators departed (cleaned on depart event)
            if self.state.application.orchestrators_dict:
                if (
                    not orchestrators.main_app
                    and orchestrators.failover_app
                    # if result of scale up after 0 the statuses will be set from cluster manager
                    and Directive.WAIT_FOR_PEER_CLUSTER_RELATION
                    not in self.state.application.deployment_desc.pending_directives
                ):
                    if self.state.should_promote_failover_to_main():
                        status_list.append(
                            PeerClusterStatuses.PEER_CLUSTER_WAITING_FOR_FAILOVER_PROMOTION.value
                        )
                    else:
                        status_list.append(
                            PeerClusterStatuses.PEER_CLUSTER_MAIN_ORCHESTRATOR_REMOVED_WITHOUT_MAJORITY.value
                        )

                elif not orchestrators.main_app and not orchestrators.failover_app:
                    status_list.append(
                        PeerClusterStatuses.PEER_CLUSTER_ORCHESTRATORS_REMOVED.value
                    )
            for peer_cluster in self.state.peer_clusters(remote=True, is_provider=False):
                # check if there is an error
                if error_data := peer_cluster.error_data:
                    status_list.append(error_data.get_status())

                # requirer errors
                if data := peer_cluster.data():
                    requirer_errors = self.requirer_errors(
                        orchestrators=orchestrators,
                        deployment_desc=self.state.application.deployment_desc,
                        peer_cluster_rel_data=data,
                        # only check if we have orchestrators in the data bag
                        event_rel_id=peer_cluster.relation.id if orchestrators.main_app else None,
                    )
                    if requirer_errors and (status := requirer_errors.get_status()):
                        status_list.append(status)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
