#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Peer Cluster manager."""

import json
import logging
from typing import Any, MutableMapping

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
from opensearch_single_kernel.common.statuses import CharmStatuses
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
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PeerClusterManager(BaseManager):
    """OpenSearch Peer Cluster manager class.

    This class is responsible for managing the peer cluster relation,
    which is used for communication between different OpenSearch clusters.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "peer_cluster_manager"

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
        peer_cluster = self.state.peer_cluster_by_relation_id(
            is_provider=is_provider, relation_id=rel_id
        )
        peer_cluster.update({"app": current_app.to_str()})

        # update content of fleet in the current app's peer databag
        related_peer_cluster = self.state.related_peer_cluster_by_relation_id(
            relation_id=rel_id, is_provider=is_provider
        )
        related_cluster_fleet_apps = related_peer_cluster.cluster_fleet_apps
        related_cluster_fleet_apps.update({deployment_desc.app.id: current_app})

        # Update peer application databag
        cluster_fleet_apps = self.state.application.cluster_fleet_apps
        cluster_fleet_apps.update(related_cluster_fleet_apps)
        self.state.application.cluster_fleet_apps = cluster_fleet_apps

    def update_main_orchestrator_registered(self, rel_id: int) -> None:
        """Update whether the main orchestrator is registered in the relation data."""
        orchestrators = self.state.application.orchestrators
        if rel_id == -1:
            return
        local_peer_cluster_data = self.state.peer_cluster_by_relation_id(
            is_provider=False, relation_id=rel_id
        )
        if local_peer_cluster_data:
            local_peer_cluster_data.main_orchestrator_registered = (
                orchestrators.main_app is not None
            )

    def remove_main_orchestrator_registered(self, rel_id: int) -> None:
        """Remove the main_orchestrator_registered key form relation data."""
        if local_peer_cluster_data := self.state.peer_cluster_by_relation_id(
            is_provider=False, relation_id=rel_id
        ):
            local_peer_cluster_data.update({"main_orchestrator_registered": ""})

    def reconcile_orchestrators_from_provider_data(
        self,
        related_peer_cluster: PeerCluster,
        data: MutableMapping[str, str],
        trigger: str | None,
        relation_id: str,
        relation_app_name: str,
        relation_units: int,
    ) -> PeerClusterOrchestrators:
        """Fetch related orchestrator IDs and App names."""
        if not (orchestrators_dict := related_peer_cluster.orchestrators.to_dict()):
            orchestrators_dict = json.loads(data["orchestrators"])

        # fetch the (main/failover)-cluster-orchestrator relations
        for related_peer_cluster in self.state.related_peer_clusters(is_provider=False):
            orchestrators_dict.update(related_peer_cluster.orchestrators.to_dict())

        local_orchestrators = self.state.application.orchestrators.to_dict()

        if (trigger in {"main", "failover"}) and (relation_units > 0):
            logger.debug(
                "Updating local orchestrator from provider %s. trigger %s The orchestrators are %s",
                relation_app_name,
                trigger,
                orchestrators_dict,
            )
            local_orchestrators.update(
                {
                    f"{trigger}_rel_id": relation_id,
                    f"{trigger}_app": orchestrators_dict[f"{trigger}_app"],
                }
            )

        return PeerClusterOrchestrators.from_dict(local_orchestrators)

    def error_set_from_providers(
        self,
        orchestrators: PeerClusterOrchestrators,
        event_data: MutableMapping[str, Any] | None,
    ) -> PeerClusterRelErrorData | None:
        """Check if the providers are ready and set error if not."""
        orchestrator_rel_ids = [
            rel_id
            for rel_id in [orchestrators.main_rel_id, orchestrators.failover_rel_id]
            if rel_id != -1
        ]

        error = None
        for rel_id in orchestrator_rel_ids:
            related_peer_cluster = self.state.related_peer_cluster_by_relation_id(
                relation_id=rel_id, is_provider=False
            )
            data = (
                related_peer_cluster.relation_data.get("data", {}) if related_peer_cluster else {}
            )
            error_data = (
                related_peer_cluster.get_object("error_data") if related_peer_cluster else {}
            )
            if not data and not error_data:  # relation data still incomplete
                raise OpenSearchPeerClusterRelationDataIncompleteError(
                    f"Peer cluster relation data is incomplete for relation id {rel_id}"
                )

            if error_data:
                error = error_data
                break

        # we handle the case where the error came from the provider of a wrong relation
        if not error and "error_data" in (event_data or {}):
            error = json.loads(event_data["error_data"])

        return PeerClusterRelErrorData.from_dict(error) if error else None

    def requirer_errors(  # noqa: C901
        self,
        orchestrators: PeerClusterOrchestrators,
        deployment_desc: DeploymentDescription,
        peer_cluster_rel_data: PeerClusterRelData,
        event_rel_id: int,
    ) -> bool:
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
                and cluster_fleet_apps[provider_app_id]["planned_units"] > 0
            ):
                blocked_msg = CharmStatuses.PEER_CLUSTER_MAIN_IS_REQUIRER.value.message
        elif event_rel_id not in [
            orchestrators.main_rel_id,
            orchestrators.failover_rel_id,
        ]:
            blocked_msg = (
                "A cluster can only be related to 1 main and 1 failover-clusters at most."
            )
        elif peer_cluster_rel_data.cluster_name != deployment_desc.config.cluster_name:
            contains_inherit_directive = (
                Directive.INHERIT_CLUSTER_NAME in deployment_desc.pending_directives
            )
            if not contains_inherit_directive or (
                contains_inherit_directive
                and not provider_deployment_desc.cluster_name_autogenerated
            ):
                blocked_msg = "Cannot relate 2 clusters with different 'cluster_name' values."

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

        peer_cluster = self.state.peer_cluster_by_relation_id(
            is_provider=False, relation_id=orchestrators.main_rel_id
        )
        if not peer_cluster:
            return None

        peer_cluster.security_index_initialised = True

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

            peer_cluster = self.state.related_peer_cluster_by_relation_id(
                relation_id=rel_id, is_provider=False
            )
            data = peer_cluster.relation_data.get("data", {}) if peer_cluster else {}

            if not data:  # not ready yet
                continue

            data = PeerClusterRelData.peer_cluster_rel_data_from_str(self.state.secrets, data)
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

    def reconcile_is_candidate_failover_orchestrator(self, relation_id: int) -> None:
        """Reconcile the is_candidate_failover_orchestrator key in relation data"""
        deployment_desc = self.state.application.deployment_desc
        if not deployment_desc:
            return

        peer_cluster = self.state.related_peer_cluster_by_relation_id(
            relation_id=relation_id, is_provider=False
        )
        if not peer_cluster:
            return
        if deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR:
            peer_cluster.update({"is_candidate_failover_orchestrator": "true"})
        else:
            peer_cluster.update({"is_candidate_failover_orchestrator": ""})

    def delete_departed_orchestrator(self, event_src_cluster_type: str) -> None:
        """Delete the orchestrator that left the relation from the state and cluster fleet."""
        orchestrators = self.state.application.orchestrators
        # delete the orchestrator that triggered this event
        orchestrator_app_id = (
            orchestrators.main_app.id
            if event_src_cluster_type == "main"
            else orchestrators.failover_app.id
        )
        cluster_fleet_apps = self.state.application.cluster_fleet_apps
        cluster_fleet_apps.pop(orchestrator_app_id, None)
        self.state.application.cluster_fleet_apps = cluster_fleet_apps

        orchestrators.delete(event_src_cluster_type)
        self.state.application.orchestrators = orchestrators

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
