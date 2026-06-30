#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for OpenSearch peer cluster events."""

import logging
from typing import TYPE_CHECKING

from ops import (
    Object,
    Relation,
    RelationChangedEvent,
    RelationDepartedEvent,
    RelationJoinedEvent,
)

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    KIBANA_SERVER_USER,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    CertType,
    DeploymentType,
    Directive,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchPeerClusterRelationDataIncompleteError,
)
from opensearch_single_kernel.common.statuses import (
    PeerClusterErrorDataStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.core.models import (
    PeerClusterApp,
    PeerClusterRelData,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.utils.peer_cluster import is_failover_promoted

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


logger = logging.getLogger(__name__)


class PeerClusterEventsHandler(Object):
    """Handler for OpenSearch peer cluster events."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, key="peer_cluster_events_handler")
        self.charm = charm

        self.framework.observe(
            charm.on[PEER_CLUSTER_ORCHESTRATOR_RELATION].relation_joined,
            self._on_peer_cluster_orchestrator_relation_joined,
        )
        self.framework.observe(
            charm.on[PEER_CLUSTER_ORCHESTRATOR_RELATION].relation_changed,
            self._on_peer_cluster_orchestrator_relation_changed,
        )
        self.framework.observe(
            charm.on[PEER_CLUSTER_ORCHESTRATOR_RELATION].relation_departed,
            self._on_peer_cluster_orchestrator_relation_departed,
        )

        self.framework.observe(
            charm.on[PEER_CLUSTER_RELATION].relation_changed,
            self._on_peer_cluster_relation_changed,
        )
        self.framework.observe(
            charm.on[PEER_CLUSTER_RELATION].relation_departed,
            self._on_peer_cluster_relation_departed,
        )

    # ---- PEER CLUSTER ORCHESTRATOR RELATION EVENTS ----

    def _on_peer_cluster_orchestrator_relation_joined(self, event: RelationJoinedEvent):
        """Received by all units in main/failover apps when new application joins the rel."""
        if not self.charm.unit.is_leader():
            logger.debug("Node not a leader. Skipping refresh relation data")
            return

        if not self.charm.state.application.deployment_desc:
            logger.debug("Current cluster not ready. Deferring event.")
            event.defer()
            return

        self.charm.peer_cluster_orchestrator_manager.refresh_relation_data(
            event.relation.id if hasattr(event, "relation") else None
        )

    def _on_peer_cluster_orchestrator_relation_changed(  # noqa: C901
        self, event: RelationChangedEvent
    ):
        """Handle peer cluster orchestrator relation changed event."""
        logger.debug("Peer cluster orchestrator relation changed: %s", event)

        if not self.charm.unit.is_leader():
            logger.debug("Node not a leader. Skipping refresh relation data")
            return

        if not event.relation.active:
            logger.debug("Relation no longer active")
            return

        if not event.relation.units:
            logger.debug("No units in relation. Skipping refresh relation data")
            return

        if not self.charm.state.peer_cluster_orchestrator_relations:
            logger.debug("Node not a provider. Skipping refresh relation data")
            return

        if not (deployment_desc := self.charm.state.application.deployment_desc):
            logger.debug("Current cluster not ready. Deferring event.")
            event.defer()
            return

        # if this is a failover orchestrator, check if it should promote itself
        if (
            deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR
            and self.charm.tls_manager.is_fully_configured()
            and self.charm.peer_cluster_orchestrator_manager.should_promote_failover_to_main()
        ):
            self.charm.cluster_manager.promote_deployment_type()
            self.charm.peer_cluster_orchestrator_manager.promote_failover()
            # check if any credentials exist without relations
            self.check_credentials_with_missing_relations()
            if self.charm.peer_cluster_orchestrator_manager.refresh_relation_data(
                event.relation.id
            ):
                event.defer()
            return

        is_waiting_for_peer_relation = (
            Directive.WAIT_FOR_PEER_CLUSTER_RELATION in deployment_desc.pending_directives
        )
        # Do not defer the event if we are waiting for a peer cluster relation
        # Once the relation is established and the cluster starts we will re-process the event
        if (
            self.charm.peer_cluster_orchestrator_manager.refresh_relation_data(event.relation.id)
            and not is_waiting_for_peer_relation
        ):
            event.defer()

        if is_waiting_for_peer_relation:
            return

        # only the main-orchestrator is able to designate a failover
        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            return

        if not (data := event.relation.data.get(event.app)):
            return

        self.charm.peer_cluster_orchestrator_manager.reconcile_security_index_initialised()
        # Reconcile the first data node in the cluster
        if (
            first_data_node := self.charm.peer_cluster_orchestrator_manager.first_data_node_in_all_clusters
        ):
            self.charm.state.application.first_data_node = first_data_node

        # fetch emitting app planned units and broadcast
        related_peer_cluster_app = PeerClusterApp.from_str(data.get("app"))
        self.charm.peer_cluster_orchestrator_manager.save_cluster_fleet_apps(
            deployment_desc=deployment_desc,
            p_cluster_app=related_peer_cluster_app,
            trigger_rel_id=event.relation.id,
        )

        if (
            deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
            and "data" in related_peer_cluster_app.roles
            and self.charm.state.application.is_admin_user_initialized
            and self.charm.tls_manager.is_fully_configured()
        ):
            # TODO migrate to _on_start hook instead
            self.handle_joining_data_node()

        if data.get("is_candidate_failover_orchestrator", "").lower() != "true":
            if self.charm.peer_cluster_orchestrator_manager.refresh_relation_data(
                event.relation.id
            ):
                event.defer()
            return

        # This is run to elect failover

        candidate_failover_app = related_peer_cluster_app.app
        orchestrators = self.charm.state.application.orchestrators

        target_relation_ids = self.charm.state.peer_clusters_relations_ids(is_provider=True)
        if orchestrators.failover_app and orchestrators.failover_rel_id in target_relation_ids:
            logger.info("A failover cluster orchestrator is already registered.")
            if self.charm.peer_cluster_orchestrator_manager.refresh_relation_data(
                event.relation.id
            ):
                event.defer()
            return

        # register the new failover in the current main peer relation data
        logger.debug(f"Electing {candidate_failover_app.name} as new failover orchestrator")
        orchestrators.failover_app = candidate_failover_app
        orchestrators.failover_rel_id = event.relation.id
        self.charm.state.application.orchestrators = orchestrators

        self.charm.peer_cluster_orchestrator_manager.broadcast_new_failover_app(
            related_peer_cluster_app
        )

    def _on_peer_cluster_orchestrator_relation_departed(self, event: RelationDepartedEvent):
        """Handle peer cluster orchestrator relation departed event."""
        logger.debug("Peer cluster orchestrator relation departed: %s", event)

        if not (self.charm.unit.is_leader() and len(event.relation.units) > 0):
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            # if this unit is the one departing, dont update fleet apps
            # otherwise, update fleet apps after service restarts and event is re-emitted
            logger.debug("Node is not up. Deferring event.")
            event.defer()
            return

        if not (
            trigger_app := self.charm.state.application.cluster_fleet_apps_rels.get(
                str(event.relation.id)
            )
        ):
            logger.debug("Trigger app not found for relation id %s. Skipping.", event.relation.id)
            return

        self.charm.peer_cluster_orchestrator_manager.save_cluster_fleet_apps(
            deployment_desc=self.charm.state.application.deployment_desc,
            p_cluster_app=trigger_app,
            trigger_rel_id=event.relation.id,
        )
        # if the trigger app is the failover orchestrator and there are no planned units, delete it
        # So if it has at least one unit we skip
        if len(event.relation.units) > 0:
            return
        # If it has no units
        # Remove the cluster_fleet_app
        cluster_fleet_apps = self.charm.state.application.cluster_fleet_apps
        cluster_fleet_apps.pop(trigger_app.app.id, None)
        self.charm.state.application.cluster_fleet_apps = cluster_fleet_apps

        # Update the orchestrators
        orchestrators = self.charm.state.application.orchestrators
        if orchestrators.failover_rel_id == event.relation.id:
            orchestrators.delete("failover")
            self.charm.state.application.orchestrators = orchestrators

    # ---- PEER CLUSTER RELATION EVENTS ----
    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):  # noqa: C901
        """Handle peer cluster relation changed event."""
        logger.debug("Peer cluster relation changed: %s", event)
        if not (deployment_desc := self.charm.state.application.deployment_desc):
            logger.debug("Current cluster not ready. Deferring event.")
            event.defer()
            return

        if not self.charm.unit.is_leader():
            return

        if (
            len(event.relation.units) == 0
        ):  # ensure not a deferred event from a departed orchestrator
            return

        # register in the 'main/failover'-CMs the number of planned units of the current app
        self.charm.peer_cluster_manager.set_current_app_in_cluster_fleet(
            rel_id=event.relation.id,
            deployment_desc=deployment_desc,
            is_provider=False,
        )
        # set the main orchestrator registered flag for this relation
        if (
            self.charm.state.application.is_admin_user_initialized
            and self.charm.tls_manager.is_fully_configured()
        ):
            self.charm.peer_cluster_manager.update_main_orchestrator_registered(
                rel_id=event.relation.id,
                value=(self.charm.state.application.orchestrators.main_app is not None),
            )

        if not (data := event.relation.data.get(event.app)):
            logger.debug("No data found in relation.")
            return

        logger.debug(
            "PeerClusterRelationChanged from provider %s data: %s", event.relation.app.name, data
        )
        # fetch the trigger of this event
        trigger = data.get("trigger")

        # Get orchestrators from remote peer cluster
        remote_peer_cluster = self.charm.state.peer_cluster_by_relation_id(
            relation_id=event.relation.id, is_provider=False, remote=True
        )
        if not remote_peer_cluster or not remote_peer_cluster.orchestrators:
            logger.warning("No orchestrators found in remote peer cluster data.")
            return

        orchestrators = self.charm.peer_cluster_manager.reconcile_orchestrators_from_provider_data(
            remote_peer_cluster,
            data,
            trigger,
            relation_id=event.relation.id,
            relation_app_name=event.relation.app.name,
            relation_units=len(event.relation.units),
        )

        logger.debug(f"Orchestrators: {orchestrators}")
        if is_failover_promoted(orchestrators):
            self.charm.peer_cluster_manager.remove_main_orchestrator_registered(
                orchestrators.failover_rel_id
            )
            orchestrators.delete("failover")

        if orchestrators.failover_app:
            # should we add a check where the failover rel has data while the main has none yet?
            if not orchestrators.main_app:
                self.charm.peer_cluster_manager.update_main_orchestrator_registered(
                    orchestrators.failover_rel_id, value=False
                )
                logger.debug("Current cluster has no main orchestrator. Deferring event.")
                event.defer()
                return

            self.charm.peer_cluster_manager.update_main_orchestrator_registered(
                orchestrators.failover_rel_id, value=True
            )

        reconcile_deployment_desc = False
        try:
            # check if any errors sent by providers
            errors_data, rel_error_id = self.charm.peer_cluster_manager.error_set_from_providers(
                orchestrators, data, event_rel_id=event.relation.id
            )
            logger.debug(f"Errors from providers: {errors_data}, rel_error_id: {rel_error_id}")
            if errors_data:
                reconcile_deployment_desc = True
        except OpenSearchPeerClusterRelationDataIncompleteError as e:
            logger.warning(f"Peer cluster relation data incomplete: {e}")
            reconcile_deployment_desc = True

        if reconcile_deployment_desc:
            # check if valid data is present if so update the seed hosts
            if data.get("data"):
                # In case the main orchestrator was scaled down to 0 and back
                # we need to update the seed hosts with the data from the relation
                # to pick up the new IPs and enable the data node see it
                logger.debug(
                    "Error from provider but valid data found in relation data, updating seed hosts."
                )
                data = PeerClusterRelData.peer_cluster_rel_data_from_str(
                    self.charm.state.secrets, data["data"]
                )
                self._reconcile_deployment_desc_from_peer_cluster_data(data)
            return

        data = PeerClusterRelData.peer_cluster_rel_data_from_str(
            self.charm.state.secrets, data["data"]
        )
        logger.debug(f"Checking Requirer errors with data: {data}")
        requirer_errors = self.charm.peer_cluster_manager.requirer_errors(
            orchestrators, deployment_desc, data, event.relation.id
        )
        logger.debug(f"Requirer errors: {requirer_errors}")
        if requirer_errors:
            logger.debug("Error from requirer")
            return

        # this means it's a previous "main orchestrator" that was unrelated then re-related
        if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            self.charm.cluster_manager.demote_deployment_type()
            self.charm.peer_cluster_orchestrator_manager.clean_all_provider_relation_data()
            deployment_desc = self.charm.state.application.deployment_desc
            # demoted main orchestrator should remove secrets it created for plugins
            self.charm.plugin_manager.remove_plugin_secrets()
            self.charm.peer_cluster_orchestrator_manager.refresh_relation_data(event.relation.id)

        # we need to differentiate between plugins being None and {}
        # when an empty dict, plugins have been removed from the main orchestrator
        # and we need to also remove them in subclusters
        if (plugin_configs := data.plugins) is not None:
            self.charm.plugin_manager.update_plugin_configs(plugin_configs)

        # broadcast that this cluster is a failover candidate, and let the main CM elect it or not
        self.charm.peer_cluster_manager.reconcile_is_candidate_failover_orchestrator(
            event.relation.id
        )

        # register main and failover cm app names if any
        logger.debug("Requirer updating orchestrators %s", orchestrators)
        self.charm.state.application.orchestrators = orchestrators

        # clear or set missing orchestrator status
        self.apply_orchestrator_status()

        if data.security_index_initialised:
            self.charm.state.application.is_security_index_initialised = True

        # let the charm know this is an already bootstrapped cluster
        self.charm.state.application.bootstrapped = True
        # store the security related settings in secrets, peer_data, disk
        logger.debug("We received this peer cluster relation data: %s", data)
        if data.credentials.admin_tls:
            logger.debug("Admin TLS credentials received from peer cluster relation data.")
            self._set_security_conf(data)

        # check if there are any security misconfigurations / violations
        tls_errors = self.charm.tls_manager.peer_cluster_error_from_tls(data)
        self.reconcile_peer_cluster_errors(label="error_from_tls", error=tls_errors)
        if tls_errors:
            logger.debug("TLS/Security misconfigurations detected. Deferring event.")
            event.defer()
            return

        # aggregate all CMs (main + failover if any)
        data.cm_nodes = self.charm.peer_cluster_manager.cm_nodes(orchestrators)

        # recompute the deployment desc
        self._reconcile_deployment_desc_from_peer_cluster_data(data)

    def _on_peer_cluster_relation_departed(self, event: RelationDepartedEvent):
        """Handle when 'main/failover'-CMs leave the relation (app or relation removal)."""
        logger.debug("Peer cluster relation departed: %s", event)
        if not self.charm.unit.is_leader():
            return

        self._clean_main_orchestrator_is_requirer_status(event.relation)
        # fetch current deployment_desc
        deployment_desc = self.charm.state.application.deployment_desc

        orchestrators = self.charm.state.application.orchestrators

        # handle scale-down at the charm level storage detaching
        if len(event.relation.units) > 0:
            return

        # check the departed cluster which triggered this hook
        event_src_cluster_type = (
            "main" if event.relation.id == orchestrators.main_rel_id else "failover"
        )

        self.charm.peer_cluster_manager.delete_departed_orchestrator(event_src_cluster_type)
        # the 'main' cluster orchestrator is the one being removed
        if event_src_cluster_type == "main" and orchestrators.failover_app:
            if orchestrators.failover_app.id != deployment_desc.app.id:
                self.charm.peer_cluster_manager.update_main_orchestrator_registered(
                    orchestrators.failover_rel_id, value=False
                )
            elif self.charm.peer_cluster_orchestrator_manager.should_promote_failover_to_main():
                logger.info("Promoting failover orchestrator to main orchestrator")
                self.charm.peer_cluster_orchestrator_manager.promote_failover()
                self.charm.plugin_manager.remove_plugin_secret_ids()
                self.charm.peer_cluster_orchestrator_manager.refresh_relation_data(
                    event.relation.id if hasattr(event, "relation") else None
                )

        # clear or set missing orchestrator status
        self.apply_orchestrator_status()

        # we leave in case not an orchestrator
        if (
            self.charm.state.application.deployment_desc.typ == DeploymentType.OTHER
            or deployment_desc.app.id
            not in [app.id for app in (orchestrators.main_app, orchestrators.failover_app) if app]
        ):
            return

        # the current is an orchestrator, let's broadcast the new conf to all related apps
        for local_peer_cluster in self.charm.state.peer_clusters(
            is_provider=True, must_have_units=False, remote=False
        ):
            local_peer_cluster.cluster_fleet_apps = self.charm.state.application.cluster_fleet_apps

    def check_credentials_with_missing_relations(self) -> None:
        """Checks if the relation data has credentials for non-related apps"""
        if not self.charm.unit.is_leader():
            return

        plugins_missing_relations = self.charm.plugin_manager.missing_plugins_relations()
        snapshots_missing_relations = self.charm.snapshots_manager.missing_backup_relations()
        if plugins_missing_relations:
            self.charm.state.add_status_if_not_present(
                PeerClusterStatuses.PEER_CLUSTER_MISSING_RELATIONS.value,
                scope="app",
                component=self.charm.plugin_manager.name,
                dynamic_params={"relation": plugins_missing_relations[0]},
            )
            self.charm.state.application.missing_relations = True
            return
        elif snapshots_missing_relations:
            self.charm.state.add_status_if_not_present(
                PeerClusterStatuses.PEER_CLUSTER_MISSING_RELATIONS.value,
                scope="app",
                component=self.charm.snapshots_manager.name,
                dynamic_params={"relation": snapshots_missing_relations[0]},
            )
            self.charm.state.application.missing_relations = True
            return

        # No missing relations, clean up any previous state
        del self.charm.state.application.missing_relations
        self.charm.state.remove_status_if_present(
            PeerClusterStatuses.PEER_CLUSTER_MISSING_RELATIONS.value,
            scope="app",
            component=self.charm.plugin_manager.name,
            interpolated=True,
        )
        self.charm.state.remove_status_if_present(
            PeerClusterStatuses.PEER_CLUSTER_MISSING_RELATIONS.value,
            scope="app",
            component=self.charm.snapshots_manager.name,
            interpolated=True,
        )

    def handle_joining_data_node(self) -> None:
        """Start Opensearch on a cluster-manager node when a data-node is joining"""
        if self.charm.state.server.started:
            self.charm.state.remove_status_if_present(
                PeerClusterStatuses.PEER_CLUSTER_NO_DATA_NODE.value,
                scope="app",
                component=self.charm.peer_cluster_manager.name,
            )
            return

        try:
            config_profile = self.charm.profiles_manager.get_config_profile()
        except ValueError:
            return

        if not self.charm.profiles_manager.check_profile_requirements():
            return

        self.charm.config_manager._update_jvm_heap_size(
            config_profile.get_jvm_heap_size(self.charm.workload.memtotal())
        )
        # store profile in unit state
        self.charm.state.server.profile = config_profile
        self.charm.start_opensearch_event.emit(ignore_lock=True)

    def reconcile_peer_cluster_errors(
        self, label: str, error: PeerClusterRelErrorData | None
    ) -> None:
        """Set error status from the passed errors and store for future deletion."""
        if error:
            err_message = error.blocked_message
            status = error.get_status()
            if status:
                # set the message
                self.charm.state.add_status_if_not_present(
                    status,
                    scope="app",
                    component=self.charm.peer_cluster_manager.name,
                )

            # we should keep track of set messages for targeted deletion later
            self.charm.state.application.update({label: err_message})
        else:
            # if there is no error, we should clear the status and stored message for this label
            error_message = self.charm.state.application.relation.data[self.model.app].get(
                label, ""
            )
            status = PeerClusterRelErrorData.get_status_from_message(error_message)
            if status:
                self.charm.state.remove_status_if_present(
                    status,
                    scope="app",
                    component=self.charm.peer_cluster_manager.name,
                )
            self.charm.state.application.relation.data[self.model.app].pop(label, None)

    def apply_orchestrator_status(self) -> None:
        """Sets or clears status based on presence of local orchestrators."""
        if not self.charm.unit.is_leader():
            return

        deployment_desc = self.charm.state.application.deployment_desc
        if not (orchestrators := self.charm.state.application.orchestrators):
            return

        if orchestrators.failover_app and orchestrators.failover_app.id == deployment_desc.app.id:
            return

        if orchestrators.main_app:
            self.charm.state.remove_status_if_present(
                PeerClusterStatuses.PEER_CLUSTER_ORCHESTRATORS_REMOVED.value,
                scope="app",
                component=self.charm.peer_cluster_manager.name,
            )
            self.charm.state.remove_status_if_present(
                PeerClusterStatuses.PEER_CLUSTER_WAITING_FOR_FAILOVER_PROMOTION.value,
                scope="app",
                component=self.charm.peer_cluster_manager.name,
            )
        elif orchestrators.failover_app:
            self.charm.state.add_status_if_not_present(
                PeerClusterStatuses.PEER_CLUSTER_WAITING_FOR_FAILOVER_PROMOTION.value,
                scope="app",
                component=self.charm.peer_cluster_manager.name,
            )
        else:
            self.charm.state.add_status_if_not_present(
                PeerClusterStatuses.PEER_CLUSTER_ORCHESTRATORS_REMOVED.value,
                scope="app",
                component=self.charm.peer_cluster_manager.name,
            )

    def _set_security_conf(self, data: PeerClusterRelData) -> None:
        """Store security related config."""
        # set admin secrets
        self.charm.peer_cluster_manager.update_admin_secrets_from_relation(data)

        # store the app admin TLS resources if not stored
        logger.debug("Storing TLS resources from peer cluster relation data.")
        self.charm.tls_manager.store_new_tls_resources(
            CertType.APP_ADMIN, data.credentials.admin_tls
        )

        if self.charm.state.ca_rotation_complete_in_cluster:
            # must only happen if no CA-rotation, otherwise will cause TLS errors for API-requests
            self.charm.tls_manager.update_request_ca_bundle()

        # take over the internal users from the main orchestrator
        self.charm.internal_users_manager.put_internal_user(
            ADMIN_USER, data.credentials.admin_password_hash
        )
        self.charm.internal_users_manager.put_internal_user(
            KIBANA_SERVER_USER, data.credentials.kibana_password_hash
        )

        self.charm.snapshots_manager.update_backup_credentials_from_peer_relation(data)

    def _clean_main_orchestrator_is_requirer_status(self, departing_relation: Relation) -> None:
        """Clean the status if there are no more peer cluster requirer relations."""
        if (
            not self.charm.unit.is_leader()
            or not (deployment_desc := self.charm.state.application.deployment_desc)
            or deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR
        ):
            return

        peer_cluster_requirer_relations = [
            rel
            for rel in self.charm.state.peer_cluster_orchestrator_relations
            if rel.id != departing_relation.id
        ]
        # clean the status if it is set
        if not peer_cluster_requirer_relations:
            self.charm.state.remove_status_if_present(
                PeerClusterErrorDataStatuses.PEER_CLUSTER_MAIN_IS_REQUIRER.value,
                scope="app",
                component=self.charm.peer_cluster_manager.name,
            )

    def _reconcile_deployment_desc_from_peer_cluster_data(self, data: PeerClusterRelData) -> None:
        """Reconcile the deployment desc from the peer cluster relation data."""
        self.charm.cluster_manager.reconcile_cluster_config_with_relation_data(data)
        self.charm.config_manager.update_seeds_config(data.cm_nodes)
        self.charm.opensearch_events.apply_status_from_deployment_desc(
            self.charm.state.application.deployment_desc
        )
