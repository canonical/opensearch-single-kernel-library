#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for General OpenSearch charm events."""

import time
from typing import TYPE_CHECKING, List, Optional

from ops import (
    BlockedStatus,
    EventSource,
    InstallEvent,
    Object,
    SecretChangedEvent,
    StartEvent,
    WaitingStatus,
)

from opensearch_single_kernel.common.constants import (
    NODE_LOCK_RELATION,
    OPENSEARCH_SYSTEM_USERS,
    DeploymentType,
    Directive,
    HealthColors,
    Scope,
    StartMode,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
    OpenSearchInstallError,
    OpenSearchMissingError,
    OpenSearchNotFullyReadyError,
    OpenSearchStartError,
    OpenSearchStartTimeoutError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import (
    WAITING_FOR_BUSY_SHARDS,
    CharmStatuses,
)
from opensearch_single_kernel.core.models import DeploymentDescription
from opensearch_single_kernel.events.custom_events import StartOpenSearch
from opensearch_single_kernel.utils.helpers import trigger_peer_rel_changed
from opensearch_single_kernel.utils.logging import WithLogging
from opensearch_single_kernel.utils.status import Status
from opensearch_single_kernel.utils.topology import ClusterTopology

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


class OpenSearchEventsHandler(Object, WithLogging):
    """Class implementing OpenSearch Charm events handling."""

    _start_opensearch_event = EventSource(StartOpenSearch)

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, key="opensearch_events")
        self.charm = charm

        # --- OpenSearch charm events ---
        self.framework.observe(self.charm.on.install, self._on_install)
        self.framework.observe(self.charm.on.start, self._on_start)
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)
        self.framework.observe(
            self.charm.on[NODE_LOCK_RELATION].relation_changed, self._on_node_lock_relation_changed
        )

        # --- OpenSearch Custom events ---
        self.framework.observe(self._start_opensearch_event, self._on_start_opensearch)

    def _on_install(self, event: InstallEvent):
        """Event handler for install event."""
        if self.charm.substrate == Substrates.VM:
            self.charm.unit.status = CharmStatuses.INSTALL_IN_PROGRESS.value
            try:
                self.charm.workload.install()
                self.charm.status.clear(CharmStatuses.INSTALL_IN_PROGRESS.value)
            except OpenSearchInstallError:
                self.charm.unit.status = CharmStatuses.INSTALL_ERROR.value

    def _on_start(self, event: StartEvent):  # noqa: C901
        """Event handler for start event."""
        if self.charm.cluster_manager.is_node_up():
            self.cleanup_start_state()
            return

        elif self.marked_as_started_but_service_not_started:
            # This logic will only be triggered if the service has started (i.e. "started")
            # if we had a "start" hook (i.e. the actual machine has rebooted)
            # and we are a cluster_manager with the service down
            # After these conditions are met, then we can simply restart the service.
            self.logger.debug(
                "Start hook: snap already installed and service should be up, but it is not. Restarting it..."
            )

            # We had a reboot in this node.
            # We execute the same logic as above:
            self.cleanup_start_state()

            # Now, reissue a restart: we should not have stopped in the first place
            # as "started" flag is still set to True.
            # We do not wait for the 200 return, as maybe more than one unit is coming back
            try:
                self.charm.workload.start_service_only()
                # We're done here, we can return
                return
            except OpenSearchStartError as e:
                self.logger.warning(
                    f"Machine restart detected but error at service start with: {e}"
                )
                # Defer and retry later
                event.defer()
                return
            except OpenSearchMissingError:
                # This is unlike to happen, unless the snap has been manually removed
                self.logger.error("Service previously started but now misses the snap.")
                return
        # apply the directives computed and emitted by the peer cluster manager
        if not self._apply_peer_cm_directives_and_check_if_can_start():
            self.logger.debug("cannot start peer cm had a blocking directive")
            event.defer()
            return

        if (
            not self.charm.state.application.is_admin_user_configured
            or not self.charm.tls_manager.is_fully_configured()
        ):
            if not self.charm.state.tls_relation:
                status = CharmStatuses.TLS_RELATION_MISSING.value
            else:
                if self.charm.state.application.is_admin_user_configured:
                    status = CharmStatuses.ADMIN_USER_NOT_CONFIGURED.value
                else:
                    status = CharmStatuses.TLS_NOT_FULLY_CONFIGURED.value
            self.charm.status.set(status)
            event.defer()
            return

        self.charm.status.clear(CharmStatuses.ADMIN_USER_NOT_CONFIGURED.value)
        self.charm.status.clear(CharmStatuses.TLS_NOT_FULLY_CONFIGURED.value)
        self.charm.status.clear(CharmStatuses.TLS_RELATION_MISSING.value)

        if self.charm.state.unit.is_app_leader:
            self.charm.status.clear(CharmStatuses.PEER_CLUSTER_NO_RELATION, app=True)

        # Configure OpenSearch Users
        if not self.charm.state.server.is_app_leader:
            self.charm.users_manager.purge_initial_users()
            for user in OPENSEARCH_SYSTEM_USERS:
                user_hash = self.charm.state.secrets.hash_key(user)
                hashed_pwd = self.charm.state.secrets.get(Scope.APP, user_hash)
                self.charm.users_manager.save_user_locally(user, hashed_pwd)

        # Configure Client Authentication
        self.charm.cluster_manager.set_client_auth()

        deployment_desc = self.charm.state.application.deployment_desc
        # only start the main orchestrator if a data node is available
        # this allows for "cluster-manager-only" nodes in large deployments
        # workflow documentation:
        # no "data" role in deployment desc -> start gets deferred
        # when "data" node joins -> start cluster-manager via _on_peer_cluster_relation_changed
        # cluster-manager notifies "data" node via refresh of peer cluster relation data
        # "data" node starts and initializes security index
        if (
            deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
            and not deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            and "data" not in deployment_desc.config.roles
            and not self.charm.state.application.security_index_initialised
        ):
            self.charm.status.set(CharmStatuses.PEER_CLUSTER_NO_DATA_NODE.value)
            event.defer()
            return
        # We are requesting start of openSearch
        self.charm.status = CharmStatuses.REQUEST_LOCK_ON_START.value

        # In large deployments one data node needs to start to initialize the security index
        # this first node ignores the lock
        # if there are multiple data apps in the cluster
        # we synchronize the start of the first data node through peer cluster relation
        # all leader data units request to start as first data node
        #   ->(app databag key: first_data_node on data app)
        # main orchestrator will choose which node to start first
        #   ->(app databag key: first_data_node on main orchestrator app)

        # TODO: Add checks on whether we should ignore lock. Since we are not
        # adding large deployment yet, we always ignore
        if self.charm.lock_manager._should_ignore_lock(deployment_desc):
            self.logger.debug(
                f"Requesting start as first data node without lock: {self.unit_name}"
            )
            # TODO:
            # self.peer_cluster_requirer.set_first_data_node(self.unit_name)
            event.defer()
            return

        if self.state.opensearch_unit.is_app_leader:
            self._start_opensearch_event.emit(ignore_lock=True, is_first_data_node=True)
        self._start_opensearch_event.emit()

    def _on_start_opensearch(self, event: StartOpenSearch):  # noqa: C901
        """Start OpenSearch, with a generated or passed conf, if all resources configured."""
        if (
            not self.charm.state.application.deployment_desc()
            and self.charm.state.planned_units == 0
        ):
            # canonical/opensearch-operator#444
            # https://bugs.launchpad.net/juju/+bug/2076599
            # This condition is a corner case where we have:
            #   1) a single-node cluster
            #   2) an unfinished (re)start: yet to run _post_start_init() method
            #   3) LP#2076599: remove-application was called in-between and peer databag is empty
            # TODO: remove this IF condition once LP#2076599 is fixed in Juju.
            return

        # TODO: Update Peer Cluster relation data

        if self.charm.cluster_manager.is_opensearch_started:
            try:
                self._post_start_init(event)
            except (
                OpenSearchHttpError,
                OpenSearchNotFullyReadyError,
            ):
                # check if cluster should have started but is blocked
                self.logger.debug("OpenSearch already started, but post-start init failed.")
                if (
                    ClusterTopology.is_data_role_in_cluster_fleet_apps(self)
                    and self.charm.state.application.bootstrapped
                    # and self.opensearch_peer_cm.is_provider(typ="main")
                ):
                    # In large deployments with cluster-manager-only-nodes,
                    # the startup might fail if the cluster was bootstrapped earlier
                    # and the cluster-manager node lost its data
                    self.logger.warning(
                        "Node is not ready to start, but data node exists and"
                        " the cluster was previously bootstrapped."
                    )
                    self.status.set(CharmStatuses.SERVICE_START_ERROR.value)

                event.defer()
            except OpenSearchUserMgmtError as e:
                # Either generic start failure or cluster is not read to create the internal users
                self.logger.warning(e)
                self.charm.lock_manager.release()
                self.charm.status.set(CharmStatuses.SERVICE_START_ERROR.value)
                event.defer()
            # finally:
            # if self.opensearch_peer_cm.is_provider(typ="main"):
            # self.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
            return

        self.charm.state.unit.update({"started": None})

        if not self.can_service_start(event.is_first_data_node):
            self.logger.info("Conditions not met to start opensearch. Will retry next event.")
            event.defer()
            return

        if event.ignore_lock:
            # Only used for force upgrades and starting 1 data node on a large deployment
            # where the main orchestrator has cluster-manager only nodes
            self.logger.debug("Starting without lock")
        elif not self.charm.lock_manager.acquired:
            self.logger.debug("Lock to start opensearch not acquired. Will retry next event")
            event.defer()
            return

        if self.charm.workload.is_failed():
            self.charm.lock_manager.release()
            self.status.set(CharmStatuses.SERVICE_START_ERROR.value)
            event.defer()
            return
        self.charm.status.set(CharmStatuses.WAITING_TO_START.value)

        try:
            # Retrieve the nodes of the cluster, needed to configure this node
            nodes = self.charm.cluster_manager.get_nodes(False)

            # Set the configuration of the node
            self.charm.cluster_manager.set_node_conf(nodes)
        except OpenSearchHttpError as e:
            self.logger.debug(f"error getting the nodes: {e}")
            self.charm.lock_manager.release()
            event.defer()
            return

        try:
            self.charm.cluster_manager.start(
                wait_until_http_200=(
                    not self.charm.state.server.is_app_leader
                    or self.charm.state.application.security_index_initialised
                )
            )
            self._post_start_init(event)
        except (
            OpenSearchHttpError,
            OpenSearchStartTimeoutError,
            OpenSearchStartError,
            OpenSearchUserMgmtError,
        ) as e:
            self.logger.debug("error of type: %s", type(e).__name__)
            self.charm.lock_manager.release()
            self.logger.warning(e)
            self.charm.status.set(CharmStatuses.SERVICE_START_ERROR.value)
            event.defer()
        except OpenSearchNotFullyReadyError as e:
            self.charm.lock_manager.release()
            self.logger.debug("Node started but not fully ready: %s", e)
            event.defer()
        finally:
            # In large deployments with cluster-manager-only-nodes, the startup might fail
            # for the cluster-manager if a joining data node did not yet initialize the
            # security index. We still want to update and broadcast the latest relation data.
            # TODO:
            # if self.opensearch_peer_cm.is_provider(typ="main"):
            #    self.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
            pass

    def _post_start_init(self, event: StartOpenSearch):
        """Initialisation post OpenSearch start"""
        # initialize the security index if needed (and certs written on disk etc.)
        # this happens only on the first data node to join the cluster
        if self.charm.cluster_manager.should_initialize_security_index():
            self.charm.status.set(CharmStatuses.SECURITY_INDEX_INIT_IN_PROGRESS.value)
            try:
                self.charm.cluster_manager.initialise_security_index()
                self.charm.status.clear(CharmStatuses.SECURITY_INDEX_INIT_IN_PROGRESS.value)
            except OpenSearchError:
                event.defer()
                return

        # Wait for opensearch to be fully ready or throw error
        self.charm.cluster_manager.wait_for_opensearch_up()

        # Get online nodes
        try:
            nodes = self.charm.cluster_manager.get_nodes(
                use_localhost=self.charm.cluster_manager.is_node_up()
            )
        except OpenSearchHttpError:
            self.logger.info("Failed to get online nodes")
            event.defer()
            return

        for node in nodes:
            if node.name == self.charm.state.unit_name:
                break
        else:
            raise OpenSearchNotFullyReadyError("Node online but not in cluster.")

        if self.charm.state.server.bootstrap_contributor:
            self.charm.cluster_manager.cleanup_bootstrap_conf()

        self.charm.exclusions_manager.delete_current()

        # Add a timestamp to always trigger relation changed
        self.peers_data.put(Scope.UNIT, "started", time.time())

    def _on_node_lock_relation_changed(self, _=None):
        """Event handler for when the node-lock relation changed"""
        self.charm.lock_manager.refresh_lock()

    def can_service_start(self, is_first_data_node: bool = False) -> bool:
        """Return if the opensearch service can start."""
        if self.check_profile_missing_requirements():
            return False

        if not (deployment_desc := self.charm.state.application.deployment_desc):
            return False

        if not self.charm.cluster_manager.can_start(deployment_desc):
            return False

        if not self.charm.state.application.is_admin_user_configured:
            return False

        # Case of the first "main" cluster to get started.
        if (
            not self.charm.state.application.security_index_initialised
            or not self.charm.cluster_manager.alt_hosts
        ):
            return self.charm.state.server.is_app_leader and (
                deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
                # first data node in a cluster-manager-only deployment
                or (
                    (
                        deployment_desc.start == StartMode.WITH_GENERATED_ROLES
                        or "data" in deployment_desc.config.roles
                    )
                    and is_first_data_node
                )
            )
        # When a new unit joins, replica shards are automatically added to it. In order to prevent
        # overloading the cluster, units must be started one at a time. So we defer starting
        # opensearch until all shards in other units are in a "started" or "unassigned" state.
        try:
            if (
                self.apply_health(wait_for_green_first=True, use_localhost=False, app=False)
                == HealthColors.YELLOW_TEMP
            ):
                return False
        except OpenSearchHttpError:
            # this means that the leader unit is not reachable (not started yet),
            # meaning it's a new cluster, so we can safely start the OpenSearch service
            pass

        return True

    def apply_health(
        self,
        wait_for_green_first: bool = False,
        use_localhost: bool = True,
        app: bool = True,
        unit: bool = True,
    ):
        """Fetch cluster health and set it on the app status."""
        status = self.charm.health_manager.get(
            wait_for_green_first=wait_for_green_first, use_localhost=use_localhost
        )
        self.logger.info(f"Current health of cluster: {status}")

        if unit:
            self._apply_for_unit(status)
        if app:
            self._apply_for_app(status)

        return status

    def _apply_health_for_app(self, status: str) -> None:
        """Cluster wide / app status."""
        if not self.charm.state.server.is_app_leader:
            trigger_peer_rel_changed(self.charm, on_other_units=True)
            return

        if status == HealthColors.GREEN:
            # health green: cluster healthy
            self.charm.status.clear(CharmStatuses.CLUSTER_HEALTH_RED.value, app=True)
            self.charm.status.clear(CharmStatuses.CLUSTER_HEALTH_YELLOW.value, app=True)
            self.charm.status.clear(CharmStatuses.WAITING_FOR_BUSY_SHARDS.value, app=True)
        elif status == HealthColors.RED:
            # health RED: some primary shards are unassigned
            self.charm.status.set(CharmStatuses.CLUSTER_HEALTH_RED.value, app=True)
        elif status == HealthColors.YELLOW_TEMP:
            # health is yellow but temporarily (shards are relocating or initializing)
            self.charm.status.set(CharmStatuses.WAITING_FOR_BUSY_SHARDS.value, app=True)
        elif status == HealthColors.YELLOW:
            # health is yellow permanently (some replica shards are unassigned)
            self.charm.status.set(CharmStatuses.CLUSTER_HEALTH_YELLOW.value, app=True)

    def _apply_for_unit(self, status: str, host: Optional[str] = None):
        """Apply the health status on the current unit."""
        if status != HealthColors.YELLOW_TEMP:
            self.charm.status.clear(
                WAITING_FOR_BUSY_SHARDS, pattern=Status.CheckPattern.Interpolated
            )
            return

        busy_shards = self.charm.health_manager.opensearch_client.busy_shards_by_unit(
            host=host, alt_hosts=self.charm.health_manager.alt_hosts
        )
        if not busy_shards:
            self.charm.status.clear(
                WAITING_FOR_BUSY_SHARDS, pattern=Status.CheckPattern.Interpolated
            )
            return

        message = sorted([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
        message = WAITING_FOR_BUSY_SHARDS.format(" - ".join(message))
        self.charm.status.set(WaitingStatus(message))

    def check_profile_missing_requirements(self, set_status: bool = True) -> List[str]:
        """Check all requirements of profile

        Requirements include:
        - System requirements
        - Memory requirements
        - Cluster topology requirements
        """
        missing_requirements: List[str] = []
        try:
            profile = self.charm.profiles_manager.config_profile
        except ValueError:
            self.logger.error(
                "Invalid profile configuration. Value: %s", self.state.config.get("profile")
            )
            self.charm.status.set(CharmStatuses.INVALID_PROFILE_CONFIG_OPTION.value.message)
            return [CharmStatuses.INVALID_PROFILE_CONFIG_OPTION.value.message]

        missing_requirements.extend(
            self.charm.profiles_manager.check_missing_system_requirements()
        )
        missing_requirements.extend(self.charm.profiles_manager.check_memory_requirements(profile))
        missing_requirements.extend(self.charm.profiles_manager.check_cluster_topology(profile))

        if set_status:
            if missing_requirements:
                self.logger.error("Missing profile requirements: %s", missing_requirements)
                self.charm.status.set(
                    BlockedStatus(f"Missing requirements: {' - '.join(missing_requirements)}")
                )
            else:
                self.charm.status.clear(
                    status_message="Missing requirements:", pattern=Status.CheckPattern.Start
                )

        return missing_requirements

    def cleanup_start_state(self):
        """Clean Up Start statuses and state."""
        if self.charm.state.application.security_index_initialised:
            self.charm.status.clear(CharmStatuses.WAITING_TO_START.value)
            self.charm.status.clear(CharmStatuses.PEER_CLUSTER_NO_DATA_NODE.value)
        if self.charm.state.unit.bootstrap_contributor:
            self.charm.cluster_manager.cleanup_bootstrap_conf()

    def _apply_peer_cm_directives_and_check_if_can_start(self) -> bool:
        """Apply the directives computed by the opensearch peer cluster manager."""
        if not (deployment_desc := self.charm.state.application.deployment_desc()):
            # the deployment description hasn't finished being computed by the leader
            return False

        # check possibility to start
        self.logger.debug("Checking if cluster can start with deploy desc: %s", deployment_desc)
        if self.charm.cluster_manager.can_start(deployment_desc):
            try:
                self.charm.cluster_manager.get_nodes(False)
            except OpenSearchHttpError:
                return False
            return True

        if self.unit.is_leader():
            self._apply_status_if_needed(deployment_desc, show_status_only_once=False)

        return False

    def _apply_status_if_needed(
        self,
        deployment_desc: Optional[DeploymentDescription] = None,
        show_status_only_once: bool = True,
    ):
        """Resolve and applies corresponding status from the deployment state."""
        if not (deployment_desc := deployment_desc or self.deployment_desc()):
            return

        if Directive.SHOW_STATUS not in deployment_desc.pending_directives:
            return

        # remove show_status directive which is applied below
        if show_status_only_once:
            self.clear_directive(Directive.SHOW_STATUS)

        blocked_status_messages = [
            CharmStatuses.CM_ROLE_REMOVAL_FORBIDDEN.value.message,
            CharmStatuses.CM_VO_PROVIDED_INVALID.value.message,
            CharmStatuses.DATA_ROLE_REMOVAL_FORBIDDEN.value.message,
            CharmStatuses.PEER_CLUSTER_NO_RELATION.value.message,
            CharmStatuses.PEER_CLUSTER_WRONG_RELATION.value.message,
            CharmStatuses.PEER_CLUSTER_WRONG_ROLES_PROVIDED.value.messages,
        ]
        if deployment_desc.state.message not in blocked_status_messages:
            for message in blocked_status_messages:
                self.charm.status.clear(message, app=True)
            return

        self.charm.app.status = BlockedStatus(deployment_desc.state.message)

    @property
    def marked_as_started_but_service_not_started(self) -> bool:
        """Start Process Edge Case.

        This handles an edge case where the charm is a cluster manager
        the unit is marked as started but service couldn't start
        """
        return (
            self.charm.state.unit.started
            and "cluster_manager" in self.charm.cluster_manager.roles
            and not self.charm.workload.is_service_started()
        )

    def _on_secret_changed(self, event: SecretChangedEvent):  # noqa: C901
        """Refresh secret and re-run corresponding actions if needed."""
        secret = event.secret
        secret.get_content(refresh=True)

        if not event.secret.label:
            self.logger.info("Secret %s has no label, ignoring it.", event.secret.id)
            return

        # TODO: Address secrets management in a separate PR
