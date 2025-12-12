#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for General OpenSearch charm events."""

from typing import TYPE_CHECKING

from ops import EventSource, InstallEvent, Object, SecretChangedEvent, StartEvent

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    NODE_LOCK_RELATION,
    OPENSEARCH_SYSTEM_USERS,
    DeploymentType,
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
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.core.state import CharmState
from opensearch_single_kernel.events.custom_events import StartOpenSearch
from opensearch_single_kernel.utils.logging import WithLogging

if TYPE_CHECKING:
    from opensearch_single_kernel.events.base_charm import OpenSearchBaseCharm


class OpenSearchEventsHandler(Object, WithLogging):
    """Class implementing OpenSearch Charm events handling."""

    _start_opensearch_event = EventSource(StartOpenSearch)

    def __init__(self, charm: "OpenSearchBaseCharm", state: CharmState):
        super().__init__(charm, key="opensearch_events")
        self.charm = charm

        # --- OpenSearch charm events ---
        self.framework.observe(self.charm.on.install, self._on_install)
        self.framework.observe(self.charm.on.start, self._on_start)
        self.framework.observe(self._charm.on.secret_changed, self._on_secret_changed)
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

        elif self.cluster_manager_marked_as_started_but_service_not_started:
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
                self.opensearch.start_service_only()
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
        if not self.charm.cluster_manager._apply_peer_cm_directives_and_check_if_can_start():
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

        # TODO: Clear PClusterNoRelation

        # Configure OpenSearch Users
        if not self.charm.state.opensearch_unit.is_app_leader:
            self.charm.users_manager.purge_initial_users()
            for user in OPENSEARCH_SYSTEM_USERS:
                user_hash = self.charm.state.secrets.hash_key(user)
                hashed_pwd = self.charm.state.secrets.get(Scope.APP, user_hash)
                self.charm.users_manager.save_user_locally(user, hashed_pwd)

        # Configure Client Authentication
        self.charm.config_manager.set_client_auth()

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

        # TODO: Update Peer relation data

        if self.charm.cluster_manager.is_opensearch_started:
            try:
                self._post_start_init(event)
            except (
                OpenSearchHttpError,
                OpenSearchNotFullyReadyError,
            ):
                # check if cluster should have started but is blocked
                self.logger.debug("OpenSearch already started, but post-start init failed.")
                # if (
                #    ClusterTopology.is_data_role_in_cluster_fleet_apps(self)
                #    and self.peers_data.get(Scope.APP, "bootstrapped", False)
                #    and self.opensearch_peer_cm.is_provider(typ="main")
                # ):
                # In large deployments with cluster-manager-only-nodes,
                # the startup might fail if the cluster was bootstrapped earlier
                # and the cluster-manager node lost its data
                #    logger.warning(
                #        "Node is not ready to start, but data node exists and"
                #        " the cluster was previously bootstrapped."
                #    )
                #    self.status.set(BlockedStatus(ServiceStartError))

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

        # TODO: Can service start

        if event.ignore_lock:
            # Only used for force upgrades and starting 1 data node on a large deployment
            # where the main orchestrator has cluster-manager only nodes
            self.logger.debug("Starting without lock")
        elif not self.charm.lock_manager.acquired:
            self.logger.debug("Lock to start opensearch not acquired. Will retry next event")
            event.defer()
            return

        # TODO: Check if opensearch is failed

        self.charm.status.set(CharmStatuses.WAITING_TO_START)

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
        admin_field = self.charm.state.secrets.password_key("admin")
        admin_secret = self.charm.state.secrets.get(Scope.APP, admin_field)
        opensearch_client = OpenSearchClient(
            self.workload, self.state.host, self.state.port, admin_secret
        )
        try:
            nodes = self.charm.topology_manager.get_nodes(
                use_localhost=opensearch_client.is_node_up()
            )
        except OpenSearchHttpError:
            self.logger.info("Failed to get online nodes")
            event.defer()
            return

        for node in nodes:
            if node.name == self.unit_name:
                break
        else:
            raise OpenSearchNotFullyReadyError("Node online but not in cluster.")

        if self.charm.state.opensearch_unit.bootstrap_contributor:
            self.charm.cluster_manager.cleanup_bootstrap_conf()

        self.charm.exclusions_manager.delete_current()

    def _on_node_lock_relation_changed(self, _=None):
        """Event handler for when the node-lock relation changed"""
        self.charm.lock_manager.refresh_lock()

    def cleanup_start_state(self):
        """Clean Up Start state"""
        if self.charm.state.application.security_index_initialised:
            self.charm.status.clear(CharmStatuses.WAITING_TO_START.value)
            self.charm.status.clear(CharmStatuses.PEER_CLUSTER_NO_DATA_NODE.value)
        if self.charm.state.unit.bootstrap_contributor:
            self.charm.cluster_manager.cleanup_bootstrap_conf()

    @property
    def cluster_manager_marked_as_started_but_service_not_started(self) -> bool:
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
        """TODO: Address this when things get clearer
        try:
            label_parts = self.breakdown_label(event.secret.label)
        except ValueError:
            self.logger.info(f"Label {event.secret.label} was meaningless for us, returning")
            return

        # We need to take action on 5 secret types
        # 1. TLS credentials change
        #     - Action: update credentials files
        # 2. 'kibanaserver' user credentials change
        #     - Action: Dashboard relation (secret) needs to be updated
        # 3. System user hash secret update
        #     - Action: Every unit needs to update local internal_users.yml
        #     - Note: Leader is updated already
        # 4. S3 credentials (secret / access keys) in large relations
        #     - Action: write them into the opensearch.yml by running backup module
        # 5. Azure credentials (storage account / secret key)
        #
        # On a separate note: Handling for JWT-config related secrets (e.g. signing-key) happens
        # in the `JwtHandler` class, as it is a secret that is provided from another application

        system_user_hash_keys = [
            self._charm.secrets.hash_key(user) for user in OPENSEARCH_SYSTEM_USERS
        ]
        keys_to_process = system_user_hash_keys + [
            CertType.APP_ADMIN.val,
            self._charm.secrets.password_key(KIBANA_SERVER_USER),
            S3_CREDENTIALS,
            AZURE_CREDENTIALS,
        ]

        # Variables for better readability
        label_key = label_parts["key"]
        is_leader = self._charm.unit.is_leader()

        # Matching secrets by label
        if (
            label_parts["application_name"] != self._charm.app.name
            or label_parts["scope"] != Scope.APP
            or label_key not in keys_to_process
        ):
            self.logger.info("Secret %s was not relevant for us.", event.secret.label)
            return

        self.logger.debug("Secret change for %s", str(label_key))

        if is_leader and label_key == self._charm.secrets.password_key(KIBANA_SERVER_USER):
            self._charm.opensearch_provider.update_dashboards_password()

        # Non-leader units need to maintain local users in internal_users.yml
        elif not is_leader and label_key in system_user_hash_keys:
            password = event.secret.get_content()[label_key]
            if sys_user := self._user_from_hash_key(label_key):
                self._charm.user_manager.put_internal_user(sys_user, password)

        # broadcast secret updates to related sub-clusters
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
        """
