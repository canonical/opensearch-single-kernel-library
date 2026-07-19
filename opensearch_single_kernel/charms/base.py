#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Base Charm."""

import logging
from abc import ABC, abstractmethod
from time import time_ns

import ops
from data_platform_helpers.advanced_statuses import StatusHandler
from ops import EventSource
from ops.charm import CharmEvents

from opensearch_single_kernel.common.constants import (
    AZURE_RELATION,
    GCS_RELATION,
    PEER_RELATION,
    S3_RELATION,
    SMTP_RELATION,
    Scope,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchExclusionsException,
    OpenSearchHttpError,
)
from opensearch_single_kernel.common.pebble_observer import PebbleObserver
from opensearch_single_kernel.common.statuses import GeneralStatuses
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.events.cos import CosEventsHandler
from opensearch_single_kernel.events.custom_events import (
    PebbleCanConnectEvent,
    ReloadKeystoreEvent,
    RestartOpenSearch,
    StartOpenSearch,
    UpgradeOpenSearch,
    VerifySnapshotsCredentialsEvent,
)
from opensearch_single_kernel.events.external_clients import (
    ExternalClientsEventsHandler,
)
from opensearch_single_kernel.events.jwt import JWTEventsHandler
from opensearch_single_kernel.events.keystore import KeystoreEventsHandler
from opensearch_single_kernel.events.notifications import NotificationsEvents
from opensearch_single_kernel.events.oauth import OAuthEventsHandler
from opensearch_single_kernel.events.opensearch import OpenSearchEventsHandler
from opensearch_single_kernel.events.peer_cluster import PeerClusterEventsHandler
from opensearch_single_kernel.events.snapshots import SnapshotsEventsHandler
from opensearch_single_kernel.events.tls import TLSEventsHandler
from opensearch_single_kernel.events.upgrades import UpgradesEventsHandler
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.azure_storage import (
    AzureStorageRequires,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.gcs_storage import (
    GcsStorageRequires,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.s3 import S3Requirer
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import SmtpRequires
from opensearch_single_kernel.managers.cluster import ClusterManager
from opensearch_single_kernel.managers.config import ConfigManager
from opensearch_single_kernel.managers.exclusions import NodesExclusionsManager
from opensearch_single_kernel.managers.external_clients import ExternalClientsManager
from opensearch_single_kernel.managers.health import HealthManager
from opensearch_single_kernel.managers.internal_users import InternalUsersManager
from opensearch_single_kernel.managers.keystore import KeystoreManager
from opensearch_single_kernel.managers.lock import LockManager
from opensearch_single_kernel.managers.notification import NotificationsManager
from opensearch_single_kernel.managers.peer_cluster import PeerClusterManager
from opensearch_single_kernel.managers.peer_cluster_orchestrator import (
    PeerClusterOrchestratorManager,
)
from opensearch_single_kernel.managers.plugin import PluginManager
from opensearch_single_kernel.managers.profiles import ProfilesManager
from opensearch_single_kernel.managers.snapshots import SnapshotsManager
from opensearch_single_kernel.managers.tls import TlsManager
from opensearch_single_kernel.managers.upgrades_k8s import UpgradesManagerK8s
from opensearch_single_kernel.managers.upgrades_vm import UpgradesManagerVM
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class OpenSearchCharmEvents(CharmEvents):
    """Custom charm events for OpenSearch, extending Juju's built-in CharmEvents."""

    pebble_can_connect = EventSource(PebbleCanConnectEvent)


class OpenSearchBaseCharm(ops.CharmBase, ABC):
    """Base OpenSearch Charm, this will include base structure for both machine and k8s charms."""

    on = OpenSearchCharmEvents()  # type: ignore[assignment]

    # Custom Events
    restart_opensearch_event = EventSource(RestartOpenSearch)
    start_opensearch_event = EventSource(StartOpenSearch)
    upgrade_opensearch_event = EventSource(UpgradeOpenSearch)
    verify_snapshots_credentials_event = EventSource(VerifySnapshotsCredentialsEvent)
    reload_keystore_event = EventSource(ReloadKeystoreEvent)

    def __init__(self, *args):
        super().__init__(*args)

        # State
        self.state = ClusterState(
            self,
            self.substrate,
            SmtpRequires(self, SMTP_RELATION),
            S3Requirer(self, S3_RELATION),
            AzureStorageRequires(self, AZURE_RELATION),
            GcsStorageRequires(self, GCS_RELATION),
        )

        # Managers
        self.tls_manager = TlsManager(self.state, self.workload)
        self.internal_users_manager = InternalUsersManager(self.state, self.workload)
        self.cluster_manager = ClusterManager(self.state, self.workload)
        self.exclusions_manager = NodesExclusionsManager(self.state, self.workload)
        self.external_clients_manager = ExternalClientsManager(self.state, self.workload)
        self.lock_manager = LockManager(self.state, self.workload)
        self.profiles_manager = ProfilesManager(self.state, self.workload)
        self.health_manager = HealthManager(self.state, self.workload)
        self.config_manager = ConfigManager(self.state, self.workload)
        self.peer_cluster_orchestrator_manager = PeerClusterOrchestratorManager(
            self.state, self.workload
        )
        self.peer_cluster_manager = PeerClusterManager(self.state, self.workload)
        self.keystore_manager = KeystoreManager(self.state, self.workload)
        self.plugin_manager = PluginManager(self.state, self.workload)
        self.notifications_manager = NotificationsManager(self.state, self.workload)
        self.snapshots_manager = SnapshotsManager(self.state, self.workload)
        if self.substrate == Substrates.K8S:
            self.upgrades_manager = UpgradesManagerK8s(self.state, self.workload)
        else:
            self.upgrades_manager = UpgradesManagerVM(self.state, self.workload)

        # Events
        self.opensearch_events = OpenSearchEventsHandler(self)
        self.upgrade_events = UpgradesEventsHandler(self)
        self.tls_events = TLSEventsHandler(self)
        self.peer_cluster_events = PeerClusterEventsHandler(self)
        self.external_clients_events = ExternalClientsEventsHandler(self)
        self.keystore_events = KeystoreEventsHandler(self)
        self.snapshots_events = SnapshotsEventsHandler(self)
        self.notifications_events = NotificationsEvents(self)
        self.cos_events = CosEventsHandler(self)
        self.jwt_events = JWTEventsHandler(self)
        self.oauth_events = OAuthEventsHandler(self)

        # Re-dispatch deferred events once pebble is ready; without this, a slow pebble startup
        # leaves the charm stuck with all events deferred and no trigger to replay them.
        self.pebble_observer = PebbleObserver(self)

        # Status priority (earlier = higher juju status urgency): critical
        # upgrades, config/TLS, health, topology, lock, backups, plugins,
        # clients, notifications.
        self.status_handler = StatusHandler(
            self,
            self.upgrades_manager,
            self.profiles_manager,
            self.tls_manager,
            self.health_manager,
            self.peer_cluster_manager,
            self.cluster_manager,
            self.plugin_manager,
            self.lock_manager,
            self.snapshots_manager,
            self.internal_users_manager,
            self.external_clients_manager,
            self.notifications_manager,
        )

    def trigger_peer_rel_changed(
        self,
        only_by_leader: bool = False,
        on_other_units: bool = True,
        on_current_unit: bool = False,
    ) -> None:
        """Force trigger a peer rel changed event."""
        if only_by_leader and not self.unit.is_leader():
            return

        if on_other_units or not on_current_unit:
            if only_by_leader:
                self.state.application.update_ts = time_ns()
            else:
                self.state.server.update_ts = time_ns()

        if on_current_unit:
            self.on[PEER_RELATION].relation_changed.emit(self.state.peer_relation)

    def stop_opensearch(self, *, restart: bool = False) -> None:
        """Stop OpenSearch service."""
        self.status_handler.set_running_status(
            GeneralStatuses.SERVICE_IS_STOPPING.value,
            "unit",
            component_name=self.cluster_manager.name,
        )

        if self.cluster_manager.opensearch_client.is_node_up():
            try:
                nodes = self.cluster_manager.get_nodes(True)
                # do not add exclusions if it's the last unit to stop
                # otherwise cluster manager election will be blocked when starting up again
                # and reusing storage
                if len(nodes) > 1:
                    # 1. Add current node to the voting + alloc exclusions
                    self.exclusions_manager.add_current(
                        scope=Scope.APP if self.unit.is_leader() else Scope.UNIT,
                        voting=True,
                        allocation=not restart,
                    )
            except (OpenSearchHttpError, OpenSearchExclusionsException):
                logger.error("Failed to get online nodes, voting and alloc exclusions not added")

        # block until all primary shards are moved away from the unit that is stopping
        self.health_manager.wait_for_shards_relocation()

        # Stop the workload
        self.cluster_manager.stop_workload()

    def apply_health(
        self,
        wait_for_green_first: bool = False,
        use_localhost: bool = True,
        app: bool = True,
        unit: bool = True,
    ):
        """Fetch cluster health and set it on the app status."""
        if app and not self.unit.is_leader():
            self.trigger_peer_rel_changed(on_other_units=True)
            return

        status = self.health_manager.get(
            wait_for_green_first=wait_for_green_first, use_localhost=use_localhost
        )
        logger.info("Current health of cluster: %s", status)
        return status

    @property
    @abstractmethod
    def workload(self) -> BaseWorkload:
        """Access current workload."""
        pass

    @property
    @abstractmethod
    def substrate(self) -> Substrates:
        """Access current substrate."""
        pass
