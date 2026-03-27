#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Base Charm."""

import logging
from abc import ABC, abstractmethod
from time import time_ns

import ops
from data_platform_helpers.advanced_statuses import StatusHandler
from ops import EventSource

from opensearch_single_kernel.common.constants import (
    PEER_RELATION,
    Scope,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchExclusionsException,
    OpenSearchHttpError,
)
from opensearch_single_kernel.common.statuses import GeneralStatuses
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.events.cos import CosEventsHandler
from opensearch_single_kernel.events.custom_events import (
    ReloadKeystoreEvent,
    RestartOpenSearch,
    StartOpenSearch,
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
from opensearch_single_kernel.events.snapshots import SnapshotsEventsHandler
from opensearch_single_kernel.events.tls import TLSEventsHandler
from opensearch_single_kernel.managers.cluster import ClusterManager
from opensearch_single_kernel.managers.config import ConfigManager
from opensearch_single_kernel.managers.exclusions import NodesExclusionsManager
from opensearch_single_kernel.managers.external_clients import ExternalClientsManager
from opensearch_single_kernel.managers.health import HealthManager
from opensearch_single_kernel.managers.internal_users import InternalUsersManager
from opensearch_single_kernel.managers.keystore import KeystoreManager
from opensearch_single_kernel.managers.lock import LockManager
from opensearch_single_kernel.managers.notification import NotificationsManager
from opensearch_single_kernel.managers.plugin import PluginManager
from opensearch_single_kernel.managers.profiles import ProfilesManager
from opensearch_single_kernel.managers.snapshots import SnapshotsManager
from opensearch_single_kernel.managers.tls import TlsManager
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class OpenSearchBaseCharm(ops.CharmBase, ABC):
    """Base OpenSearch Charm, this will include base structure for both machine and k8s charms."""

    # Custom Events
    restart_opensearch_event = EventSource(RestartOpenSearch)
    start_opensearch_event = EventSource(StartOpenSearch)
    verify_snapshots_credentials_event = EventSource(VerifySnapshotsCredentialsEvent)
    reload_keystore_event = EventSource(ReloadKeystoreEvent)

    def __init__(self, *args):
        super().__init__(*args)

        # State
        self.state = ClusterState(self, self.substrate)

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
        self.keystore_manager = KeystoreManager(self.state, self.workload)
        self.plugin_manager = PluginManager(self.state, self.workload)
        self.notifications_manager = NotificationsManager(self.state, self.workload)
        self.snapshots_manager = SnapshotsManager(self.state, self.workload)

        # Event Handlers
        self.opensearch_events = OpenSearchEventsHandler(self)
        self.tls_events = TLSEventsHandler(self)
        self.external_clients_events = ExternalClientsEventsHandler(self)
        self.keystore_events = KeystoreEventsHandler(self)
        self.snapshots_events = SnapshotsEventsHandler(self)
        self.notifications_events = NotificationsEvents(self)
        self.cos_events = CosEventsHandler(self)
        self.jwt_events = JWTEventsHandler(self)
        self.oauth_events = OAuthEventsHandler(self)

        self.status_handler = StatusHandler(
            self,
            self.profiles_manager,
            self.cluster_manager,
            self.internal_users_manager,
            self.tls_manager,
            self.health_manager,
            self.lock_manager,
            self.external_clients_manager,
            self.notifications_manager,
            self.snapshots_manager,
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

        return self.health_manager.apply_health(
            wait_for_green_first=wait_for_green_first,
            use_localhost=use_localhost,
            app=app,
            unit=unit,
        )

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
