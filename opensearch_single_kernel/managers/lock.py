#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Lock manager.

Ensure that only one node (re)starts, joins the cluster, or leaves the cluster at a time.

The workflow logic goes alongside the following:

1. If there are opensearch online nodes:
   a) the node requesting the lock attempts to create a doc with the name of the node
   b) if it succeeds => the unit gets the lock
   c) if it fails => the unit doesn't get the lock as it is held by another unit
   d) when the unit completes with their locked operation => releases the lock => deletes the doc
2. if there are no online nodes:
   a) we make use of a flag in the relation data
   b) we check on the existence of the flag to know if the lock is held or not
   c) if not there => we set the lock (flag in the peer rel data)
   d) we release the lock by removing that flag from the rel data
"""

import logging
import os

from ops import Relation

from opensearch_single_kernel.common.constants import DeploymentType, StartMode
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchLockError,
)
from opensearch_single_kernel.common.statuses import LockStatuses
from opensearch_single_kernel.core.models import DeploymentDescription
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import format_unit_name
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PeerLockManager(BaseManager):
    """Fallback lock when all units of OpenSearch are offline."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "lock_manager")

    def acquire(self) -> bool:
        """Attempt to acquire lock.

        Returns:
            Whether lock was acquired
        """
        if not self.state.lock_relation:
            return False

        self.state.server_lock.lock_requested = True

        if self.state.server.is_app_leader:
            logger.debug("[Node lock] Requested peer lock as leader unit")
            # A separate relation-changed event won't get fired
            self.refresh_lock()

        if self.state.application_lock.unit_with_lock != self.state.unit_name:
            logger.debug(
                "[Node lock] Not acquired. Unit with peer databag lock: %s",
                self.state.application_lock.unit_with_lock,
            )
            return False

        if (
            self.state.server.is_app_leader
            and self.state.application_lock.leader_acquired_after_juju_event_id
            == os.environ["JUJU_CONTEXT_ID"]
        ):
            # `unit-with-lock` was set in this Juju event
            # If the charm code raises an uncaught exception later in the Juju event,
            # `unit-with-lock` will be reverted to its previous value—which could allow another
            # unit to get the lock.
            # Therefore, we cannot use the lock now. We must wait until the next Juju event,
            # when `unit-with-lock` has been committed (i.e. won't be reverted), to use the
            # lock.
            if self.state.planned_units <= 1:
                # No other unit will get peer relation changed
                # Therefore, no other unit will be able to trigger peer relation changed on this
                # unit. We must use the lock now and accept that `unit-with-lock` could be reverted
                # if the charm code raises an uncaught exception later in the Juju event.
                logger.debug(
                    "[Node lock] Single unit deployment. Not waiting until next Juju event to use peer "
                    "databag lock for leader unit"
                )
            else:
                logger.debug(
                    "[Node lock] Not acquired. Waiting until next Juju event to use peer databag lock "
                    "for leader unit"
                )
                return False

        logger.debug("[Node lock] Acquired via peer databag")
        self.state.remove_status_if_present(
            LockStatuses.REQUEST_LOCK_ON_START.value, "unit", self.name
        )
        return True

    def release(self) -> None:
        """Release lock for this unit."""
        if not self.state.lock_relation:
            return

        logger.debug(f"Releasing peer databag lock for {self.state.unit_name}")

        self.state.server_lock.lock_requested = False
        logger.debug(f"Released peer databag lock {self.state.server_lock.lock_requested}")
        if self.state.server.is_app_leader:
            # A separate relation-changed event won't get fired
            self.refresh_lock()
            logger.debug("[Node lock] Released peer lock as leader unit")

        self.state.remove_status_if_present(
            LockStatuses.REQUEST_LOCK_ON_START.value, "unit", self.name
        )

    def refresh_lock(self) -> Relation | None:
        """Grant & release lock."""
        if not self.state.lock_relation:
            raise OpenSearchLockError("Failed to refresh lock due to lock relation absence")

        if not (deployment_desc := self.state.application.deployment_desc):
            return

        if not self.state.server.is_app_leader:
            if self.state.application_lock.leader_acquired_after_juju_event_id:
                # Trigger peer relation changed event on leader unit
                # Without this, the leader unit might not receive another event (to use the lock it
                # holds) until the next update status event
                self.state.server_lock.trigger_relation_changed()
            return

        if (granted_unit := self.state.lock_granted_server) and granted_unit.lock_requested:
            # Lock still in use, do not release
            logger.debug("[Node lock] (leader) lock still in use")
            return

        # TODO: adjust which unit gets priority on lock after leader?
        # During initial startup, leader unit must start first
        # Give priority to leader unit

        for unit in self.state.server_locks:
            if unit.lock_requested:
                self.state.application_lock.unit_with_lock = format_unit_name(
                    unit.unit, app=deployment_desc.app
                )
                logger.debug("[Node lock] (leader) granted peer lock to %s", unit.unit.name)
                break
        else:
            logger.debug("[Node lock] (leader) cleared peer lock")
            del self.state.application_lock.unit_with_lock


class LockManager(PeerLockManager):
    """OpenSearch Lock Manager."""

    OPENSEARCH_INDEX = ".charm_node_lock"

    def should_ignore_lock(self, deployment_desc: DeploymentDescription) -> bool:
        """Check if we should ignore the lock when starting OpenSearch."""
        return (
            self.state.server.is_app_leader
            # data unit
            and (
                "data" in deployment_desc.config.roles
                or deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            )
            and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR
            and (
                not self.state.application.is_security_index_initialised
                or (
                    # in case all data-nodes are powered down after being previously started
                    # ignore the lock to get a data-node started, as it holds security index
                    bool(self.state.server.started) and not self.workload.is_service_started()
                )
            )
            # TODO: Handle large deployment cases
            # and self.peer_cluster_requirer.get_cluster_first_data_node() is None
            # and (
            # deployment_desc.typ != DeploymentType.FAILOVER_ORCHESTRATOR
            # or self._is_failover_and_sole_data_app()
            # )
        )

    def acquire(self) -> bool:  # noqa: C901
        """Attempt to acquire lock.

        Returns:
            Whether lock was acquired
        """
        logger.debug("[Node lock] Attempting to acquire lock")
        host = self.state.node_host if self.opensearch_client.is_node_up() else None
        alt_hosts = self.alt_hosts
        if host or alt_hosts:
            logger.debug("[Node lock] 1+ opensearch nodes online")
            try:
                online_nodes = len(self._nodes(use_localhost=host is not None, hosts=alt_hosts))
            except OpenSearchHttpError:
                logger.exception("Error getting OpenSearch nodes")
                return False

            logger.debug("[Node lock] Opensearch %s", online_nodes)
            if not online_nodes:
                raise OpenSearchLockError("Failed to acquire lock due to absence of online nodes")
            try:
                unit_with_lock = self.opensearch_client.get_unit_with_lock(host, self.alt_hosts)
                logger.debug("[Node lock] Unit with opensearch lock: %s", unit_with_lock)
            except OpenSearchHttpError:
                logger.exception("Error checking which unit has OpenSearch lock")
                # if the node lock cannot be acquired, fall back to peer databag lock
                # this avoids hitting deadlock situations in cases where
                # the .charm_node_lock index is not available
                if online_nodes <= 1:
                    logger.debug(
                        "[Node lock] Falling back to peer databag lock due to error checking OpenSearch lock and 1 or fewer online nodes"
                    )
                    return super().acquire()
                else:
                    return False
            # If online_nodes == 1, we should acquire the lock via the peer databag.
            # If we acquired the lock via OpenSearch and this unit was stopping, we would be unable
            # to release the OpenSearch lock. For example, when scaling to 0.
            # Then, when 1+ OpenSearch nodes are online, a unit that no longer exists could hold
            # the lock.
            if not unit_with_lock and online_nodes > 0:
                logger.debug(
                    "[Node lock] Attempting to acquire opensearch lock via opensearch itself"
                )
                # Acquire opensearch lock
                # Create index if it doesn't exist
                if not self.opensearch_client.create_lock_index_if_needed(
                    host, alt_hosts, self.state.application.app.planned_units() > 1
                ):
                    logger.debug("[Node lock] Failed to create lock index")
                    return False

                # Attempt to create document id 0
                try:
                    if not self.opensearch_client.create_lock_document(
                        host, self.alt_hosts, self.state.unit_name
                    ):
                        logger.debug("[Node lock] Failed to create lock document")
                        return False
                except OpenSearchHttpError:
                    logger.exception("Error creating OpenSearch lock document")
                    # in this case, try to acquire peer databag lock as fallback
                    return super().acquire()

                logger.debug("[Node lock] Created lock document to acquire opensearch lock")
                unit_with_lock = self.state.unit_name

            logger.debug(
                "[Node lock] Unit with opensearch lock after attempting to acquire: %s",
                unit_with_lock,
            )
            if unit_with_lock == self.state.unit_name:
                # Lock acquired
                # Release peer databag lock, if any
                logger.debug("[Node lock] Acquired via opensearch")
                super().release()
                logger.debug("[Node lock] Released redundant peer lock (if held)")
                return True

            if unit_with_lock:
                # Another unit has lock
                logger.debug(
                    "[Node lock] Not acquired. Unit with opensearch lock: %s", unit_with_lock
                )
                return False

            if online_nodes != 1:
                raise OpenSearchLockError("Single online node expected to acquire lock")
            logger.debug("[Node lock] No unit has opensearch lock")
        logger.debug("[Node lock] Using peer databag for lock")
        # Request peer databag lock
        # If return value is True:
        # - Lock granted in previous Juju event
        # - OR, unit is leader & lock granted in this Juju event
        return super().acquire()

    def release(self) -> None:
        """Release lock.

        Limitation: if lock acquired via OpenSearch document and all units offline, OpenSearch
        document lock will not be released
        """
        logger.debug("[Node lock] Releasing lock")

        # fetch current app description
        current_app = self.state.application.deployment_desc.app

        host = self.state.node_host if self.opensearch_client.is_node_up() else None
        alt_hosts = self.alt_hosts
        if host or alt_hosts:
            logger.debug("[Node lock] Checking which unit has opensearch lock")
            # Check if this unit currently has lock
            # or if there is a stale lock from a unit no longer existing
            # for large deployments the MAIN/FAILOVER orchestrators should broadcast info
            # over non-online units in the relation. This info should be considered here as well.
            unit_with_lock = self.opensearch_client.get_unit_with_lock(host, self.alt_hosts)
            current_app_units = [
                format_unit_name(unit, app=current_app) for unit in self.state.all_units
            ]

            # handle case of large deployments
            other_apps_units = []
            if all_apps := self.state.application.cluster_fleet_apps:
                for p_cluster_app in all_apps.values():
                    if p_cluster_app.app.id == current_app.id:
                        continue

                    units = [
                        format_unit_name(unit, app=p_cluster_app.app)
                        for unit in p_cluster_app.units
                    ]
                    other_apps_units.extend(units)

            if unit_with_lock and (
                unit_with_lock == self.state.unit_name
                or unit_with_lock not in current_app_units + other_apps_units
            ):
                logger.debug("[Node lock] Releasing opensearch lock")
                # Delete document id 0
                self.opensearch_client.delete_lock_document(host, alt_hosts)
                logger.debug("[Node lock] Released opensearch lock")
        super().release()
        logger.debug("[Node lock] Released peer lock (if held)")
        logger.debug("[Node lock] Released lock")
