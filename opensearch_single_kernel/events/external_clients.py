#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for Charm External Clients Events."""

import logging
from typing import TYPE_CHECKING

from ops import Object, RelationBrokenEvent, RelationChangedEvent, RelationDepartedEvent

from opensearch_single_kernel.common.constants import CLIENT_RELATION
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import ExternalClientsStatuses
from opensearch_single_kernel.core.state import ExternalOpenSearchClient
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    IndexRequestedEvent,
    OpenSearchProvides,
)
from opensearch_single_kernel.utils.helpers import validate_index_name
from opensearch_single_kernel.utils.status import format_status

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class ExternalClientsEventsHandler(Object):
    """Handler for Charm External Clients Events."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, key="external_clients_events_handler")
        self.charm = charm

        self.opensearch_provides = OpenSearchProvides(
            self.charm,
            relation_name=CLIENT_RELATION,
        )

        self.framework.observe(
            self.opensearch_provides.on.index_requested, self._on_index_requested
        )
        self.framework.observe(
            charm.on[CLIENT_RELATION].relation_changed, self._on_relation_changed
        )
        self.framework.observe(
            charm.on[CLIENT_RELATION].relation_departed, self._on_relation_departed
        )
        self.framework.observe(charm.on[CLIENT_RELATION].relation_broken, self._on_relation_broken)

    def _on_index_requested(self, event: IndexRequestedEvent) -> None:  # noqa: C901
        """Handle client index-requested event.

        The read-only-endpoints field of DatabaseProvides is unused in this relation because this
        concept is irrelevant to OpenSearch. In this relation, the application charm should have
        control over node & index security policies, and therefore differentiating between types of
        network endpoints is unnecessary.

        Raises:
            OpenSearchIndexError if the index name is invalid
            OpenSearchHttpError if we can't create the required index
        """
        if self.charm.upgrades_manager.in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
            event.defer()
            return

        if not self.charm.unit.is_leader():
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up() or not event.index:
            event.defer()
            return
        if not (external_client := self.charm.state.external_client_by_relation(event.relation)):
            logger.error("No external client found for relation id %d", event.relation.id)
            return

        if not validate_index_name(event.index):
            # Status pure-computed by ExternalClientsManager.get_statuses
            logger.error(
                "Invalid index name %s on client relation %s",
                event.index,
                event.relation.id,
            )
            return

        self.charm.status_handler.set_running_status(
            format_status(
                ExternalClientsStatuses.NEW_INDEX_REQUESTED.value,
                {
                    "index": event.index,
                    "id": event.relation.id,
                },
            ),
            "unit",
            component_name=self.charm.external_clients_manager.name,
        )

        try:
            self.charm.external_clients_manager.opensearch_client.create_index(event.index)
        except OpenSearchHttpError as e:
            logger.error(
                f"Failed to create index {event.index} for client relation {event.relation.id}: {e}"
            )
            # Status pure-computed by ExternalClientsManager.get_statuses
            event.defer()
            return

        try:
            username, pwd = self.charm.external_clients_manager.create_opensearch_users(
                external_client, event.index, extra_user_roles=event.extra_user_roles
            )
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            # Status pure-computed by ExternalClientsManager.get_statuses
            event.defer()
            return
        try:
            external_client.version = self.charm.workload.version
        except OpenSearchCmdError as e:
            logger.error("Failed to update relation version info: %s", str(e))
            event.defer()
            return
        external_client.username = username
        external_client.password = pwd
        external_client.index = event.index
        try:
            external_client.tls_ca = self.charm.state.application.admin_secrets["chain"]
        except KeyError as e:
            logger.error("Failed to update relation TLS info: missing key %s", str(e))
            event.defer()
            return

        self.update_external_client_endpoints(external_client)

        logger.info("new index %s available", event.index)

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handle opensearch client relation-changed event."""
        if not self.charm.unit.is_leader():
            return

        external_client = self.charm.state.external_client_by_relation(event.relation)
        if not external_client:
            logger.error("No external client found for relation id %d", event.relation.id)
            return
        if self.charm.cluster_manager.opensearch_client.is_node_up():
            self.update_external_client_endpoints(external_client)
        else:
            event.defer()

    def _on_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Check if this relation is being removed, and update the peer databag accordingly."""
        if not self.charm.unit.is_leader():
            return
        external_client = self.charm.state.external_client_by_relation(event.relation)
        if not external_client:
            logger.error("No external client found for relation id %d", event.relation.id)
            return
        # remove departing unit from endpoints available to requirer charm.
        if event.departing_unit.app == self.charm.app:
            self.charm.state.server.set_relation_departing(event.relation)
            departing_unit_ip = self.charm.state.unit_ip(event.departing_unit)
            self.update_external_client_endpoints(
                external_client, omit_endpoints={departing_unit_ip}
            )
        self.charm.external_clients_manager.remove_lingering_relation_users_and_roles(
            external_client
        )

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle client relation-broken event."""
        if not self.charm.unit.is_leader():
            return
        if not (external_client := self.charm.state.external_client_by_relation(event.relation)):
            logger.error("No external client found for relation id %d", event.relation.id)
            return
        if self.charm.state.server.get_relation_departing(event.relation):
            self.charm.state.server.remove_relation_departing(event.relation)
            return
        if self.charm.upgrades_manager.in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
        self.charm.external_clients_manager.remove_lingering_relation_users_and_roles(
            external_client
        )

    def update_external_client_endpoints(
        self, external_client: ExternalOpenSearchClient, omit_endpoints: set | None = None
    ) -> None:
        """Update the external client state with endpoints."""
        if self.charm.unit.is_leader():
            try:
                nodes = self.charm.cluster_manager.get_nodes(use_localhost=True)
            except OpenSearchHttpError as e:
                logger.error("unable to get nodes %s", str(e))
                nodes = []
            self.charm.external_clients_manager.update_relation_endpoints(
                external_client, nodes, omit_endpoints=omit_endpoints
            )
