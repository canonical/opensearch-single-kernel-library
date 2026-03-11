#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for Charm External Clients Events."""

import logging
from typing import TYPE_CHECKING

from ops import Object, RelationBrokenEvent, RelationChangedEvent, RelationDepartedEvent

from opensearch_single_kernel.common.constants import (
    CLIENT_RELATION,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchIndexError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.core.state import ExternalOpenSearchClient
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    IndexRequestedEvent,
    OpenSearchProvides,
)
from opensearch_single_kernel.utils.helpers import validate_index_name
from opensearch_single_kernel.utils.status import Status

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

    def _on_index_requested(self, event: IndexRequestedEvent) -> None:  # noqa
        """Handle client index-requested event.

        The read-only-endpoints field of DatabaseProvides is unused in this relation because this
        concept is irrelevant to OpenSearch. In this relation, the application charm should have
        control over node & index security policies, and therefore differentiating between types of
        network endpoints is unnecessary.

        Raises:
            OpenSearchIndexError if the index name is invalid
            OpenSearchHttpError if we can't create the required index
        """
        # TODO: If upgrade in progress then defer event

        if not self.charm.unit.is_leader():
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up() or not event.index:
            event.defer()
            return
        external_client = self.charm.state.external_client_by_relation(event.relation)
        if not validate_index_name(event.index):
            raise OpenSearchIndexError(f"invalid index name: {event.index}")

        self.charm.status.set(
            CharmStatuses.NEW_INDEX_REQUESTED, dynamic_params={"index": event.index}
        )

        try:
            self.charm.external_clients_manager.opensearch_client.create_index(event.index)
        except OpenSearchHttpError as e:
            logger.error(
                CharmStatuses.INDEX_CREATION_FAILED.value.message.format(index=event.index)
                + f"\nresponse error: {e}"
            )
            self.charm.status.set(
                CharmStatuses.INDEX_CREATION_FAILED, dynamic_params={"index": event.index}
            )
            event.defer()
            return

        try:
            username, pwd = self.charm.external_clients_manager.create_opensearch_users(
                external_client, event.index, extra_user_roles=event.extra_user_roles
            )
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            self.charm.status.set(
                CharmStatuses.USER_CREATION_FAILED,
                dynamic_params={"rel_name": CLIENT_RELATION, "id": event.relation.id},
            )
            return

        external_client.version = self.charm.external_clients_manager.version 
        external_client.username = username
        external_client.password = pwd
        external_client.index = event.index
        try:
            self.charm.external_clients_manager.update_relation_tls_info(external_client)
        except KeyError as e:
            logger.error(f"Failed to update relation TLS info: missing key {e}")
            event.defer()
            return
        

        self.update_external_client_endpoints(external_client)

        logger.info(f"new index {event.index} available")
        # Clear old statuses set by this hook
        self.charm.status.clear(
            CharmStatuses.NEW_INDEX_REQUESTED, pattern=Status.CheckPattern.Interpolated
        )
        self.charm.status.clear(
            CharmStatuses.INDEX_CREATION_FAILED, pattern=Status.CheckPattern.Interpolated
        )
        self.charm.status.clear(
            CharmStatuses.USER_CREATION_FAILED, pattern=Status.CheckPattern.Interpolated
        )

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handle opensearch client relation-changed event."""
        if not self.charm.unit.is_leader():
            return

        external_client = self.charm.state.external_client_by_relation(event.relation)
        if not external_client:
            logger.error("No external client found for relation id %d", event.relation.id)
            event.defer()
            return
        if self.charm.cluster_manager.opensearch_client.is_node_up():
            self.update_external_client_endpoints(external_client)
        else:
            event.defer()

    def _on_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Check if this relation is being removed, and update the peer databag accordingly."""
        external_client = self.charm.state.external_client_by_relation(event.relation)
        if not external_client:
            logger.error("No external client found for relation id %d", event.relation.id)
            return
        # remove departing unit from endpoints available to requirer charm.
        if event.departing_unit.app == self.charm.app:
            departing_unit_ip = self.charm.state.unit_ip(event.departing_unit)
            self.update_external_client_endpoints(
                external_client, omit_endpoints={departing_unit_ip}
            )
        if event.departing_unit == self.charm.unit:
            external_client.set_relation_departing()
        if self.charm.unit.is_leader():
            self.charm.external_clients_manager.remove_lingering_relation_users_and_roles(
                external_client
            )

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle client relation-broken event."""
        if not self.charm.unit.is_leader():
            return

        external_client = self.charm.state.external_client_by_relation(event.relation)
        if not external_client:
            logger.error("No external client found for relation id %d", event.relation.id)
            return
        if external_client.is_relation_departing():
            # This unit is being removed.
            external_client.delete_relation_departing_flag()
            return
        # TODO: Handle upgrades
        # if self.charm.upgrade_in_progress:
        #    logger.warning(
        # "Modifying relations during an upgrade is not supported."
        # "The charm may be in a broken, unrecoverable state"
        # )
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
            except OpenSearchHttpError:
                logger.error("unable to get nodes")
                nodes = []
            self.charm.external_clients_manager.update_relation_endpoints(
                external_client, nodes, omit_endpoints=omit_endpoints
            )
