#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for Charm External Clients Events."""

import logging
from typing import TYPE_CHECKING

from ops import (
    Object,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationDepartedEvent,
)

from opensearch_single_kernel.common.constants import CLIENT_RELATION, OLD_CA_ALIAS
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import ExternalClientsStatuses
from opensearch_single_kernel.core.state import ExternalOpenSearchClient
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    ENTITY_GROUP,
    ENTITY_USER,
    IndexEntityRequestedEvent,
    IndexRequestedEvent,
    OpenSearchProvides,
)
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
            self.opensearch_provides.on.index_requested, self._on_client_requested
        )
        self.framework.observe(
            self.opensearch_provides.on.index_entity_requested, self._on_client_requested
        )
        self.framework.observe(
            charm.on[CLIENT_RELATION].relation_changed, self._on_relation_changed
        )
        self.framework.observe(
            charm.on[CLIENT_RELATION].relation_departed, self._on_relation_departed
        )
        self.framework.observe(charm.on[CLIENT_RELATION].relation_broken, self._on_relation_broken)

    def _on_client_requested(self, event: IndexRequestedEvent | IndexEntityRequestedEvent) -> None:
        """Handle client index-requested & index-entity-requested events.

        The read-only-endpoints field of DatabaseProvides is unused in this relation because this
        concept is irrelevant to OpenSearch. In this relation, the application charm should have
        control over node & index security policies, and therefore differentiating between types of
        network endpoints is unnecessary.

        """
        if not (external_client := self.charm.state.external_client_by_relation(event.relation)):
            logger.error("No external client found for relation id %d", event.relation.id)
            return

        if self._is_user_entity_requested(external_client):
            return

        if not self._validate_client_request(event, external_client):
            return

        requested_entity = external_client.get_requested_entity()

        try:
            # The index is created before the entity granted access to it: nothing is provided
            # to the client if it fails.
            self._provide_client_index(event, external_client)
            self.charm.external_clients_manager.provide_client_entity(
                external_client, requested_entity
            )
        except OpenSearchUserMgmtError as e:
            logger.error("Failed to provide client or entity: %s", str(e))
            event.defer()
            return

        try:
            external_client.version = self.charm.workload.version
        except OpenSearchCmdError as e:
            logger.error("Failed to update relation version info: %s", str(e))
            event.defer()
            return

        try:
            external_client.tls_ca = self.charm.state.application.admin_secrets["chain"]
        except KeyError as e:
            logger.error("Failed to update relation TLS info: missing key %s", str(e))
            event.defer()
            return

        self.update_external_client_endpoints(external_client)
        if external_client.entity_type != ENTITY_GROUP:
            # A user was provided: the LDAP authorization has to skip it.
            self.charm.reconcile_security_config(event)

        logger.info("new index %s available", event.index)

    def _provide_client_index(
        self,
        event: IndexRequestedEvent | IndexEntityRequestedEvent,
        external_client: ExternalOpenSearchClient,
    ) -> None:
        """Create the index requested by a client relation while reporting it in the status."""
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

        self.charm.external_clients_manager.provide_client_index(external_client)

    def _is_user_entity_requested(self, external_client: ExternalOpenSearchClient) -> bool:
        """Check whether a client relation requests a USER entity, which is not supported.

        Nothing is provided to such a relation: the status of the app reports it.
        """
        if external_client.entity_type != ENTITY_USER:
            return False

        logger.error(
            "Ignoring client relation %d: entity-type=USER is not supported.",
            external_client.relation.id,
        )
        return True

    def _validate_client_request(
        self,
        event: IndexRequestedEvent | IndexEntityRequestedEvent,
        external_client: ExternalOpenSearchClient,
    ) -> bool:
        """Validate client request and return whether we should process it.

        Event deferring may also happen here from checks related on current charm state.
        """
        if self.charm.upgrades_manager.in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
            event.defer()
            return False

        if not self.charm.unit.is_leader():
            return False

        if (
            not self.charm.cluster_manager.opensearch_client.is_node_up()
            or not self.charm.state.application.is_security_index_initialised
        ):
            event.defer()
            return False

        # The node is up: the deployment description, hence the type of the app, is known.
        if not self.charm.state.is_main_orchestrator:
            logger.error(
                "Client relation %s must be created with the main orchestrator.",
                event.relation.id,
            )
            return False

        try:
            if self.charm.tls_manager.read_stored_ca(alias=OLD_CA_ALIAS):
                logger.debug("CA rotation in progress. Deferring index/entity requested event.")
                event.defer()
                return False
        except OpenSearchFileOperationError as e:
            logger.error("Failed to read stored CA: %s", str(e))
            event.defer()
            return False

        try:
            error = self.charm.external_clients_manager.get_request_error(external_client)
        except OpenSearchHttpError as e:
            logger.error("Failed to validate the request of client relation: %s", str(e))
            event.defer()
            return False

        if error:
            logger.error(
                "Cannot serve the request of client relation %s: %s",
                event.relation.id,
                error.name,
            )
            # A conflicting entity is released once the relation owning it, or the role
            # holding its name, is removed.
            if error is ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT:
                event.defer()
            return False

        return True

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handle opensearch client relation-changed event."""
        if not self.charm.unit.is_leader():
            return

        external_client = self.charm.state.external_client_by_relation(event.relation)
        if not external_client:
            logger.error("No external client found for relation id %d", event.relation.id)
            return
        if self._is_user_entity_requested(external_client):
            return
        if self.charm.cluster_manager.opensearch_client.is_node_up():
            self.update_external_client_endpoints(external_client)
        else:
            event.defer()

    def _on_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Remove the departing OpenSearch unit from the endpoints exposed to the client."""
        if not self.charm.unit.is_leader():
            return
        external_client = self.charm.state.external_client_by_relation(event.relation)
        if not external_client:
            logger.error("No external client found for relation id %d", event.relation.id)
            return
        if self._is_user_entity_requested(external_client):
            return
        # remove departing unit from endpoints available to requirer charm.
        if event.departing_unit and event.departing_unit.app == self.charm.app:
            departing_unit_ip = self.charm.state.unit_ip(event.departing_unit)
            self.update_external_client_endpoints(
                external_client, omit_endpoints={departing_unit_ip}
            )

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle client relation-broken event."""
        if self.charm.is_unit_going_away(event):
            logger.info(
                "Unit is going away, keeping the user of client relation %d.", event.relation.id
            )
            return
        if not self.charm.unit.is_leader():
            return
        if self.charm.upgrades_manager.in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
        self.charm.external_clients_manager.remove_lingering_relation_users_and_roles()
        # The users which were removed are no longer to be skipped by the LDAP authorization.
        self.charm.reconcile_security_config(event)

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
