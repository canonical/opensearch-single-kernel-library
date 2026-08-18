#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for Charm External Clients Events."""

import logging
from typing import TYPE_CHECKING

from dpcharmlibs.interfaces import (
    ResourceProviderModel,
    ResourceRequestedEvent,
)
from ops import (
    ConfigChangedEvent,
    Object,
    Relation,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationDepartedEvent,
    UpdateStatusEvent,
)

from opensearch_single_kernel.common.constants import (
    CLIENT_RELATION,
    PEER_RELATION,
    DeploymentType,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import ExternalClientsStatuses
from opensearch_single_kernel.utils.helpers import (
    validate_index_name,
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

        self.framework.observe(
            self.charm.state.opensearch_provides.on.resource_requested, self._on_resource_requested
        )
        self.framework.observe(
            charm.on[CLIENT_RELATION].relation_changed, self._on_relation_changed
        )
        self.framework.observe(
            charm.on[CLIENT_RELATION].relation_departed, self._on_relation_departed
        )
        self.framework.observe(charm.on[CLIENT_RELATION].relation_broken, self._on_relation_broken)

        self.framework.observe(charm.on.config_changed, self._on_config_changed)
        self.framework.observe(charm.on.update_status, self._on_update_status)
        self.framework.observe(
            self.charm.on[PEER_RELATION].relation_changed,
            self._on_peer_relation_changed,
        )

    def _on_resource_requested(self, event: ResourceRequestedEvent) -> None:
        """Handle client resource-requested event (previously index-requested)."""
        if self.charm.upgrades_manager.in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
            event.defer()
            return

        if not self.charm.unit.is_leader():
            return

        index_name = self._validate_request(event)
        if not index_name:
            return

        self.charm.status_handler.set_running_status(
            ExternalClientsStatuses.NEW_INDEX_REQUESTED.value,
            "unit",
            component_name=self.charm.external_clients_manager.name,
        )

        self.charm.status_handler.set_running_status(
            format_status(
                ExternalClientsStatuses.NEW_INDEX_REQUESTED.value,
                {
                    "index": index_name,
                    "id": event.relation.id,
                },
            ),
            "unit",
            component_name=self.charm.external_clients_manager.name,
        )

        if not self._create_index(event, index_name):
            return

        credentials = self._create_user(event, index_name)
        if not credentials:
            return
        username, pwd = credentials

        conn_data = self._get_connection_data(event)
        if not conn_data:
            return

        response = ResourceProviderModel(
            request_id=event.request.request_id,
            salt=event.request.salt,
            resource=index_name,
            username=username,
            password=pwd,
            endpoints=conn_data["endpoints"],
            uris=conn_data["endpoints"],
            tls_ca=conn_data["tls_ca"],
            version=conn_data["version"],
        )

        self.charm.state.opensearch_provides.set_response(event.relation.id, response)
        logger.info("new index %s available", index_name)

        self.update_external_client_endpoints(event.relation)

    def _validate_request(self, event: ResourceRequestedEvent) -> str | None:
        """Validates the event and returns the index name if valid, otherwise None."""
        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            event.defer()
            return None

        index_name = event.request.resource
        if not index_name:
            event.defer()
            return None

        if not validate_index_name(index_name):
            self.charm.state.add_status_if_not_present(
                ExternalClientsStatuses.INVALID_INDEX_NAME.value,
                "unit",
                self.charm.external_clients_manager.name,
                dynamic_params={"id": event.relation.id, "index": index_name},
            )
            return None
        self.charm.state.remove_status_if_present(
            ExternalClientsStatuses.INVALID_INDEX_NAME.value,
            "unit",
            self.charm.external_clients_manager.name,
            interpolated=True,
            search_parameters={"id": event.relation.id},
        )
        return index_name

    def _create_index(self, event: ResourceRequestedEvent, index_name: str) -> bool:
        """Attempts to create an OpenSearch index. Returns True on success."""
        try:
            self.charm.external_clients_manager.opensearch_client.create_index(index_name)
        except OpenSearchHttpError as e:
            logger.error(
                f"Failed to create index {index_name} for client relation {event.relation.id}: {e}"
            )
            self.charm.state.add_status_if_not_present(
                ExternalClientsStatuses.INDEX_CREATION_FAILED.value,
                "unit",
                self.charm.external_clients_manager.name,
                dynamic_params={"id": event.relation.id, "index": index_name},
            )
            event.defer()
            return False
        self.charm.state.remove_status_if_present(
            ExternalClientsStatuses.INDEX_CREATION_FAILED.value,
            "unit",
            self.charm.external_clients_manager.name,
            interpolated=True,
            search_parameters={"id": event.relation.id},
        )
        return True

    def _create_user(
        self, event: ResourceRequestedEvent, index_name: str
    ) -> tuple[str, str] | None:
        """Creates a user and returns a (username, password) tuple, or None on failure."""
        try:
            logger.debug(f"Creating user for {index_name} with: {event.request.extra_user_roles}")
            credentials = self.charm.external_clients_manager.create_opensearch_users(
                index_name, event.relation, extra_user_roles=event.request.extra_user_roles
            )
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            self.charm.state.add_status_if_not_present(
                ExternalClientsStatuses.USER_CREATION_FAILED.value,
                "unit",
                self.charm.external_clients_manager.name,
                dynamic_params={"id": event.relation.id},
            )
            event.defer()
            return None
        self.charm.state.remove_status_if_present(
            ExternalClientsStatuses.USER_CREATION_FAILED.value,
            "unit",
            self.charm.external_clients_manager.name,
            interpolated=True,
            search_parameters={"id": event.relation.id},
        )
        return credentials

    def _get_connection_data(self, event: ResourceRequestedEvent) -> dict | None:
        """Gathers version, TLS certificates, and endpoint data."""
        try:
            version = self.charm.workload.version
        except OpenSearchCmdError as e:
            logger.error("Failed to update relation version info: %s", str(e))
            event.defer()
            return None

        try:
            tls_ca = self.charm.state.application.admin_chain
        except KeyError as e:
            logger.error("Failed to update relation TLS info: missing key %s", str(e))
            event.defer()
            return None

        try:
            nodes = self.charm.cluster_manager.get_nodes(use_localhost=True)
            endpoints = self.charm.external_clients_manager.get_relation_endpoints(nodes)
        except OpenSearchHttpError as e:
            logger.error("unable to get nodes %s", str(e))
            endpoints = ""

        return {"version": version, "tls_ca": tls_ca, "endpoints": endpoints}

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handle opensearch client relation-changed event."""
        if not self.charm.unit.is_leader():
            return

        if self.charm.cluster_manager.opensearch_client.is_node_up():
            self.update_external_client_endpoints(event.relation)
        else:
            event.defer()

    def _on_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Check if this relation is being removed, and update the peer databag accordingly."""
        if self.charm.upgrades_manager.in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
        if not self.charm.unit.is_leader():
            return

        if event.departing_unit.app == self.charm.unit.app:
            if event.departing_unit == self.charm.unit:
                self.charm.state.server.unit_dying = True
            departing_unit_ip = self.charm.state.unit_ip(event.departing_unit)
            self.update_external_client_endpoints(
                event.relation, omit_endpoints={departing_unit_ip}
            )

        self.charm.external_clients_manager.remove_lingering_relation_users_and_roles(
            event.relation
        )

        # Clear old statuses when the relation is departed
        self.charm.state.remove_status_if_present(
            ExternalClientsStatuses.INVALID_INDEX_NAME.value,
            "unit",
            self.charm.external_clients_manager.name,
            interpolated=True,
            search_parameters={"id": event.relation.id},
        )
        self.charm.state.remove_status_if_present(
            ExternalClientsStatuses.INDEX_CREATION_FAILED.value,
            "unit",
            self.charm.external_clients_manager.name,
            interpolated=True,
            search_parameters={"id": event.relation.id},
        )
        self.charm.state.remove_status_if_present(
            ExternalClientsStatuses.USER_CREATION_FAILED.value,
            "unit",
            self.charm.external_clients_manager.name,
            interpolated=True,
            search_parameters={"id": event.relation.id},
        )

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle client relation-broken event."""
        if not self.charm.unit.is_leader():
            return
        if self.charm.state.server.unit_dying:
            return
        if self.charm.upgrades_manager.in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
        self.charm.external_clients_manager.remove_lingering_relation_users_and_roles(
            event.relation
        )

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Handle config changed event for external clients."""
        if not self.charm.unit.is_leader():
            return

        try:
            self.charm.external_clients_manager.update_relations_roles_mapping()
        except OpenSearchUserMgmtError as e:
            logger.warning("Failed to update relations roles mapping: %s", e)
            event.defer()
            return

    def _on_update_status(self, event: UpdateStatusEvent) -> None:
        """Handle periodic checks for external clients."""
        if not self.charm.unit.is_leader():
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            return

        deployment_desc = self.charm.state.application.deployment_description
        if not deployment_desc:
            return

        # Endpoints are always refreshed; only user/role cleanup is unsafe mid-upgrade.
        for relation in self.charm.model.relations[CLIENT_RELATION]:
            self.update_external_client_endpoints(relation)

        if self.charm.upgrades_manager.in_progress:
            logger.debug(
                "Skipping `remove_lingering_users_and_roles` because upgrade is in-progress"
            )
        elif deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            self.charm.external_clients_manager.remove_lingering_relation_users_and_roles()

    def _on_peer_relation_changed(self, event: RelationChangedEvent) -> None:
        if not self.charm.unit.is_leader():
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            return

        deployment_desc = self.charm.state.application.deployment_description
        if not deployment_desc:
            return

        for relation in self.charm.model.relations[CLIENT_RELATION]:
            self.update_external_client_endpoints(relation)

    def update_external_client_endpoints(
        self, relation: Relation, omit_endpoints: set | None = None
    ) -> None:
        """Update the external client endpoints"""
        if not self.charm.unit.is_leader():
            return

        try:
            nodes = self.charm.cluster_manager.get_nodes(use_localhost=True)
            new_endpoints = self.charm.external_clients_manager.get_relation_endpoints(
                nodes, omit_endpoints=omit_endpoints
            )
        except OpenSearchHttpError as e:
            logger.error("unable to get nodes %s", str(e))
            return

        responses = self.charm.state.opensearch_provides.responses(relation, ResourceProviderModel)
        if not responses:
            return

        updated = False
        for response in responses:
            if response.endpoints != new_endpoints:
                response.endpoints = new_endpoints
                response.uris = new_endpoints
                updated = True

        if updated:
            version = relation.data[relation.app].get("version", "v0") if relation.app else "v0"

            if version == "v0":
                relation.data[self.charm.app].update({"endpoints": new_endpoints})
            else:
                self.charm.state.opensearch_provides.set_responses(relation.id, responses)
