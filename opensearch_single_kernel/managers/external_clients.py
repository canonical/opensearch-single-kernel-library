#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch External Clients manager."""

import copy
import logging
from typing import Any

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from ops import Relation
from overrides import override
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import (
    DEFAULT_EXTRA_USER_ROLE,
    KIBANA_SERVER_ROLE,
    KIBANA_SERVER_USER,
    OPENSEARCH_HTTP_PORT,
    RESERVED_ENTITY_NAMES,
    ExtraUserRolePermissions,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import (
    ExternalClientsStatuses,
    GeneralStatuses,
)
from opensearch_single_kernel.core.external_clients_relation import (
    ExternalOpenSearchClient,
)
from opensearch_single_kernel.core.models import ExternalClientRequestedEntity, Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    ENTITY_GROUP,
)
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import (
    generate_password,
    hash_string,
    validate_index_name,
)
from opensearch_single_kernel.utils.status import format_status, running_statuses
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ExternalClientsManager(BaseManager):
    """OpenSearch External Clients Manager."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "external_clients_manager")

    def provide_client_entity(
        self,
        external_client: ExternalOpenSearchClient,
        requested_entity: ExternalClientRequestedEntity | None,
    ) -> None:
        """Create the entity requested by a client relation and push it back to the client.

        Depending on the entity type requested on the relation:
        - GROUP: only a role is created, mapped to the users holding the group as backend role,
        - otherwise: a user is created along with a dedicated role scoped to its index.

        Args:
            external_client: the client relation to provide the entity for.
            requested_entity: the entity name and password requested by the client, mandatory
                for the GROUP entity type. If absent otherwise, a relation-specific username
                and a random password are generated.

        Raises:
            OpenSearchUserMgmtError: if the kibana server password is not available yet or
                the entity could not be created in OpenSearch.
        """
        try:
            if external_client.entity_type == ENTITY_GROUP:
                self._provide_group(external_client, requested_entity)
            else:
                self._provide_legacy_user(external_client, requested_entity)
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

    def _provide_legacy_user(
        self,
        external_client: ExternalOpenSearchClient,
        requested_entity: ExternalClientRequestedEntity | None,
    ) -> None:
        """Provide a user holding a dedicated role scoped to the index of the relation."""
        extra_user_roles = external_client.extra_user_roles
        extra_user_roles = (
            extra_user_roles.lower() if extra_user_roles else DEFAULT_EXTRA_USER_ROLE
        )
        if extra_user_roles == KIBANA_SERVER_ROLE:
            if not (password := self.state.application.kibana_server_password):
                raise OpenSearchUserMgmtError("Cannot provide kibana user")
            external_client.username = KIBANA_SERVER_USER
            external_client.password = password
            return

        user = requested_entity.username if requested_entity else external_client.relation_username
        password = (requested_entity and requested_entity.password) or generate_password()

        # Create a new role for this relation, encapsulating the permissions we care about. We
        # can't create a "default" and an "admin" role once because the permissions need to be
        # set to this relation's specific index.
        self.opensearch_client.create_role(
            user, **self.get_extra_user_role_permissions(extra_user_roles, external_client.index)
        )
        self.opensearch_client.create_user(user, [user], hash_string(password))
        self.opensearch_client.patch_user(
            user,
            [
                {
                    "op": "replace",
                    "path": "/opendistro_security_roles",
                    "value": [user],
                }
            ],
        )
        self._register_client_entity(external_client, user)

        external_client.username = user
        external_client.password = password

    def _provide_group(
        self,
        external_client: ExternalOpenSearchClient,
        requested_entity: ExternalClientRequestedEntity | None,
    ) -> None:
        """Provide a role mapped to the users holding the group as backend role.

        The role holds the entity permissions requested by the relation or, if none are
        requested, the default permissions on the index of the relation.
        """
        if not requested_entity:
            raise OpenSearchUserMgmtError("Cannot provide a group without a requested entity")

        role = requested_entity.username
        try:
            permissions = external_client.entity_permissions
        except ValidationError as e:
            raise OpenSearchUserMgmtError(e)

        if not permissions:
            permissions = {
                "index_permissions": [
                    {**index_permissions, "index_patterns": [external_client.index]}
                    for index_permissions in ExtraUserRolePermissions.DEFAULT.value[
                        "index_permissions"
                    ]
                ]
            }
        self.opensearch_client.create_role(role, **permissions)
        self._register_client_entity(external_client, role)

        external_client.entity_name = role

    def _register_client_entity(
        self, external_client: ExternalOpenSearchClient, name: str
    ) -> None:
        """Save the entity provided to a client relation and refresh the roles mappings."""
        relation_id = str(external_client.relation.id)
        client_users_dict = self.state.application.client_users_dict

        if registered_user := client_users_dict.get(relation_id):
            logger.warning(
                "User %s is already registered in Peer Relation data for relation %s.",
                registered_user,
                relation_id,
            )

        client_users_dict[relation_id] = name
        self.state.application.client_users_dict = client_users_dict

        self.reconcile_role_mappings()

    def provide_client_index(self, external_client: ExternalOpenSearchClient) -> None:
        """Create the index requested by a client relation and push name back via it.

        Args:
            external_client: the client relation that requested the index.

        Raises:
            OpenSearchUserMgmtError: if the index could not be created.
        """
        index = external_client.index

        try:
            self.opensearch_client.create_index(index)
        except OpenSearchHttpError as e:
            logger.error(
                f"Failed to create index {index} for client relation {external_client.relation.id}: {e}"
            )
            raise OpenSearchUserMgmtError(e)

        external_client.index = index

    def get_extra_user_role_permissions(self, extra_user_roles: str, index: str) -> dict[str, Any]:
        """Get relation role permissions from the extra_user_roles field.

        Args:
            extra_user_roles: role requested by the requirer unit, provided in relation databag.
                This needs to be one of "admin" or "default", or it will be set to "default".
                TODO should this fail and raise an error instead so provider charm authors can
                guarantee they're getting the perms they expect?
            index: if these permissions are index-specific, they will be assigned to this index.

        Returns:
            A dict containing the required permissions for the requested role.
        """
        roles = set(extra_user_roles.split(","))
        # The presets are shared: work on copies so that a request never alters them.
        permissions = copy.deepcopy(ExtraUserRolePermissions.DEFAULT.value)

        # Merge the permissions for all roles into one permissions dict. Currently no checking if
        # this would create an invalid role config.
        for role in roles:
            if role.upper() in ExtraUserRolePermissions._member_names_:
                for perm_scope, perms in ExtraUserRolePermissions[role.upper()].value.items():
                    permissions[perm_scope] += copy.deepcopy(perms)

        for perm_set in permissions["index_permissions"]:
            # If this isn't a set of admin permissions (which applies to all indices) then set it
            # to index.
            if not perm_set["index_patterns"]:
                perm_set["index_patterns"] = [index]

        return permissions

    def update_all_external_clients_relation_endpoints(self, nodes: list[Node]) -> None:
        """Update the relation databags of all external clients with network endpoints."""
        for external_client in self.state.external_clients:
            self.update_relation_endpoints(external_client, nodes)

    def update_relation_endpoints(
        self,
        external_client: ExternalOpenSearchClient,
        nodes: list[Node],
        omit_endpoints: set[str] | None = None,
    ) -> None:
        """Update the relation databag with network endpoints.

        Make sure to call this only when the unit is leader.
        """
        if (
            not self.opensearch_client.is_node_up()
            or not external_client.relation.app
            or not self.state.application.is_security_index_initialised
        ):
            return

        if not nodes:
            # `get_nodes()` returns [] when the cluster is unreachable: keep current endpoints.
            logger.debug("No nodes provided, keeping the currently advertised endpoints.")
            return

        if not omit_endpoints:
            omit_endpoints = set()

        ips = set([node.ip for node in nodes])

        port = OPENSEARCH_HTTP_PORT
        endpoints = set(sorted([f"{ip}:{port}" for ip in ips - omit_endpoints]))
        databag_endpoints = external_client.endpoints

        if endpoints != databag_endpoints:
            external_client.endpoints = endpoints

    def remove_lingering_relation_users_and_roles(  # noqa: C901
        self, departed_external_client: ExternalOpenSearchClient | None = None
    ):
        """Removes lingering relation users and roles from opensearch.

        Make sure to call this only when the unit is leader.

        Args:
            departed_external_client: if a relation is departing, pass in the
            ExternalOpenSearchClient and its user will be deleted.
        """
        if not self.opensearch_client.is_node_up():
            return
        relation_users = self.state.application.client_users_dict

        if (
            departed_external_client
            and departed_external_client.relation
            and (not relation_users or departed_external_client.relation.id not in relation_users)
        ):
            logging.warning(
                "User for relation %d wasn't registered in internal cham workflows.",
                departed_external_client.relation.id,
            )

        cleanup_rel_ids = []
        if departed_external_client:
            cleanup_rel_ids = [str(departed_external_client.relation.id)]

        rel_ids = [str(relation.id) for relation in self.state.external_client_relations]
        cleanup_rel_ids += list(set(relation_users.keys()) - set(rel_ids))

        for rel_id in cleanup_rel_ids:
            if username := relation_users.get(rel_id):
                try:
                    self.opensearch_client.remove_user(username)
                except OpenSearchHttpError:
                    logger.error("failed to remove user %s", username)

                try:
                    self.opensearch_client.remove_role(username)
                except OpenSearchHttpError:
                    logger.error("failed to remove role %s", username)

                try:
                    self.opensearch_client.remove_role_mapping(username)
                except OpenSearchHttpError:
                    logger.error("failed to remove role mapping for %s", username)

                del relation_users[rel_id]
        self.state.application.client_users_dict = relation_users

        self.reconcile_role_mappings()

    def reconcile_role_mappings(self) -> None:
        """Refreshe all of the managed roles mappings."""
        if not self.opensearch_client.is_node_up():
            logger.debug(
                "Cannot update relations roles mapping as node is not active. Deferring event"
            )
            raise OpenSearchUserMgmtError(
                "Cannot update relations roles mapping as node is not active."
            )
        existing_mappings = self.opensearch_client.get_role_mappings()
        mapped_users = self.state.mapped_users
        mapped_roles = self.state.mapped_roles
        for role in self.state.managed_mappings:
            users = mapped_users.get(role, [])
            roles = mapped_roles.get(role, [])
            if not users and not roles and role not in existing_mappings:
                continue

            existing_mapping = existing_mappings.get(role, {})
            if sorted(existing_mapping.get("users", [])) == sorted(users) and sorted(
                existing_mapping.get("backend_roles", [])
            ) == sorted(roles):
                continue

            self.opensearch_client.put_role_mapping(role, users, roles)

    def update_dashboards_password(self):
        """Update each Opensearch Dashboards relation with the latest kibanaserver."""
        # only get the secret once to optimize performance
        pwd = self.state.application.kibana_server_password
        for dashboards_client in self.state.dashboards_clients:
            dashboards_client.username = KIBANA_SERVER_USER
            dashboards_client.password = pwd

    @override
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute external-client statuses from state."""
        status_list = running_statuses(self.state.statuses, scope, self.name)

        if scope == "unit" and self.state.application.deployment_desc:
            for relation in self.state.external_client_relations:
                self._add_relation_statuses(status_list, relation)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]

    def get_request_error(
        self, external_client: ExternalOpenSearchClient
    ) -> ExternalClientsStatuses | None:
        """Get the status describing why the request of a client relation cannot be served."""
        if not external_client.index or not validate_index_name(external_client.index):
            return ExternalClientsStatuses.INVALID_INDEX_NAME

        entity_type = external_client.entity_type
        requested_entity = external_client.get_requested_entity()

        if entity_type == ENTITY_GROUP and not requested_entity:
            return ExternalClientsStatuses.USER_ENTITY_GROUP_INVALID

        if entity_type == ENTITY_GROUP:
            try:
                external_client.entity_permissions
            except ValidationError as e:
                logger.debug(
                    "Invalid entity-permissions on client relation %s: %s",
                    external_client.relation.id,
                    e,
                )
                return ExternalClientsStatuses.ENTITY_PERMISSIONS_INVALID

        if not requested_entity:
            return None

        if requested_entity.username in RESERVED_ENTITY_NAMES:
            return ExternalClientsStatuses.ENTITY_NAME_RESERVED

        if requested_entity.username in [
            name
            for relation_id, name in self.state.application.client_users_dict.items()
            if relation_id != str(external_client.relation.id)
        ]:
            return ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT

        return None

    def _add_relation_statuses(self, status_list: list[StatusObject], relation: Relation) -> None:
        """Compute the manager's app statuses for relation and append them to list."""
        if (
            not self.state.server.is_app_leader
            or not (index := relation.data[relation.app].get("index"))
            or not (external_client := self.state.external_client_by_relation(relation))
        ):
            return

        if not self.state.is_main_orchestrator:
            status_list.append(
                format_status(ExternalClientsStatuses.RELATION_INVALID.value, {"id": relation.id})
            )
            return

        if error := self.get_request_error(external_client):
            status_list.append(format_status(error.value, {"id": relation.id, "index": index}))
            return

        if str(relation.id) not in self.state.application.client_users_dict and (
            external_client.entity_type == ENTITY_GROUP
            or external_client.extra_user_roles.lower() != KIBANA_SERVER_ROLE
        ):
            status_list.append(
                format_status(
                    ExternalClientsStatuses.USER_CREATION_FAILED.value, {"id": relation.id}
                )
            )
            return

        try:
            if not self.opensearch_client.is_node_up():
                return

            if index not in self.opensearch_client.indices():
                status_list.append(
                    format_status(
                        ExternalClientsStatuses.INDEX_CREATION_FAILED.value,
                        {"id": relation.id, "index": index},
                    )
                )
                return
        except OpenSearchHttpError as e:
            logger.error("Failed to check external client status: %s", str(e))
            return
