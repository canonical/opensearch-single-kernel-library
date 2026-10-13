#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch External Clients manager."""

import copy
import logging
import re
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
    ENTITY_USER,
)
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import (
    generate_password,
    hash_string,
    validate_entity_name,
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
        relation_id = str(external_client.relation.id)
        # A request may be handled more than once: the password already provided is kept.
        provided_password = (
            external_client.password
            if self.state.application.client_users_dict.get(relation_id) == user
            else None
        )
        password = (
            (requested_entity and requested_entity.password)
            or provided_password
            or generate_password()
        )

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
        """Save the entity provided to a client relation and refresh the roles mappings.

        Users and groups are saved apart: the entity of a GROUP client relation is a role.
        """
        relation_id = str(external_client.relation.id)
        application = self.state.application
        is_group = external_client.entity_type == ENTITY_GROUP
        entities = application.client_groups_dict if is_group else application.client_users_dict

        if registered_entity := entities.get(relation_id):
            logger.warning(
                "%s %s is already registered in Peer Relation data for relation %s.",
                "Group" if is_group else "User",
                registered_entity,
                relation_id,
            )

        entities[relation_id] = name
        if is_group:
            application.client_groups_dict = entities
        else:
            application.client_users_dict = entities

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

    def remove_lingering_relation_users_and_roles(self) -> None:
        """Removes lingering relation users and roles from opensearch.

        Make sure to call this only when the unit is leader.
        """
        if not self.opensearch_client.is_node_up():
            return
        relation_users = self.state.application.client_users_dict
        relation_groups = self.state.application.client_groups_dict

        rel_ids = {str(relation.id) for relation in self.state.external_client_relations}
        cleanup_rel_ids = (set(relation_users) | set(relation_groups)) - rel_ids

        for rel_id in cleanup_rel_ids:
            if username := relation_users.pop(rel_id, None):
                try:
                    self.opensearch_client.remove_user(username)
                except OpenSearchHttpError:
                    logger.error("failed to remove user %s", username)

                self._remove_role_and_mapping(username)

            if group := relation_groups.pop(rel_id, None):
                self._remove_role_and_mapping(group)

        self.state.application.client_users_dict = relation_users
        self.state.application.client_groups_dict = relation_groups

        if not self.state.is_main_orchestrator:
            # The roles mappings are shared by the whole cluster: only its main orchestrator
            # owns them.
            return

        try:
            self.reconcile_role_mappings()
        except OpenSearchUserMgmtError as e:
            logger.error("Failed to refresh the roles mappings: %s", e)

    def _remove_role_and_mapping(self, role: str) -> None:
        """Remove the role created for a client relation along with its mapping."""
        try:
            self.opensearch_client.remove_role(role)
        except OpenSearchHttpError:
            logger.error("failed to remove role %s", role)

        try:
            self.opensearch_client.remove_role_mapping(role)
        except OpenSearchHttpError:
            logger.error("failed to remove role mapping for %s", role)

    def reconcile_role_mappings(self) -> None:
        """Refresh the mappings of all the managed roles.

        Raises:
            OpenSearchUserMgmtError: if the node is not up or a mapping could not be refreshed.
        """
        if not self.opensearch_client.is_node_up():
            raise OpenSearchUserMgmtError(
                "Cannot update relations roles mapping as node is not active."
            )
        try:
            existing_mappings = self.opensearch_client.get_role_mappings()
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

        failed_roles = []
        mapped_users = self.state.mapped_users
        mapped_roles = self.state.mapped_roles
        for role in self.state.managed_roles:
            users = mapped_users.get(role, [])
            roles = mapped_roles.get(role, [])
            if not users and not roles and role not in existing_mappings:
                continue

            existing_mapping = existing_mappings.get(role, {})
            if sorted(existing_mapping.get("users", [])) == sorted(users) and sorted(
                existing_mapping.get("backend_roles", [])
            ) == sorted(roles):
                continue

            try:
                self.opensearch_client.put_role_mapping(role, users, roles)
            except OpenSearchHttpError:
                # A failing mapping does not prevent the other ones from being refreshed.
                failed_roles.append(role)

        if failed_roles:
            raise OpenSearchUserMgmtError(
                f"Failed to refresh the mappings of roles: {', '.join(failed_roles)}"
            )

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
        """Get the status describing why the request of a client relation cannot be served.

        Raises:
            OpenSearchHttpError: if the requested entity could not be looked up.
        """
        if not external_client.index or not validate_index_name(external_client.index):
            return ExternalClientsStatuses.INVALID_INDEX_NAME

        entity_type = external_client.entity_type
        if entity_type == ENTITY_USER:
            return ExternalClientsStatuses.ENTITY_TYPE_UNSUPPORTED

        requested_entity = external_client.get_requested_entity()

        if entity_type == ENTITY_GROUP:
            if not requested_entity:
                return ExternalClientsStatuses.USER_ENTITY_GROUP_INVALID

            try:
                external_client.entity_permissions
            except ValidationError as e:
                logger.debug(
                    "Invalid entity-permissions on client relation %s: %s",
                    external_client.relation.id,
                    e,
                )
                return ExternalClientsStatuses.ENTITY_PERMISSIONS_INVALID
        elif external_client.extra_user_roles.lower() == KIBANA_SERVER_ROLE:
            # The kibana server user is provided: no entity is created.
            return None

        return self._get_entity_name_error(external_client, requested_entity)

    def _get_entity_name_error(
        self,
        external_client: ExternalOpenSearchClient,
        requested_entity: ExternalClientRequestedEntity | None,
    ) -> ExternalClientsStatuses | None:
        """Get the status describing why the name of the entity of a client cannot be used.

        The name is the requested one or, by default, the one generated for the relation.

        Raises:
            OpenSearchHttpError: if the requested entity could not be looked up.
        """
        entity_name = external_client.relation_username
        if requested_entity:
            entity_name = requested_entity.username
            if not validate_entity_name(entity_name):
                return ExternalClientsStatuses.USER_ENTITY_GROUP_INVALID

            if entity_name in RESERVED_ENTITY_NAMES or (
                # The names generated for the client relations cannot be requested by another one.
                entity_name != external_client.relation_username
                and re.fullmatch(rf"{re.escape(external_client.relation_name)}_\d+", entity_name)
            ):
                return ExternalClientsStatuses.ENTITY_NAME_RESERVED

        if entity_name in [
            name
            for relation_id, name in self.state.application.client_entities_dict.items()
            if relation_id != str(external_client.relation.id)
        ]:
            return ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT

        if requested_entity and self._is_entity_foreign(external_client, entity_name):
            return ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT

        return None

    def _is_entity_foreign(self, external_client: ExternalOpenSearchClient, name: str) -> bool:
        """Check whether an entity exists without having been created for the client relation.

        A GROUP client relation is provided with a role, any other one with a user and its role.

        Raises:
            OpenSearchHttpError: if the entity could not be looked up.
        """
        relation_id = str(external_client.relation.id)
        if self.state.application.client_entities_dict.get(relation_id) == name:
            return False

        if self.opensearch_client.get_role(name) is not None:
            return True

        return (
            external_client.entity_type != ENTITY_GROUP
            and self.opensearch_client.get_user(name) is not None
        )

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

        try:
            error = self.get_request_error(external_client)
        except OpenSearchHttpError as e:
            # Statuses are computed on every hook: a node which is down is not worth an error.
            logger.debug("Failed to check external client status: %s", str(e))
            return

        if error:
            status_list.append(format_status(error.value, {"id": relation.id, "index": index}))
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

        if str(relation.id) not in self.state.application.client_entities_dict and (
            external_client.entity_type == ENTITY_GROUP
            or external_client.extra_user_roles.lower() != KIBANA_SERVER_ROLE
        ):
            status_list.append(
                format_status(
                    ExternalClientsStatuses.USER_CREATION_FAILED.value, {"id": relation.id}
                )
            )
