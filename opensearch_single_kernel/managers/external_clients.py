#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch External Clients manager."""

import logging
from typing import Any

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from ops import Relation
from overrides import override

from opensearch_single_kernel.common.constants import (
    DEFAULT_EXTRA_USER_ROLE,
    KIBANA_SERVER_ROLE,
    KIBANA_SERVER_USER,
    OPENSEARCH_HTTP_PORT,
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
from opensearch_single_kernel.core.models import Node
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

    def provide_client_user(
        self,
        external_client: ExternalOpenSearchClient,
        index: str,
        extra_user_roles: str | None = None,
    ) -> tuple[str, str]:
        """Generate and create opensearch users and permissions for this relation.

        Args:
            external_client: the external opensearch client relation state.
            index: the index this relation will be using.
            extra_user_roles: the extra roles mapping for the user.

        Returns:
            username and password for the created entity.

        Raises:
            OpenSearchUserMgmtError if user creation fails
        """
        extra_user_roles = (
            extra_user_roles.lower() if extra_user_roles else DEFAULT_EXTRA_USER_ROLE
        )
        if extra_user_roles == KIBANA_SERVER_ROLE:
            return KIBANA_SERVER_USER, self.state.application.kibana_server_password

        username = external_client.relation_username
        password = generate_password()

        # Create a new role for this relation, encapsulating the permissions we care about. We
        # can't create a "default" and an "admin" role once because the permissions need to be
        # set to this relation's specific index.
        permissions = self.get_extra_user_role_permissions(extra_user_roles, index)
        self.put_client_user(external_client.relation.id, username, password, permissions)
        try:
            self.opensearch_client.patch_user(
                username,
                [
                    {
                        "op": "replace",
                        "path": "/opendistro_security_roles",
                        "value": [username],
                    }
                ],
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)
        return username, password

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
        permissions = ExtraUserRolePermissions.DEFAULT.value

        # Merge the permissions for all roles into one permissions dict. Currently no checking if
        # this would create an invalid role config.
        for role in roles:
            if role.upper() in ExtraUserRolePermissions._member_names_:
                for perm_scope, perms in ExtraUserRolePermissions[role.upper()].value.items():
                    permissions[perm_scope] += perms

        for perm_set in permissions["index_permissions"]:
            # If this isn't a set of admin permissions (which applies to all indices) then set it
            # to index.
            if not perm_set["index_patterns"]:
                perm_set["index_patterns"] = [index]

        return permissions

    def put_client_user(
        self, relation_id: int, user: str, password: str, role_permissions: dict[str, Any] | None
    ) -> None:
        """Push client users & related roles to OpenSearch and register them in state.

        Raises:
            OpenSearchUserMgmtError if user creation fails.
        """
        if (users := self.state.application.client_users_dict).get(str(relation_id)):
            logger.warning(
                "User %s is already registered in Peer Relation data for relation %d.",
                user,
                relation_id,
            )

        try:
            self.opensearch_client.create_user_role(role_name=user, permissions=role_permissions)

            self.opensearch_client.create_user(user, [user], hash_string(password))

            self.opensearch_client.put_role_mapping(
                user,
                self.state.mapped_users.get(user, []),
                self.state.mapped_roles.get(user, []),
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

        users[str(relation_id)] = user
        self.state.application.client_users_dict = users

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
                    self.opensearch_client.remove_user_role(username)
                except OpenSearchHttpError:
                    logger.error("failed to remove role %s", username)

                try:
                    self.opensearch_client.remove_user_role_mapping(username)
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
        roles_mapped_users = self.state.mapped_users
        roles_mapped_roles = self.state.mapped_roles
        for role in self.state.managed_mappings:
            self.opensearch_client.put_role_mapping(
                role, roles_mapped_users.get(role, []), roles_mapped_roles.get(role, [])
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

    def _add_relation_statuses(self, status_list: list[StatusObject], relation: Relation) -> None:
        """Compute the manager's app statuses for relation and append them to list."""
        if (
            not self.state.server.is_app_leader
            or not (index := relation.data[relation.app].get("index"))
            or not (external_client := self.state.external_client_by_relation(relation))
        ):
            return

        if not validate_index_name(index):
            status_list.append(
                format_status(
                    ExternalClientsStatuses.INVALID_INDEX_NAME.value,
                    {"id": relation.id, "index": index},
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

            if (
                external_client.entity_type == ENTITY_GROUP
                and not external_client.get_requested_entity()
            ):
                status_list.append(
                    format_status(
                        ExternalClientsStatuses.USER_ENTITY_GROUP_INVALID.value,
                        {"id": relation.id},
                    )
                )
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
        except OpenSearchHttpError as e:
            logger.error("Failed to check external client status: %s", str(e))
            return
