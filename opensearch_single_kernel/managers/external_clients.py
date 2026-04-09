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
from opensearch_single_kernel.core.models import Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    ResourceProviderModel,
)
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import (
    generate_hashed_password,
    validate_index_name,
)
from opensearch_single_kernel.utils.status import format_status
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ExternalClientsManager(BaseManager):
    """OpenSearch External Clients Manager."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "external_clients_manager")

    def create_opensearch_users(
        self,
        index: str,
        relation: Relation,
        extra_user_roles: str | None = None,
    ) -> tuple[str, str]:
        """Creates necessary opensearch users and permissions for this relation.

        Args:
            index: the index this relation will be using.
            relation: relation of external client
            extra_user_roles: the extra user roles for opensearch
        Raises:
            OpenSearchUserMgmtError if user creation fails
        """
        extra_user_roles = (
            extra_user_roles.lower() if extra_user_roles else DEFAULT_EXTRA_USER_ROLE
        )
        if extra_user_roles == KIBANA_SERVER_ROLE:
            username = KIBANA_SERVER_USER
            pwd = self.state.application.kibana_server_password
        else:
            username = f"{relation.name}_{relation.id}"
            hashed_pwd, pwd = generate_hashed_password()

            # Create a new role for this relation, encapsulating the permissions we care about. We
            # can't create a "default" and an "admin" role once because the permissions need to be
            # set to this relation's specific index.
            permissions = self.get_extra_user_role_permissions(extra_user_roles, index)
            self._put_relation_user(username, permissions, hashed_pwd, relation.id)
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
        return username, pwd

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

    def _put_relation_user(
        self, user: str, permissions: dict[str, Any], hashed_pwd: str, relation_id: int
    ) -> None:
        """Create a relation user.

        Relation users are registered with a dedicated role which maps to the username,
        and their name is saved in the databag for later reference.

        Raises:
            OpenSearchUserMgmtError: In case of role creation or user creation error.
        """
        try:
            self.opensearch_client.create_user_role(role_name=user, permissions=permissions)
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

        users = self.state.application.client_users_dict

        if users.get(str(relation_id)):
            logger.warning(
                "User %s is already registered in Peer Relation data for relation %d.",
                user,
                relation_id,
            )
        try:
            self.opensearch_client.create_user(user, [user], hashed_pwd)
        except OpenSearchHttpError as e:
            logger.error("Couldn't create user %s", str(e))
            raise OpenSearchUserMgmtError(e)

        try:
            self.opensearch_client.create_user_role_mapping(
                user, self.state.get_relation_mapped_users(user)
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)
        users[str(relation_id)] = user
        self.state.application.client_users_dict = users

    def get_relation_endpoints(
        self,
        nodes: list[Node],
        omit_endpoints: set[str] | None = None,
    ) -> str:
        """Calculates the active network endpoints for external clients."""
        if (
            not self.opensearch_client.is_node_up()
            or not self.state.application.is_security_index_initialised
        ):
            return ""

        omit_endpoints = omit_endpoints or set()
        ips = {node.ip for node in nodes}

        port = OPENSEARCH_HTTP_PORT
        endpoints = sorted([f"{ip}:{port}" for ip in ips - omit_endpoints])

        return ",".join(endpoints)

    def remove_lingering_relation_users_and_roles(  # noqa: C901
        self, departed_relation: Relation | None = None
    ):
        """Removes lingering relation users and roles from opensearch.

        Make sure to call this only when the unit is leader.

        Args:
            departed_relation: departing relation
        """
        if not self.opensearch_client.is_node_up():
            return
        relation_users = self.state.application.client_users_dict

        if departed_relation and (
            not relation_users or str(departed_relation.id) not in relation_users.keys()
        ):
            logger.warning(
                "User for relation %d wasn't registered in internal charm workflows.",
                departed_relation.id,
            )

        cleanup_rel_ids = []
        if departed_relation:
            cleanup_rel_ids = [str(departed_relation.id)]

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

    def update_relations_roles_mapping(self) -> None:
        """Updates all the relations roles mapping due to config change.

        Returns:
            Whether operation was successful. If negative value returned,
            processing event should be deferred.
        """
        if not self.opensearch_client.is_node_up():
            logger.debug(
                "Cannot update relations roles mapping as node is not active. Deferring event"
            )
            raise OpenSearchUserMgmtError(
                "Cannot update relations roles mapping as node is not active."
            )
        users = self.state.application.client_users_dict
        for _, user in users.items():
            self.opensearch_client.create_user_role_mapping(
                user, self.state.get_relation_mapped_users(user)
            )

    def update_dashboards_password(self):
        """Update each Opensearch Dashboards relation with new password."""
        pwd = self.state.application.kibana_server_password
        for relation in self.state.get_dashboards_relations():
            responses = self.state.opensearch_provides.responses(relation, ResourceProviderModel)
            if not responses:
                continue

            updated = False
            for response in responses:
                response.username = KIBANA_SERVER_USER
                response.password = pwd
                updated = True

            if updated:
                self.state.opensearch_provides.set_responses(relation.id, responses)

    @override
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute the manager's statuses."""
        if not recompute:
            return self.state.statuses.get(scope, self.name).root or [
                GeneralStatuses.ACTIVE_IDLE.value
            ]

        status_list: list[StatusObject] = []

        if scope == "unit":
            for relation in self.state.external_client_relations:
                self._add_relation_statuses(status_list, relation)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]

    def _add_relation_statuses(self, status_list: list[StatusObject], relation: Relation) -> None:
        """Compute the manager's app statuses for relation and append them to list."""
        if (
            not self.state.server.is_app_leader
            or not (index := relation.data[relation.app].get("index"))
            or not self.opensearch_client.is_node_up()
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
            if index not in self.opensearch_client.indices():
                status_list.append(
                    format_status(
                        ExternalClientsStatuses.INDEX_CREATION_FAILED.value,
                        {"id": relation.id, "index": index},
                    )
                )
                return

            extra_user_roles = relation.data[relation.app].get("extra-user-roles")
            extra_user_roles = (
                extra_user_roles.lower() if extra_user_roles else DEFAULT_EXTRA_USER_ROLE
            )

            for response in self.state.opensearch_provides.responses(
                relation, ResourceProviderModel
            ):
                if extra_user_roles != KIBANA_SERVER_ROLE and not self.opensearch_client.get_user(
                    response.username
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
