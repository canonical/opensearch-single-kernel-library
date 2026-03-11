#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch External Clients manager."""

import logging
from typing import Any

from opensearch_single_kernel.common.constants import (
    DEFAULT_EXTRA_USER_ROLE,
    KIBANA_SERVER_ROLE,
    KIBANA_SERVER_USER,
    OPENSEARCH_HTTP_PORT,
    CertType,
    ExtraUserRolePermissions,
    Scope,
)
from functools import cached_property
from opensearch_single_kernel.utils.secrets import (
    password_key,
)
from opensearch_single_kernel.common.exceptions import OpenSearchUserMgmtError
from opensearch_single_kernel.core.models import Node
from opensearch_single_kernel.core.state import ClusterState, ExternalOpenSearchClient
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import generate_hashed_password
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ExternalClientsManager(BaseManager):
    """OpenSearch External Clients Manager."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "external_clients_manager"

    def create_opensearch_users(
        self,
        external_client: ExternalOpenSearchClient,
        index: str,
        extra_user_roles: str | None = None,
    ) -> tuple[str, str] | None:
        """Creates necessary opensearch users and permissions for this relation.

        Args:
            external_client: the external opensearch client relation state.
            index: the index this relation will be using.

        Raises:
            OpenSearchUserMgmtError if user creation fails
        """
        extra_user_roles = (
            extra_user_roles.lower() if extra_user_roles else DEFAULT_EXTRA_USER_ROLE
        )
        if extra_user_roles == KIBANA_SERVER_ROLE:
            username = KIBANA_SERVER_USER
            pwd = self.state.secrets.get(Scope.APP, password_key(username))
        else:
            username = external_client.relation_username
            hashed_pwd, pwd = generate_hashed_password()

            # Create a new role for this relation, encapsulating the permissions we care about. We
            # can't create a "default" and an "admin" role once because the permissions need to be
            # set to this relation's specific index.
            permissions = self.get_extra_user_role_permissions(extra_user_roles, index)
            self._put_relation_user(username, permissions, hashed_pwd, external_client.relation.id)
            self.opensearch_client.patch_user(
                username,
                [{"op": "replace", "path": "/opendistro_security_roles", "value": [username]}],
            )
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
            if perm_set["index_patterns"] == []:
                perm_set["index_patterns"] = [index]

        return permissions

    def _put_relation_user(
        self, user: str, permissions: dict[str, Any], hashed_pwd: str, relation_id: int
    ):
        """Create a relation user.

        Relation users are registered with a dedicated role which maps to the username,
        and their name is saved in the databag for later reference.
        """
        self.opensearch_client.create_role(role_name=user, permissions=permissions)
        users = self.state.application.client_users_dict

        if users.get(str(relation_id)):
            logger.warning(
                "User %s is already registered in Peer Relation data for relation %d.",
                user,
                relation_id,
            )

        self.opensearch_client.create_user(user, [user], hashed_pwd)
        self.opensearch_client.create_role_mapping(
            user, self.state.get_relation_mapped_users(user)
        )
        users[str(relation_id)] = user
        self.state.application.client_users_dict = users



    def update_relation_credentials(
        self, external_client: ExternalOpenSearchClient, username: str, password: str
    ):
        """Update the relation databag with credentials."""
        external_client.username = username
        external_client.password = password

    def update_relation_tls_info(
        self, external_client: ExternalOpenSearchClient, ca_chain: str | None = None
    ):
        """Update the relation databag with TLS info."""
        try:
            # If the ca_chain=None, then we try to load the CA from the app-admin secret.
            # If neither ca_chain nor the secret exists, we'll raise a KeyError.
            _ch_chain = (
                ca_chain
                or self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)["chain"]
            )
            external_client.tls_ca = _ch_chain
        except AttributeError:
            # cert doesn't exist - presumably we don't yet have a TLS relation.
            logger.warning("unable to get ca_chain")
            return
        except TypeError:
            raise KeyError("unable to get ca_chain")

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

        if departed_external_client and departed_external_client.relation and (
            not relation_users or departed_external_client.relation.id not in relation_users
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
                except OpenSearchUserMgmtError:
                    logger.error(f"failed to remove user {username}")

                try:
                    self.opensearch_client.remove_role(username)
                except OpenSearchUserMgmtError:
                    logger.error(f"failed to remove role {username}")

                try:
                    self.opensearch_client.remove_role_mapping(username)
                except OpenSearchUserMgmtError:
                    logger.error(f"failed to remove role mapping for {username}")

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
            raise OpenSearchUserMgmtError("Cannot update relations roles mapping as node is not active.")
        users = self.state.application.client_users_dict
        for _, user in users.items():
            self.opensearch_client.create_role_mapping(
                user, self.state.get_relation_mapped_users(user)
            )

    def update_dashboards_password(self):
        """Update each Opensearch Dashboards relation with the latest kibanaserver."""
        pwd = self.state.secrets.get(
            Scope.APP, password_key(KIBANA_SERVER_USER)
        )
        for dashboards_client in self.state.dashboards_clients:
            dashboards_client.username = KIBANA_SERVER_USER
            dashboards_client.password = pwd


    @cached_property
    def version(self) -> str:
        """Returns the version number of this opensearch instance.

        Raises:
            OpenSearchError if the GET request fails.
        """
        # Will have a format similar to:
        # Version: 2.14.0, Build: tar/.../2024-05-27T21:17:37.476666822Z, JVM: 21.0.2
        result = self.workload.run_cmd("opensearch.opensearch-bin", args="--version 2>/dev/null")
        output = result.out.strip()
        logger.debug(f"version call output: {output}")
        return output.split(", ")[0].split(": ")[1]
