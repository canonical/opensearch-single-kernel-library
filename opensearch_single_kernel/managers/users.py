#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Configuration manager."""
from typing import Dict, List, Optional

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_ROLE,
    COS_USER,
    KIBANA_SERVER_USER,
    OPENSEARCH_SYSTEM_USERS,
    OPENSEARCH_USERS,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.logging import WithLogging
from opensearch_single_kernel.workload.base import BaseWorkload

USER_ENDPOINT = "/_plugins/_security/api/internalusers"
ROLE_ENDPOINT = "/_plugins/_security/api/roles"
ROLESMAPPING_ENDPOINT = "/_plugins/_security/api/rolesmapping"


class UsersManager(WithLogging):
    """OpenSearch Users Manager.

    This manager handles everything related to configuring users in OpenSearch.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        self.name = "users_manager"
        self.workload = workload
        self.state = state
        self.yaml_setter = YamlConfigSetter(self.workload.paths.conf)

    def purge_initial_users(self):
        """Removes all users from internal_users yaml config.

        This is to be used when starting up the charm, to remove unnecessary default users.
        """
        try:
            internal_users = self.yaml_setter.load("opensearch-security/internal_users.yml").keys()
        except FileNotFoundError:
            # internal_users.yml hasn't been initialised yet, so skip purging for now.
            return

        for user in internal_users:
            if user != "_meta":
                self.yaml_setter.delete("opensearch-security/internal_users.yml", user)

    def save_user_locally(self, user: str, hashed_pwd: str):
        """Save the user in internal_users.yaml"""
        # System users have to be saved locally in internal_users.yml
        if user in OPENSEARCH_SYSTEM_USERS:
            self.put_internal_user(user, hashed_pwd)

    def get_roles(self) -> Dict[str, any]:
        """Gets list of roles.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        try:
            return self.opensearch.request("GET", f"{ROLE_ENDPOINT}/")
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

    def create_role(
        self,
        role_name: str,
        permissions: Optional[Dict[str, str]] = None,
        action_groups: Optional[Dict[str, str]] = None,
    ) -> Dict[str, any]:
        """Creates a role with the given permissions.

        This method assumes the dicts provided are valid opensearch config. If not, raises
        OpenSearchUserMgmtError.

        Args:
            role_name: name of the role
            permissions: A valid dict of existing opensearch permissions.
            action_groups: A valid dict of existing opensearch action groups.

        Raises:
            OpenSearchUserMgmtError: If the role creation request fails.

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.opensearch.request(
                "PUT",
                f"{ROLE_ENDPOINT}/{role_name}",
                payload={**(permissions or {}), **(action_groups or {})},
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            self.logger.error(f"Couldn't create role: {resp}")
            raise OpenSearchUserMgmtError(f"creating role {role_name} failed")

        return resp

    def remove_role(self, role_name: str) -> Dict[str, any]:
        """Remove the given role from opensearch distribution.

        Args:
            role_name: name of the role to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if role_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        if not role_name:
            raise OpenSearchUserMgmtError(
                "role name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        try:
            resp = self.opensearch.request("DELETE", f"{ROLE_ENDPOINT}/{role_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return {
                    "status": "OK",
                    "response": "role does not exist, and therefore has not been removed",
                }
            else:
                raise OpenSearchUserMgmtError(e)

        self.logger.debug(resp)
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing role {role_name} failed")

        return resp

    def get_users(self) -> Dict[str, any]:
        """Gets list of users.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        try:
            return self.opensearch.request("GET", f"{USER_ENDPOINT}/")
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

    def create_user(
        self, user_name: str, roles: Optional[List[str]], hashed_pwd: str
    ) -> Dict[str, any]:
        """Create or update user and assign the requested roles to the user.

        Args:
            user_name: name of the user to be created.
            roles: list of roles to be applied to the user. These must already exist.
            hashed_pwd: the hashed password for the user.

        Raises:
            OpenSearchUserMgmtError: If the request fails.

        Returns:
            HTTP response to opensearch API request.
        """
        payload = {"hash": hashed_pwd}
        if roles:
            payload["opendistro_security_roles"] = roles

        try:
            resp = self.opensearch.request(
                "PUT",
                f"{USER_ENDPOINT}/{user_name}",
                payload=payload,
            )
        except OpenSearchHttpError as e:
            self.logger.error(f"Couldn't create user {str(e)}")
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            raise OpenSearchUserMgmtError(f"creating user {user_name} failed")

        return resp

    def remove_user(self, user_name: str) -> Dict[str, any]:
        """Remove the given user from opensearch distribution.

        Args:
            user_name: name of the user to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if user_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        if not user_name:
            raise OpenSearchUserMgmtError(
                "user name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        try:
            resp = self.opensearch.request("DELETE", f"{USER_ENDPOINT}/{user_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return {
                    "status": "OK",
                    "response": "user does not exist, and therefore has not been removed",
                }
            else:
                raise OpenSearchUserMgmtError(e)

        self.logger.debug(resp)
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing user {user_name} failed")
        return resp

    def patch_user(self, user_name: str, patches: List[Dict[str, any]]) -> Dict[str, any]:
        """Applies patches to user.

        Args:
            user_name: name of the user to be created.
            patches: a list of patches to be applied to the user in question.

        Raises:
            OpenSearchUserMgmtError: If the request fails.

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.opensearch.request(
                "PATCH",
                f"{USER_ENDPOINT}/{user_name}",
                payload=patches,
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"patching user {user_name} failed")

        return resp

    def create_role_mapping(self, role: str, mapped_users: List[str]) -> None:
        """Creates or replaces role mapping for selected role with all of its users mapped to it.

        Args:
            role: name of the role for users being mapped to.
            mapped_users: all the users, that should be mapped to the specified role.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        try:
            resp = self.opensearch.request(
                "PUT",
                f"{ROLESMAPPING_ENDPOINT}/{role}",
                payload={"users": mapped_users, "backend_roles": [role]},
            )
        except OpenSearchHttpError as e:
            self.logger.error(f"Couldn't create role mapping {str(e)}")
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            raise OpenSearchUserMgmtError(f"creating role mapping {role} failed")

    def remove_role_mapping(self, role: str) -> None:
        """Remove the given role mapping if it exists.

        Args:
            role: name of the role mapping to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if role is empty
        """
        if not role:
            raise OpenSearchUserMgmtError(
                "role name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        try:
            resp = self.opensearch.request("DELETE", f"{ROLESMAPPING_ENDPOINT}/{role}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                resp = {
                    "status": "OK",
                    "response": "role mapping does not exist, and therefore has not been removed",
                }
            else:
                raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing role mapping {role} failed")

    def update_user_password(self, username: str, hashed_pwd: str = None):
        """Change user hashed password."""
        resp = self.opensearch.request(
            "PATCH",
            f"/_plugins/_security/api/internalusers/{username}",
            [{"op": "replace", "path": "/hash", "value": hashed_pwd}],
        )
        if resp.get("status") != "OK":
            raise OpenSearchError(f"{resp}")

    def put_internal_user(self, user: str, hashed_pwd: str):
        """User creation for specific system users."""
        if user not in OPENSEARCH_USERS:
            raise OpenSearchError(f"User {user} is not an internal user.")

        if user == ADMIN_USER:
            # reserved: False, prevents this resource from being update-protected from:
            # updates made on the dashboard or the rest api.
            # we grant the admin user all opensearch access + security_rest_api_access
            self.logger.debug("putting admin to internal_users.yml")
            self.opensearch.config.put(
                "opensearch-security/internal_users.yml",
                "admin",
                {
                    "hash": hashed_pwd,
                    "reserved": False,
                    "backend_roles": [ADMIN_USER],
                    "opendistro_security_roles": [
                        "security_rest_api_access",
                        "all_access",
                    ],
                    "description": "Admin user",
                },
            )
        elif user == KIBANA_SERVER_USER:
            self.opensearch.config.put(
                "opensearch-security/internal_users.yml",
                f"{KIBANA_SERVER_USER}",
                {
                    "hash": hashed_pwd,
                    "reserved": False,
                    "description": "Kibanaserver user",
                },
            )
        elif user == COS_USER:
            roles = [COS_ROLE]
            self.create_user(COS_USER, roles, hashed_pwd)
            self.patch_user(
                COS_USER,
                [{"op": "replace", "path": "/opendistro_security_roles", "value": roles}],
            )
