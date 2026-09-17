#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Configuration manager."""

import logging

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_ROLE,
    COS_USER,
    KIBANA_SERVER_USER,
    OPENSEARCH_SYSTEM_USERS,
    OPENSEARCH_USERS,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.core.base_models import stripped_or_none
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import generate_hashed_password
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class InternalUsersManager(BaseManager):
    """OpenSearch Users Manager.

    This manager handles everything related to configuring users in OpenSearch.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "internal_users_manager")
        self.yaml_setter = YamlConfigSetter(self.workload)

    def put_or_update_internal_user_leader(  # noqa: C901
        self,
        user: str,
        pwd: str | None = None,
        update: bool = True,
    ) -> bool:
        """Create system user or update it with a new password.

        Args:
            user: The system user to create or update.
            pwd: The password to set for the user. If None, a random password will be generated.
            update: If True, update the user's password if it already exists. If False,
                do not update the password if the user already exists.

        Returns:
            True if the user was created or updated, False if an error occurred.
        """
        # Leader is to set new password and hash, others populate existing hash locally
        if user == ADMIN_USER:
            # admin_password may hold a single-space placeholder to force secret
            # creation (see initialize_empty_secrets)
            password_secret = stripped_or_none(self.state.application.admin_password)
        elif user == KIBANA_SERVER_USER:
            password_secret = self.state.application.kibana_server_password
        elif user == COS_USER:
            password_secret = self.state.application.monitor_password
        else:
            raise ValueError(f"User {user} is not an internal user.")
        if password_secret and not update:
            try:
                self.save_user_locally(user)
                return True
            except (OpenSearchUserMgmtError, OpenSearchFileOperationError) as e:
                logger.error("An error occurred while saving internal user %s: %s", user, str(e))
                return False

        hashed_pwd, pwd = generate_hashed_password(pwd)

        # Updating security index
        # We need to do this for all credential changes
        if password_secret and update:
            try:
                self.opensearch_client.patch_user_password(user, hashed_pwd)
            except OpenSearchHttpError as e:
                logger.error("Failed to update user %s password: %s", user, e)
                return False

        # In case it's a new user, OR it's a system user (that has an entry in internal_users.yml)
        # we either need to initialize or update (local) credentials as well
        if not password_secret or user in OPENSEARCH_SYSTEM_USERS:
            try:
                self.put_internal_user(user, hashed_pwd)
            except (OpenSearchUserMgmtError, OpenSearchFileOperationError) as e:
                logger.error("An error occurred while updating internal user %s: %s", user, str(e))
                return False

        # Secrets need to be maintained
        # For System Users we also save the hash key
        # so all units can fetch it for local users (internal_users.yml) updates.

        if user == ADMIN_USER:
            self.state.application.update(
                {
                    "admin_password": pwd,
                    "admin_hashed_password": hashed_pwd,
                    "admin_user_initialized": True,
                }
            )
        elif user == KIBANA_SERVER_USER:
            self.state.application.update(
                {"kibana_server_password": pwd, "kibana_server_hashed_password": hashed_pwd}
            )
        elif user == COS_USER:
            self.state.application.monitor_password = pwd
        return True

    def purge_initial_default_users(self) -> None:
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

    def save_user_locally(self, user: str) -> None:
        """Save the user in internal_users.yaml"""
        # System users have to be saved locally in internal_users.yml
        if user == ADMIN_USER:
            hashed_pwd = self.state.application.admin_hashed_password
        elif user == KIBANA_SERVER_USER:
            hashed_pwd = self.state.application.kibana_server_hashed_password
        elif user == COS_USER:
            hashed_pwd = self.state.application.monitor_hashed_password
        else:
            raise ValueError(f"User {user} is not an internal user.")
        self.put_internal_user(user, hashed_pwd)

    def put_internal_user(self, user: str, hashed_pwd: str) -> None:
        """User creation for specific system users.

        Raises:
            OpenSearchUserMgmtError: If user is not an internal user.
            OpenSearchFileOperationError: If internal_users.yml cannot be read or written
              due to any reason
        """
        if user not in OPENSEARCH_USERS:
            raise OpenSearchUserMgmtError(f"User {user} is not an internal user.")

        logger.debug("Creating internal user %s", user)

        if user == ADMIN_USER:
            # reserved: False, prevents this resource from being update-protected from:
            # updates made on the dashboard or the rest api.
            # we grant the admin user all opensearch access + security_rest_api_access
            logger.debug("putting admin to internal_users.yml")
            self.yaml_setter.put(
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
            self.yaml_setter.put(
                "opensearch-security/internal_users.yml",
                f"{KIBANA_SERVER_USER}",
                {
                    "hash": hashed_pwd,
                    "reserved": False,
                    "description": "Kibanaserver user",
                },
            )

    def create_cos_user(self, pwd: str | None = None) -> None:
        """Create COS user using the OpenSearch API."""
        hashed_pwd, pwd = generate_hashed_password(pwd)

        roles = [COS_ROLE]
        try:
            self.opensearch_client.create_user(COS_USER, roles, hashed_pwd)
            self.opensearch_client.patch_user(
                COS_USER,
                [
                    {
                        "op": "replace",
                        "path": "/opendistro_security_roles",
                        "value": roles,
                    }
                ],
            )
            self.state.application.monitor_password = pwd
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)
