#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
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
    Scope,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import generate_hashed_password
from opensearch_single_kernel.utils.secrets import (
    hash_key,
    password_key,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class InternalUsersManager(BaseManager):
    """OpenSearch Users Manager.

    This manager handles everything related to configuring users in OpenSearch.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "internal_users_manager"
        self.yaml_setter = YamlConfigSetter(self.workload)

    def put_or_update_internal_user_leader(
        self,
        user: str,
        pwd: str | None = None,
        update: bool = True,
    ) -> None:
        """Create system user or update it with a new password.

        Raise:
            OpenSearchUserMgmtErorr: In case of error when updating user password.
        """
        # Leader is to set new password and hash, others populate existing hash locally
        secret = self.state.secrets.get(Scope.APP, password_key(user))
        if secret and not update:
            self.save_user_locally(user)
            return

        hashed_pwd, pwd = generate_hashed_password(pwd)

        # Updating security index
        # We need to do this for all credential changes
        if secret and update:
            try:
                self.opensearch_client.update_user_password(user, hashed_pwd)
            except OpenSearchHttpError as e:
                raise OpenSearchUserMgmtError(e)

        # In case it's a new user, OR it's a system user (that has an entry in internal_users.yml)
        # we either need to initialize or update (local) credentials as well
        if not secret or user in OPENSEARCH_SYSTEM_USERS:
            self.put_internal_user(user, hashed_pwd)

        # Secrets need to be maintained
        # For System Users we also save the hash key
        # so all units can fetch it for local users (internal_users.yml) updates.
        self.state.secrets.put(Scope.APP, password_key(user), pwd)

        if user in OPENSEARCH_SYSTEM_USERS:
            self.state.secrets.put(Scope.APP, hash_key(user), hashed_pwd)

        if user == ADMIN_USER:
            self.state.application.update({"admin_user_initialized": "True"})

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
        user_hash = hash_key(user)
        hashed_pwd = self.state.secrets.get(Scope.APP, user_hash)
        # System users have to be saved locally in internal_users.yml
        self.put_internal_user(user, hashed_pwd)

    def put_internal_user(self, user: str, hashed_pwd: str) -> None:
        """User creation for specific system users."""
        if user not in OPENSEARCH_USERS:
            raise OpenSearchError(f"User {user} is not an internal user.")
        logger.debug(f"Creating internal user {user}, with {hashed_pwd}")

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
                [{"op": "replace", "path": "/opendistro_security_roles", "value": roles}],
            )
            self.state.secrets.put(Scope.APP, password_key(COS_USER), pwd)
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)
