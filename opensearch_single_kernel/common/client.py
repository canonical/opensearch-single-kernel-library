#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Client."""

import json
import logging
import random
from datetime import datetime
from typing import Any

import requests
import urllib3
from tenacity import (
    RetryCallState,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_fixed,
)
from tenacity.wait import WaitBaseT

from opensearch_single_kernel.common.constants import (
    OPENSEARCH_BACKUP_ID_FORMAT,
    OPENSEARCH_NODE_LOCK_INDEX,
    SYSTEM_INDICES,
    USER_ENDPOINT,
    USER_ROLE_ENDPOINT,
    USER_ROLESMAPPING_ENDPOINT,
    ObjectStorageType,
)
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.core.models import App, Node, ObjectStorageConfig
from opensearch_single_kernel.utils.object_storage import (
    repository_name,
    repository_type,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class OpenSearchClient:
    """Handle OpenSearch Interaction with Server."""

    def __init__(
        self,
        workload: BaseWorkload,
        host: str,
        port: int,
        admin_secret: str | None = None,
    ):
        """Initialise the client.

        The host, port and admin_secret should be retrieved from state.
        """
        self.host = host
        self.port = port
        self.workload = workload
        self.admin_secret = admin_secret

    def create_repository(
        self,
        object_storage_type: ObjectStorageType,
        object_storage_config: ObjectStorageConfig,
        name: str | None = None,
        alt_hosts: list[str] | None = None,
    ) -> str | None:
        """Create an opensearch repository for storing backups.

        Args:
            object_storage_type (ObjectStorageType): Object storage type
            object_storage_config (ObjectStorageConfig): Object storage config
            name (str, optional): Name of the repository. Defaults to None.

        Returns:
            str: Repository name
        """
        repo_name = name or repository_name(object_storage_type)
        settings = {}
        if object_storage_type == ObjectStorageType.S3:
            settings = {
                "bucket": object_storage_config.s3.bucket,
                "base_path": object_storage_config.s3.base_path,
                "region": object_storage_config.s3.region,
                "endpoint": object_storage_config.s3.endpoint,
            }
        elif object_storage_type == ObjectStorageType.AZURE:
            settings = {
                "container": object_storage_config.azure.container,
                "base_path": object_storage_config.azure.base_path,
            }
        elif object_storage_type == ObjectStorageType.GCS:
            settings = {
                "bucket": object_storage_config.gcs.bucket,
                "base_path": object_storage_config.gcs.base_path,
            }

        repo_type = repository_type(object_storage_type)
        response = self.request(
            "PUT",
            f"_snapshot/{repo_name}?verify=false",
            payload={"type": repo_type, "settings": settings},
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_fixed(3),
        )
        logger.debug("Snapshot repository creation response: %s", response)

        # This should always pass and is set for documentation purposes
        assert response.get("acknowledged") is True
        return repo_name

    def verify_repository(
        self, object_storage_type: ObjectStorageType, alt_hosts: list[str] | None = None
    ) -> bool:
        """Verify repository by listing snapshots.

        Args:
            object_storage_type (ObjectStorageType): Object storage type

        Returns:
            True if the repository can be listed successfully.

        Raises:
            OpenSearchHttpError if there are any backend issues such as auth/perm errors.
        """
        repository = repository_name(object_storage_type)
        # If creds/endpoint/perm are wrong, this call raises OpenSearchHttpError with a 500.
        self.request(
            "GET",
            f"_snapshot/{repository}/_all",
            alt_hosts=alt_hosts,
            timeout=30,
            retries=3,
            wait_strategy=wait_fixed(3),
        )
        return True

    def get_snapshot(
        self,
        object_storage_type: ObjectStorageType,
        snapshot_id: str,
        alt_hosts: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """Fetch a snapshot by id.

        Args:
            object_storage_type (ObjectStorageType): Object storage type.
            snapshot_id (str): Snapshot id.

        Returns:
            dict[str, Any] | None: Snapshot information.
        """
        repo_name = repository_name(object_storage_type)
        try:
            response = self.request(
                "GET",
                f"_snapshot/{repo_name}/{snapshot_id}",
                alt_hosts=alt_hosts,
                timeout=30,
                retries=3,
                wait_strategy=wait_fixed(3),
            )
            return response["snapshots"][0]
        except OpenSearchHttpError as e:
            if e.response_body.get("error", {}).get("type") == "snapshot_missing_exception":
                return
            raise

    def list_snapshots(
        self, object_storage_type: ObjectStorageType, alt_hosts: list[str] | None = None
    ) -> dict[Any, dict[str, Any]]:
        """List all snapshots in the current repository.

        Args:
            object_storage_type (ObjectStorageType): Object storage type.

        Returns:
            dict: Snapshot information.
        """
        repo_name = repository_name(object_storage_type)
        response = self.request(
            "GET",
            f"_snapshot/{repo_name}/_all",
            alt_hosts=alt_hosts,
            timeout=30,
            retries=3,
            wait_strategy=wait_fixed(3),
        )
        snapshots = {
            snapshot["snapshot"]: {
                "state": snapshot["state"].lower(),
                "indices": snapshot.get("indices", []),
            }
            for snapshot in response.get("snapshots", [])
        }
        return dict(sorted(snapshots.items(), reverse=True))

    def is_repository_created(
        self,
        object_storage_type: ObjectStorageType,
        repository: str = None,
        alt_hosts: list[str] | None = None,
    ) -> bool:
        """Check if a repository is created.

        Args:
            object_storage_type (ObjectStorageType): Object storage type.
            repository (str): The name of the repository to check.

        Returns:
            True if repository is created else False
        """
        repo_name = repository or repository_name(object_storage_type)
        try:
            response = self.request(
                "GET",
                f"_snapshot/{repo_name}",
                alt_hosts=alt_hosts,
                retries=3,
                wait_strategy=wait_fixed(3),
            )
            return response.get(repo_name) is not None
        except OpenSearchHttpError as e:
            if e.response_body.get("error", {}).get("type") == "repository_missing_exception":
                return False
            raise

    def is_snapshot_in_progress(self, alt_hosts: list[str] | None = None) -> bool:
        """Check if a backup is running.

        Returns:
            True if snapshot is running else False
        """
        response = self.request(
            "GET", "_snapshot/_status", alt_hosts=alt_hosts, retries=3, wait_strategy=wait_fixed(3)
        )
        return len(response.get("snapshots", [])) > 0

    def is_restore_in_progress(self, alt_hosts: list[str] | None = None) -> bool:
        """Check if a restore operation is running.

        Returns:
            True if restore operation is running else False
        """
        response: list[dict[str, str]] = self.request(
            "GET",
            "/_cat/recovery?format=json&h=type,stage",
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_fixed(3),
        )
        for operation in response:
            if operation["type"] == "snapshot" and operation["stage"] == "open":
                return True
        return False

    def remove_repository(
        self,
        object_storage_type: ObjectStorageType,
        name: str | None = None,
        alt_hosts: list[str] | None = None,
    ) -> None:
        """Remove the snapshot repository with retries and optional health gating.

        Args:
            object_storage_type: Object storage type to use
            name: Name of the repository to remove
            alt_hosts: Optional list of alternative hosts to perform the operation on
        """
        repo_name = name or repository_name(object_storage_type)

        try:
            resp = self.request(
                "DELETE",
                f"_snapshot/{repo_name}",
                alt_hosts=alt_hosts,
                retries=3,
                wait_strategy=wait_fixed(3),
            )
            assert resp.get("acknowledged") is True
        except OpenSearchHttpError as e:
            body = e.response_body or {}
            err_type = (
                (body.get("error") or {}).get("type") if isinstance(body, dict) else str(body)
            )
            if "repository_missing_exception" in str(err_type):
                return
            raise

    def create_snapshot(
        self, object_storage_type: ObjectStorageType, alt_hosts: list[str] | None = None
    ) -> str:
        """Create an OpenSearch snapshot.

        Args:
            object_storage_type: Object storage type to use

        Returns:
            snapshot_id: Snapshot ID
        """
        repo_name = repository_name(object_storage_type)
        snapshot_id = datetime.now().strftime(OPENSEARCH_BACKUP_ID_FORMAT).lower()
        ignore = [f"-{idx}" for idx in SYSTEM_INDICES]
        indices_clause = ",".join(["*"] + ignore)
        logger.info("indices_clause: %s", indices_clause)
        # create snapshot
        response = self.request(
            "PUT",
            f"_snapshot/{repo_name}/{snapshot_id}?wait_for_completion=false",
            payload={
                "indices": indices_clause,
                "ignore_unavailable": True,
                "include_global_state": True,
            },
            alt_hosts=alt_hosts,
            timeout=30,
            retries=3,
            wait_strategy=wait_fixed(3),
        )

        logger.info("Snapshot request submitted with backup-id: %s", snapshot_id)
        logger.debug("Create snapshot request with id: %s - response: %s", snapshot_id, response)

        # This should always pass and is set for documentation purposes
        assert response.get("accepted") is True

        return snapshot_id

    def restore_snapshot(
        self,
        object_storage_type: ObjectStorageType,
        snapshot: dict[str, Any],
        alt_hosts: list[str] | None = None,
    ) -> set[str]:
        """Restore an OpenSearch snapshot.

        Args:
            object_storage_type: Object storage type to use
            snapshot: Snapshot to restore

        Returns:
            Empty set if snapshot was restored else set includes not restored indices
        """
        repo_name = repository_name(object_storage_type)
        snapshot_id = snapshot.get("snapshot")
        ignore = [f"-{idx}" for idx in SYSTEM_INDICES]
        indices_clause = ",".join(["*"] + ignore)

        payload = {
            "indices": indices_clause,
            "ignore_unavailable": True,
            "include_global_state": False,
        }

        restore_resp = self.request(
            "POST",
            f"_snapshot/{repo_name}/{snapshot_id}/_restore?wait_for_completion=true",
            payload=payload,
            alt_hosts=alt_hosts,
            timeout=10 * 60,
            retries=3,
            wait_strategy=wait_fixed(3),
        )
        logger.info("Restore of snapshot '%s' response: %s", snapshot_id, restore_resp)

        # this only serves as documentation and should always be true if no previous HTTP error
        snapshot_field = restore_resp.get("snapshot")
        assert "accepted" in restore_resp or (
            isinstance(snapshot_field, dict) and snapshot_field.get("snapshot") == snapshot_id
        ), f"Unexpected restore response: {restore_resp}"

        # sanity check on the restore success
        recovery_resp: list[dict[str, str]] = self.request(
            "GET", "_cat/recovery?format=json", alt_hosts=alt_hosts
        )
        snapshot_recoveries = [
            recovery
            for recovery in recovery_resp
            if (
                recovery["type"] == "snapshot"
                and recovery["repository"] == repo_name
                and recovery["snapshot"] == snapshot_id
            )
        ]
        restored_indices = set(
            [recovery["index"] for recovery in snapshot_recoveries if recovery["stage"] == "done"]
        )
        expected_indices = set(snapshot.get("indices", []))
        return expected_indices - restored_indices

    def close_snapshot_indices_open_in_cluster(
        self, snapshot: dict[str, Any], alt_hosts: list[str] | None = None
    ) -> tuple[list[str] | None, dict[str, Any] | None]:
        """Close the non-system indices included in a given snapshot.

        Args:
            snapshot (dict): Snapshot to close.

        Returns:
            Tuple: closed_indices, failed_to_closed_indices
        """
        if not (
            indices_to_close := self._get_snapshot_indices_open_in_cluster(
                snapshot, alt_hosts=alt_hosts
            )
        ):
            logger.info("No indices to close.")
            return None, None

        logger.info("Attempting closing the indices: %s", indices_to_close)
        response = self.request(
            "POST",
            f"{','.join(indices_to_close)}/_close",
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_fixed(3),
        )

        # verify that the relevant indices are closed
        if response["acknowledged"] and response["shards_acknowledged"]:
            logger.info("Successfully closed all indices: %s.", indices_to_close)
            return indices_to_close, None

        indices_failed_to_close = {
            index: payload
            for index, payload in response["indices"].items()
            if not payload["closed"]
        }
        closed_indices = [
            index for index in indices_to_close if index not in indices_failed_to_close
        ]

        logger.error("Failed to close some indices: \n%s", indices_failed_to_close)
        return closed_indices, indices_failed_to_close

    def _get_snapshot_indices_open_in_cluster(
        self, snapshot: dict[str, Any], alt_hosts: list[str] | None = None
    ) -> list[str]:
        """Fetch the current open indices in the current cluster.

        Args:
            snapshot (dict): Snapshot information

        Returns:
            list[str] | None: List of indices which are open
        """
        current_indices = self.indices(alt_hosts=alt_hosts)
        return sorted(
            [
                idx
                for idx in snapshot.get("indices", [])
                if idx in current_indices
                and idx not in SYSTEM_INDICES
                and current_indices[idx]["status"] == "open"
            ]
        )

    def indices(
        self,
        host: str | None = None,
        alt_hosts: list[str] | None = None,
    ) -> dict[str, dict[str, str]]:
        """Get all shards of all indices in the cluster."""
        # Get cluster state
        cluster_state = self.request(
            "GET",
            "/_cluster/state?filter_path=metadata.indices",
            host=host,
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )
        indices_state = cluster_state["metadata"]["indices"]

        # Get cluster health
        cluster_health = self.request(
            "GET",
            "/_cluster/health?level=indices",
            host=host,
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )
        indices_health = cluster_health["indices"]

        idx = {}
        for index in indices_state.keys():
            idx[index] = {
                "health": indices_health[index]["status"],
                "status": indices_state[index]["state"],
            }
        return idx

    def create_index(self, index_name: str) -> None:
        """Create an index in OpenSearch.

        Args:
            index_name: The name of the index to create.
        """
        try:
            self.request("PUT", f"/{index_name}")
        except OpenSearchHttpError as e:
            if (
                e.response_code == 400
                and e.response_body.get("error", {}).get("type")
                == "resource_already_exists_exception"
            ):
                logger.warning("Index failed to be created as it already exists, continuing...")
            else:
                raise e

    def create_user_role(
        self,
        role_name: str,
        permissions: dict[str, str] | None = None,
        action_groups: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Creates a role with the given permissions.

        This method assumes the dicts provided are valid opensearch config. If not, raises
        OpenSearchHttpError

        Args:
            role_name: name of the role
            permissions: A valid dict of existing opensearch permissions.
            action_groups: A valid dict of existing opensearch action groups.

        Raises:
            OpenSearchHttpError: If the role creation request fails.

        Returns:
            HTTP response to opensearch API request.
        """
        resp = self.request(
            "PUT",
            f"{USER_ROLE_ENDPOINT}/{role_name}",
            payload={**(permissions or {}), **(action_groups or {})},
        )

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            logger.error("Couldn't create role: %s", resp)
            raise OpenSearchHttpError(f"creating role {role_name} failed")

        return resp

    def remove_user_role(self, role_name: str) -> dict[str, Any]:
        """Remove the given role from opensearch distribution.

        Args:
            role_name: name of the role to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if role_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.request("DELETE", f"{USER_ROLE_ENDPOINT}/{role_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return {
                    "status": "OK",
                    "response": "role does not exist, and therefore has not been removed",
                }
            raise e

        if resp.get("status") != "OK":
            raise OpenSearchHttpError(f"removing role {role_name} failed")

        return resp

    def create_user(
        self, user_name: str, roles: list[str] | None, hashed_pwd: str
    ) -> dict[str, Any]:
        """Create or update user and assign the requested roles to the user.

        Args:
            user_name: name of the user to be created.
            roles: list of roles to be applied to the user. These must already exist.
            hashed_pwd: the hashed password for the user.

        Raises:
            OpenSearchHttpError: If the request fails.

        Returns:
            HTTP response to opensearch API request.
        """
        payload = {"hash": hashed_pwd}
        if roles:
            payload["opendistro_security_roles"] = roles

        resp = self.request(
            "PUT",
            f"{USER_ENDPOINT}/{user_name}",
            payload=payload,
        )

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            raise OpenSearchHttpError(f"creating user {user_name} failed")

        return resp

    def get_user(self, user_name: str) -> dict[str, Any] | None:
        """Get the given user from opensearch distribution.

        Args:
            user_name: name of the user to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if user_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.request("GET", f"{USER_ENDPOINT}/{user_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return None
            raise e

        logger.debug(resp)
        return resp

    def remove_user(self, user_name: str) -> dict[str, Any]:
        """Remove the given user from opensearch distribution.

        Args:
            user_name: name of the user to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if user_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.request("DELETE", f"{USER_ENDPOINT}/{user_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return {
                    "status": "OK",
                    "response": "user does not exist, and therefore has not been removed",
                }
            raise e

        logger.debug(resp)
        if resp.get("status") != "OK":
            raise OpenSearchHttpError(f"removing user {user_name} failed")
        return resp

    def patch_user(self, user_name: str, patches: list[dict[str, Any]]) -> dict[str, Any]:
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
            resp = self.request(
                "PATCH",
                f"{USER_ENDPOINT}/{user_name}",
                payload=patches,
            )
        except OpenSearchHttpError as e:
            raise e

        if resp.get("status") != "OK":
            raise OpenSearchHttpError(f"patching user {user_name} failed")

        return resp

    def create_user_role_mapping(self, role: str, mapped_users: list[str]) -> None:
        """Creates or replaces role mapping for selected role with all of its users mapped to it.

        Args:
            role: name of the role for users being mapped to.
            mapped_users: all the users, that should be mapped to the specified role.

        Raises:
            OpenSearchHttpError: If the request fails.
        """
        try:
            resp = self.request(
                "PUT",
                f"{USER_ROLESMAPPING_ENDPOINT}/{role}",
                payload={"users": mapped_users, "backend_roles": [role]},
            )
        except OpenSearchHttpError as e:
            logger.error("Couldn't create role mapping: %s", str(e))
            raise e

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            raise OpenSearchHttpError(f"creating role mapping {role} failed")

    def remove_user_role_mapping(self, role: str) -> None:
        """Remove the given role mapping if it exists.

        Args:
            role: name of the role mapping to be removed.

        Raises:
            OpenSearchHttpError: If the request fails, or if role is empty
        """
        try:
            resp = self.request("DELETE", f"{USER_ROLESMAPPING_ENDPOINT}/{role}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                resp = {
                    "status": "OK",
                    "response": "role mapping does not exist, and therefore has not been removed",
                }
            else:
                raise e

        if resp.get("status") != "OK":
            raise OpenSearchHttpError(f"removing role mapping {role} failed")

    def patch_user_password(self, username: str, hashed_pwd: str):
        """Change user hashed password."""
        resp = self.request(
            "PATCH",
            f"{USER_ENDPOINT}/{username}",
            [{"op": "replace", "path": "/hash", "value": hashed_pwd}],
        )
        if resp.get("status") != "OK":
            raise OpenSearchHttpError(f"{resp}")

    def flush_translog(self, alt_hosts: list[str] | None = None) -> None:
        """Flush the OpenSearch translog to ensure all operations are committed to disk."""
        self.request(
            "POST",
            "/_flush/synced",
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )

    def disable_shard_allocation(self, alt_hosts: list[str] | None = None) -> None:
        """Disable shard allocation to primaries only (used before node restart/upgrade)."""
        self.request(
            "PUT",
            "/_cluster/settings",
            payload={
                "persistent": {
                    "cluster.routing.allocation.enable": "primaries",
                    "action.auto_create_index": False,
                }
            },
            alt_hosts=alt_hosts,
        )

    def enable_shard_allocation(self, alt_hosts: list[str] | None = None) -> None:
        """Re-enable full shard allocation (used after rollback or node restart)."""
        self.request(
            "PUT",
            "/_cluster/settings",
            payload={
                "persistent": {
                    "cluster.routing.allocation.enable": "all",
                    "action.auto_create_index": True,
                }
            },
            alt_hosts=alt_hosts,
        )

    def apply_auto_replication_to_index(
        self,
        index: str,
    ) -> None:
        """Apply replication settings to an index.

        This will set the auto_expand_replicas to 0-all, which means that OpenSearch
        will automatically adjust the number of replicas for indexes based on the
        number of data nodes in the cluster. In this case 0 is the minimum number
        of replicas and "all" means the max limit which is the number of data nodes
        minus one.

        Args:
            index: the name of the index to apply the settings to.
        """
        self.request(
            method="PUT",
            endpoint=f"/{index}/_settings",
            payload={"index": {"auto_expand_replicas": "0-all"}},
            retries=2,
            wait_strategy=wait_exponential(min=2),
        )

    def fetch_voting_exclusions_config(self, alt_hosts: list[str] | None = None) -> set[str]:
        """Fetch the voting exclusions config."""
        try:
            resp = self.request(
                "GET",
                "/_cluster/state/metadata/voting_config_exclusions",
                alt_hosts=alt_hosts,
                retries=3,
                wait_strategy=wait_exponential(min=2),
            )
            return set(
                sorted(
                    [
                        node["node_name"]
                        for node in resp["metadata"]["cluster_coordination"][
                            "voting_config_exclusions"
                        ]
                    ]
                )
            )
        except KeyError:
            # no voting exclusions set
            return set()

    def remove_voting_exclusions(self, alt_hosts: list[str] | None = None) -> bool:
        """Remove voting exclusions from OpenSearch cluster."""
        response = self.request(
            "DELETE",
            "/_cluster/voting_config_exclusions?wait_for_removal=false",
            alt_hosts=alt_hosts,
            resp_status_code=True,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )
        if response >= 400:
            logger.debug("Failed to remove voting exclusions, response %s", response)
            return False

        logger.debug("Removed voting exclusions.")
        return True

    def add_voting_exclusions(
        self, exclusions: set[str], alt_hosts: list[str] | None = None
    ) -> bool:
        """Add voting exclusions to OpenSearch cluster."""
        response = self.request(
            "POST",
            f"/_cluster/voting_config_exclusions?node_names={','.join(sorted(exclusions))}&timeout=1m",
            alt_hosts=alt_hosts,
            resp_status_code=True,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )
        if response >= 400:
            logger.debug("Failed to add voting exclusions, response %s", response)
            return False

        logger.debug("Added voting exclusions for:  %s", exclusions)
        return True

    def fetch_allocation_exclusions(self, alt_hosts: list[str] | None = None) -> set[str]:
        """Fetch the registered allocation exclusions."""
        try:
            resp = self.request(
                "GET",
                "/_cluster/settings",
                alt_hosts=alt_hosts,
                retries=3,
                wait_strategy=wait_exponential(min=2),
            )
            if exclusions := resp["persistent"]["cluster"]["routing"]["allocation"]["exclude"][
                "_name"
            ]:
                return set(exclusions.split(","))
        except KeyError:
            pass

        return set()

    def add_allocation_exclusions(
        self,
        node: Node,
        allocations: set[str] | None = None,
        override: bool = False,
        alt_hosts: list[str] | None = None,
    ) -> bool:
        """Register new allocation exclusions."""
        existing = set() if override else self.fetch_allocation_exclusions(alt_hosts=alt_hosts)
        all_exclusions = existing.union(allocations if allocations is not None else {node.name})
        response = self.request(
            "PUT",
            "/_cluster/settings",
            {"persistent": {"cluster.routing.allocation.exclude._name": ",".join(all_exclusions)}},
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )
        return "acknowledged" in response

    def get_current_node(
        self, unit_name: str, unit_id: int, alt_hosts: list[str] | None
    ) -> Node | None:
        """Get the current OpenSearch node information.

        Args:
            unit_name: The name of opensearch unit.
            unit_id: The id of the unit.
            alt_hosts: (Optional[List[str]]): List of alternative hosts.

        Returns:
            node (Node | None): Current opensearch node information.
        """
        nodes = self.request(
            "GET",
            "/_nodes",
            retries=3,
            alt_hosts=alt_hosts,
        ).get("nodes")

        for node in nodes.values():
            if node["name"] == unit_name:
                return Node(
                    name=node["name"],
                    roles=node["roles"],
                    ip=node["ip"],
                    app=App(id=node.get("attributes", {}).get("app_id")),
                    unit_number=unit_id,
                    temperature=node.get("attributes", {}).get("temp"),
                )
        return None

    def get_roles_by_unit_name(
        self, unit_name: str, unit_number: int, alt_hosts: list[str] | None
    ) -> list[str]:
        """Get the list of the roles assigned to this node.

        Args:
            unit_name (str): The name of the unit.
            alt_hosts: (Optional[List[str]]): List of alternative hosts.

        Returns:
            roles (List[str]): List of opensearch unit roles.
        """
        node = self.get_current_node(unit_name, unit_id=unit_number, alt_hosts=alt_hosts)
        return node.roles if node else []

    def get_shards(
        self,
        host: str | None = None,
        alt_hosts: list[str] | None = None,
        verbose: bool = False,
    ) -> list[dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        cluster_state = self.request(
            "GET",
            "_cluster/state/routing_table,metadata,nodes",
            host=host,
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )

        nodes = cluster_state["nodes"]

        shards_info = []
        for index_name, index_data in cluster_state["routing_table"]["indices"].items():
            for shard_num, shard_data in index_data["shards"].items():
                for shard in shard_data:
                    node_data = nodes.get(shard["node"], {})
                    node_name = node_data.get("name", None)
                    node_ip = (
                        node_data["transport_address"].split(":")[0]
                        if "transport_address" in node_data
                        else None
                    )

                    shard_info = {
                        "index": index_name,
                        "shard": shard_num,
                        "prirep": "p" if shard.get("primary") else "r",
                        "state": shard["state"],
                        "ip": node_ip,
                        "node": node_name,
                    }
                    if verbose:
                        shard_info["unassigned.reason"] = shard.get("unassigned_info", {}).get(
                            "reason", None
                        )
                    shards_info.append(shard_info)
        return shards_info

    def get_busy_shards_by_unit(
        self,
        host: str | None = None,
        alt_hosts: list[str] | None = None,
    ) -> dict[str, list[str]]:
        """Get the busy shards of each index in the cluster."""
        shards = self.get_shards(host=host, alt_hosts=alt_hosts)

        busy_shards = {}
        for shard in shards:
            state = shard.get("state")
            if state not in ["INITIALIZING", "RELOCATING"]:
                continue

            unit_name = shard["node"]
            if unit_name not in busy_shards:
                busy_shards[unit_name] = []

            busy_shards[unit_name].append(shard["index"])

        return busy_shards

    def reload_tls_certificates(self, cert_files: tuple[str] | None = None) -> None:
        """Reload TLS certificates in OpenSearch unit using REST API."""
        url_http = "_plugins/_security/api/ssl/http/reloadcerts"
        url_transport = "_plugins/_security/api/ssl/transport/reloadcerts"
        try:
            # Reload http certificates
            self.request(
                "PUT",
                url_http,
                cert_files=cert_files,
                retries=3,
            )
            # Reload transport certificates
            self.request(
                "PUT",
                url_transport,
                cert_files=cert_files,
                retries=3,
            )
        except OpenSearchHttpError as e:
            logger.error("Error reloading TLS certificates via API: %s", str(e))
            raise

    def get_allocation_explain(
        self,
        host: str | None = None,
        alt_hosts: list[str] | None = None,
    ) -> list[dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        return self.request(
            "GET",
            "/_cluster/allocation/explain?include_disk_info=true&include_yes_decisions=true",
            host=host,
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )

    def get_health(
        self, host: str | None, wait_for_green: bool, alt_hosts: list[str] | None = None
    ) -> dict[str, Any] | None:
        """Fetch the cluster health."""
        endpoint = "/_cluster/health"

        timeout = 5
        if wait_for_green:
            endpoint = f"{endpoint}?wait_for_status=green&timeout=1m"
            timeout = 61

        try:
            return self.request(
                "GET",
                endpoint,
                host=host,
                alt_hosts=alt_hosts,
                timeout=timeout,
                retries=3,
                wait_strategy=wait_exponential(min=2),
            )
        except OpenSearchHttpError as e:
            logger.error("HTTP error when checking cluster health: %s", e)
            return None

    def get_indices(
        self,
        host: str | None = None,
        alt_hosts: list[str] | None = None,
    ) -> dict[str, dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        if not host:
            host = self.host
        # Get cluster state
        cluster_state = self.request(
            "GET",
            "/_cluster/state?filter_path=metadata.indices",
            host=host,
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )
        indices_state = cluster_state["metadata"]["indices"]

        # Get cluster health
        cluster_health = self.request(
            "GET",
            "/_cluster/health?level=indices",
            host=host,
            alt_hosts=alt_hosts,
            retries=3,
            wait_strategy=wait_exponential(min=2),
        )
        indices_health = cluster_health["indices"]

        idx = {}
        for index in indices_state.keys():
            idx[index] = {
                "health": indices_health[index]["status"],
                "status": indices_state[index]["state"],
            }
        return idx

    def get_nodes(self, host: str | None = None, alt_hosts: list[str] | None = None):
        """Call the /_nodes API endpoint of opensearch"""
        return self.request("GET", "/_nodes", host=host, alt_hosts=alt_hosts, retries=3)

    def is_node_up(self, host: str | None = None) -> bool:
        """Get status of node.

        This assumes OpenSearch is Running. Defaults to this unit
        """
        # This function needs to give us a quick response
        host = host or self.host
        if not self.workload.is_reachable(host, self.port):
            return False

        try:
            resp_code = self.request(
                "GET",
                "/",
                host=host,
                check_hosts_reach=False,
                resp_status_code=True,
                timeout=1,
            )
            return resp_code < 400
        except (OpenSearchHttpError, Exception) as e:
            logger.debug("Error when checking if host %s is up: %s", host, e)
            return False

    def create_notification_config(
        self, *, config_id: str, name: str, config: dict[str, object]
    ) -> None:
        """Create notification config.

        Args:
            config_id: Notification Config ID
            name: Notification Name
            config: Notification Config
        """
        payload = {"config_id": config_id, "name": name, "config": config}
        self.request("POST", "/_plugins/_notifications/configs/", payload=payload)

    def notification_config_exists(self, config_id: str) -> bool:
        """Check if config exists.

        Args:
            config_id: Notification Config ID

        Returns:
            True if config exists, False if 404.
        """
        try:
            self.request("GET", f"/_plugins/_notifications/configs/{config_id}")
            return True
        except OpenSearchHttpError as exc:
            if getattr(exc, "response_code", None) == 404:
                return False
            raise

    def put_notification_config(
        self, *, config_id: str, name: str, config: dict[str, object]
    ) -> None:
        """Create config if missing, otherwise update.

        Args:
            config_id: Notification Config ID
            name: Notification Name
            config: Notification Config
        """
        if self.notification_config_exists(config_id):
            self.update_notification_config(config_id=config_id, config=config)
        else:
            self.create_notification_config(config_id=config_id, name=name, config=config)

    def update_notification_config(self, *, config_id: str, config: dict[str, object]) -> None:
        """Update notification config.

        Args:
            config_id: Notification Config ID
            config: Notification Config
        """
        payload = {"config": config}
        self.request("PUT", f"/_plugins/_notifications/configs/{config_id}", payload=payload)

    def delete_notification_config(self, config_id: str) -> None:
        """Delete config by id.

        If the request returns code 404 (config already gone)
        it is treated as success and function returns.

        Args:
            config_id: Notification Config ID
        """
        try:
            self.request("DELETE", f"/_plugins/_notifications/configs/{config_id}")
        except OpenSearchHttpError as exc:
            if getattr(exc, "response_code", None) == 404:
                return
            raise

    def reload_secure_settings(self) -> bool:
        """Reload secure settings. Doesn't throw an exception.

        Returns:
            bool: whether operation was successful.
        """
        try:
            response = self.request("POST", "_nodes/reload_secure_settings")
        except OpenSearchHttpError as e:
            logger.error("Could not reload secure settings: %s", e)
            return False
        return isinstance(response, dict) and response.get("_nodes", {}).get("failed", -1) == 0

    def request(  # noqa
        self,
        method: str,
        endpoint: str,
        payload: str | dict[str, Any] | list[dict[str, Any]] | None = None,
        host: str | None = None,
        alt_hosts: list[str] | None = None,
        check_hosts_reach: bool = True,
        resp_status_code: bool = False,
        retries: int = 1,
        wait_strategy: WaitBaseT = wait_fixed(1),
        ignore_retry_on: list | None = None,
        timeout: int = 5,
        cert_files: tuple[str, str] | None = None,
    ) -> dict[str, Any] | list[Any] | int:
        """Make an HTTP request.

        Args:
            method: matching the known http methods.
            endpoint: relative to the base uri.
            payload: str, JSON obj or array body payload.
            host: host of the node we wish to make a request on, by default current host.
            alt_hosts: in case the default host is unreachable, fallback/alternative hosts.
            check_hosts_reach: if true, performs a ping for each host
            resp_status_code: whether to only return the HTTP code from the response.
            retries: number of retries
            ignore_retry_on: don't retry for specific error codes
            timeout: number of seconds before a timeout happens
            cert_files: tuple of cert and key files to use for authentication

        Raises:
            ValueError if method or endpoint are missing
            OpenSearchHttpError if hosts are unreachable
        """

        def call(urls: list[str]) -> requests.Response:
            """Performs an HTTP request."""
            random.shuffle(urls)

            retry = retry_if_exception_type(requests.RequestException) | retry_if_exception_type(
                urllib3.exceptions.HTTPError
            )
            for attempt in Retrying(
                retry=retry,
                stop=stop_after_attempt(retries),
                wait=wait_strategy,
                before_sleep=self.get_log_error_http_retry(retries, method, urls, payload),
                reraise=True,
            ):
                with attempt, requests.Session() as s:
                    url = urls[(attempt.retry_state.attempt_number - 1) % len(urls)]
                    if cert_files:
                        s.cert = cert_files
                    else:
                        s.auth = ("admin", self.admin_secret)

                    request_kwargs = {
                        "method": method.upper(),
                        "url": url,
                        "verify": self.workload.chain_path(),
                        "headers": {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                        },
                        "timeout": (timeout, timeout),
                    }
                    if payload:
                        request_kwargs["data"] = (
                            json.dumps(payload) if not isinstance(payload, str) else payload
                        )

                    response = s.request(**request_kwargs)
                    try:
                        response.raise_for_status()
                    except requests.RequestException as ex:
                        if (ex.response is not None) and (
                            ex.response.status_code in (ignore_retry_on or [])
                        ):
                            raise OpenSearchHttpError(
                                response_text=ex.response.text,
                                response_code=ex.response.status_code,
                            )
                        raise

                    return response

        if None in [endpoint, method]:
            raise ValueError("endpoint or method missing")

        if endpoint.startswith("/"):
            endpoint = endpoint[1:]

        urls = []
        for host_candidate in (host or self.host, *(alt_hosts or [])):
            if check_hosts_reach and not self.is_node_up(host_candidate):
                continue
            urls.append(f"https://{host_candidate}:{self.port}/{endpoint}")
        if not urls:
            raise OpenSearchHttpError(
                f"Host {host or self.host}:{self.port} and alternative_hosts: {alt_hosts or []} not reachable."
            )

        resp = None
        try:
            resp = call(urls)
            if resp_status_code:
                return resp.status_code

            return resp.json()
        except OpenSearchHttpError as e:
            if resp_status_code:
                return e.response_code
            raise
        except (requests.RequestException, urllib3.exceptions.HTTPError) as e:
            if not isinstance(e, requests.RequestException) or e.response is None:
                raise OpenSearchHttpError(response_text=str(e))

            if resp_status_code:
                return e.response.status_code

            raise OpenSearchHttpError(
                response_text=e.response.text, response_code=e.response.status_code
            )
        except requests.JSONDecodeError:
            raise OpenSearchHttpError(response_text=resp.text)
        except Exception as e:
            raise OpenSearchHttpError(response_text=str(e))

    def get_log_error_http_retry(
        self,
        retry_max: int,
        method: str,
        urls: list[str],
        payload: dict[str, Any] | None,
    ):
        """Return a custom log function to run before a new Tenacity retry."""

        def log_error(retry_state: RetryCallState):
            url = urls[(retry_state.attempt_number - 1) % len(urls)]
            logger.debug(
                "Request %s to %s with payload: %s failed. (Attempts left: %s)\n\tError: %s",
                method,
                url,
                payload,
                retry_max - retry_state.attempt_number,
                retry_state.outcome.exception(),
            )

        return log_error

    def get_unit_with_lock(self, host: str | None, alt_hosts: list[str] | None) -> str | None:
        """Get unit name that has acquired OpenSearch lock."""
        try:
            document_data = self.request(
                "GET",
                endpoint=f"/{OPENSEARCH_NODE_LOCK_INDEX}/_source/0",
                host=host,
                alt_hosts=alt_hosts,
                retries=3,
                ignore_retry_on=[404],
            )
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                # No unit has lock or index not available
                return None
            raise
        return document_data["unit-name"]

    def create_lock_index_if_needed(
        self, host: str, alt_hosts: list[str] | None, wait_for_cluster: bool = False
    ) -> bool:
        """Try creating the lock index if it doesn't exist yet.

        Args:
            host: connection host.
            alt_hosts: alternative connection hosts.
            wait_for_cluster: whether to wait for green status of lock index if it already exists.

        Returns:
            whether the operation was successful.
        """
        # we do this, to circumvent opensearch raising a 429 error,
        # complaining about spamming the index creation endpoint
        try:
            indices = self.get_indices(host, alt_hosts)
            if OPENSEARCH_NODE_LOCK_INDEX in indices:
                logger.debug(
                    "%s already created. Skipping creation attempt. List:%s",
                    OPENSEARCH_NODE_LOCK_INDEX,
                    indices,
                )
                if wait_for_cluster:
                    self.request(
                        "GET",
                        endpoint=f"/_cluster/health/{OPENSEARCH_NODE_LOCK_INDEX}?wait_for_status=green",
                        resp_status_code=True,
                    )
                return True
        except OpenSearchHttpError:
            pass

        # Create index if it doesn't exist
        try:
            self.request(
                "PUT",
                endpoint=f"/{OPENSEARCH_NODE_LOCK_INDEX}?wait_for_active_shards=all",
                host=host,
                alt_hosts=alt_hosts,
                retries=3,
                ignore_retry_on=[400],
                payload={"settings": {"index": {"auto_expand_replicas": "0-all"}}},
            )
        except OpenSearchHttpError as e:
            if (
                e.response_code == 400
                and e.response_body.get("error", {}).get("type")
                == "resource_already_exists_exception"
            ):
                # Index already created
                return True
            else:
                logger.error("Could not create OpenSearch lock index: %s", e)
                return False

        try:
            self.request(
                "POST",
                endpoint=f"/{OPENSEARCH_NODE_LOCK_INDEX}/_refresh",
                host=host,
                alt_hosts=alt_hosts,
                retries=3,
            )
        except OpenSearchHttpError as e:
            logger.error("Could not refresh OpenSearch lock index: %s", e)

        return True

    def delete_lock_document(self, host: str, alt_hosts: list[str] | None) -> None:
        """Delete lock document from lock index."""
        try:
            self.request(
                "DELETE",
                endpoint=f"/{OPENSEARCH_NODE_LOCK_INDEX}/_doc/0?refresh=true",
                host=host,
                alt_hosts=alt_hosts,
                retries=3,
                ignore_retry_on=[404],
            )
        except OpenSearchHttpError as e:
            if e.response_code != 404:
                raise

    def create_lock_document(self, host: str, alt_hosts: list[str] | None, unit_name: str) -> bool:
        """Create lock document in lock index with granted unit name.

        Also ensures it propagated all over the cluster. If propagation is failed,
        the document is deleted and negative result returned.

        Args:
            host: connection host.
            alt_hosts: alternative connection hosts.
            unit_name: granted unit name.

        Returns:
            whether the operation was successful.
        """
        try:
            response = self.request(
                "PUT",
                endpoint=f"/{OPENSEARCH_NODE_LOCK_INDEX}/_create/0?refresh=true&wait_for_active_shards=all",
                host=host,
                alt_hosts=alt_hosts,
                retries=0,
                payload={"unit-name": unit_name},
            )
        except OpenSearchHttpError as e:
            if e.response_code == 409 and "document already exists" in e.response_body.get(
                "error", {}
            ).get("reason", ""):
                # Document already created
                logger.debug(
                    "[Node lock] Another unit acquired OpenSearch lock while this unit attempted "
                    "to acquire lock"
                )
                return False
            else:
                raise
        else:
            # Ensure write was successful on all nodes
            # "It is important to note that this setting [`wait_for_active_shards`] greatly
            # reduces the chances of the write operation not writing to the requisite
            # number of shard copies, but it does not completely eliminate the possibility,
            # because this check occurs before the write operation commences. Once the
            # write operation is underway, it is still possible for replication to fail on
            # any number of shard copies but still succeed on the primary. The `_shards`
            # section of the write operation’s response reveals the number of shard copies
            # on which replication succeeded/failed."
            # from
            # https://www.elastic.co/guide/en/elasticsearch/reference/8.13/docs-index_.html#index-wait-for-active-shards
            if response["_shards"]["failed"] > 0:
                logger.error("Failed to write OpenSearch lock document to all nodes.")
                logger.debug(
                    "[Node lock] Deleting OpenSearch lock after failing to write to all nodes"
                )
                # Delete document id 0
                self.delete_lock_document(host, alt_hosts)
                logger.debug(
                    "[Node lock] Deleted OpenSearch lock after failing to write to all nodes"
                )
                return False
        return True
