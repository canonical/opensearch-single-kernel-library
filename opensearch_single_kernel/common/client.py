#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Client."""

import json
import logging
import random
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
    USER_ENDPOINT,
    USER_ROLE_ENDPOINT,
    USER_ROLESMAPPING_ENDPOINT,
)
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.core.models import App, Node
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
            else:
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
            else:
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

    def update_user_password(self, username: str, hashed_pwd: str):
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

    def get_node_id(self, unit_name: str) -> str | None:
        """Get the OpenSearch node id corresponding to the unit.

        Args:
            unit_name: The name of opensearch unit.

        Returns:
            node_id (Optional[str]): The opensearch unit id.
        """
        nodes = self.request(
            "GET",
            "/_nodes",
            retries=3,
        ).get("nodes")

        for n_id, node in nodes.items():
            if node["name"] == unit_name:
                return n_id
        return None

    def get_current_node(self, node_id: str, unit_id: int, alt_hosts: list[str] | None) -> Node:
        """Get the current OpenSearch node information."""
        nodes = self.request("GET", f"/_nodes/{node_id}", retries=3, alt_hosts=alt_hosts)

        current_node = nodes["nodes"][node_id]
        return Node(
            name=current_node["name"],
            roles=current_node["roles"],
            ip=current_node["ip"],
            app=App(id=current_node["attributes"]["app_id"]),
            unit_number=unit_id,
            temperature=current_node.get("attributes", {}).get("temp"),
        )

    def get_roles_by_unit_name(self, unit_name: str, alt_hosts: list[str] | None) -> list[str]:
        """Get the list of the roles assigned to this node.

        Args:
            unit_name (str): The name of the unit.
            alt_hosts: (Optional[List[str]]): List of alternative hosts.

        Returns:
            roles (List[str]): List of opensearch unit roles.
        """
        node_id = self.get_node_id(unit_name)
        if not node_id:
            return []
        nodes = self.request(
            "GET",
            f"/_nodes/{node_id}",
            retries=3,
            wait_strategy=wait_exponential(min=2),
            alt_hosts=alt_hosts,
        )
        return nodes["nodes"][node_id]["roles"]

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
        self, host: str, wait_for_green: bool, alt_hosts: list[str] | None = None
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
        except OpenSearchHttpError:
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

            for attempt in Retrying(
                retry=retry_if_exception_type(requests.RequestException)
                | retry_if_exception_type(urllib3.exceptions.HTTPError),
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
                    # TODO: Handle this when implementing the k8s version of start workflow.
                    request_kwargs = {
                        "method": method.upper(),
                        "url": url,
                        "verify": f"{self.workload.paths.certs}/chain.pem",
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
