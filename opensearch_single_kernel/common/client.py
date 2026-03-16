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
from charmlibs import pathops
from ops.pebble import ConnectionError as PebbleConnectionError
from tenacity import (
    RetryCallState,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_fixed,
)
from tenacity.wait import WaitBaseT

from opensearch_single_kernel.common.exceptions import (
    OpenSearchFileOperationError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.core.models import App, Node
from opensearch_single_kernel.utils.helpers import path_as_posix
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

    def _get_chain_pem_path(self) -> str | bool:  # noqa: C901
        """Get the path to chain.pem file for certificate verification.

        For both VM and K8s, requests runs in the charm container, so we stage a copy of the
        CA chain into the charm container filesystem.

        TODO: Stop relying on a workload-side chain.pem file.
        # Instead, retrieve the CA chain directly from Juju secrets
        # and pass it to requests without persisting it on disk.

        Returns:
            str | bool: Path to chain.pem file accessible from the charm container, or
            False / raises when the CA chain is not available yet.
        """
        staged_dir = pathops.LocalPath("/tmp") / "opensearch-certs"
        staged_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        staged_path = staged_dir / "chain.pem"

        chain_path = self.workload.paths.certs / "chain.pem"
        chain_path_str = path_as_posix(chain_path)

        if self.workload.workload_present:
            try:
                if chain_path.exists():
                    chain_content = self.workload.read_text(chain_path)
                    if isinstance(chain_content, str) and "BEGIN CERTIFICATE" in chain_content:
                        staged_path.write_text(chain_content)
                        staged_path.chmod(0o644)
                        return path_as_posix(staged_path)
            except (PebbleConnectionError, OpenSearchFileOperationError) as e:
                logger.warning(
                    "Failed to read chain.pem from %s (%s); falling back to staged copy if present",
                    chain_path_str,
                    e,
                )

        # workload not ready/unreachable or chain.pem missing, fall back to last staged copy.
        if staged_path.exists():
            try:
                cached = staged_path.read_text()
            except OSError:
                cached = ""
            if "BEGIN CERTIFICATE" in cached:
                return path_as_posix(staged_path)

        # wait until workload becomes available again.
        if not self.workload.workload_present:
            raise OpenSearchHttpError(
                response_text="Workload not ready and no staged chain.pem available yet"
            )

        return False

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

    def get_roles(self, unit_name: str, alt_hosts: list[str] | None) -> list[str]:
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
            logger.error(f"Error reloading TLS certificates via API: {e}")
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
        except OpenSearchHttpError as e:
            logger.debug("HTTP error when checking cluster health, returning None. Error: %s", e)
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
            logger.debug(f"Error when checking if host {host} is up: {e}")
            return False

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

                    # For K8s, chain.pem is in workload container
                    # but requests runs in charm container
                    # We need to get the file path that charm container can access.
                    verify_path = self._get_chain_pem_path()
                    request_kwargs = {
                        "method": method.upper(),
                        "url": url,
                        "verify": verify_path,
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
                f"Request {method} to {url} with payload: {payload} failed."
                f"(Attempts left: {retry_max - retry_state.attempt_number})\n"
                f"\tError: {retry_state.outcome.exception()}"
            )

        return log_error

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
