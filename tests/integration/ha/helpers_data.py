#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions for data related tests, such as indexing, searching etc.."""

import base64
import json
import logging
from random import randint
from typing import Any, Dict, List, Optional

from pytest_operator.plugin import OpsTest
from tenacity import Retrying, retry, stop_after_attempt, wait_fixed, wait_random

from tests.helpers import Substrate
from tests.integration.conftest import CLIENT_CHARM
from tests.integration.helpers import (
    _find_k8s_unit_for_endpoint,
    _k8s_unit_fqdn,
    get_secrets,
    http_request,
    run_action,
)

logger = logging.getLogger(__name__)


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def create_dummy_indexes(
    ops_test: OpsTest, app: str, unit_ip: str, max_r_shards: int, count: int = 5
) -> None:
    """Create indexes."""
    for index_id in range(count):
        p_shards = index_id % 2 + 2
        r_shards = max_r_shards if p_shards == 2 else max_r_shards - 1
        logger.info(
            f"Creating: index_{index_id} -- number_of_shards: {p_shards} -- number_of_replicas: {r_shards}"
        )
        await http_request(
            ops_test,
            "PUT",
            f"https://{unit_ip}:9200/index_{index_id}",
            {
                "settings": {
                    "index": {
                        "number_of_shards": p_shards,
                        "number_of_replicas": r_shards,
                    }
                }
            },
            app=app,
        )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def update_dummy_indexes(
    ops_test: OpsTest, app: str, unit_ip: str, max_r_shards: int, count: int = 5
) -> None:
    """Update the replication factors of dummy indexes."""
    for index_id in range(count):
        p_shards = index_id % 2 + 2
        r_shards = max_r_shards if p_shards == 2 else max_r_shards - 1
        logger.info(
            f"Updating: index_{index_id} -- number_of_shards: {p_shards} -- number_of_replicas: {r_shards}"
        )

        await http_request(
            ops_test,
            "PUT",
            f"https://{unit_ip}:9200/index_{index_id}/_settings",
            {"index": {"number_of_replicas": r_shards}},
            app=app,
        )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def delete_dummy_indexes(ops_test: OpsTest, app: str, unit_ip: str, count: int = 5) -> None:
    """Delete dummy indexes."""
    for index_id in range(count):
        await http_request(
            ops_test,
            "DELETE",
            f"https://{unit_ip}:9200/index_{index_id}",
            app=app,
        )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def create_dummy_docs(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    count: int = 5,
    substrate: Substrate = "vm",
) -> None:
    """Store documents in the dummy indexes."""
    if substrate == "k8s":
        admin_secrets = await get_secrets(ops_test, app=app)
        k8s_unit = await _find_k8s_unit_for_endpoint(
            ops_test, f"https://{unit_ip}:9200/_bulk", app
        )
        if not k8s_unit:
            raise RuntimeError(
                f"Could not find k8s unit for {app} to create dummy docs through {CLIENT_CHARM} action"
            )
        logger.info(f"Creating dummy docs through {CLIENT_CHARM} action on unit {k8s_unit.name}")
        action = await run_action(
            ops_test,
            app=CLIENT_CHARM,
            action_name="create-dummy-docs",
            params={
                "count": count,
                "host": _k8s_unit_fqdn(ops_test, app, k8s_unit),
                "username": "admin",
                "password": admin_secrets["password"],
                "ca_cert": base64.b64encode(admin_secrets["ca-chain"].encode()).decode(),
            },
            unit_id=None,
        )
        if action.status != "completed":
            raise RuntimeError(f"Failed to create dummy docs through {CLIENT_CHARM} action")
        return

    all_docs = ""
    for index_id in range(count):
        for doc_id in range(count * 1000):
            all_docs = (
                f"{all_docs}"
                f'{{"create":{{"_index":"index_{index_id}", "_id":"{doc_id}"}}}}\n'
                f'{{"ProductId": "{1000 + doc_id}", '
                f'"Amount": "{randint(10, 1000)}", '
                f'"Quantity": "{randint(0, 50)}", '
                f'"Store_Id": "{randint(1, 250)}"}}\n'
            )

    await http_request(ops_test, "PUT", f"https://{unit_ip}:9200/_bulk", payload=all_docs, app=app)


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def create_index(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    index_name: str,
    p_shards: int = 1,
    r_shards: int = 1,
    extra_index_settings: Optional[Dict[str, Any]] = None,
    extra_mappings: Optional[Dict[str, Any]] = None,
) -> None:
    """Create an index with a set number of primary and replica shards.

    Optionally, add extra settings and mappings to the new index.
    """
    content = {
        "settings": {"index": {"number_of_shards": p_shards, "number_of_replicas": r_shards}}
    }
    if extra_index_settings:
        content["settings"]["index"] = {
            **content["settings"]["index"],
            **extra_index_settings,
        }
    if extra_mappings:
        content["mappings"] = extra_mappings
    await http_request(
        ops_test,
        "PUT",
        f"https://{unit_ip}:9200/{index_name}",
        content,
        app=app,
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def bulk_insert(ops_test: OpsTest, app: str, unit_ip: str, payload: str) -> None:
    """Insert a set of docs in a single bulk request."""
    await http_request(
        ops_test,
        "PUT",
        f"https://{unit_ip}:9200/_bulk",
        payload=payload,
        app=app,
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def bulk_insert_generated(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    index_names: list[str],
    docs_count: int,
    blob_size: int = 100,
) -> None:
    """Generate docs near OpenSearch and insert them through the bulk endpoint."""
    endpoint = f"https://{unit_ip}:9200/_bulk"
    k8s_unit = await _find_k8s_unit_for_endpoint(ops_test, endpoint, app)
    if k8s_unit:
        admin_secrets = await get_secrets(ops_test, app=app)
        logger.info(
            f"Creating generated bulk docs through {CLIENT_CHARM} action on unit {k8s_unit.name}"
        )
        action = await run_action(
            ops_test,
            app=CLIENT_CHARM,
            action_name="bulk-insert",
            params={
                "index-names": json.dumps(index_names),
                "docs-count": docs_count,
                "blob-size": blob_size,
                "host": _k8s_unit_fqdn(ops_test, app, k8s_unit),
                "username": "admin",
                "password": admin_secrets["password"],
                "ca_cert": base64.b64encode(admin_secrets["ca-chain"].encode()).decode(),
            },
            unit_id=None,
        )
        logger.debug(action)
        if action.status != "completed":
            raise RuntimeError(
                f"Failed to create generated bulk docs through {CLIENT_CHARM} action: "
                f"{action.response}"
            )

        status_code = int(action.response["status-code"])
        result = action.response.get("result", {})
        if status_code >= 300 or result.get("errors", "False") != "False":
            raise RuntimeError(f"Generated bulk insert failed with status {status_code}: {result}")
        return

    await http_request(
        ops_test,
        "PUT",
        endpoint,
        payload=_generated_bulk_body(index_names, docs_count, blob_size),
        app=app,
    )


def _generated_bulk_body(index_names: list[str], docs_count: int, blob_size: int) -> str:
    """Generate deterministic NDJSON for local bulk insertion."""
    blob = "A" * blob_size
    lines = []
    for index_name in index_names:
        for doc_id in range(docs_count):
            lines.append(json.dumps({"index": {"_index": index_name}}))
            lines.append(json.dumps({"x": doc_id, "blob": blob}))
    return "\n".join(lines) + "\n"


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def index_doc(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    index_name: str,
    doc_id: int,
    doc: Optional[Dict[str, Any]] = None,
    refresh: bool = True,
) -> None:
    """Index a simple document."""
    if not doc:
        doc = default_doc(index_name, doc_id)

    await http_request(
        ops_test,
        "PUT",
        f"https://{unit_ip}:9200/{index_name}/_doc/{doc_id}",
        payload=doc,
        app=app,
    )

    # a refresh makes the indexed data available for search, runs by default every 30 sec,
    # but we can manually trigger it like below
    if refresh:
        await http_request(
            ops_test, "POST", f"https://{unit_ip}:9200/{index_name}/_refresh", app=app
        )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def get_doc(
    ops_test: OpsTest, app: str, unit_ip: str, index_name: str, doc_id: int
) -> Dict[str, Any]:
    """Fetch a document by id."""
    return await http_request(
        ops_test, "GET", f"https://{unit_ip}:9200/{index_name}/_doc/{doc_id}", app=app
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def delete_doc(
    ops_test: OpsTest, app: str, unit_ip: str, index_name: str, doc_id: int
) -> None:
    """Delete a document by id."""
    await http_request(
        ops_test,
        "DELETE",
        f"https://{unit_ip}:9200/{index_name}/_doc/{doc_id}",
        app=app,
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def delete_index(ops_test: OpsTest, app: str, unit_ip: str, index_name: str) -> None:
    """Delete an index."""
    await http_request(
        ops_test,
        "DELETE",
        f"https://{unit_ip}:9200/{index_name}/",
        app=app,
    )


def default_doc(index_name: str, doc_id: int) -> Dict[str, Any]:
    """Return a default document used in the tests."""
    return {"title": f"title_{doc_id}", "val": doc_id, "path": f"{index_name}/{doc_id}"}


async def search(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    index_name: str,
    query: Optional[Dict[str, Any]] = None,
    preference: Optional[str] = None,
    retries: int = 15,
) -> Optional[List[Dict[str, Any]]]:
    """Search documents."""
    endpoint = f"https://{unit_ip}:9200/{index_name}/_search"
    if preference:
        endpoint = f"{endpoint}?preference={preference}"
    for attempt in Retrying(
        stop=stop_after_attempt(retries), wait=wait_fixed(wait=5) + wait_random(0, 5)
    ):
        with attempt:  # Raises RetryError if failed after "retries"
            resp = await http_request(ops_test, "GET", endpoint, payload=query, app=app)
            return resp["hits"]["hits"]


async def index_docs_count(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    index_name: str,
    retries: int = 15,
) -> int:
    """Returns the number of documents in an index."""
    endpoint = f"https://{unit_ip}:9200/{index_name}/"
    for attempt in Retrying(
        stop=stop_after_attempt(retries), wait=wait_fixed(wait=5) + wait_random(0, 5)
    ):
        with attempt:  # Raises RetryError if failed after "retries"
            # We need to refresh and then count the docs
            resp = await http_request(ops_test, "POST", endpoint + "_refresh", app=app)
            logger.debug(f"Index refresh response: {resp}")

            resp = await http_request(ops_test, "GET", endpoint + "_count", app=app)
            logger.debug(f"Index count response: {resp['count']}")
            if isinstance(resp["count"], int):
                return resp["count"]
            return int(resp["count"])
