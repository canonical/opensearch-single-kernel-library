#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions related to testing the different plugins."""

import base64
import json
import logging
import random
from typing import Any, Callable, Dict, List, Optional

from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    TryAgain,
    retry,
    stop_after_attempt,
    stop_after_delay,
    wait_fixed,
    wait_random,
)

from tests.helpers import Substrate
from tests.integration.conftest import CLIENT_CHARM

from ..ha.helpers_data import bulk_insert, create_index
from ..helpers import (
    _find_k8s_unit_for_endpoint,
    _k8s_unit_fqdn,
    get_secrets,
    http_request,
    run_action,
)

logger = logging.getLogger(__name__)


async def k8s_generate_bulk_training_data(
    ops_test: OpsTest,
    index_name: str,
    vector_name: str,
    docs_count: int = 100,
    dimensions: int = 4,
    has_result: bool = True,
    unit_ip: str = "",
    app: str = "",
) -> list[float]:
    admin_secrets = await get_secrets(ops_test, app=app)
    k8s_unit = await _find_k8s_unit_for_endpoint(ops_test, f"https://{unit_ip}:9200/_bulk", app)
    if not k8s_unit:
        raise RuntimeError(
            f"Could not find k8s unit for {app} to create dummy docs through {CLIENT_CHARM} action"
        )
    logger.info(f"Creating dummy docs through {CLIENT_CHARM} action on unit {k8s_unit.name}")
    action = await run_action(
        ops_test,
        app=CLIENT_CHARM,
        action_name="generate-bulk-training-data",
        params={
            "index-name": index_name,
            "vector-name": vector_name,
            "docs-count": docs_count,
            "dimensions": dimensions,
            "has-result": has_result,
            "host": _k8s_unit_fqdn(ops_test, app, k8s_unit),
            "username": "admin",
            "password": admin_secrets["password"],
            "ca_cert": base64.b64encode(admin_secrets["ca-chain"].encode()).decode(),
        },
        unit_id=None,
    )
    if action.status != "completed":
        raise RuntimeError(f"Failed to create dummy docs through {CLIENT_CHARM} action")
    result = action.response.get("result", {})
    vector = json.loads(action.response.get("vector", "[]"))
    logger.info("Dummy docs created with result: %s", result)
    return vector


def generate_bulk_training_data(
    index_name: str,
    vector_name: str,
    docs_count: int = 100,
    dimensions: int = 4,
    has_result: bool = False,
) -> tuple[str, list[list[float]]]:
    random.seed("seed")
    print("The seed for randomness is: 'seed'")

    data = random.randbytes(docs_count * dimensions)
    if has_result:
        responses = random.randbytes(docs_count)
    result = ""
    result_list: list[list[float]] = []
    for i in range(docs_count):
        result += json.dumps({"index": {"_index": index_name, "_id": i}}) + "\n"
        result_list.append([float(data[j]) for j in range(i * dimensions, (i + 1) * dimensions)])
        inter = {vector_name: result_list[i]}
        if has_result:
            inter["price"] = float(responses[i])
        result += json.dumps(inter) + "\n"
    return result, result_list


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def run_knn_training(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    model_name: str,
    payload: Dict[str, Any],
) -> Optional[List[Dict[str, Any]]]:
    """Sets models."""
    endpoint = f"https://{unit_ip}:9200/_plugins/_knn/models/{model_name}/_train"
    return await http_request(ops_test, "POST", endpoint, payload=payload, app=app)


async def is_knn_training_complete(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    model_name: str,
) -> bool:
    """Waits training models."""
    endpoint = f"https://{unit_ip}:9200/_plugins/_knn/models/{model_name}"
    try:
        for attempt in Retrying(stop=stop_after_attempt(15), wait=wait_fixed(wait=5)):
            with attempt:
                resp = await http_request(ops_test, "GET", endpoint, app=app)
                if "created" not in resp.get("state", ""):
                    raise Exception
                return True
    except RetryError:
        return False


async def create_index_and_bulk_insert(
    ops_test: OpsTest,
    app: str,
    endpoint: str,
    index_name: str,
    shards: int,
    vector_name: str,
    model_name: str | None = None,
    substrate: Substrate = "vm",
) -> list[float]:
    if model_name:
        extra_mappings = {
            "properties": {
                vector_name: {
                    "type": "knn_vector",
                    "model_id": model_name,
                }
            }
        }
        extra_index_settings = {"knn": "true"}
    else:
        extra_mappings = {
            "properties": {
                vector_name: {
                    "type": "knn_vector",
                    "dimension": 4,
                }
            }
        }
        extra_index_settings = {}

    await create_index(
        ops_test,
        app,
        endpoint,
        index_name,
        r_shards=shards,
        extra_index_settings=extra_index_settings,
        extra_mappings=extra_mappings,
    )
    if substrate == "k8s":
        vector = await k8s_generate_bulk_training_data(
            ops_test=ops_test,
            index_name=index_name,
            vector_name=vector_name,
            docs_count=1000,
            dimensions=4,
            has_result=True,
            unit_ip=endpoint,
            app=app,
        )
        return vector

    payload, payload_list = generate_bulk_training_data(
        index_name, vector_name, docs_count=1000, dimensions=4, has_result=True
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, endpoint, payload)
    return payload_list[0]


def bulk_encode(docs: List[Dict[str, Any]], index_name: str) -> str:
    """Helper method to encode docs for bulk insert"""
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index_name}}))
        lines.append(json.dumps(doc))

    return "\n".join(lines) + "\n"


async def poll_until(
    ops_test: OpsTest,
    endpoint: str,
    condition: Callable,
    timeout: int = 60,
    interval: int = 5,
) -> bool:
    """Poll endpoint until condition is true or timeout"""
    logger.info(f"Polling {endpoint}...")
    try:
        for attempt in Retrying(
            stop=stop_after_delay(timeout), wait=wait_fixed(wait=interval), reraise=True
        ):
            with attempt:
                response = await http_request(ops_test, "GET", endpoint)
                if condition(response):
                    logger.info(f"Done. Condition met: {response}")
                    return True
                logger.info(f"Condition not met: {response}")
                raise TryAgain
    except (RetryError, TryAgain):
        logger.info("Polling timed out")
        return False
