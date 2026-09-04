#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import socket
from typing import Optional

import yaml
from pytest_operator.plugin import OpsTest
from tenacity import (
    AsyncRetrying,
    RetryError,
    retry,
    stop_after_attempt,
    stop_after_delay,
    wait_fixed,
)

from tests.integration.helpers import run_action


async def _get_show_unit_relation_info(
    ops_test: OpsTest,
    unit_name: str,
    relation_name: str,
    relation_id: str = None,
) -> list:
    """Helper to fetch and filter relation info from juju show-unit."""
    raw_data = (await ops_test.juju("show-unit", unit_name))[1]
    if not raw_data:
        raise ValueError(f"no unit info could be grabbed for {unit_name}")
    data = yaml.safe_load(raw_data)
    # Filter the data based on the relation name.
    relation_data = [
        v for v in data[unit_name].get("relation-info", []) if v["endpoint"] == relation_name
    ]

    if relation_id:
        # Filter the data based on the relation id.
        relation_data = [v for v in relation_data if str(v["relation-id"]) == str(relation_id)]
    if not relation_data:
        raise ValueError(
            f"no relation data could be grabbed on relation with endpoint {relation_name}"
        )
    return relation_data


async def get_application_relation_data(
    ops_test: OpsTest,
    unit_name: str,
    relation_name: str,
    key: str,
    relation_id: str = None,
) -> Optional[str]:
    """Get relation data for an application."""
    relation_data = await _get_show_unit_relation_info(
        ops_test, unit_name, relation_name, relation_id
    )
    return relation_data[0].get("application-data", {}).get(key)


async def get_secret_uri_from_relation(
    ops_test: OpsTest,
    app_unit: str,
    relation_name: str,
    is_v0: bool = True,
) -> str:
    """Return the secret-user URI from either a v0 or v1 relation databag."""
    if not is_v0:
        requests_str = await get_application_relation_data(
            ops_test, app_unit, relation_name, "requests"
        )
        data = json.loads(requests_str)
        first_response = data[0]
        return first_response["secret-user"]
    return await get_application_relation_data(ops_test, app_unit, relation_name, "secret-user")


async def get_endpoints_from_relation(
    ops_test: OpsTest,
    app_unit: str,
    relation_name: str,
    is_v0: bool = True,
) -> str:
    """Return the endpoints string from either a v0 or v1 relation databag."""
    if not is_v0:
        requests_str = await get_application_relation_data(
            ops_test, app_unit, relation_name, "requests"
        )
        data = json.loads(requests_str)
        first_response = data[0]
        return first_response["endpoints"]
    return await get_application_relation_data(ops_test, app_unit, relation_name, "endpoints")


async def get_version_from_relation(
    ops_test: OpsTest,
    app_unit: str,
    relation_name: str,
    is_v0: bool = True,
) -> str:
    """Return the version string from either a v0 or v1 relation databag."""
    if not is_v0:
        requests_str = await get_application_relation_data(
            ops_test, app_unit, relation_name, "requests"
        )
        data = json.loads(requests_str)
        first_response = data[0]
        return first_response["version"]
    return await get_application_relation_data(ops_test, app_unit, relation_name, "version")


async def get_secret_data(ops_test: OpsTest, secret_uri: str) -> dict:
    """Retrieve secret data using juju show-secret."""
    secret_unique_id = secret_uri.split("/")[-1]
    complete_command = f"show-secret {secret_uri} --reveal --format=json"
    _, stdout, _ = await ops_test.juju(*complete_command.split())
    return json.loads(stdout)[secret_unique_id]["content"]["Data"]


async def wait_for_relation_joined_between(
    ops_test: OpsTest, endpoint_one: str, endpoint_two: str
) -> None:
    """Wait for relation to be created before checking if it's waiting or idle.

    Args:
        ops_test: running OpsTest instance
        endpoint_one: one endpoint of the relation, as "application[:endpoint]".
        endpoint_two: the other endpoint of the relation, as "application[:endpoint]".
    """
    try:
        async for attempt in AsyncRetrying(stop=stop_after_delay(3 * 60), wait=wait_fixed(3)):
            with attempt:
                assert new_relation_joined(ops_test, endpoint_one, endpoint_two)
    except RetryError:
        assert False, "New relation failed to join after 3 minutes."


def new_relation_joined(ops_test: OpsTest, endpoint_one: str, endpoint_two: str) -> bool:
    """Check if a relation matching both endpoint specs exists in the model.

    Specs are matched against both the application name and the endpoint name, so
    relations of different applications reusing the same endpoint name (e.g. two
    deployments of the same client charm) are told apart.
    """
    for rel in ops_test.model.relations:
        if rel.matches(endpoint_one, endpoint_two):
            return True
    return False


async def wait_for_relation_removed_between(
    ops_test: OpsTest, endpoint_one: str, endpoint_two: str
) -> None:
    """Wait for a relation to be fully removed before re-adding it.

    Juju keeps a removed relation in a "dying" state for a while; re-adding the
    relation during that window fails with "relation ... is dying, but not yet
    removed".

    Args:
        ops_test: running OpsTest instance
        endpoint_one: one endpoint of the relation, as "application[:endpoint]".
        endpoint_two: the other endpoint of the relation, as "application[:endpoint]".
    """
    try:
        async for attempt in AsyncRetrying(stop=stop_after_delay(3 * 60), wait=wait_fixed(3)):
            with attempt:
                assert not new_relation_joined(ops_test, endpoint_one, endpoint_two)
    except RetryError:
        assert False, "Relation failed to be removed after 3 minutes."


@retry(wait=wait_fixed(wait=15), stop=stop_after_attempt(15))
async def run_request(
    ops_test,
    unit_name: str,
    relation_name: str,
    relation_id: int,
    method: str,
    endpoint: str,
    payload: str = None,
):
    # python can't have variable names with a hyphen, and Juju can't have action variables with an
    # underscore, so this is a compromise.
    params = {
        "relation-id": relation_id,
        "relation-name": relation_name,
        "method": method,
        "endpoint": endpoint,
    }
    if payload:
        params["payload"] = payload
    result = await run_action(
        ops_test,
        unit_id=int(unit_name.split("/")[-1]),
        action_name="run-request",
        params=params,
        app="/".join(unit_name.split("/")[:-1]),
    )
    logging.info(f"request results: {result}")

    if result.status != "completed":
        raise Exception(result.response)

    return result.response


def ip_to_url(ip_str: str) -> str:
    """Return a version of an IPV4 or IPV6 address that's fit for a URL."""
    try:
        # Check if it's an IPV4 address
        socket.inet_aton(ip_str)
        return ip_str
    except socket.error:
        return f"[{ip_str}]"
