#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
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


async def get_application_relation_data(
    ops_test: OpsTest,
    unit_name: str,
    relation_name: str,
    key: str,
    relation_id: str = None,
) -> Optional[str]:
    """Get relation data for an application.

    Args:
        ops_test: The ops test framework instance
        unit_name: The name of the unit
        relation_name: name of the relation to get connection data from
        key: key of data to be retrieved
        relation_id: id of the relation to get connection data from

    Returns:
        the data that was requested or None
            if no data in the relation

    Raises:
        ValueError if it's not possible to get application unit data
            or if there is no data for the particular relation endpoint
            and/or alias.
    """
    raw_data = (await ops_test.juju("show-unit", unit_name))[1]
    if not raw_data:
        raise ValueError(f"no unit info could be grabbed for {unit_name}")
    data = yaml.safe_load(raw_data)
    # Filter the data based on the relation name.
    relation_data = [v for v in data[unit_name]["relation-info"] if v["endpoint"] == relation_name]
    if relation_id:
        # Filter the data based on the relation id.
        relation_data = [v for v in relation_data if v["relation-id"] == relation_id]
    if not relation_data:
        raise ValueError(
            f"no relation data could be grabbed on relation with endpoint {relation_name}"
        )
    return relation_data[0]["application-data"].get(key)


async def get_unit_relation_data(
    ops_test: OpsTest,
    unit_name: str,
    target_unit_name: str,
    relation_name: str,
    key: str,
    relation_id: str = None,
) -> Optional[str]:
    """Get relation data for an application.

    Args:
        ops_test: The ops test framework instance
        unit_name: The name of the unit
        relation_name: name of the relation to get connection data from
        key: key of data to be retrieved
        relation_id: id of the relation to get connection data from

    Returns:
        the data that was requested or None
            if no data in the relation

    Raises:
        ValueError if it's not possible to get application unit data
            or if there is no data for the particular relation endpoint
            and/or alias.
    """
    raw_data = (await ops_test.juju("show-unit", unit_name))[1]
    if not raw_data:
        raise ValueError(f"no unit info could be grabbed for {unit_name}")
    data = yaml.safe_load(raw_data)
    # Filter the data based on the relation name.
    relation_data = [v for v in data[unit_name]["relation-info"] if v["endpoint"] == relation_name]
    if relation_id:
        # Filter the data based on the relation id.
        relation_data = [v for v in relation_data if v["relation-id"] == relation_id]
    if not relation_data:
        raise ValueError(
            f"no relation data could be grabbed on relation with endpoint {relation_name}"
        )
    # Consider the case we are dealing with subordinate charms, e.g. grafana-agent
    # The field "relation-units" is structured slightly different.
    for idx in range(len(relation_data)):
        if target_unit_name in relation_data[idx]["related-units"]:
            break
    else:
        return {}
    return (
        relation_data[idx]["related-units"].get(target_unit_name, {}).get("data", {}).get(key, {})
    )


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
