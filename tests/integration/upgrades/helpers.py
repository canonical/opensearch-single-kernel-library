#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import re
import subprocess
import time
from typing import Optional

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_attempt, wait_fixed

from opensearch_single_kernel.common.constants import UPGRADE_RELATION
from opensearch_single_kernel.common.statuses import GeneralStatuses, LockStatuses
from tests.integration.conftest import CONFIG_OPTS
from tests.integration.models import Unit

from ..helpers import (
    EmptyBlockedStatus,
    cluster_health,
    get_application_units,
    get_unit_relation_data,
    http_request,
    run_action,
    wait_until,
    wait_until_async_condition_on_units,
    wait_until_condition_on_units,
)

OPENSEARCH_CHARM = "opensearch"
OPENSEARCH_CHANNEL = "2/edge"
PROFILES_REVISION = 185

TIMEOUT = 2400
IDLE_PERIOD = 30
FAST_INTERVAL = "60s"

VM_VERSION_N = "2.19.4"
VM_VERSION_N_MINUS_1 = "2.18.0"
VM_VERSION_N_MINUS_2 = "2.17.0"

VM_VERSION_TO_REVISION = {
    VM_VERSION_N_MINUS_2: {"jammy": 168, "noble": 206},
    VM_VERSION_N_MINUS_1: {"jammy": 209, "noble": 208},
}

K8S_VERSION_N = "2.19.5"
K8S_VERSION_N_MINUS_1 = "2.19.4"
K8S_VERSION_TO_RESOURCE = {
    K8S_VERSION_N_MINUS_1: {"opensearch-image": "ghcr.io/canonical/opensearch:2.19.4-24.04_edge"}
}

FROM_VERSION_PREFIX = "from_v{}_to_local"

UPGRADE_PARAMS = [
    pytest.param(
        version,
        id=FROM_VERSION_PREFIX.format(version),
        marks=pytest.mark.group(
            id="two_version_upgrade" if version == VM_VERSION_N_MINUS_2 else "one_version_upgrade"
        ),
    )
    for version in VM_VERSION_TO_REVISION.keys()
]

logger = logging.getLogger(__name__)


def testing_config_if_supported(revision: int) -> dict[str, str]:
    """Returns 'testing' profile config if given revision supports profiles"""
    return CONFIG_OPTS if revision >= PROFILES_REVISION else {}


def refresh(
    ops_test: OpsTest,
    app_name: str,
    *,
    revision: Optional[int] = None,
    switch: Optional[str] = None,
    channel: Optional[str] = None,
    path: Optional[str] = None,
    config: Optional[dict[str, str]] = None,
    resources: Optional[dict[str, str]] = None,
) -> None:
    # due to: https://github.com/juju/python-libjuju/issues/1057
    # the following call does not work:
    # application = ops_test.model.applications[APP_NAME]
    # await application.refresh(
    #     revision=rev,
    # )

    # Point to the right model, as we are calling the juju cli directly
    args = [f"--model={ops_test.model.info.name}"]
    if revision:
        args.append(f"--revision={revision}")
    if switch:
        args.append(f"--switch={switch}")
    if channel:
        args.append(f"--channel={channel}")
    if path:
        args.append(f"--path={path}")
    if resources:
        for resource_name, resource_path in resources.items():
            args.extend(["--resource", f"{resource_name}={resource_path}"])
    if config:
        for key, val in config.items():
            args.extend(["--config", f"{key}={val}"])

    for attempt in Retrying(stop=stop_after_attempt(6), wait=wait_fixed(wait=30)):
        with attempt:
            cmd = ["juju", "refresh"]
            cmd.append(app_name)
            cmd.extend(args)
            subprocess.check_output(cmd)


def get_version_on_unit(unit: str, model: str, substrate):
    """Returns version of OpenSearch running on given unit"""
    if substrate == "k8s":
        cmd = f"juju ssh --model {model} --container opensearch {unit} '$OPENSEARCH_BIN/opensearch --version'"
        output = subprocess.check_output(cmd, shell=True, text=True).strip()
    else:
        # opensearch.opensearch-bin not exposed in older snap revisions
        cmd = [
            "juju",
            "exec",
            "--model",
            model,
            "--unit",
            unit,
            "--",
            "sudo",
            "snap",
            "run",
            "--shell",
            "opensearch.daemon",
            "-c",
            "$OPENSEARCH_BIN/opensearch --version",
        ]
        output = subprocess.check_output(cmd, text=True)
    match = re.search(r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)", output)
    return match.group(1) if match else None


async def assert_version_units(ops_test: OpsTest, app: str, expected_version: str, substrate):
    """Ensures all units in given app are running expected OpenSearch version"""
    logger.info("Ensuring units in '%s' running version %s", app, expected_version)

    units = [f"{app}/{unit.id}" for unit in await get_application_units(ops_test, app)]
    versions = [get_version_on_unit(unit, ops_test.model.info.name, substrate) for unit in units]
    assert all(
        version == expected_version for version in versions
    ), f"Expected {expected_version} on all units, found versions: {list(zip(units, versions))}"
    logger.info("All units in '%s' running version %s", app, expected_version)


async def assert_upgrade_to_revision(
    ops_test: OpsTest,
    app: str,
    revision: int,
    config: dict[str, str] = {},
):
    """Upgrades app to revision"""
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    # run pre-upgrade-check action on leader
    action = await run_action(ops_test, leader_id, "pre-upgrade-check", app=app)
    logger.info("pre-upgrade-check: %s", action)
    assert action.status == "completed"

    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info("Refreshing '%s' to revision %s", app, revision)
        refresh(
            ops_test,
            app,
            revision=revision,
            config=testing_config_if_supported(revision) | config,
        )

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses={app: [EmptyBlockedStatus]},
            wait_for_exact_units={
                app: len(units),
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        # run resume-upgrade action on leader
        action = await run_action(ops_test, leader_id, "resume-upgrade", app=app)
        logger.info("resume-upgrade: %s", action)
        assert action.status == "completed"

        await wait_until(
            ops_test,
            apps=[app],
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info("Upgrade of '%s' completed", app)


async def wait_until_upgrade_state_healthy(ops_test: OpsTest, app: str):
    """Waits until the given unit is healthy after an upgrade"""

    async def is_highest_order_unit_healthy(units: list[Unit]) -> bool:
        highest_unit = sorted(units, key=lambda u: u.id)[-1]
        logger.info("Waiting for unit '%s' to be healthy...", highest_unit.name)
        # Check relation data
        relation_data = await get_unit_relation_data(
            ops_test,
            unit_name=highest_unit.short_name.replace("-", "/"),
            target_unit_name=highest_unit.short_name.replace("-", "/"),
            relation_name=UPGRADE_RELATION,
            local_unit=True,
            key="state",
        )
        return relation_data == "healthy"

    await wait_until_async_condition_on_units(
        ops_test,
        app=app,
        condition=is_highest_order_unit_healthy,
        timeout=TIMEOUT,
    )


async def assert_upgrade_to_local(
    ops_test: OpsTest,
    app: str,
    charm: str,
    substrate: str,
    charm_resources: dict[str, str] | None = None,
    config: dict[str, str] = {},
):
    """Upgrades to local charm"""
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    # run pre-upgrade-check action on leader
    action_name = "pre-upgrade-check" if substrate == "vm" else "pre-refresh-check"
    for attempt in Retrying(stop=stop_after_attempt(6), wait=wait_fixed(wait=30)):
        with attempt:
            action = await run_action(ops_test, leader_id, action_name, app=app)
            logger.info("%s: %s", action_name, action)
            if action.status != "completed":
                raise Exception(f"Action {action_name} failed with status: {action.status}")

            assert action.status == "completed"

    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info("Refreshing '%s' local charm", app)
        if substrate == "k8s":
            refresh(
                ops_test, app, path=charm, config=CONFIG_OPTS | config, resources=charm_resources
            )
        else:
            refresh(ops_test, app, path=charm, config=CONFIG_OPTS | config)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses={app: [EmptyBlockedStatus]},
            wait_for_exact_units={
                app: len(units),
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        await wait_until_upgrade_state_healthy(ops_test, app)
        # run resume-upgrade action on leader
        action_name = "resume-upgrade" if substrate == "vm" else "resume-refresh"
        for attempt in Retrying(stop=stop_after_attempt(6), wait=wait_fixed(wait=30)):
            with attempt:
                action = await run_action(ops_test, leader_id, action_name, app=app)
                logger.info("%s: %s", action_name, action)
                # if the cluster is not healthy, the action may fail, so we retry
                if (
                    action.status == "failed"
                    and action.message
                    and "unhealthy" in action.message.lower()
                ):
                    raise Exception(f"Action {action_name} failed due to unhealthy cluster")

                # If leader is second unit to upgrade, the task would be terminated
                # Since unit will restart
                second_unit = sorted(units, key=lambda u: u.id, reverse=True)[1]
                if substrate == "k8s" and second_unit.id == leader_id:
                    logger.info(
                        "Unit '%s' is leader, action may be terminated due to unit restart."
                        " Skipping status check.",
                        second_unit,
                    )
                else:
                    assert action.status == "completed"

        await wait_until(
            ops_test,
            apps=[app],
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info("Upgrade of '%s' completed", app)


async def assert_rollback_to_revision(
    ops_test: OpsTest,
    app: str,
    charm: str,
    revision: int,
    config: dict[str, str] = {},
):
    """Upgrades to local charm and rolls back to revision mid-upgrade"""
    units = await get_application_units(ops_test, app)
    highest_unit_id = sorted([unit.id for unit in units])[-1]
    leader_id = [unit.id for unit in units if unit.is_leader][0]
    leader_ip = [unit.ip for unit in units if unit.id == leader_id][0]
    nodes = await http_request(
        ops_test,
        "GET",
        f"https://{leader_ip}:9200/_cat/nodes?format=json",
    )
    cluster_size = len(nodes)

    # run pre-upgrade-check action on leader
    action = await run_action(ops_test, leader_id, "pre-upgrade-check", app=app)
    logger.info("pre-upgrade-check: %s", action)
    assert action.status == "completed"

    n_units = len(units)
    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info("Refreshing '%s' to local charm", app)
        refresh(ops_test, app, path=charm, config=CONFIG_OPTS | config)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses={app: [EmptyBlockedStatus]},
            wait_for_exact_units={
                app: n_units,
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        # switch to store charm
        refresh(
            ops_test,
            app,
            switch=OPENSEARCH_CHARM,
            channel=OPENSEARCH_CHANNEL,
            config=CONFIG_OPTS | config,
        )

        time.sleep(5)
        # roll back to revision
        logger.info("Rolling back '%s' to revision: %s", app, revision)
        refresh(
            ops_test,
            app,
            revision=revision,
            config=testing_config_if_supported(revision) | config,
        )

        logger.info("Waiting for rolled back unit to attempt restart...")

        await wait_until_condition_on_units(
            ops_test,
            app=app,
            condition=lambda units: any(
                GeneralStatuses.WAITING_TO_START.value.message
                in (unit.workload_status.message or "")
                or unit.workload_status.value
                == "error"  # the unit may be in an error state on rollback
                for unit in units
                if unit.id == highest_unit_id
            ),
            timeout=300,
        )

        await recover_from_rollback(ops_test, app, expected_cluster_size=cluster_size)

        await wait_until(
            ops_test,
            apps=[app],
            wait_for_exact_units={
                app: n_units,
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info("Recovery from rollback of '%s' completed", app)


async def recover_from_rollback(ops_test: OpsTest, app: str, expected_cluster_size: int):
    """Recover from refreshing back mid-upgrade"""
    units = await get_application_units(ops_test, app)
    rolled_back_unit_id = sorted([unit.id for unit in units])[-1]
    # make calls to any unit which is not the rolled back unit
    unit_ip = [unit.ip for unit in units if unit.id != rolled_back_unit_id][0]
    rolled_back_node = [unit.name for unit in units if unit.id == rolled_back_unit_id][0]

    # re-enable allocation
    logger.info("Re-enabling cluster routing allocation")
    await http_request(
        ops_test,
        "PUT",
        f"https://{unit_ip}:9200/_cluster/settings",
        payload={"persistent": {"cluster.routing.allocation.enable": "all"}},
    )

    time.sleep(5)

    # get health
    cluster_health_resp = await cluster_health(ops_test, unit_ip)
    logger.info("Cluster health response: %s", cluster_health_resp["status"])
    if cluster_health_resp["status"] == "red":
        # identify problematic index
        shards = await http_request(
            ops_test,
            "GET",
            f"https://{unit_ip}:9200/_cat/shards?format=json&h=index,shard,state,unassigned.reason",
        )

        indices = set()
        for shard in shards:
            if (
                shard.get("state") == "UNASSIGNED"
                and shard.get("unassigned.reason") == "NODE_LEFT"
            ):
                indices.add(shard.get("index"))

        # delete the indices
        logger.info("Unassigned indices: %s", indices)
        for index in indices:
            await http_request(
                ops_test,
                "DELETE",
                f"https://{unit_ip}:9200/{index}",
            )

        cluster_health_resp = await cluster_health(ops_test, unit_ip)
        logger.info(
            "Cluster health response after removing indices: %s", cluster_health_resp["status"]
        )
    # add unit
    logger.info("Adding new unit")
    await ops_test.model.applications[app].add_unit(count=1)

    # destroy rolled back unit
    logger.info("Destroying unit '%s/%s'", app, rolled_back_unit_id)
    await ops_test.model.destroy_unit(
        f"{app}/{rolled_back_unit_id}", destroy_storage=True, force=True
    )
    await ops_test.model.block_until(
        lambda: len(ops_test.model.applications[app].units) == len(units), timeout=300
    )

    remaining_units = await get_application_units(ops_test, app)
    new_unit_id = sorted([unit.id for unit in remaining_units])[-1]
    logger.info("Waiting for new unit '%s/%s'...", app, new_unit_id)
    await wait_until_condition_on_units(
        ops_test,
        app=app,
        condition=lambda units: any(
            LockStatuses.REQUEST_LOCK_ON_START.value.message
            in (unit.workload_status.message or "")  # unit may be stuck waiting for lock
            or unit.agent_status.value == "idle"
            for unit in units
            if unit.id == new_unit_id
        ),
        timeout=TIMEOUT,
    )

    # check if lock with departed unit
    logger.info("Rolled back OpenSearch node: %s", rolled_back_node)
    lock_doc = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/.charm_node_lock/_doc/0",
    )
    if node_with_lock := lock_doc.get("_source", {}).get("unit-name"):
        logger.info("Unit with lock: %s", node_with_lock)

        if node_with_lock == rolled_back_node:
            logger.info("Deleting lock document")
            await http_request(
                ops_test,
                "DELETE",
                f"https://{unit_ip}:9200/.charm_node_lock/_doc/0?refresh=true",
            )

    await wait_until(
        ops_test,
        apps=[app],
        wait_for_exact_units=len(remaining_units),
        timeout=TIMEOUT,
        idle_period=IDLE_PERIOD,
    )

    # verify node joined cluster
    nodes = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/nodes?format=json",
    )
    node_names = [node["name"] for node in nodes]
    logger.info("Nodes in cluster: %s", ", ".join(node_names))

    new_node_name = [unit.name for unit in remaining_units if unit.id == new_unit_id][0]
    assert new_node_name in node_names, f"Replacement node '{new_node_name}' not found in cluster."
    assert (
        len(nodes) == expected_cluster_size
    ), f"Expected cluster size of {expected_cluster_size} but found {len(nodes)}"
