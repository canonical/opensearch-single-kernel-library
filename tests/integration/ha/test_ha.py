#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time

import jubilant
import pytest

from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
)
from tests.integration.ha.conftest import (
    ORIGINAL_RESTART_DELAY,
    RESTART_DELAY,
)
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    all_processes_down,
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
    get_elected_cm_unit_id,
    get_shards_by_index,
    send_kill_signal_to_process,
    update_restart_delay,
)
from tests.integration.ha.helpers_data import (
    create_index,
    default_doc,
    delete_index,
    index_doc,
    search,
)
from tests.integration.ha.k8s_helpers.helpers import (
    k8s_all_processes_down,
    pebble_patch_restart_delay,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    _series_to_base,
    app_name,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_ids,
    get_application_unit_ids_ips,
    get_application_unit_names,
    get_leader_unit_ip,
    get_reachable_unit_ips,
    is_up,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


NUM_HA_UNITS = 3


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    juju: jubilant.Juju, charm, series, substrate, charm_resources
) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(juju):
        return

    juju.model_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    os_deploy_kwargs = {
        "app": APP_NAME,
        "num_units": NUM_HA_UNITS,
        "config": CONFIG_OPTS,
    }
    if substrate != "k8s":
        os_deploy_kwargs["base"] = _series_to_base(series)
    if substrate == "k8s":
        os_deploy_kwargs["resources"] = charm_resources
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    juju.deploy(charm, **os_deploy_kwargs)

    # Relate it to OpenSearch to set up TLS.
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        juju,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        wait_for_exact_units={
            TLS_CERTIFICATES_APP_NAME: 1,
            APP_NAME: NUM_HA_UNITS,
        },
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(juju.status().apps[APP_NAME].units) == NUM_HA_UNITS


@pytest.mark.abort_on_fail
async def test_replication_across_members(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check consistency, ie write to node, read data from remaining nodes.

    1. Create index with replica shards equal to number of nodes - 1.
    2. Index data.
    3. Query data from all the nodes (all the nodes should contain a copy of the data).
    """
    app = (await app_name(juju)) or APP_NAME

    units = await get_application_unit_ids_ips(juju, app=app)
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_index"
    await create_index(juju, app, leader_unit_ip, index_name, r_shards=len(units) - 1)

    # index document
    doc_id = 12
    await index_doc(juju, app, leader_unit_ip, index_name, doc_id)

    # check that the doc can be retrieved from any node
    for u_ip in units.values():
        docs = await search(
            juju,
            app,
            u_ip,
            index_name,
            query={"query": {"term": {"_id": doc_id}}},
            preference="_only_local",
        )
        assert len(docs) == 1
        assert docs[0]["_source"] == default_doc(index_name, doc_id)

    await delete_index(juju, app, leader_unit_ip, index_name)

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_kill_db_process_node_with_primary_shard(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_balanced_writes_runner, substrate
) -> None:
    """Check cluster can self-heal + data indexed/read when process dies on node with P_shard."""
    app = (await app_name(juju)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(juju, app)
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    # find unit hosting the primary shard of the index "series-index"
    shards = await get_shards_by_index(juju, leader_unit_ip, ContinuousWrites.INDEX_NAME, app=app)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]

    # Killing the only instance can be disastrous.
    if len(juju.status().apps[app].units) < 2:
        old_units_count = len(juju.status().apps[app].units)
        if substrate == "k8s":
            juju.add_unit(app, num_units=1)
        else:
            juju.add_unit(app, num_units=1)
        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # Kill the opensearch process
    await send_kill_signal_to_process(
        juju, app, first_unit_with_primary_shard, signal="SIGKILL", substrate=substrate
    )

    await assert_continuous_writes_increasing(c_writes)

    # verify that the opensearch service is back running on the old primary unit
    assert await is_up(
        juju, units_ips[first_unit_with_primary_shard], app=app
    ), "OpenSearch service hasn't restarted."

    # fetch unit hosting the new primary shard of the previous index
    shards = await get_shards_by_index(juju, leader_unit_ip, ContinuousWrites.INDEX_NAME, app=app)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2
    for unit_id in units_with_p_shards:
        assert (
            unit_id != first_unit_with_primary_shard
        ), "Primary shard still assigned to the unit where the service was killed."

    # check that the unit previously hosting the primary shard now hosts a replica
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    # verify the node with the old primary successfully joined the rest of the fleet
    assert await check_cluster_formation_successful(
        juju, leader_unit_ip, get_application_unit_names(juju, app=app), app=app
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_kill_db_process_node_with_elected_cm(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_balanced_writes_runner, substrate
) -> None:
    """Check cluster can self-heal, data indexed/read when process dies on node with elected CM."""
    app = (await app_name(juju)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(juju, app)
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    # find unit currently elected cluster_manager
    first_elected_cm_unit_id = await get_elected_cm_unit_id(juju, leader_unit_ip, app=app)

    # Killing the only instance can be disastrous.
    if len(juju.status().apps[app].units) < 2:
        old_units_count = len(juju.status().apps[app].units)
        if substrate == "k8s":
            juju.add_unit(app, num_units=1)
        else:
            juju.add_unit(app, num_units=1)
        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # Kill the opensearch process
    await send_kill_signal_to_process(
        juju, app, first_elected_cm_unit_id, signal="SIGKILL", substrate=substrate
    )

    await assert_continuous_writes_increasing(c_writes)

    # verify that the opensearch service is back running on the old elected cm unit
    assert await is_up(
        juju, units_ips[first_elected_cm_unit_id], app=app
    ), "OpenSearch service hasn't restarted."

    # fetch the current elected cluster manager
    current_elected_cm_unit_id = await get_elected_cm_unit_id(juju, leader_unit_ip, app=app)
    assert (
        current_elected_cm_unit_id != first_elected_cm_unit_id
    ), "Cluster manager election did not happen."

    # verify the node with the old elected cm successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        juju, leader_unit_ip, get_application_unit_names(juju, app=app), app=app
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_freeze_db_process_node_with_primary_shard(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_balanced_writes_runner, substrate
) -> None:
    """Check cluster can self-heal + data indexed/read on process freeze on node with P_shard."""
    app = (await app_name(juju)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(juju, app)
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    # find unit hosting the primary shard of the index "series-index"
    shards = await get_shards_by_index(juju, leader_unit_ip, ContinuousWrites.INDEX_NAME, app=app)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]

    # Killing the only instance can be disastrous.
    if len(juju.status().apps[app].units) < 2:
        old_units_count = len(juju.status().apps[app].units)
        if substrate == "k8s":
            juju.add_unit(app, num_units=1)
        else:
            juju.add_unit(app, num_units=1)
        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # Freeze the opensearch process
    opensearch_pid = await send_kill_signal_to_process(
        juju, app, first_unit_with_primary_shard, signal="SIGSTOP", substrate=substrate
    )

    # wait until the SIGSTOP fully takes effect
    time.sleep(10)

    # verify the unit is not reachable
    is_node_up = await is_up(
        juju, units_ips[first_unit_with_primary_shard], retries=3, app=app, timeout=30
    )
    assert not is_node_up

    logger.info("CW check")
    await assert_continuous_writes_increasing(c_writes)

    # get reachable unit to perform requests against, in case the previously stopped unit
    # is leader unit, so its address is not reachable
    reachable_ip = (await get_reachable_unit_ips(juju, app=app))[0]

    # fetch unit hosting the new primary shard of the previous index
    shards = await get_shards_by_index(juju, reachable_ip, ContinuousWrites.INDEX_NAME, app=app)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2
    for unit_id in units_with_p_shards:
        assert (
            unit_id != first_unit_with_primary_shard
        ), "Primary shard still assigned to the unit where the service was stopped."

    # Un-Freeze the opensearch process in the node previously hosting the primary shard
    await send_kill_signal_to_process(
        juju,
        app,
        first_unit_with_primary_shard,
        signal="SIGCONT",
        opensearch_pid=opensearch_pid,
        substrate=substrate,
    )

    # verify that the opensearch service is back running on the unit previously hosting the p_shard
    assert await is_up(
        juju, units_ips[first_unit_with_primary_shard], retries=3, app=app
    ), "OpenSearch service hasn't restarted."

    # fetch unit hosting the new primary shard of the previous index
    shards = await get_shards_by_index(juju, leader_unit_ip, ContinuousWrites.INDEX_NAME, app=app)

    # check that the unit previously hosting the primary shard now hosts a replica
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    # verify the node with the old primary successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        juju, leader_unit_ip, get_application_unit_names(juju, app=app)
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_freeze_db_process_node_with_elected_cm(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_balanced_writes_runner, substrate
) -> None:
    """Check cluster can self-heal, data indexed/read on process freeze on node with elected CM."""
    app = (await app_name(juju)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(juju, app)
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    # find unit currently elected cluster_manager
    first_elected_cm_unit_id = await get_elected_cm_unit_id(juju, leader_unit_ip, app=app)

    # Killing the only instance can be disastrous.
    if len(juju.status().apps[app].units) < 2:
        old_units_count = len(juju.status().apps[app].units)
        if substrate == "k8s":
            juju.add_unit(app, num_units=1)
        else:
            juju.add_unit(app, num_units=1)
        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # Freeze the opensearch process
    opensearch_pid = await send_kill_signal_to_process(
        juju, app, first_elected_cm_unit_id, signal="SIGSTOP", substrate=substrate
    )

    # wait until the SIGSTOP fully takes effect
    time.sleep(10)

    # verify the unit is not reachable
    is_node_up = await is_up(juju, units_ips[first_elected_cm_unit_id], retries=3, app=app)
    assert not is_node_up

    await assert_continuous_writes_increasing(c_writes)

    # get reachable unit to perform requests against, in case the previously stopped unit
    # is leader unit, so its address is not reachable
    reachable_ip = (await get_reachable_unit_ips(juju, app=app))[0]

    # fetch the current elected cluster_manager
    current_elected_cm_unit_id = await get_elected_cm_unit_id(juju, reachable_ip, app=app)
    assert (
        current_elected_cm_unit_id != first_elected_cm_unit_id
    ), "Cluster manager still assigned to the unit where the service was stopped."

    # Un-Freeze the opensearch process in the node previously elected CM
    await send_kill_signal_to_process(
        juju,
        app,
        first_elected_cm_unit_id,
        signal="SIGCONT",
        opensearch_pid=opensearch_pid,
        substrate=substrate,
    )

    # verify that the opensearch service is back running on the unit previously elected CM unit
    assert await is_up(
        juju, units_ips[first_elected_cm_unit_id], retries=3, app=app
    ), "OpenSearch service hasn't restarted."

    # verify the previously elected CM node successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        juju, leader_unit_ip, get_application_unit_names(juju, app=app), app=app
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_restart_db_process_node_with_elected_cm(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_balanced_writes_runner, substrate
) -> None:
    """Check cluster self-healing & data indexed/read on process restart on CM node."""
    app = (await app_name(juju)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(juju, app)
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    # find unit currently elected cluster manager
    first_elected_cm_unit_id = await get_elected_cm_unit_id(juju, leader_unit_ip, app=app)

    # Killing the only instance can be disastrous.
    if len(juju.status().apps[app].units) < 2:
        old_units_count = len(juju.status().apps[app].units)
        if substrate == "k8s":
            juju.add_unit(app, num_units=1)
        else:
            juju.add_unit(app, num_units=1)
        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # restart the opensearch process
    await send_kill_signal_to_process(
        juju, app, first_elected_cm_unit_id, signal="SIGTERM", substrate=substrate
    )

    await assert_continuous_writes_increasing(c_writes)

    # verify that the opensearch service is back running on the unit previously elected CM unit
    assert await is_up(
        juju, units_ips[first_elected_cm_unit_id]
    ), "OpenSearch service hasn't restarted."

    # fetch the current elected cluster manager
    current_elected_cm_unit_id = await get_elected_cm_unit_id(juju, leader_unit_ip, app=app)
    assert (
        current_elected_cm_unit_id != first_elected_cm_unit_id
    ), "Cluster manager election did not happen."

    # verify the previously elected CM node successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        juju, leader_unit_ip, get_application_unit_names(juju, app=app), app=app
    )

    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_restart_db_process_node_with_primary_shard(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_balanced_writes_runner, substrate
) -> None:
    """Check cluster can self-heal, data indexed/read on process restart on primary shard node."""
    app = (await app_name(juju)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(juju, app)
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    # find unit hosting the primary shard of the index "series-index"
    shards = await get_shards_by_index(juju, leader_unit_ip, ContinuousWrites.INDEX_NAME, app=app)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]

    # Killing the only instance can be disastrous.
    if len(juju.status().apps[app].units) < 2:
        old_units_count = len(juju.status().apps[app].units)
        if substrate == "k8s":
            juju.add_unit(app, num_units=1)
        else:
            juju.add_unit(app, num_units=1)
        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # restart the opensearch process
    await send_kill_signal_to_process(
        juju, app, first_unit_with_primary_shard, signal="SIGTERM", substrate=substrate
    )

    await assert_continuous_writes_increasing(c_writes)

    # verify that the opensearch service is back running on the previous primary shard unit
    assert await is_up(
        juju, units_ips[first_unit_with_primary_shard]
    ), "OpenSearch service hasn't restarted."

    # fetch unit hosting the new primary shard of the previous index
    shards = await get_shards_by_index(juju, leader_unit_ip, ContinuousWrites.INDEX_NAME, app=app)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2
    for unit_id in units_with_p_shards:
        assert (
            unit_id != first_unit_with_primary_shard
        ), "Primary shard still assigned to the unit where the service was killed."

    # check that the unit previously hosting the primary shard now hosts a replica
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    # verify the node with the old primary successfully joined the rest of the fleet
    assert await check_cluster_formation_successful(
        juju, leader_unit_ip, get_application_unit_names(juju, app=app), app=app
    )

    await assert_continuous_writes_consistency(juju, c_writes, [app])


async def test_full_cluster_crash(
    juju: jubilant.Juju,
    c_writes: ContinuousWrites,
    c_balanced_writes_runner,
    reset_restart_delay,
    substrate,
) -> None:
    """Check cluster can operate normally after all nodes SIGKILL at same time and come back up."""
    app = (await app_name(juju)) or APP_NAME

    leader_ip = await get_leader_unit_ip(juju, app)

    # update all units to have a new RESTART_DELAY. Modifying the Restart delay to 3 minutes
    # should ensure enough time for all replicas to be down at the same time.
    logger.info("Updating restart delay for all units.")
    for unit_id in get_application_unit_ids(juju, app):
        if substrate == "k8s":
            pebble_patch_restart_delay(
                juju.model,
                f"{app}/{unit_id}",
                RESTART_DELAY,
                ensure_replan=True,
            )
        else:
            await update_restart_delay(juju, app, unit_id, RESTART_DELAY)

    logger.info("Killing all units simultaneously.")
    # kill all units simultaneously
    await asyncio.gather(
        *[
            send_kill_signal_to_process(juju, app, unit_id, signal="SIGKILL", substrate=substrate)
            for unit_id in get_application_unit_ids(juju, app)
        ]
    )

    logger.info("All kill signals sent. Verifying that all units are down.")
    # check that all units being down at the same time.
    if substrate == "k8s":
        assert await k8s_all_processes_down(juju, app), "Not all units down at the same time."
    else:
        assert await all_processes_down(juju, app), "Not all units down at the same time."

    # Reset restart delay
    logger.info("Resetting restart delay for all units.")
    for unit_id in get_application_unit_ids(juju, app):
        if substrate == "k8s":
            pebble_patch_restart_delay(
                juju.model,
                f"{app}/{unit_id}",
                None,
                ensure_replan=True,
            )
        else:
            await update_restart_delay(juju, app, unit_id, ORIGINAL_RESTART_DELAY)

    # sleep for restart delay + 45 secs max for the election time + node start + cluster formation
    # around 10 sec enough in a good machine - 45 secs for CI
    logger.info("Sleeping for restart delay + 45 seconds to allow cluster to restart and form.")
    time.sleep(ORIGINAL_RESTART_DELAY + 45)

    # verify all units are up and running
    for unit_id, unit_ip in (await get_application_unit_ids_ips(juju, app)).items():
        logger.info("Verifying that unit %s is up after restart.", unit_id)
        assert await is_up(juju, unit_ip), f"Unit {unit_id} not restarted after cluster crash."

    # check all nodes successfully joined the same cluster
    assert await check_cluster_formation_successful(
        juju, leader_ip, get_application_unit_names(juju, app=app), app=app
    )

    await assert_continuous_writes_increasing(c_writes)

    # check that cluster health is green (all primary and replica shards allocated)
    health_resp = await cluster_health(juju, leader_ip, app=app)
    assert health_resp["status"] == "green", f"Cluster {health_resp['status']} - expected green."

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_full_cluster_restart(
    juju: jubilant.Juju,
    c_writes: ContinuousWrites,
    c_balanced_writes_runner,
    reset_restart_delay,
    substrate,
) -> None:
    """Check cluster can operate normally after all nodes SIGTERM at same time and come back up."""
    app = (await app_name(juju)) or APP_NAME

    leader_ip = await get_leader_unit_ip(juju, app)

    # update all units to have a new RESTART_DELAY. Modifying the Restart delay to 3 minutes
    # should ensure enough time for all replicas to be down at the same time.
    for unit_id in get_application_unit_ids(juju, app):
        if substrate == "k8s":
            pebble_patch_restart_delay(
                juju.model,
                f"{app}/{unit_id}",
                RESTART_DELAY,
                ensure_replan=True,
            )
        else:
            await update_restart_delay(juju, app, unit_id, RESTART_DELAY)

    # kill all units simultaneously
    await asyncio.gather(
        *[
            send_kill_signal_to_process(juju, app, unit_id, signal="SIGTERM", substrate=substrate)
            for unit_id in get_application_unit_ids(juju, app)
        ]
    )

    # check that all units being down at the same time.
    if substrate == "k8s":
        assert await k8s_all_processes_down(juju, app), "Not all units down at the same time."
    else:
        assert await all_processes_down(juju, app), "Not all units down at the same time."

    # Reset restart delay
    for unit_id in get_application_unit_ids(juju, app):
        if substrate == "k8s":
            pebble_patch_restart_delay(
                juju.model,
                f"{app}/{unit_id}",
                None,
                ensure_replan=True,
            )
        else:
            await update_restart_delay(juju, app, unit_id, ORIGINAL_RESTART_DELAY)

    # sleep for restart delay + 45 secs max for the election time + node start + cluster formation
    # around 10 sec enough in a good machine - 45 secs for CI
    time.sleep(ORIGINAL_RESTART_DELAY + 45)

    # verify all units are up and running
    for unit_id, unit_ip in (await get_application_unit_ids_ips(juju, app)).items():
        assert await is_up(
            juju, unit_ip, app=app
        ), f"Unit {unit_id} not restarted after cluster crash."

    # check all nodes successfully joined the same cluster
    assert await check_cluster_formation_successful(
        juju, leader_ip, get_application_unit_names(juju, app=app), app=app
    )

    await assert_continuous_writes_increasing(c_writes)

    # check that cluster health is green (all primary and replica shards allocated)
    health_resp = await cluster_health(juju, leader_ip, app=app)
    assert health_resp["status"] == "green", f"Cluster {health_resp['status']} - expected green."

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])
