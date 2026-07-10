#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time

import jubilant
import pytest

from opensearch_single_kernel.common.statuses import HealthStatuses
from tests.helpers import Substrate
from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    IDLE_PERIOD,
    MODEL_CONFIG,
)
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    all_nodes,
    assert_continuous_writes_consistency,
    get_elected_cm_unit_id,
    get_number_of_shards_by_node,
    get_shards_by_index,
    get_shards_by_state,
    nodes_count_by_role,
)
from tests.integration.ha.helpers_data import (
    create_dummy_docs,
    create_dummy_indexes,
    delete_dummy_indexes,
)
from tests.integration.helpers import (
    _series_to_base,
    app_name,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_ids,
    get_application_unit_names,
    get_leader_unit_id,
    get_leader_unit_ip,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


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
        "num_units": 1,
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
        timeout=1600,
    )
    assert len(juju.status().apps[APP_NAME].units) == 1


@pytest.mark.abort_on_fail
async def test_horizontal_scale_up(
    juju: jubilant.Juju,
    c_writes: ContinuousWrites,
    c_writes_runner,
    substrate,
) -> None:
    """Tests that new added units to the cluster are discoverable."""
    app = (await app_name(juju)) or APP_NAME
    init_units_count = len(juju.status().apps[app].units)

    # scale up
    if substrate == "k8s":
        juju.add_unit(app, num_units=2)
    else:
        juju.add_unit(app, num_units=2)
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=init_units_count + 2,
        idle_period=IDLE_PERIOD,
    )
    num_units = len(juju.status().apps[app].units)
    assert num_units == init_units_count + 2

    unit_names = get_application_unit_names(juju, app=app)
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    assert await check_cluster_formation_successful(juju, leader_unit_ip, unit_names)

    cluster_health_resp = await cluster_health(juju, leader_unit_ip)
    assert cluster_health_resp["status"] == "green"

    shards_by_status = await get_shards_by_state(juju, leader_unit_ip)
    assert not shards_by_status.get("INITIALIZING")
    assert not shards_by_status.get("RELOCATING")
    assert not shards_by_status.get("UNASSIGNED")

    # check roles, expecting all nodes to be cm_eligible
    nodes = await all_nodes(juju, leader_unit_ip)
    num_units = len(juju.status().apps[app].units)
    assert (
        nodes_count_by_role(nodes)["cluster_manager"] == num_units
        if num_units % 2 != 0
        else num_units - 1
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_safe_scale_down_shards_realloc(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner, substrate: Substrate
) -> None:
    """Tests the shutdown of a node, and re-allocation of shards to a newly joined unit.

    The goal of this test is to make sure that shards are automatically relocated after
    a Yellow status on the cluster caused by a scale-down event.
    """
    app = (await app_name(juju)) or APP_NAME
    init_units_count = len(juju.status().apps[app].units)

    # scale up
    if substrate == "k8s":
        juju.add_unit(app, num_units=1)
    else:
        juju.add_unit(app, num_units=1)
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=init_units_count + 1,
        idle_period=IDLE_PERIOD,
    )

    leader_unit_ip = await get_leader_unit_ip(juju, app=app)
    leader_unit_id = await get_leader_unit_id(juju, app=app)

    # fetch all nodes
    unit_ids = get_application_unit_ids(juju, app=app)
    unit_id_to_stop = [unit_id for unit_id in unit_ids if unit_id != leader_unit_id][0]
    unit_ids_to_keep = [unit_id for unit_id in unit_ids if unit_id != unit_id_to_stop]

    # create indices with right num of primary and replica shards, and populate with data
    await create_dummy_indexes(juju, app, leader_unit_ip, max_r_shards=init_units_count)
    await create_dummy_docs(juju, app, leader_unit_ip, substrate=substrate)

    # get initial cluster health - expected to be all good: green
    logger.info("Checking initial cluster health and allocation...")
    cluster_health_resp = await cluster_health(
        juju, leader_unit_ip, wait_for_green_first=True, app=app
    )
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0

    # get initial cluster allocation (nodes and their corresponding shards)
    init_shards_per_node = await get_number_of_shards_by_node(juju, leader_unit_ip, app=app)
    assert init_shards_per_node.get(-1, 0) == 0  # unallocated shards

    # remove the service in the chosen unit
    if substrate == "k8s":
        juju.remove_unit(app, num_units=1)
    else:
        juju.remove_unit(f"{app}/{unit_id_to_stop}")
    await wait_until(
        juju,
        apps=[app],
        apps_statuses={app: [HealthStatuses.CLUSTER_HEALTH_YELLOW.value]},
        wait_for_exact_units=init_units_count,
        idle_period=IDLE_PERIOD,
    )

    # check if at least partial shard re-allocation happened
    new_shards_per_node = await get_number_of_shards_by_node(juju, leader_unit_ip, app=app)

    # some shards should have been reallocated, NOT ALL due to already existing replicas elsewhere
    assert new_shards_per_node.get(-1, 0) > 0  # some shards not reallocated

    are_some_shards_reallocated = False

    if substrate == "k8s":
        unit_ids_to_keep = get_application_unit_ids(juju, app=app)

    for unit_id in unit_ids_to_keep:
        are_some_shards_reallocated = (
            are_some_shards_reallocated
            or new_shards_per_node[unit_id] > init_shards_per_node[unit_id]
        )
    assert are_some_shards_reallocated

    # get new cluster health
    cluster_health_resp = await cluster_health(juju, leader_unit_ip, app=app)

    # not all replica shards should have been reallocated
    assert cluster_health_resp["status"] == "yellow"

    # scale up by 1 unit
    if substrate == "k8s":
        juju.add_unit(app, num_units=1)
    else:
        juju.add_unit(app, num_units=1)
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=init_units_count + 1,
        idle_period=IDLE_PERIOD,
    )

    new_shards_per_node = await get_number_of_shards_by_node(juju, leader_unit_ip, app=app)
    if substrate == "vm":
        # on k8s we will have the same unit id for the new unit
        new_unit_id = [
            int(unit_name.split("/")[1])
            for unit_name in juju.status().apps[app].units
            if int(unit_name.split("/")[1]) not in unit_ids
        ][0]

        # check if the previously unallocated shards have successfully moved to the newest unit
        assert new_shards_per_node[new_unit_id] > 0

    # get new cluster health
    cluster_health_resp = await cluster_health(juju, leader_unit_ip, app=app)
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0
    assert new_shards_per_node.get(-1, 0) == 0

    # delete the dummy indexes
    await delete_dummy_indexes(juju, app, leader_unit_ip)

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


# skip if k8s as we cannot target units
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("k8s")
async def test_safe_scale_down_remove_leaders(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner, substrate: Substrate
) -> None:
    """Tests the removal of specific units (elected cm, juju leader, node with prim shard).

    The goal of this test is to make sure that:
     - the CM reelection happens successfully.
     - the leader-elected event gets triggered successfully and
        leadership related events on the charm work correctly, i.e: roles reassigning.
     - the primary shards reelection happens successfully.
    It is worth noting that we're going into this test with an odd number of units.
    """
    app = (await app_name(juju)) or APP_NAME
    init_units_count = len(juju.status().apps[app].units)

    if init_units_count < 5:
        # scale up by 5 - init units
        added_units = 5 - init_units_count
        juju.add_unit(app, num_units=added_units)

        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=init_units_count + added_units,
            idle_period=IDLE_PERIOD,
            timeout=1800,
        )

        init_units_count += added_units

    # scale down: remove the juju leader
    leader_unit_id = await get_leader_unit_id(juju, app=app)

    juju.remove_unit(f"{app}/{leader_unit_id}")
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=init_units_count - 1,
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    # scale-down: remove the current elected CM
    first_elected_cm_unit_id = await get_elected_cm_unit_id(juju, leader_unit_ip)
    assert first_elected_cm_unit_id != -1
    juju.remove_unit(f"{app}/{first_elected_cm_unit_id}")
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=init_units_count - 2,
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    # check if CM re-election happened
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)
    second_elected_cm_unit_id = await get_elected_cm_unit_id(juju, leader_unit_ip)
    assert second_elected_cm_unit_id != -1
    assert second_elected_cm_unit_id != first_elected_cm_unit_id

    # check health of cluster
    cluster_health_resp = await cluster_health(juju, leader_unit_ip, wait_for_green_first=True)
    assert cluster_health_resp["status"] == "green"

    # remove node containing primary shard of index "series_index"
    shards = await get_shards_by_index(juju, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]
    juju.remove_unit(f"{app}/{unit_with_primary_shard}")
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=init_units_count - 3,
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    writes = await c_writes.count()

    # check that the primary shard reelection happened
    leader_unit_ip = await get_leader_unit_ip(juju, app=app)
    shards = await get_shards_by_index(juju, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 1

    for unit_id in units_with_p_shards:
        assert (
            unit_id != unit_with_primary_shard
        ), "Primary shard still assigned to destroyed unit."

    # check that writes are still going after the removal / p_shard reelection
    time.sleep(3)
    new_writes = await c_writes.count()
    assert new_writes > writes

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])
