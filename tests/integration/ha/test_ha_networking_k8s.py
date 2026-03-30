#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""HA networking tests on Kubernetes using Chaos Mesh.

On k8s we use
Chaos Mesh NetworkChaos with MicroK8s (microk8s kubectl), matching the pattern in
mongo-single-kernel-library.
"""

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.conftest import APP_NAME, CONFIG_OPTS, MODEL_CONFIG
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
    get_elected_cm_unit_id,
    get_shards_by_index,
)
from tests.integration.ha.k8s_chaos_mesh import (
    cut_network_from_unit_k8s,
    restore_network_for_unit_k8s,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    app_name,
    check_cluster_formation_successful,
    get_application_unit_ids_ips,
    get_application_unit_names,
    get_constraints,
    get_leader_unit_ip,
    is_up,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)

# Allow time for cluster_manager re-election after isolating the current CM.
CM_REELECTION_WAIT_SEC = 60


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    ops_test: OpsTest, charm, series, substrate, charm_resources
) -> None:
    """Build and deploy one unit of OpenSearch (k8s entry point for this module)."""
    if await app_name(ops_test):
        return

    await ops_test.model.set_config(MODEL_CONFIG)
    config = {"ca-common-name": "CN_CA"}
    os_deploy_kwargs = {
        "application_name": APP_NAME,
        "num_units": 3,
        "series": series,
        "config": CONFIG_OPTS,
    }
    if substrate == "k8s":
        os_deploy_kwargs["resources"] = charm_resources
    else:
        constraints = await get_constraints(ops_test)
        if constraints:
            os_deploy_kwargs["constraints"] = constraints
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(charm, **os_deploy_kwargs),
    )

    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.usefixtures("chaos_mesh")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("vm")
async def test_network_partition_elected_cm_k8s(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_balanced_writes_runner,
) -> None:
    """Partition the elected cluster_manager pod.

    Expect CM re-election and self-heal after restore.
    """
    app = (await app_name(ops_test)) or APP_NAME

    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    first_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    first_elected_cm_unit_ip = unit_ids_ips[first_elected_cm_unit_id]
    first_elected_cm_unit_name = f"{app}/{first_elected_cm_unit_id}"

    if len(ops_test.model.applications[app].units) < 2:
        old_units_count = len(ops_test.model.applications[app].units)
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    assert await is_up(
        ops_test, first_elected_cm_unit_ip
    ), "Initial elected cluster manager node not online."

    cut_network_from_unit_k8s(ops_test, first_elected_cm_unit_name)
    logger.info("Network cut from elected CM unit %s", first_elected_cm_unit_name)

    assert not await is_up(
        ops_test, first_elected_cm_unit_ip, retries=3
    ), "Connection still possible to the CM node where the network was cut."

    await assert_continuous_writes_increasing(c_writes)

    await asyncio.sleep(CM_REELECTION_WAIT_SEC)

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    current_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    assert current_elected_cm_unit_id != first_elected_cm_unit_id, "No CM re-election happened."

    restore_network_for_unit_k8s(ops_test)

    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(unit_ids_ips),
        idle_period=IDLE_PERIOD,
        timeout=2000,
    )

    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)
    restored_cm_ip = unit_ids_ips[first_elected_cm_unit_id]

    assert await is_up(ops_test, restored_cm_ip), "Unit still not up after network restore."

    assert await check_cluster_formation_successful(
        ops_test, restored_cm_ip, get_application_unit_names(ops_test, app)
    ), "Unit did NOT join the rest of the cluster."

    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.usefixtures("chaos_mesh")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("vm")
async def test_network_partition_primary_shard_k8s(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_balanced_writes_runner,
) -> None:
    """Partition the pod hosting a primary shard, expect promotion and self-heal after restore."""
    app = (await app_name(ops_test)) or APP_NAME

    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]
    first_unit_with_primary_shard_ip = unit_ids_ips[first_unit_with_primary_shard]
    unit_name = f"{app}/{first_unit_with_primary_shard}"

    if len(ops_test.model.applications[app].units) < 2:
        old_units_count = len(ops_test.model.applications[app].units)
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    assert await is_up(
        ops_test, first_unit_with_primary_shard_ip
    ), "Initial node with primary shard not online."

    cut_network_from_unit_k8s(ops_test, unit_name)
    logger.info("Network cut from primary-shard unit %s", unit_name)

    assert not await is_up(
        ops_test, first_unit_with_primary_shard_ip, retries=3
    ), "Connection still possible after network cut on primary shard unit."

    await assert_continuous_writes_increasing(c_writes)

    await asyncio.sleep(CM_REELECTION_WAIT_SEC)

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2
    for uid in units_with_p_shards:
        assert (
            uid != first_unit_with_primary_shard
        ), "Primary shard still assigned to the partitioned unit."

    restore_network_for_unit_k8s(ops_test)

    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(unit_ids_ips),
        idle_period=IDLE_PERIOD,
        timeout=2000,
    )

    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)
    restored_ip = unit_ids_ips[first_unit_with_primary_shard]

    assert await is_up(ops_test, restored_ip), "Unit still not up after network restore."

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    assert await check_cluster_formation_successful(
        ops_test, restored_ip, get_application_unit_names(ops_test, app)
    ), "Unit did NOT join the rest of the cluster."

    await assert_continuous_writes_consistency(ops_test, c_writes, [app])
