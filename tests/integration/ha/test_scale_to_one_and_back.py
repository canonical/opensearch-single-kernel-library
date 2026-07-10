#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

from tests.helpers import Substrate
from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
)
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
    get_elected_cm_unit_id,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    _series_to_base,
    app_name,
    cluster_health,
    cluster_voting_config_exclusions,
    execute_update_status_manually,
    get_leader_unit_ip,
    set_watermark,
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

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    os_deploy_kwargs = {
        "app": APP_NAME,
        "num_units": 3,
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
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(juju.status().apps[APP_NAME].units) == 3

    # This test will manually issue update-status hooks, as we want to see the change in behavior
    # when applying `settle_voting` during start/stop and during update-status.
    MODEL_CONFIG["update-status-hook-interval"] = "360m"

    juju.model_config(MODEL_CONFIG)

    # Set watermark
    await set_watermark(juju, app=APP_NAME)


@pytest.mark.abort_on_fail
async def test_scale_down(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_0_repl_writes_runner, substrate: Substrate
) -> None:
    """Tests the shutdown of a node, and see the voting exclusions to be applied.

    This test will remove the elected cluster manager.
    """
    app = (await app_name(juju)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(juju, app=app)
    voting_exclusions = await cluster_voting_config_exclusions(
        juju, unit_ip=leader_unit_ip, app=app
    )
    assert len(voting_exclusions) == 0

    count = len(juju.status().apps[app].units)
    while count > 1:
        # find unit currently elected cluster_manager
        elected_cm_unit_id = await get_elected_cm_unit_id(juju, leader_unit_ip, app=app)

        if substrate == "k8s":
            juju.remove_unit(app, num_units=1)
        else:
            # remove the service in the chosen unit
            juju.remove_unit(f"{app}/{elected_cm_unit_id}")

        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=count - 1,
            idle_period=IDLE_PERIOD,
        )

        # Check voting exclusions
        leader_unit_ip = await get_leader_unit_ip(juju, app=app)
        voting_exclusions = await cluster_voting_config_exclusions(
            juju, unit_ip=leader_unit_ip, app=app
        )
        assert len(voting_exclusions) == 0
        # Test the cleanup() method
        await execute_update_status_manually(juju, app=app)
        voting_exclusions = await cluster_voting_config_exclusions(
            juju, unit_ip=leader_unit_ip, app=app
        )
        assert len(voting_exclusions) == 0

        # get initial cluster health - expected to be all good: green
        leader_unit_ip = await get_leader_unit_ip(juju, app=app)
        cluster_health_resp = await cluster_health(juju, leader_unit_ip, wait_for_green_first=True)
        assert cluster_health_resp["status"] == "green"
        assert cluster_health_resp["unassigned_shards"] == 0

        # Make sure we continue to be writable
        await assert_continuous_writes_increasing(c_writes)

        count = len(juju.status().apps[app].units)

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_scale_back_up(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_0_repl_writes_runner, substrate: Substrate
) -> None:
    """Tests the scaling back to 3x node-cluster and see the voting exclusions to be applied."""
    app = (await app_name(juju)) or APP_NAME

    init_count = len(juju.status().apps[app].units)
    while init_count < 3:
        # find unit currently elected cluster_manager
        leader_unit_ip = await get_leader_unit_ip(juju, app=app)

        # remove the service in the chosen unit
        if substrate == "k8s":
            juju.add_unit(app, num_units=1)
        else:
            juju.add_unit(app, num_units=1)
        await wait_until(
            juju,
            apps=[app],
            wait_for_exact_units=init_count + 1,
            idle_period=IDLE_PERIOD,
        )

        # get initial cluster health - expected to be all good: green
        leader_unit_ip = await get_leader_unit_ip(juju, app=app)
        cluster_health_resp = await cluster_health(
            juju, leader_unit_ip, wait_for_green_first=True, app=app
        )
        assert cluster_health_resp["status"] == "green"
        assert cluster_health_resp["unassigned_shards"] == 0

        # Adding new units should not trigger a new voting exclusion
        voting_exclusions = await cluster_voting_config_exclusions(
            juju, unit_ip=leader_unit_ip, app=app
        )
        assert len(voting_exclusions) == 0

        # Make sure we continue to be writable
        await assert_continuous_writes_increasing(c_writes)

        init_count = len(juju.status().apps[app].units)

    # Make sure update status is executed and fixes the voting exclusions
    await execute_update_status_manually(juju, app=app)
    voting_exclusions = await cluster_voting_config_exclusions(
        juju, unit_ip=leader_unit_ip, app=app
    )
    assert len(voting_exclusions) == 0

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.abort_on_fail
async def test_gracefully_cluster_remove(juju: jubilant.Juju) -> None:
    """Tests removing the entire application at once."""
    app = (await app_name(juju)) or APP_NAME

    # This removal must not leave units in error.
    # We will block until it is finished.
    juju.remove_application(app, destroy_storage=True)
