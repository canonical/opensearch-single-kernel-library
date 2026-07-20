#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
)
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    all_nodes,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    app_name,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_names,
    get_leader_unit_ip,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    ops_test: OpsTest, charm, series, substrate, charm_resources
) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(ops_test):
        return

    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    os_deploy_kwargs = {
        "application_name": APP_NAME,
        "num_units": 3,
        "series": series,
        "config": CONFIG_OPTS,
    }
    if substrate == "k8s":
        os_deploy_kwargs["resources"] = charm_resources
        os_deploy_kwargs["trust"] = True
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(charm, **os_deploy_kwargs),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        wait_for_exact_units={TLS_CERTIFICATES_APP_NAME: 1, APP_NAME: 3},
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.abort_on_fail
async def test_set_roles_manually(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check roles changes in all nodes."""
    app = (await app_name(ops_test)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    cluster_name = (await cluster_health(ops_test, leader_unit_ip, app=app))[
        "cluster_name"
    ]
    nodes = await all_nodes(ops_test, leader_unit_ip, app=app)
    for node in nodes:
        assert sorted(node.roles) == [
            "cluster_manager",
            "data",
            "ingest",
            "ml",
        ]
        assert node.temperature is None, "Node temperature was erroneously set."

    # change cluster name and roles + temperature, should trigger a rolling restart

    logger.info("Changing cluster name and roles + temperature.")
    await ops_test.model.applications[app].set_config(
        {"cluster_name": "new_cluster_name", "roles": "cluster_manager, data.cold"}
    )
    await wait_until(
        ops_test,
        apps=[app],
        wait_for_exact_units=len(nodes),
        idle_period=IDLE_PERIOD,
    )

    logger.info("Checking if the cluster name and roles + temperature were changed.")
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app), app=app
    )
    new_cluster_name = (await cluster_health(ops_test, leader_unit_ip, app=app))[
        "cluster_name"
    ]
    assert new_cluster_name == cluster_name, "Oops - cluster name changed."

    nodes = await all_nodes(ops_test, leader_unit_ip, app=app)
    for node in nodes:
        assert sorted(node.roles) == ["cluster_manager", "data"], "roles unchanged"
        assert node.temperature == "cold", "Temperature unchanged."


@pytest.mark.abort_on_fail
async def test_switch_back_to_auto_generated_roles(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check roles changes in all nodes."""
    app = (await app_name(ops_test)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    nodes = await all_nodes(ops_test, leader_unit_ip, app=app)

    await ops_test.model.applications[app].set_config({"roles": ""})
    await wait_until(
        ops_test,
        apps=[app],
        wait_for_exact_units=len(nodes),
        idle_period=IDLE_PERIOD,
    )

    # check that nodes' roles have indeed changed
    nodes = await all_nodes(ops_test, leader_unit_ip, app=app)
    for node in nodes:
        assert sorted(node.roles) == [
            "cluster_manager",
            "data",
            "ingest",
            "ml",
        ]
        assert node.temperature is None, "Node temperature was erroneously set."
