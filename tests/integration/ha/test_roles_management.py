#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

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
    _series_to_base,
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
        wait_for_exact_units={TLS_CERTIFICATES_APP_NAME: 1, APP_NAME: 3},
        idle_period=IDLE_PERIOD,
    )
    assert len(juju.status().apps[APP_NAME].units) == 3


@pytest.mark.abort_on_fail
async def test_set_roles_manually(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check roles changes in all nodes."""
    app = (await app_name(juju)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(juju, app=app)

    cluster_name = (await cluster_health(juju, leader_unit_ip, app=app))["cluster_name"]
    nodes = await all_nodes(juju, leader_unit_ip, app=app)
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
    juju.config(app, {"cluster_name": "new_cluster_name", "roles": "cluster_manager, data.cold"})
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=len(nodes),
        idle_period=IDLE_PERIOD,
    )

    logger.info("Checking if the cluster name and roles + temperature were changed.")
    assert await check_cluster_formation_successful(
        juju, leader_unit_ip, get_application_unit_names(juju, app=app), app=app
    )
    new_cluster_name = (await cluster_health(juju, leader_unit_ip, app=app))["cluster_name"]
    assert new_cluster_name == cluster_name, "Oops - cluster name changed."

    nodes = await all_nodes(juju, leader_unit_ip, app=app)
    for node in nodes:
        assert sorted(node.roles) == ["cluster_manager", "data"], "roles unchanged"
        assert node.temperature == "cold", "Temperature unchanged."


@pytest.mark.abort_on_fail
async def test_switch_back_to_auto_generated_roles(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check roles changes in all nodes."""
    app = (await app_name(juju)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(juju, app=app)
    nodes = await all_nodes(juju, leader_unit_ip, app=app)

    juju.config(app, {"roles": ""})
    await wait_until(
        juju,
        apps=[app],
        wait_for_exact_units=len(nodes),
        idle_period=IDLE_PERIOD,
    )

    # check that nodes' roles have indeed changed
    nodes = await all_nodes(juju, leader_unit_ip, app=app)
    for node in nodes:
        assert sorted(node.roles) == [
            "cluster_manager",
            "data",
            "ingest",
            "ml",
        ]
        assert node.temperature is None, "Node temperature was erroneously set."
