#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging

import jubilant
import pytest
from data_platform_helpers.advanced_statuses import StatusObject

from opensearch_single_kernel.common.constants import PEER_RELATION, DeploymentType
from opensearch_single_kernel.core.models import (
    DeploymentDescription,
    PeerClusterOrchestrators,
)
from tests.integration.conftest import CONFIG_OPTS, MODEL_CONFIG
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    _series_to_base,
    wait_until,
)
from tests.integration.relations.helpers import get_application_relation_data
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "app"

APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 3, DATA_APP: 1}

NO_DATA_NODE_STATUS = StatusObject(
    status="blocked",
    message="Missing requirements: At least 1 data nodes are required.",
)
NO_CM_STATUS = StatusObject(
    status="blocked",
    message="Missing requirements: At least 1 cluster manager nodes are required.",
)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(juju: jubilant.Juju, charm, series) -> None:
    """Build and deploy one unit of OpenSearch."""
    juju.model_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    juju.deploy(
        charm,
        app=MAIN_APP,
        num_units=APP_UNITS[MAIN_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager"} | CONFIG_OPTS,
    )
    juju.deploy(
        charm,
        app=FAILOVER_APP,
        num_units=APP_UNITS[FAILOVER_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager", "init_hold": True}
        | CONFIG_OPTS,
    )
    juju.deploy(
        charm,
        app=DATA_APP,
        num_units=APP_UNITS[DATA_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data.hot,ml"}
        | CONFIG_OPTS,
    )
    await wait_until(
        juju,
        apps=[TLS_CERTIFICATES_APP_NAME],
        wait_for_exact_units={TLS_CERTIFICATES_APP_NAME: 1},
        idle_period=IDLE_PERIOD,
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP]:
        juju.integrate(app, TLS_CERTIFICATES_APP_NAME)

    juju.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    juju.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    juju.integrate(f"{DATA_APP}:{REL_PEER}", f"{FAILOVER_APP}:{REL_ORCHESTRATOR}")
    await wait_until(
        juju,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )


@pytest.mark.abort_on_fail
async def test_large_deployment_sever_main_failover_relation(juju: jubilant.Juju) -> None:
    """Test that the main-failover relation can be removed and re-added."""
    juju.remove_relation(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await wait_until(
        juju,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )
    # re-relate main and failover
    juju.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await wait_until(
        juju,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )


@pytest.mark.abort_on_fail
async def test_large_deployment_remove_orchestrators(juju: jubilant.Juju) -> None:
    """Test that the orchestrator apps can be deleted."""
    unit = list(juju.status().apps[MAIN_APP].units.keys())[-1]
    deployment_desc = await get_application_relation_data(
        juju, unit_name=unit, relation_name=PEER_RELATION, key="deployment-description"
    )
    deployment_desc = DeploymentDescription.from_dict(json.loads(deployment_desc))

    assert deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR

    # delete the main orchestrator
    juju.remove_application(MAIN_APP)
    # failover should be promoted
    await wait_until(
        juju,
        apps=[FAILOVER_APP, DATA_APP],
        wait_for_exact_units={
            DATA_APP: APP_UNITS[DATA_APP],
            FAILOVER_APP: APP_UNITS[FAILOVER_APP],
        },
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    unit = list(juju.status().apps[FAILOVER_APP].units.keys())[-1]
    deployment_desc = await get_application_relation_data(
        juju, unit_name=unit, relation_name=PEER_RELATION, key="deployment-description"
    )
    deployment_desc = DeploymentDescription.from_dict(json.loads(deployment_desc))

    assert deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR

    # get orchestrators registered in data app
    unit = list(juju.status().apps[DATA_APP].units.keys())[-1]
    orchestrators = await get_application_relation_data(
        juju, unit_name=unit, relation_name=PEER_RELATION, key="orchestrators"
    )
    # ensure failover is the new main and that no failover is registered
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert orchestrators.main_app.name == FAILOVER_APP
    assert orchestrators.failover_app is None

    # delete the main orchestrator (which is now failover)
    juju.remove_application(FAILOVER_APP)
    await wait_until(
        juju,
        apps=[DATA_APP],
        # TODO: Investigate why the running status is removed even if it is set to blocked
        # apps_statuses={DATA_APP: [PeerClusterStatuses.PEER_CLUSTER_ORCHESTRATORS_REMOVED.value]},
        units_statuses={DATA_APP: [NO_CM_STATUS]},
        wait_for_exact_units={
            DATA_APP: APP_UNITS[DATA_APP],
        },
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )
