#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging

import jubilant
import pytest
from data_platform_helpers.advanced_statuses import StatusObject

from opensearch_single_kernel.common.constants import PEER_RELATION
from opensearch_single_kernel.common.statuses import (
    PeerClusterErrorDataStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.core.models import PeerClusterOrchestrators
from tests.integration.conftest import CONFIG_OPTS, MODEL_CONFIG
from tests.integration.helpers import (
    _series_to_base,
    wait_until,
)
from tests.integration.relations.helpers import get_application_relation_data
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)
MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"
DATA_APP_TWO = "opensearch-data-two"

CLUSTER_NAME = "app"

APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 1, DATA_APP: 1, DATA_APP_TWO: 1}

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

    juju.cli("create-storage-pool", "local", "lxd", "volume-type=standard")

    # Deploy TLS Certificates operator.
    tls_config = {"ca-common-name": "CN_CA"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=tls_config)
    juju.deploy(
        charm,
        app=MAIN_APP,
        num_units=APP_UNITS[MAIN_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager,data"} | CONFIG_OPTS,
        storage={"opensearch-data": "local,128G,1"},
    )
    juju.deploy(
        charm,
        app=FAILOVER_APP,
        num_units=APP_UNITS[FAILOVER_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager", "init_hold": True}
        | CONFIG_OPTS,
        storage={"opensearch-data": "local,128G,1"},
    )
    juju.deploy(
        charm,
        app=DATA_APP,
        num_units=APP_UNITS[DATA_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "roles": "data", "init_hold": True} | CONFIG_OPTS,
        storage={"opensearch-data": "local,128G,1"},
    )
    juju.deploy(
        charm,
        app=DATA_APP_TWO,
        num_units=APP_UNITS[DATA_APP_TWO],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "roles": "data", "init_hold": True} | CONFIG_OPTS,
        storage={"opensearch-data": "local,128G,1"},
    )
    for app in APP_UNITS:
        juju.integrate(app, TLS_CERTIFICATES_APP_NAME)

    for app in [FAILOVER_APP, DATA_APP, DATA_APP_TWO]:
        juju.integrate(f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster")

    for app in [DATA_APP, DATA_APP_TWO]:
        juju.integrate(f"{FAILOVER_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster")

    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_APP_TWO, TLS_CERTIFICATES_APP_NAME],
        wait_for_exact_units=1,
    )


@pytest.mark.abort_on_fail
async def test_check_orchestrators_in_rel_data(juju: jubilant.Juju) -> None:
    """Test that the orchestrators are correctly set."""
    unit_name = next(iter(juju.status().apps[DATA_APP].units.keys()))
    orchestrators = await get_application_relation_data(
        juju,
        unit_name=unit_name,
        relation_name=PEER_RELATION,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == MAIN_APP
    ), "Main orchestrator not set correctly"
    assert (
        orchestrators.failover_app and orchestrators.failover_app.name == FAILOVER_APP
    ), "Failover orchestrator not set correctly"


@pytest.mark.abort_on_fail
async def test_demotion_through_relation_removal(juju: jubilant.Juju) -> None:
    """Test that removing the main orchestrator relations demotes it and promotes the failover."""
    for app in [FAILOVER_APP, DATA_APP, DATA_APP_TWO]:
        juju.remove_relation(f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster")

    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_APP_TWO],
        wait_for_exact_units=1,
    )

    # check that failover was promoted to main orchestrator
    unit_name = next(iter(juju.status().apps[DATA_APP].units.keys()))
    orchestrators = await get_application_relation_data(
        juju,
        unit_name=unit_name,
        relation_name=PEER_RELATION,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == FAILOVER_APP
    ), "Failover was not promoted to main orchestrator"
    assert (
        orchestrators.failover_app is None
    ), "Failover orchestrator should be None after promotion"


@pytest.mark.abort_on_fail
async def test_failover_election_after_restoring_integration(juju: jubilant.Juju) -> None:
    """Test that the failover orchestrator is correctly elected after re-adding relations."""
    juju.integrate(f"{FAILOVER_APP}:peer-cluster-orchestrator", f"{MAIN_APP}:peer-cluster")
    for app in [DATA_APP, DATA_APP_TWO]:
        juju.integrate(f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster")

    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, DATA_APP_TWO],
        wait_for_exact_units=1,
    )

    # check that main app is now elected failover orchestrator
    unit_name = next(iter(juju.status().apps[DATA_APP].units.keys()))
    orchestrators = await get_application_relation_data(
        juju,
        unit_name=unit_name,
        relation_name=PEER_RELATION,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == FAILOVER_APP
    ), "Failover is supposed to be the main orchestrator"
    assert (
        orchestrators.failover_app and orchestrators.failover_app.name == MAIN_APP
    ), "Main app is supposed to be the failover orchestrator"


@pytest.mark.abort_on_fail
async def test_scale_promoted_main_to_0_then_up(juju: jubilant.Juju) -> None:
    """Test scaling main orchestrator to 0 and back to 1 unit."""
    # Main orchestrator is the failover app at this point
    status = juju.status()
    failover_unit_name = next(iter(status.apps[FAILOVER_APP].units.keys()))

    failover_app_storages = [
        storage_id
        for storage_id, storage_info in status.storage.storage.items()
        if storage_info.attachments and failover_unit_name in storage_info.attachments.units
    ]
    logger.info(f"Failover app storages: {failover_app_storages}")
    juju.remove_unit(failover_unit_name)

    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, DATA_APP_TWO],
        wait_for_exact_units=1,
    )

    # check that main app is now elected main orchestrator and that failover is None
    unit_name = next(iter(juju.status().apps[DATA_APP].units.keys()))
    orchestrators = await get_application_relation_data(
        juju,
        unit_name=unit_name,
        relation_name=PEER_RELATION,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == MAIN_APP
    ), "Main app is supposed to be the main orchestrator"
    assert (
        orchestrators.failover_app is None
    ), "Failover app is supposed to be None since there is no failover orchestrator"

    # scale back to 1 unit
    juju.add_unit(FAILOVER_APP, attach_storage=failover_app_storages)
    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_APP_TWO],
        apps_statuses={
            MAIN_APP: [PeerClusterErrorDataStatuses.PEER_CLUSTER_MAIN_IS_REQUIRER.value],
            FAILOVER_APP: [PeerClusterStatuses.PEER_CLUSTER_NO_RELATION.value],
            DATA_APP: [
                PeerClusterErrorDataStatuses.CLUSTER_CAN_ONLY_HAVE_ONE_MAIN_OR_FAILOVER.value
            ],
            DATA_APP_TWO: [
                PeerClusterErrorDataStatuses.CLUSTER_CAN_ONLY_HAVE_ONE_MAIN_OR_FAILOVER.value
            ],
        },
    )

    juju.remove_relation(f"{FAILOVER_APP}:peer-cluster-orchestrator", f"{MAIN_APP}:peer-cluster")

    juju.integrate(f"{MAIN_APP}:peer-cluster-orchestrator", f"{FAILOVER_APP}:peer-cluster")

    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, DATA_APP_TWO],
        wait_for_exact_units=1,
    )

    # check that main app is still elected main orchestrator and that failover is the failover app
    orchestrators = await get_application_relation_data(
        juju,
        unit_name=unit_name,
        relation_name=PEER_RELATION,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == MAIN_APP
    ), "Main app is supposed to be the main orchestrator"
    assert (
        orchestrators.failover_app and orchestrators.failover_app.name == FAILOVER_APP
    ), "Failover app is supposed to be the failover orchestrator"
