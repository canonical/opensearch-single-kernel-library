#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging

import pytest
from data_platform_helpers.advanced_statuses import StatusObject
from pytest_operator.plugin import OpsTest

from opensearch_single_kernel.common.constants import PEER_RELATION
from opensearch_single_kernel.common.statuses import (
    PeerClusterErrorDataStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.core.models import PeerClusterOrchestrators
from tests.integration.conftest import CONFIG_OPTS, MODEL_CONFIG
from tests.integration.helpers import (
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


async def assert_orchestrators(
    ops_test: OpsTest, *, expected_main: str, expected_failover: str | None
) -> None:
    """Check that both data applications store the expected main, failover, and relation IDs."""
    for app_name in (DATA_APP, DATA_APP_TWO):
        unit = ops_test.model.applications[app_name].units[0]
        data = await get_application_relation_data(
            ops_test, unit_name=unit.name, relation_name=PEER_RELATION, key="orchestrators"
        )
        assert data, f"No orchestrators found on {app_name}"
        orchestrators = PeerClusterOrchestrators.from_dict(json.loads(data))

        for deployment_type, provider, registered_app, relation_id in (
            ("main", expected_main, orchestrators.main_app, orchestrators.main_rel_id),
            (
                "failover",
                expected_failover,
                orchestrators.failover_app,
                orchestrators.failover_rel_id,
            ),
        ):
            if not provider:
                assert registered_app is None, (
                    f"{app_name} still has a {deployment_type} orchestrator: {registered_app}"
                )
                assert relation_id == -1, (
                    f"{app_name} still has a {deployment_type} relation ID: {relation_id}"
                )
                continue

            assert registered_app and registered_app.name == provider, (
                f"{app_name} expected {provider} as {deployment_type}, got {registered_app}"
            )

            # Check that the stored ID belongs to the relation between these two applications.
            assert any(
                int(relation.entity_id) == relation_id
                and relation.matches(
                    f"{provider}:peer-cluster-orchestrator", f"{app_name}:peer-cluster"
                )
                for relation in ops_test.model.relations
            ), f"{app_name} registered {provider} against the wrong relation: {relation_id}"


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    ops_test: OpsTest, charm, series, charm_resources, substrate
) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)

    if substrate == "vm":
        await ops_test.model.create_storage_pool("local", "lxd", "volume-type=standard")

    # Deploy TLS Certificates operator.
    tls_config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=tls_config
        ),
        ops_test.model.deploy(
            charm,
            application_name=MAIN_APP,
            num_units=APP_UNITS[MAIN_APP],
            series=series,
            resources=charm_resources,
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager,data"} | CONFIG_OPTS,
            storage={"opensearch-data": "local,128G,1"} if substrate == "vm" else None,
            trust=substrate == "k8s",
        ),
        ops_test.model.deploy(
            charm,
            application_name=FAILOVER_APP,
            num_units=APP_UNITS[FAILOVER_APP],
            series=series,
            resources=charm_resources,
            config={
                "cluster_name": CLUSTER_NAME,
                "roles": "cluster_manager",
                "init_hold": True,
            }
            | CONFIG_OPTS,
            storage={"opensearch-data": "local,128G,1"} if substrate == "vm" else None,
            trust=substrate == "k8s",
        ),
        ops_test.model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=APP_UNITS[DATA_APP],
            series=series,
            resources=charm_resources,
            config={"cluster_name": CLUSTER_NAME, "roles": "data", "init_hold": True}
            | CONFIG_OPTS,
            storage={"opensearch-data": "local,128G,1"} if substrate == "vm" else None,
            trust=substrate == "k8s",
        ),
        ops_test.model.deploy(
            charm,
            application_name=DATA_APP_TWO,
            num_units=APP_UNITS[DATA_APP_TWO],
            series=series,
            resources=charm_resources,
            config={"cluster_name": CLUSTER_NAME, "roles": "data", "init_hold": True}
            | CONFIG_OPTS,
            storage={"opensearch-data": "local,128G,1"} if substrate == "vm" else None,
            trust=substrate == "k8s",
        ),
    )
    for app in APP_UNITS:
        await ops_test.model.integrate(f"{app}:certificates", TLS_CERTIFICATES_APP_NAME)

    for app in [FAILOVER_APP, DATA_APP, DATA_APP_TWO]:
        await ops_test.model.integrate(
            f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster"
        )

    for app in [DATA_APP, DATA_APP_TWO]:
        await ops_test.model.integrate(
            f"{FAILOVER_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster"
        )

    await wait_until(
        ops_test,
        apps=[
            MAIN_APP,
            DATA_APP,
            FAILOVER_APP,
            DATA_APP_TWO,
            TLS_CERTIFICATES_APP_NAME,
        ],
        wait_for_exact_units=1,
    )


@pytest.mark.abort_on_fail
async def test_check_orchestrators_in_rel_data(ops_test: OpsTest) -> None:
    """Test that the orchestrators are correctly set."""
    await assert_orchestrators(ops_test, expected_main=MAIN_APP, expected_failover=FAILOVER_APP)


@pytest.mark.abort_on_fail
async def test_demotion_through_relation_removal(ops_test: OpsTest) -> None:
    """Test that removing the main orchestrator relations demotes it and promotes the failover."""
    main_app = ops_test.model.applications[MAIN_APP]
    assert main_app is not None

    for app in [FAILOVER_APP, DATA_APP, DATA_APP_TWO]:
        await main_app.remove_relation(
            f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster", block_until_done=True
        )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_APP_TWO],
        wait_for_exact_units=1,
    )

    # check that failover was promoted to main orchestrator
    await assert_orchestrators(ops_test, expected_main=FAILOVER_APP, expected_failover=None)


@pytest.mark.abort_on_fail
async def test_failover_election_after_restoring_integration(ops_test: OpsTest) -> None:
    """Test that the failover orchestrator is correctly elected after re-adding relations."""
    await ops_test.model.integrate(
        f"{FAILOVER_APP}:peer-cluster-orchestrator", f"{MAIN_APP}:peer-cluster"
    )
    for app in [DATA_APP, DATA_APP_TWO]:
        await ops_test.model.integrate(
            f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster"
        )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, DATA_APP_TWO],
        wait_for_exact_units=1,
    )

    # check that main app is now elected failover orchestrator
    await assert_orchestrators(ops_test, expected_main=FAILOVER_APP, expected_failover=MAIN_APP)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("k8s")  # k8s does not support storage reuse
async def test_scale_promoted_main_to_0_then_up(ops_test: OpsTest) -> None:
    """Test scaling main orchestrator to 0 and back to 1 unit."""
    # Main orchestrator is the failover app at this point
    failover_app = ops_test.model.applications[FAILOVER_APP]
    assert failover_app is not None

    storages = await ops_test.model.list_storage()
    failover_app_storages = [
        s["storage-tag"] for s in storages if failover_app.units[0].tag in s["attachments"]
    ]
    logger.info(f"Failover app storages: {failover_app_storages}")
    await failover_app.destroy_unit(failover_app.units[0].name)

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, DATA_APP_TWO],
        wait_for_exact_units=1,
    )

    # check that main app is now elected main orchestrator and that failover is None
    await assert_orchestrators(ops_test, expected_main=MAIN_APP, expected_failover=None)

    # scale back to 1 unit
    await failover_app.add_unit(attach_storage=failover_app_storages)
    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_APP_TWO],
        apps_statuses={
            MAIN_APP: [PeerClusterErrorDataStatuses.PEER_CLUSTER_MAIN_IS_REQUIRER.value],
            FAILOVER_APP: [PeerClusterStatuses.PEER_CLUSTER_NO_RELATION.value],
            DATA_APP: [PeerClusterErrorDataStatuses.WAITING_FOR_PEER_RELATION_CREATED.value],
            DATA_APP_TWO: [PeerClusterErrorDataStatuses.WAITING_FOR_PEER_RELATION_CREATED.value],
        },
    )
    await assert_orchestrators(ops_test, expected_main=MAIN_APP, expected_failover=FAILOVER_APP)

    await failover_app.remove_relation(
        f"{FAILOVER_APP}:peer-cluster-orchestrator",
        f"{MAIN_APP}:peer-cluster",
        block_until_done=True,
    )

    await ops_test.model.integrate(
        f"{MAIN_APP}:peer-cluster-orchestrator", f"{FAILOVER_APP}:peer-cluster"
    )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP, DATA_APP_TWO],
        wait_for_exact_units=1,
    )

    await assert_orchestrators(ops_test, expected_main=MAIN_APP, expected_failover=FAILOVER_APP)
