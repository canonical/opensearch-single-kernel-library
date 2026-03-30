# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""K8s storage persistence tests for OpenSearch."""

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.conftest import APP_NAME, CONFIG_OPTS, IDLE_PERIOD, MODEL_CONFIG
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import storage_id, storage_type
from tests.integration.helpers import (
    app_name,
    deploy_opensearch,
    get_application_unit_ids,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)

MARKER_FILE = "/var/lib/opensearch/storage-reuse-marker"


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest, charm, series, substrate, charm_resources
) -> None:
    """Build and deploy a two-unit K8s OpenSearch application with persistent storage."""
    if substrate != "k8s":
        pytest.skip("K8s storage persistence test is only applicable to the k8s substrate.")

    if await app_name(ops_test):
        return

    await ops_test.model.set_config(MODEL_CONFIG)
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        deploy_opensearch(
            ops_test,
            charm,
            substrate,
            APP_NAME,
            2,
            series=series,
            config=CONFIG_OPTS,
            resources=charm_resources,
        ),
    )

    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        timeout=1400,
        idle_period=IDLE_PERIOD,
        wait_for_exact_units={
            TLS_CERTIFICATES_APP_NAME: 1,
            APP_NAME: 2,
        },
    )


@pytest.mark.abort_on_fail
async def test_storage_reuse_after_scale_down_k8s(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Check K8s scale down/up preserves storage-backed state for the returning unit."""
    app = (await app_name(ops_test)) or APP_NAME

    if storage_type(ops_test, app) in (None, "rootfs"):
        pytest.skip("Persistent storage is required for the K8s storage reuse scenario.")

    try:
        await c_writes.start()
        await asyncio.sleep(20)
        writes_result = await c_writes.stop()

        unit_id = max(get_application_unit_ids(ops_test, app))
        previous_storage_id = storage_id(ops_test, app, unit_id)

        return_code, _, stderr = await ops_test.juju(
            "ssh",
            f"{app}/{unit_id}",
            "bash",
            "-lc",
            f"touch {MARKER_FILE}",
        )
        assert return_code == 0, stderr

        await ops_test.model.applications[app].destroy_unit(f"{app}/{unit_id}")
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active", "blocked"],
            units_statuses=["active"],
            timeout=1000,
            idle_period=IDLE_PERIOD,
            wait_for_exact_units={app: 1},
        )

        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            timeout=1400,
            idle_period=IDLE_PERIOD,
            wait_for_exact_units={app: 2},
        )

        new_unit_id = max(get_application_unit_ids(ops_test, app))
        new_storage_id = storage_id(ops_test, app, new_unit_id)
        if previous_storage_id and new_storage_id:
            assert previous_storage_id == new_storage_id, "Storage IDs mismatch after scale cycle."

        return_code, stdout, stderr = await ops_test.juju(
            "ssh",
            f"{app}/{new_unit_id}",
            "bash",
            "-lc",
            f"test -f {MARKER_FILE} && echo found",
        )
        assert return_code == 0, stderr
        assert (
            stdout.strip() == "found"
        ), "Expected storage marker file to survive the scale cycle."

        assert writes_result.count == await c_writes.count()
        assert writes_result.max_stored_id == await c_writes.max_stored_id()
    finally:
        await c_writes.clear()
