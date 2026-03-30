#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import dataclasses
import logging
from collections.abc import Generator
from typing import Any

import pytest
from pytest_operator.plugin import OpsTest

from tests.helpers import Substrate
from tests.integration.conftest import APP_NAME
from tests.integration.ha.continuous_writes import ContinuousWrites, ReplicationMode
from tests.integration.ha.helpers import update_restart_delay
from tests.integration.ha.k8s_chaos_mesh import deploy_chaos_mesh, destroy_chaos_mesh
from tests.integration.helpers import (
    app_name,
    get_application_unit_ids,
)

# Wait after full-cluster kill before asserting recovery.
MEDIAN_REELECTION_TIME = 12


@dataclasses.dataclass(frozen=True)
class ConnectionInformation:
    access_key_id: str
    secret_access_key: str
    bucket: str


logger = logging.getLogger(__name__)

ORIGINAL_RESTART_DELAY = 20
SECOND_APP_NAME = "second-opensearch"
RESTART_DELAY = 360


@pytest.fixture(scope="function")
async def reset_restart_delay(ops_test: OpsTest, substrate: Substrate):
    """Resets systemd (VM) or Pebble (K8s) restart delay on all units."""
    yield
    app = (await app_name(ops_test)) or APP_NAME
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY, substrate)


@pytest.fixture(scope="function")
async def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(ops_test)) or APP_NAME
    logger.debug(f"Creating ContinuousWrites instance for app with name {app}")
    return ContinuousWrites(ops_test, app)


@pytest.fixture(scope="function")
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
async def c_0_repl_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start(repl_mode=ReplicationMode.WITH_AT_LEAST_0_REPL)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_mode=ReplicationMode.WITH_AT_LEAST_1_REPL)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="module")
def chaos_mesh(ops_test: OpsTest, substrate: Substrate) -> Generator[None, Any, Any]:
    """Install Chaos Mesh on MicroK8s for k8s HA network tests."""
    if substrate == "k8s":
        deploy_chaos_mesh(ops_test.model.info.name)
        yield
        destroy_chaos_mesh(ops_test.model.info.name)
    else:
        yield
