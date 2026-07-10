#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

from ..ha.continuous_writes import ContinuousWrites
from ..helpers import APP_NAME, app_name

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
async def c_writes(juju: jubilant.Juju):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(juju)) or APP_NAME
    return ContinuousWrites(juju, app)


@pytest.fixture(scope="function")
async def c_writes_runner(juju: jubilant.Juju, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")
