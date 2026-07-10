#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from collections.abc import AsyncGenerator
from typing import Any

import jubilant
import pytest

from tests.integration.conftest import MODEL_CONFIG

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
async def failover_model(
    juju: jubilant.Juju,
) -> AsyncGenerator[jubilant.Juju, Any]:
    # deploy the failover model
    model_name = f"{juju.model}-failover"
    created = False
    try:
        juju.add_model(model_name)
        created = True
    except jubilant.CLIError:
        logger.info(f"Model {model_name} already exists")

    failover_juju = jubilant.Juju(model=model_name)
    failover_juju.model_config(MODEL_CONFIG)
    logger.info(f"Created model {model_name}")
    yield failover_juju

    if created:
        try:
            juju.destroy_model(model_name, destroy_storage=True, force=True)
        except jubilant.CLIError:
            pass


@pytest.fixture(scope="module")
async def data_model(
    juju: jubilant.Juju,
) -> AsyncGenerator[jubilant.Juju, Any]:
    # deploy the data model
    model_name = f"{juju.model}-data"
    created = False
    try:
        juju.add_model(model_name)
        created = True
    except jubilant.CLIError:
        logger.info(f"Model {model_name} already exists")

    data_juju = jubilant.Juju(model=model_name)
    data_juju.model_config(MODEL_CONFIG)
    logger.info(f"Created model {model_name}")
    yield data_juju

    if created:
        try:
            juju.destroy_model(model_name, destroy_storage=True, force=True)
        except jubilant.CLIError:
            pass
