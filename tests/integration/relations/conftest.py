#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from asyncio import sleep
from typing import Any, AsyncGenerator

import pytest
from juju.controller import Controller
from juju.model import Model
from pytest_operator.plugin import OpsTest

K8S_CLOUD_NAME = "uk8s"


@pytest.fixture(scope="module")
async def ops_test_k8s(
    request, tmp_path_factory, ops_test: OpsTest, substrate
) -> AsyncGenerator[OpsTest, Any]:
    """Create second OpsTest object, that is connected to the k8s cloud.

    Automatically creates and destroys (unless keep models parameter is used)
    corresponding Juju model. k8s and uk8s cloud are set up by spread prepare
    for OAuth tests.

    Returns:
        OpsTest object with k8s connection and Juju model.
    """
    if substrate == "k8s":
        yield ops_test
        return

    model_name = f"{ops_test.model_name}-{K8S_CLOUD_NAME}"
    request.config.option.controller = ops_test.controller_name
    request.config.option.cloud = K8S_CLOUD_NAME
    request.config.option.model = model_name
    request.config.option.model_alias = model_name
    ops_res = OpsTest(request, tmp_path_factory)
    await ops_res._setup_model()
    yield ops_res
    if not ops_test.keep_model:
        await ops_res.forget_model(alias=model_name)
        await ops_res._controller.destroy_model(model_name, destroy_storage=True, force=True)
        while model_name in await ops_res._controller.list_models():
            await sleep(5)
    await ops_res._cleanup_models()


@pytest.fixture(scope="module")
async def application_charm() -> str:
    """Build the application charm."""
    return "./tests/integration/relations/opensearch_provider/application-charm/application_ubuntu@24.04-amd64.charm"


@pytest.fixture(scope="module")
async def v1_application_charm() -> str:
    """Build the application charm."""
    return "./tests/integration/relations/opensearch_provider/application-charm-v1/v1-application_ubuntu@22.04-amd64.charm"


@pytest.fixture(scope="module")
async def k8s_model(ops_test: OpsTest, substrate) -> AsyncGenerator[Model, Any]:
    """Create new Juju model on the connected k8s cloud.

    Automatically destroys that model unless keep models parameter is used.

    Returns:
        Connected Juju model.
    """
    if substrate == "k8s":
        assert ops_test.model is not None, "OpsTest model is not connected"
        yield ops_test.model
        return
    model_name = f"{ops_test.model_name}-{K8S_CLOUD_NAME}"
    controller = Controller()
    await controller.connect()
    if model_name in await controller.list_models():
        model = await controller.get_model(model_name)
    else:
        model = await controller.add_model(model_name, cloud_name=K8S_CLOUD_NAME)

    yield model

    await model.disconnect()
    if not ops_test.keep_model:
        await controller.destroy_model(model_name, destroy_storage=True, force=True)
        while model_name in await controller.list_models():
            await asyncio.sleep(5)
    await controller.disconnect()
