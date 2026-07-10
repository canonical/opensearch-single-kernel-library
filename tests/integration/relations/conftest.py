#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import os

import jubilant
import pytest

MICROK8S_CLOUD_NAME = "uk8s"


@pytest.fixture(scope="module")
async def ops_test_microk8s(juju: jubilant.Juju, substrate) -> jubilant.Juju:
    """Create a jubilant.Juju instance connected to the MicroK8s cloud.

    Automatically creates and destroys (unless keep models parameter is used)
    corresponding Juju model. MicroK8s and uk8s cloud are set up by spread prepare
    for OAuth tests.

    Returns:
        jubilant.Juju object with MicroK8s connection and Juju model.
    """
    if substrate == "k8s":
        yield juju
        return

    model_name = f"{juju.model}-{MICROK8S_CLOUD_NAME}"
    k8s_juju = jubilant.Juju()
    k8s_juju.add_model(model_name, cloud=MICROK8S_CLOUD_NAME)
    yield k8s_juju
    if not os.environ.get("KEEP_MODELS"):
        k8s_juju.destroy_model(model_name, destroy_storage=True, force=True)


@pytest.fixture(scope="module")
async def application_charm() -> str:
    """Build the application charm."""
    return "./tests/integration/relations/opensearch_provider/application-charm/application_ubuntu@24.04-amd64.charm"


@pytest.fixture(scope="module")
async def microk8s_model(ops_test_microk8s: jubilant.Juju, substrate) -> jubilant.Juju:
    """Create new Juju model on the connected MicroK8s cloud.

    Automatically destroys that model unless keep models parameter is used.

    Returns:
        Connected jubilant.Juju instance.
    """
    yield ops_test_microk8s
