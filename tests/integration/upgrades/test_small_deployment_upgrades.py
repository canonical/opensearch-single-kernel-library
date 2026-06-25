#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.conftest import CONFIG_OPTS, MODEL_CONFIG

from ..ha.continuous_writes import ContinuousWrites
from ..ha.helpers import (
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
)
from ..helpers import APP_NAME, app_name, deploy_opensearch, set_watermark, wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .helpers import (
    K8S_VERSION_N,
    PROFILES_REVISION,
    UPGRADE_PARAMS,
    VM_VERSION_N,
    VM_VERSION_N_MINUS_1,
    VM_VERSION_N_MINUS_2,
    VM_VERSION_TO_REVISION,
    assert_rollback_to_revision,
    assert_upgrade_to_local,
    assert_upgrade_to_revision,
    assert_version_units,
)

logger = logging.getLogger(__name__)


OPENSEARCH_ORIGINAL_CHARM_NAME = "opensearch"
OPENSEARCH_CHANNEL = "2/edge"

charm = None


#######################################################################
#
#  Auxiliary functions
#
#######################################################################


async def _build_env(ops_test: OpsTest, version: str, series) -> None:
    """Deploy OpenSearch cluster from a given revision."""
    await ops_test.model.set_config(MODEL_CONFIG)

    revision = VM_VERSION_TO_REVISION[version][series]
    await ops_test.model.deploy(
        OPENSEARCH_ORIGINAL_CHARM_NAME,
        application_name=APP_NAME,
        num_units=3,
        channel=OPENSEARCH_CHANNEL,
        revision=revision,
        series=series,
        config=CONFIG_OPTS if revision > PROFILES_REVISION else {},
    )

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(f"{APP_NAME}:certificates", TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        timeout=1400,
        wait_for_exact_units={
            APP_NAME: 3,
        },
        idle_period=60,
    )

    await set_watermark(ops_test, APP_NAME)


#######################################################################
#
#  Tests
#
#######################################################################


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_latest_from_channel(
    ops_test: OpsTest, charm_version_minus_1, series, substrate
) -> None:
    """Deploy OpenSearch."""
    if substrate == "k8s":
        # Deploy from the local 2.18 charm to have n-1 version available
        # TODO: Once revision released deploy from channel and remove local charm
        await ops_test.model.set_config(MODEL_CONFIG)
        charm_resources = {"opensearch-image": "ghcr.io/canonical/opensearch:2.19.4-24.04_edge"}
        await deploy_opensearch(
            ops_test,
            charm_version_minus_1,
            substrate,
            APP_NAME,
            3,
            series=series,
            config=CONFIG_OPTS,
            resources=charm_resources,
        )
        # Deploy TLS Certificates operator.
        config = {"ca-common-name": "CN_CA"}
        await ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        )
        # Relate it to OpenSearch to set up TLS.
        await ops_test.model.integrate(f"{APP_NAME}:certificates", TLS_CERTIFICATES_APP_NAME)
        await wait_until(
            ops_test,
            apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
            timeout=1400,
            wait_for_exact_units={
                APP_NAME: 3,
            },
            idle_period=60,
        )

        await set_watermark(ops_test, APP_NAME)
    else:
        await _build_env(ops_test, VM_VERSION_N_MINUS_2, series)


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip("Can't upgrade between earlier versions")
# TODO: re-enable after two versions available
async def test_upgrade_to_n_minus_1(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, series, substrate
) -> None:
    """Test upgrade from upstream (n-2) to currently n-1 built version."""
    app = (await app_name(ops_test)) or APP_NAME
    revision = VM_VERSION_TO_REVISION[VM_VERSION_N_MINUS_1][series]
    await assert_version_units(ops_test, app, VM_VERSION_N_MINUS_2, substrate)
    await assert_upgrade_to_revision(ops_test, app=app, revision=revision)
    await assert_version_units(ops_test, app, VM_VERSION_N_MINUS_1, substrate)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
async def test_upgrade_to_local(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_writes_runner,
    charm,
    substrate,
    charm_resources,
) -> None:
    """Test upgrade from n-1 to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    await assert_upgrade_to_local(
        ops_test,
        app=app,
        charm=charm,
        substrate=substrate,
        charm_resources=charm_resources,
    )
    if substrate == "k8s":
        version = K8S_VERSION_N
    else:
        version = VM_VERSION_N
    await assert_version_units(ops_test, app, version, substrate)
    if substrate == "k8s":
        # Update since the ips have changed after upgrade
        await c_writes.update()

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


##################################################################################
#
#  test scenarios from each version:
#    Start with each version, moving to local and then rolling back mid-upgrade
#    Once this test passes, the 2nd test will rerun the upgrade, this time to
#    its end.
#
##################################################################################


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_from_version(ops_test: OpsTest, version, series) -> None:
    """Deploy OpenSearch."""
    await _build_env(ops_test, version, series)


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
@pytest.mark.skip("Rollbacks not supported")
# TODO re-enable after rollbacks best effort support is added
async def test_upgrade_rollback_from_local(
    ops_test: OpsTest, version, charm, series, substrate
) -> None:
    """Test upgrade and rollback to each version available."""
    app = (await app_name(ops_test)) or APP_NAME
    revision = VM_VERSION_TO_REVISION[version][series]
    await assert_version_units(ops_test, app, version, substrate)
    await assert_rollback_to_revision(ops_test, app=app, charm=charm, revision=revision)
    await assert_version_units(ops_test, app, version, substrate)


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
async def test_upgrade_from_version_to_local(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_writes_runner,
    version,
    charm,
    substrate,
) -> None:
    """Test upgrade from usptream to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    await assert_upgrade_to_local(ops_test, app=app, charm=charm, substrate=substrate)
    await assert_version_units(ops_test, app, VM_VERSION_N, substrate)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])
