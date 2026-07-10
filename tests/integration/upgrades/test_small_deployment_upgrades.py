#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

from tests.integration.conftest import CONFIG_OPTS, MODEL_CONFIG

from ..ha.continuous_writes import ContinuousWrites
from ..ha.helpers import (
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
)
from ..helpers import APP_NAME, _series_to_base, app_name, set_watermark, wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .helpers import (
    PROFILES_REVISION,
    UPGRADE_PARAMS,
    VERSION_N,
    VERSION_N_MINUS_1,
    VERSION_N_MINUS_2,
    VERSION_TO_REVISION,
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


async def _build_env(juju: jubilant.Juju, version: str, series) -> None:
    """Deploy OpenSearch cluster from a given revision."""
    juju.model_config(MODEL_CONFIG)

    revision = VERSION_TO_REVISION[version][series]
    juju.deploy(
        OPENSEARCH_ORIGINAL_CHARM_NAME,
        app=APP_NAME,
        num_units=3,
        channel=OPENSEARCH_CHANNEL,
        revision=revision,
        base=_series_to_base(series),
        config=CONFIG_OPTS if revision > PROFILES_REVISION else {},
    )

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)

    # Relate it to OpenSearch to set up TLS.
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        juju,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        timeout=1400,
        wait_for_exact_units={
            APP_NAME: 3,
        },
        idle_period=60,
    )

    await set_watermark(juju, APP_NAME)


#######################################################################
#
#  Tests
#
#######################################################################


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_latest_from_channel(juju: jubilant.Juju, series) -> None:
    """Deploy OpenSearch."""
    await _build_env(juju, VERSION_N_MINUS_2, series)


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip("Can't upgrade between earlier versions")
# TODO: re-enable after two versions available
async def test_upgrade_to_n_minus_1(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner, series
) -> None:
    """Test upgrade from upstream (n-2) to currently n-1 built version."""
    app = (await app_name(juju)) or APP_NAME
    revision = VERSION_TO_REVISION[VERSION_N_MINUS_1][series]
    await assert_version_units(juju, app, VERSION_N_MINUS_2)
    await assert_upgrade_to_revision(juju, app=app, revision=revision)
    await assert_version_units(juju, app, VERSION_N_MINUS_1)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(juju, c_writes, [app])


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
async def test_upgrade_to_local(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner, charm
) -> None:
    """Test upgrade from n-1 to currently locally built version."""
    app = (await app_name(juju)) or APP_NAME
    await assert_upgrade_to_local(juju, app=app, charm=charm)
    await assert_version_units(juju, app, VERSION_N)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(juju, c_writes, [app])


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
async def test_deploy_from_version(juju: jubilant.Juju, version, series) -> None:
    """Deploy OpenSearch."""
    await _build_env(juju, version, series)


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
@pytest.mark.skip("Rollbacks not supported")
# TODO re-enable after rollbacks best effort support is added
async def test_upgrade_rollback_from_local(juju: jubilant.Juju, version, charm, series) -> None:
    """Test upgrade and rollback to each version available."""
    app = (await app_name(juju)) or APP_NAME
    revision = VERSION_TO_REVISION[version][series]
    await assert_version_units(juju, app, version)
    await assert_rollback_to_revision(juju, app=app, charm=charm, revision=revision)
    await assert_version_units(juju, app, version)


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
async def test_upgrade_from_version_to_local(
    juju: jubilant.Juju, c_writes: ContinuousWrites, c_writes_runner, version, charm
) -> None:
    """Test upgrade from usptream to currently locally built version."""
    app = (await app_name(juju)) or APP_NAME
    await assert_upgrade_to_local(juju, app=app, charm=charm)
    await assert_version_units(juju, app, VERSION_N)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(juju, c_writes, [app])
