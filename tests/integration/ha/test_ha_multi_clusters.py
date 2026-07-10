#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest

from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
)
from tests.integration.ha.conftest import SECOND_APP_NAME
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import assert_continuous_writes_consistency
from tests.integration.ha.helpers_data import delete_index, index_doc, search
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    _series_to_base,
    app_name,
    get_application_unit_ids,
    get_leader_unit_ip,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    juju: jubilant.Juju, charm, series, substrate, charm_resources
) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(juju):
        return

    juju.model_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    os_deploy_kwargs = {
        "app": APP_NAME,
        "num_units": 2,
        "config": CONFIG_OPTS,
    }
    if substrate != "k8s":
        os_deploy_kwargs["base"] = _series_to_base(series)
    if substrate == "k8s":
        os_deploy_kwargs["resources"] = charm_resources
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    juju.deploy(charm, **os_deploy_kwargs)

    # Relate it to OpenSearch to set up TLS.
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        juju,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(juju.status().apps[APP_NAME].units) == 2


# put this test at the end of the list of tests, as we delete an app during cleanup
# and the safeguards we have on the charm prevent us from doing so, so we'll keep
# using a unit without need - when other tests may need the unit on the CI


async def test_multi_clusters_db_isolation(
    juju: jubilant.Juju,
    charm,
    series,
    c_writes: ContinuousWrites,
    c_writes_runner,
    substrate,
    charm_resources,
) -> None:
    """Check that writes in cluster not replicated to another cluster."""
    app = (await app_name(juju)) or APP_NAME

    # remove 1 unit (for CI)
    unit_ids = get_application_unit_ids(juju, app=app)

    # deploy new cluster
    deploy_kwargs = {
        "app": SECOND_APP_NAME,
        "num_units": 1,
        "config": CONFIG_OPTS,
    }
    if substrate != "k8s":
        deploy_kwargs["base"] = _series_to_base(series)
    if substrate == "k8s":
        deploy_kwargs["resources"] = charm_resources
    juju.deploy(charm, **deploy_kwargs)
    juju.integrate(SECOND_APP_NAME, TLS_CERTIFICATES_APP_NAME)

    # wait
    await wait_until(
        juju,
        apps=[app, SECOND_APP_NAME],
        wait_for_exact_units={app: len(unit_ids), SECOND_APP_NAME: 1},
        idle_period=IDLE_PERIOD,
        timeout=1600,
    )

    index_name = "test_index_unique_cluster_dbs"

    # index document in the current cluster
    main_app_leader_unit_ip = await get_leader_unit_ip(juju, app=app)
    await index_doc(juju, app, main_app_leader_unit_ip, index_name, doc_id=1)

    # index document in second cluster
    second_app_leader_ip = await get_leader_unit_ip(juju, app=SECOND_APP_NAME)
    await index_doc(juju, SECOND_APP_NAME, second_app_leader_ip, index_name, doc_id=2)

    # fetch all documents in each cluster
    current_app_docs = await search(juju, app, main_app_leader_unit_ip, index_name)
    second_app_docs = await search(juju, SECOND_APP_NAME, second_app_leader_ip, index_name)

    # check that the only doc indexed in each cluster is different
    assert len(current_app_docs) == 1
    assert len(second_app_docs) == 1
    assert current_app_docs[0] != second_app_docs[0]

    # cleanup
    await delete_index(juju, app, main_app_leader_unit_ip, index_name)
    juju.remove_application(SECOND_APP_NAME)

    # continuous writes checks
    await assert_continuous_writes_consistency(juju, c_writes, [app])
