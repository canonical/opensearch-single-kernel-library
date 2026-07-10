#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import jubilant
import pytest
import requests

from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    IDLE_PERIOD,
    MODEL_CONFIG,
    UNIT_IDS,
)
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.helpers import (
    deploy_opensearch,
    get_leader_unit_ip,
    get_secret_by_label,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "log-app"

APP_UNITS = {MAIN_APP: 3, FAILOVER_APP: 1, DATA_APP: 1}

SMALL_DEPLOYMENT = "small"
LARGE_DEPLOYMENT = "large"
ALL_GROUPS = {
    (deploy_type): pytest.param(
        deploy_type,
        id=deploy_type,
        marks=[
            pytest.mark.group(id=deploy_type),
        ],
    )
    for deploy_type in [SMALL_DEPLOYMENT, LARGE_DEPLOYMENT]
}
ALL_DEPLOYMENTS = list(ALL_GROUPS.values())


@pytest.mark.group(id=SMALL_DEPLOYMENT)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy_active(
    juju: jubilant.Juju, charm, series, substrate, charm_resources
) -> None:
    """Build and deploy one unit of OpenSearch."""
    juju.model_config(MODEL_CONFIG)

    await deploy_opensearch(
        juju,
        charm,
        substrate,
        APP_NAME,
        len(UNIT_IDS),
        series=series,
        config=CONFIG_OPTS,
        resources=charm_resources,
    )

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    await wait_until(juju, apps=[TLS_CERTIFICATES_APP_NAME])

    # Relate it to OpenSearch to set up TLS.
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        juju,
        apps=[APP_NAME],
        timeout=1800,
        wait_for_exact_units=len(UNIT_IDS),
        idle_period=IDLE_PERIOD,
    )


@pytest.mark.group(id=LARGE_DEPLOYMENT)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_large_deployment(
    juju: jubilant.Juju, charm, series, substrate, charm_resources
) -> None:
    """Setup a large deployments cluster."""
    # deploy new cluster
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        MAIN_APP,
        3,
        series=series,
        config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager,data"} | CONFIG_OPTS,
        resources=charm_resources,
    )
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        FAILOVER_APP,
        1,
        series=series,
        config={
            "cluster_name": CLUSTER_NAME,
            "init_hold": True,
            "roles": "cluster_manager,data",
        }
        | CONFIG_OPTS,
        resources=charm_resources,
    )
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        DATA_APP,
        1,
        series=series,
        config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data"} | CONFIG_OPTS,
        resources=charm_resources,
    )
    juju.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_STABLE_CHANNEL,
        config={"ca-common-name": "CN_CA"},
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP]:
        juju.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # create the peer-cluster-relation
    juju.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    juju.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    juju.integrate(f"{DATA_APP}:{REL_PEER}", f"{FAILOVER_APP}:{REL_ORCHESTRATOR}")

    # wait for the cluster to fully form
    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
    )


@pytest.mark.parametrize("deploy_type", ALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_rollout_new_ca(juju: jubilant.Juju, deploy_type, substrate) -> None:
    """Repeat the CA rotation test for the large deployment."""
    if substrate == "k8s" and deploy_type == LARGE_DEPLOYMENT:
        pytest.skip("Large deployments are not supported on k8s.")

    if deploy_type == SMALL_DEPLOYMENT:
        app = APP_NAME
    else:
        app = DATA_APP
    c_writes = ContinuousWrites(juju, app)
    try:
        await c_writes.start()

        with open(ContinuousWrites.CERT_PATH, "r") as f:
            orig_cert = f.read()

        # trigger a rollout of the new CA by changing the config on TLS Provider side
        new_config = {"ca-common-name": "NEW_CA"}
        juju.config(TLS_CERTIFICATES_APP_NAME, new_config)

        start_count = await c_writes.count()

        if deploy_type == SMALL_DEPLOYMENT:
            await wait_until(
                juju,
                apps=[APP_NAME],
                wait_for_exact_units=len(UNIT_IDS),
                timeout=2400,
                idle_period=IDLE_PERIOD,
            )
        else:
            await wait_until(
                juju,
                apps=[MAIN_APP, DATA_APP, FAILOVER_APP],
                wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
                timeout=2400,
                idle_period=IDLE_PERIOD,
            )

        # Check if the continuous-writes client works with the new certs as well
        await c_writes.stop()
        await c_writes.start()  # Forces the Cont. Writes to pick the new cert

        with open(ContinuousWrites.CERT_PATH, "r") as f:
            new_cert = f.read()

        assert orig_cert != new_cert, "New cert was not picked up"
        await asyncio.sleep(30)
        final_count = await c_writes.count()
        await c_writes.stop()
        assert final_count > start_count, "Writes have not continued during CA rotation"

        # using the SSL API requires authentication with app-admin cert and key
        leader_unit_ip = await get_leader_unit_ip(juju, app)
        url = f"https://{leader_unit_ip}:9200/_plugins/_security/api/ssl/certs"
        admin_secret = await get_secret_by_label(juju, f"{app}:app:app-admin")

        with open("admin.cert", "w") as cert:
            cert.write(admin_secret["cert"])

        with open("admin.key", "w") as key:
            key.write(admin_secret["key"])

        response = requests.get(url, cert=("admin.cert", "admin.key"), verify=False)
        data = response.json()
        assert new_config["ca-common-name"] in data["http_certificates_list"][0]["issuer_dn"]
    finally:
        await c_writes.stop()
