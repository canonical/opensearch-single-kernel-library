#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging

import jubilant
import pytest

from opensearch_single_kernel.common.constants import (
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    TLS_RELATION,
    DeploymentType,
)
from opensearch_single_kernel.core.models import (
    DeploymentDescription,
    PeerClusterOrchestrators,
)
from tests.integration.conftest import CONFIG_OPTS, MODEL_CONFIG
from tests.integration.helpers import _series_to_base, wait_until
from tests.integration.relations.helpers import get_application_relation_data
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)
MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "app"

APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 1, DATA_APP: 1}

MAIN_ORCHESTRATOR_OFFER = "main-integration"
FAILOVER_ORCHESTRATOR_OFFER = "failover-integration"
CERTS_OFFER = "certs-integration"
TIMEOUT = 45 * 60


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    juju: jubilant.Juju,
    charm,
    series,
    failover_model: jubilant.Juju,
    data_model: jubilant.Juju,
) -> None:
    """Build and deploy one unit of OpenSearch."""
    juju.model_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    juju.deploy(
        charm,
        app=MAIN_APP,
        num_units=APP_UNITS[MAIN_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME} | CONFIG_OPTS,
    )
    juju.integrate(MAIN_APP, TLS_CERTIFICATES_APP_NAME)

    await wait_until(juju, apps=[MAIN_APP, TLS_CERTIFICATES_APP_NAME], timeout=TIMEOUT)
    juju.offer(
        MAIN_APP,
        endpoint=PEER_CLUSTER_ORCHESTRATOR_RELATION,
        name=MAIN_ORCHESTRATOR_OFFER,
    )
    juju.offer(
        TLS_CERTIFICATES_APP_NAME,
        endpoint=TLS_RELATION,
        name=CERTS_OFFER,
    )

    main_model_name = juju.model
    consume_main = f"admin/{main_model_name}.{MAIN_ORCHESTRATOR_OFFER}"
    consume_certs = f"admin/{main_model_name}.{CERTS_OFFER}"

    failover_model.deploy(
        charm,
        app=FAILOVER_APP,
        num_units=APP_UNITS[FAILOVER_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "init_hold": True} | CONFIG_OPTS,
    )

    logger.info("Consuming offers in failover model...")
    failover_model.consume(consume_main)
    failover_model.consume(consume_certs)
    logger.info("Adding integrations in failover model...")
    failover_model.integrate(
        f"{FAILOVER_APP}",
        f"{MAIN_ORCHESTRATOR_OFFER}:{PEER_CLUSTER_ORCHESTRATOR_RELATION}",
    )
    logger.info("Integrating certs with failover...\n")
    failover_model.integrate(f"{FAILOVER_APP}", f"{CERTS_OFFER}:{TLS_RELATION}")
    await wait_until(failover_model, apps=[FAILOVER_APP], timeout=TIMEOUT)

    failover_model.offer(
        FAILOVER_APP,
        endpoint=PEER_CLUSTER_ORCHESTRATOR_RELATION,
        name=FAILOVER_ORCHESTRATOR_OFFER,
    )

    data_model.deploy(
        charm,
        app=DATA_APP,
        num_units=APP_UNITS[DATA_APP],
        base=_series_to_base(series),
        config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data.hot,ml"}
        | CONFIG_OPTS,
    )

    consume_failover = f"admin/{failover_model.model}.{FAILOVER_ORCHESTRATOR_OFFER}"
    logger.info("Consuming offers in data model...")
    data_model.consume(consume_main)
    data_model.consume(consume_failover)
    data_model.consume(consume_certs)

    logger.info("Integrating relations in data model...")
    data_model.integrate(f"{DATA_APP}", f"{CERTS_OFFER}:{TLS_RELATION}")
    data_model.integrate(
        f"{DATA_APP}",
        f"{MAIN_ORCHESTRATOR_OFFER}:{PEER_CLUSTER_ORCHESTRATOR_RELATION}",
    )
    data_model.integrate(
        f"{DATA_APP}",
        f"{FAILOVER_ORCHESTRATOR_OFFER}:{PEER_CLUSTER_ORCHESTRATOR_RELATION}",
    )
    await wait_until(data_model, apps=[DATA_APP], timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_failover_promotion(
    juju: jubilant.Juju,
    failover_model: jubilant.Juju,
    data_model: jubilant.Juju,
) -> None:
    """Test that the failover orchestrator promotes itself

    when the majority of relations with main are severed
    """
    logger.info("Removing failover-main relation...")
    failover_model.remove_relation(
        f"{FAILOVER_APP}:{PEER_CLUSTER_RELATION}",
        f"{MAIN_ORCHESTRATOR_OFFER}:{PEER_CLUSTER_ORCHESTRATOR_RELATION}",
    )
    failover_model.wait(
        lambda status: jubilant.all_agents_idle(status, FAILOVER_APP),
        timeout=TIMEOUT,
    )
    failover_model.cli("remove-saas", MAIN_ORCHESTRATOR_OFFER)

    logger.info("Ensuring failover was not promoted...")
    unit = list(failover_model.status().apps[FAILOVER_APP].units.keys())[-1]
    deployment_desc = await get_application_relation_data(
        failover_model,
        unit_name=unit,
        relation_name=PEER_RELATION,
        key="deployment-description",
    )
    deployment_desc = DeploymentDescription.from_dict(json.loads(deployment_desc))
    assert deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR

    logger.info("Removing data-main relation...")
    data_model.remove_relation(
        f"{DATA_APP}:{PEER_CLUSTER_RELATION}",
        f"{MAIN_ORCHESTRATOR_OFFER}:{PEER_CLUSTER_ORCHESTRATOR_RELATION}",
    )
    data_model.wait(
        lambda status: jubilant.all_agents_idle(status, DATA_APP),
        timeout=TIMEOUT,
    )
    data_model.cli("remove-saas", MAIN_ORCHESTRATOR_OFFER)

    logger.info("Ensuring failover was promoted to main...")
    # get orchestrators registered in data app
    unit = list(data_model.status().apps[DATA_APP].units.keys())[-1]
    orchestrators = await get_application_relation_data(
        data_model, unit_name=unit, relation_name=PEER_RELATION, key="orchestrators"
    )
    # ensure failover is the new main and that no failover is registered
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert orchestrators.main_app.name == FAILOVER_APP
    assert orchestrators.failover_app is None
