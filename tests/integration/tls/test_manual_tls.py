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
    UNIT_IDS,
)
from tests.integration.helpers import (
    EmptyActiveStatus,
    EmptyMaintenanceStatus,
    deploy_opensearch,
    wait_until,
)
from tests.integration.tls.helpers_manual_tls import (
    MANUAL_TLS_CERTIFICATES_APP_NAME,
    ManualTLSAgent,
)

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy_with_manual_tls(
    juju: jubilant.Juju, charm, series, substrate, charm_resources
) -> None:
    """Build and deploy prod cluster of OpenSearch with Manual TLS Operator integration."""
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
    juju.deploy(
        MANUAL_TLS_CERTIFICATES_APP_NAME,
        channel="stable",
    )
    await wait_until(
        juju,
        apps=[MANUAL_TLS_CERTIFICATES_APP_NAME],
    )
    logger.info("Deployed %s application", MANUAL_TLS_CERTIFICATES_APP_NAME)

    # Integrate it to OpenSearch to set up TLS.
    juju.integrate(APP_NAME, MANUAL_TLS_CERTIFICATES_APP_NAME)
    logger.info("Integrated %s with %s", APP_NAME, MANUAL_TLS_CERTIFICATES_APP_NAME)

    # Initialize the ManualTLSAgent to process the CSRs
    tls_unit_name = next(iter(juju.status().apps[MANUAL_TLS_CERTIFICATES_APP_NAME].units))
    manual_tls_daemon = ManualTLSAgent(juju, tls_unit_name)
    # Wait for len(UNIT_IDS)*2+1 CSRs to be created.
    # 1 for each unit for http and transport and 1 for the admin cert.
    logger.info("Waiting for CSRs to be created")
    await manual_tls_daemon.wait_for_csrs_in_queue(len(UNIT_IDS) * 2 + 1)

    # Sign all CSRs
    logger.info("Signing CSRs")
    await manual_tls_daemon.process_queue()

    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=len(UNIT_IDS),
        timeout=2000,
    )
    assert len(juju.status().apps[APP_NAME].units) == len(UNIT_IDS)

    logger.info("Scaling up the application by adding a new unit")

    if substrate == "k8s":
        # K8s integration currently supports only a single OpenSearch unit.
        current_scale = len(juju.status().apps[APP_NAME].units)
        juju.cli("scale-application", APP_NAME, str(current_scale + 1))
    else:
        # Scale up the application by adding a new unit
        juju.add_unit(APP_NAME, num_units=1)

    # Wait for the new unit to be in maintenance
    logger.info("Waiting for the new unit to be in maintenance waiting for certificates")
    await wait_until(
        juju,
        apps=[APP_NAME],
        units_statuses={APP_NAME: [EmptyActiveStatus, EmptyMaintenanceStatus]},
        wait_for_exact_units=len(UNIT_IDS) + 1,
    )

    # Wait for the new unit request certificates
    logger.info("Waiting for the new unit to request certificates")
    await manual_tls_daemon.wait_for_csrs_in_queue(2)

    # Sign all CSRs
    logger.info("Signing CSRs")
    await manual_tls_daemon.process_queue()

    # Wait for the new unit to be active
    logger.info("Waiting for the new unit to be active")
    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=len(UNIT_IDS) + 1,
    )
    assert len(juju.status().apps[APP_NAME].units) == len(UNIT_IDS) + 1
