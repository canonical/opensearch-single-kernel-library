#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess
import time

import jubilant
import pytest

from opensearch_single_kernel.common.statuses import TlsStatuses
from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
    UNIT_IDS,
)
from tests.integration.helpers import (
    check_cluster_formation_successful,
    cluster_health,
    deploy_opensearch,
    get_application_unit_ids,
    get_application_unit_ids_ips,
    get_application_unit_ips_names,
    get_application_unit_names,
    get_leader_unit_id,
    get_leader_unit_ip,
    run_action,
    wait_until,
)
from tests.integration.tls.helpers import (
    check_security_index_initialised,
    check_unit_tls_configured,
    get_loaded_tls_certificates,
)

logger = logging.getLogger(__name__)


TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"
# TODO update the docs to reflect the new channel once released
TLS_STABLE_CHANNEL = "1/stable"
# The expiry time of the secret carrying the certificate is set to 3 minutes for testing
SECRET_EXPIRY_TIME = 180
# Wait time for the secret to expire and be renewed
SECRET_EXPIRY_WAIT_TIME = SECRET_EXPIRY_TIME + 60


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
        wait_for_exact_units=len(UNIT_IDS),
    )
    assert len(juju.status().apps[APP_NAME].units) == len(UNIT_IDS)


@pytest.mark.abort_on_fail
async def test_security_index_initialised(juju: jubilant.Juju) -> None:
    """Test that the security index is well initialised."""
    # Wait for the leader unit to initialize the security index.
    leader_unit_ip = await get_leader_unit_ip(juju)
    assert await check_security_index_initialised(juju, leader_unit_ip)


@pytest.mark.abort_on_fail
async def test_tls_configured(juju: jubilant.Juju) -> None:
    """Test that TLS is enabled when relating to the TLS Certificates Operator."""
    for unit_name, unit_ip in (await get_application_unit_ips_names(juju)).items():
        assert await check_unit_tls_configured(juju, unit_ip, unit_name)


@pytest.mark.abort_on_fail
async def test_cluster_formation_after_tls(juju: jubilant.Juju) -> None:
    """Test that the cluster formation is successful after TLS setup."""
    unit_names = get_application_unit_names(juju)
    leader_unit_ip = await get_leader_unit_ip(juju)

    assert await check_cluster_formation_successful(juju, leader_unit_ip, unit_names)


@pytest.mark.abort_on_fail
async def test_tls_renewal(juju: jubilant.Juju, substrate) -> None:
    """Test that renewed TLS certificates are reloaded immediately without restarting."""
    leader_unit_ip = await get_leader_unit_ip(juju)
    leader_id = await get_leader_unit_id(juju)
    non_leader_id = [
        unit_id for unit_id in get_application_unit_ids(juju) if unit_id != leader_id
    ][0]
    units = await get_application_unit_ids_ips(juju, APP_NAME)

    # test against the leader unit for unit-transport cert
    current_certs = await get_loaded_tls_certificates(juju, leader_unit_ip)
    await run_action(juju, leader_id, "set-tls-private-key", params={"category": "unit-transport"})

    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=len(UNIT_IDS),
        idle_period=10,
        timeout=90,
    )

    updated_certs = await get_loaded_tls_certificates(juju, leader_unit_ip)
    assert (
        updated_certs["transport_certificates_list"][0]["not_before"]
        > current_certs["transport_certificates_list"][0]["not_before"]
    )

    # test against a random non-leader unit for unit-http cert
    current_certs = await get_loaded_tls_certificates(juju, units[non_leader_id])
    await run_action(
        juju,
        non_leader_id,
        action_name="set-tls-private-key",
        params={"category": "unit-http"},
    )

    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=len(UNIT_IDS),
        idle_period=10,
        timeout=90,
    )

    updated_certs = await get_loaded_tls_certificates(juju, units[non_leader_id])
    assert (
        updated_certs["http_certificates_list"][0]["not_before"]
        > current_certs["http_certificates_list"][0]["not_before"]
    )


@pytest.mark.abort_on_fail
async def test_tls_expiration(
    juju: jubilant.Juju, charm, series, substrate, charm_resources
) -> None:
    """Test that expiring TLS certificates are renewed."""
    # before we can run this test, need to clean up and deploy with different config
    if APP_NAME in juju.status().apps:
        logger.info(f"Removing application {APP_NAME}")
        juju.remove_application(APP_NAME, destroy_storage=True)
    if TLS_CERTIFICATES_APP_NAME in juju.status().apps:
        logger.info(f"Removing application {TLS_CERTIFICATES_APP_NAME}")
        juju.remove_application(TLS_CERTIFICATES_APP_NAME, destroy_storage=True)
    juju.wait(
        lambda status: APP_NAME not in status.apps and TLS_CERTIFICATES_APP_NAME not in status.apps
    )

    # Deploy TLS Certificates operator
    logger.info("Deploying TLS Certificates operator")
    config = {"ca-common-name": "CN_CA", "certificate-validity": "1"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    await wait_until(juju, apps=[TLS_CERTIFICATES_APP_NAME])

    # Deploy Opensearch operator
    juju.model_config(MODEL_CONFIG)

    logger.info("Deploying OpenSearch")
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        APP_NAME,
        1,
        series=series,
        config=CONFIG_OPTS,
        resources=charm_resources,
    )

    await wait_until(
        juju,
        apps=[APP_NAME],
        apps_statuses={APP_NAME: [TlsStatuses.TLS_RELATION_MISSING.value]},
        units_statuses={APP_NAME: [TlsStatuses.TLS_RELATION_MISSING.value]},
        wait_for_exact_units=1,
    )

    # Change the expiry time of the secret carrying the certificate to 3 minutes for testing
    logger.info("Changing the expiry time of the secret carrying the certificate to 3 minutes")
    unit_id = get_application_unit_ids(juju, APP_NAME)[0]
    search_expression = "expire=self._get_next_secret_expiry_time\\(certificate\\)"
    replace_expression = f"expire=timedelta\\(seconds={SECRET_EXPIRY_TIME}\\)"
    python_version = "python3.12" if series == "noble" else "python3.10"

    lib_file = f"/var/lib/juju/agents/unit-opensearch-{unit_id}/charm/venv/lib/{python_version}/site-packages/opensearch_single_kernel/lib/charms/tls_certificates_interface/v3/tls_certificates.py"
    sudo = ""
    # VM uses root user
    if substrate == "vm":
        sudo = "sudo"
    cmd = f"juju ssh {APP_NAME}/{unit_id} {sudo} sed -i 's/{search_expression}/{replace_expression}/g' {lib_file}"
    logger.info(f"Running command: {cmd}")
    subprocess.check_output(cmd, shell=True)

    # Relate OpenSearch to TLS and wait until all is settled
    logger.info("Integrating OpenSearch with TLS Certificates operator")
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)

    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=1,
    )

    # wait for the unit to be ready and API's available
    logger.info("Test cluster health")
    unit_ip = await get_leader_unit_ip(juju)
    cluster_health_resp = await cluster_health(juju, unit_ip, wait_for_green_first=True)
    assert cluster_health_resp["status"] == "green"

    # now start with the actual test
    # first get the currently used certs
    current_certs = await get_loaded_tls_certificates(juju, unit_ip)

    # now wait for the expiration period to pass by (and a bit longer for things to settle)
    # we can't use `wait_until` here because the unit might not be idle in the meantime
    # please note: minimum waiting time is 60 minutes, due to limitations on the tls-operator
    logger.info(
        f"Waiting for certificates to expire. Wait time: {SECRET_EXPIRY_WAIT_TIME / 60} minutes."
    )
    time.sleep(SECRET_EXPIRY_WAIT_TIME)

    logger.info("Test cluster health after certificate expiry")
    cluster_health_resp = await cluster_health(juju, unit_ip, wait_for_green_first=True)
    assert cluster_health_resp["status"] == "green"

    # now compare the current certificates against the earlier ones and see if they were updated
    updated_certs = await get_loaded_tls_certificates(juju, unit_ip)
    logger.info("Comparing certificates before and after expiry")
    logger.info(f"Certs: {current_certs}, {updated_certs}")
    assert (
        updated_certs["transport_certificates_list"][0]["not_before"]
        > current_certs["transport_certificates_list"][0]["not_before"]
    )

    assert (
        updated_certs["http_certificates_list"][0]["not_before"]
        > current_certs["http_certificates_list"][0]["not_before"]
    )
