#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import logging
import secrets
from datetime import datetime, timedelta, timezone

import jubilant
import jwt
import pytest
import requests

from opensearch_single_kernel.common.constants import (
    JWT_CONFIG_RELATION,
)
from opensearch_single_kernel.common.statuses import JwtStatuses
from tests.integration.conftest import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
)
from tests.integration.helpers import (
    EmptyBlockedStatus,
    deploy_opensearch,
    get_leader_unit_ip,
    http_request,
    wait_until,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


ENCODING_ALGORITHM = "HS256"
DEFAULT_NUM_UNITS = 3
JWT_APP_NAME = "jwt-integrator"
REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"
MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"
CLUSTER_NAME = "log-app"
APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 1, DATA_APP: 3}


@pytest.mark.abort_on_fail
async def test_deploy_small_cluster(
    charm, series, juju: jubilant.Juju, charm_resources, substrate
) -> None:
    """Deploy OpenSearch and JWT integrator, configure and integrate them."""
    juju.model_config(MODEL_CONFIG)

    await deploy_opensearch(
        juju,
        charm,
        substrate,
        APP_NAME,
        DEFAULT_NUM_UNITS,
        series=series,
        config=CONFIG_OPTS,
        resources=charm_resources,
    )
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    # Relate it to OpenSearch to set up TLS.
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=DEFAULT_NUM_UNITS,
    )

    juju.deploy("jwt-integrator", channel="1/edge")
    await wait_until(juju, apps=[JWT_APP_NAME], apps_statuses={JWT_APP_NAME: [EmptyBlockedStatus]})


@pytest.mark.abort_on_fail
async def test_configure_and_use_jwt(juju: jubilant.Juju) -> None:
    """Configure JWT authentication and access the cluster with the token."""
    global generated_jwt
    generated_jwt = generate_json_web_token()

    logger.info("Creating signing-key secret")
    secret_name = "jwt-signing-key"
    secret_id = juju.cli(
        "add-secret", secret_name, f"signing-key={generated_jwt['signing-key']}"
    ).strip()
    juju.grant_secret(secret_name, JWT_APP_NAME)

    logger.info(f"Configuring {JWT_APP_NAME}")
    jwt_config = {
        "signing-key": secret_id,
        "roles-key": "role",
        "subject-key": "user",
    }
    juju.config(JWT_APP_NAME, jwt_config)

    logger.info(f"Integrating {APP_NAME} with {JWT_APP_NAME}")
    juju.integrate(JWT_APP_NAME, APP_NAME)

    await wait_until(
        juju,
        apps=[APP_NAME, JWT_APP_NAME],
        wait_for_exact_units={APP_NAME: DEFAULT_NUM_UNITS, JWT_APP_NAME: 1},
    )

    logger.info("Test access to `/_cat/nodes` with JWT")
    ip_address = await get_leader_unit_ip(juju, app=APP_NAME)
    url = f"https://{ip_address}:9200/_cat/nodes"
    jwt_result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert jwt_result.status_code == 200, "Request failed"
    logger.info("Access with JWT successful")

    basic_auth_result = await http_request(juju, "GET", url, resp_status_code=True)
    assert basic_auth_result == 200, "Request failed"
    logger.info("Access with Basic Auth successful")

    logger.info(f"Remove relation with {JWT_APP_NAME}")
    remove_relation_cmd = (
        f"remove-relation {JWT_APP_NAME}:{JWT_CONFIG_RELATION} {APP_NAME}:{JWT_CONFIG_RELATION}"
    )
    juju.cli(*remove_relation_cmd.split())
    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=DEFAULT_NUM_UNITS,
    )

    logger.info("Test access to `/_cat/nodes` with JWT")
    result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert result.status_code == 401, "`Unauthorized` error expected"
    logger.info("Access with JWT failed as expected")

    basic_auth_result = await http_request(juju, "GET", url, resp_status_code=True)
    assert basic_auth_result == 200, "Request failed"
    logger.info("Access with Basic Auth successful")

    # remove Opensearch to allow for follow-up test
    logger.info("Remove Opensearch cluster")
    juju.remove_application(APP_NAME)


@pytest.mark.abort_on_fail
# TODO Add when Large deployments is implemented
@pytest.mark.skip(reason="https://warthogs.atlassian.net/browse/DPE-9182")
async def test_configure_and_use_jwt_large_cluster(
    charm, series, juju: jubilant.Juju, substrate
) -> None:
    """Create a large deployment of OpenSearch."""
    logger.info("Create large deployment cluster of Opensearch")
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        MAIN_APP,
        APP_UNITS[MAIN_APP],
        series=series,
        config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager"} | CONFIG_OPTS,
    )
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        FAILOVER_APP,
        APP_UNITS[FAILOVER_APP],
        series=series,
        config={
            "cluster_name": CLUSTER_NAME,
            "init_hold": True,
            "roles": "cluster_manager",
        }
        | CONFIG_OPTS,
    )
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        DATA_APP,
        APP_UNITS[DATA_APP],
        series=series,
        config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data"} | CONFIG_OPTS,
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP]:
        juju.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # integrate large deployment cluster
    juju.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    juju.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    juju.integrate(f"{DATA_APP}:{REL_PEER}", f"{FAILOVER_APP}:{REL_ORCHESTRATOR}")

    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
    )

    logger.info(f"Integrating {DATA_APP} with {JWT_APP_NAME} - this will result in blocked status")
    juju.integrate(
        f"{JWT_APP_NAME}:{JWT_CONFIG_RELATION}",
        f"{DATA_APP}:{JWT_CONFIG_RELATION}",
    )
    await wait_until(
        juju,
        apps=[DATA_APP],
        apps_statuses={
            DATA_APP: [JwtStatuses.JWT_RELATION_INVALID.value],
        },
        wait_for_exact_units={DATA_APP: 3},
    )

    logger.info("Test access to `/_cat/nodes` with JWT")
    ip_address = await get_leader_unit_ip(juju, app=DATA_APP)
    url = f"https://{ip_address}:9200/_cat/nodes"
    result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert result.status_code == 401, "`Unauthorized` error expected"
    logger.info("Access with JWT failed as expected")

    logger.info(f"Remove relation with {DATA_APP}")
    remove_relation_cmd = (
        f"remove-relation {JWT_APP_NAME}:{JWT_CONFIG_RELATION} {DATA_APP}:{JWT_CONFIG_RELATION}"
    )
    juju.cli(*remove_relation_cmd.split())

    await wait_until(
        juju,
        apps=[DATA_APP],
        wait_for_exact_units={DATA_APP: 3},
    )

    logger.info(f"Integrating {MAIN_APP} with {JWT_APP_NAME}")
    juju.integrate(
        f"{JWT_APP_NAME}:{JWT_CONFIG_RELATION}",
        f"{MAIN_APP}:{JWT_CONFIG_RELATION}",
    )
    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
    )

    logger.info("Test access to `/_cat/nodes` with JWT")
    ip_address = await get_leader_unit_ip(juju, app=MAIN_APP)
    url = f"https://{ip_address}:9200/_cat/nodes"
    result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert result.status_code == 200, "Request failed"
    logger.info("Access with JWT successful")


def encode_str_as_base64(input_str) -> str:
    string_as_bytes = input_str.encode("ascii")
    string_as_base64 = base64.urlsafe_b64encode(string_as_bytes).decode("utf-8")
    return string_as_base64


def generate_json_web_token() -> dict[str, str]:
    """Generate a JWT specific for testing in Opensearch.

    Returns: a dictionary containing the token and the signing key.
    """
    # Secret key for signing the JWT
    signing_key = secrets.token_urlsafe(32)

    # Payload data
    payload = {
        "role": "admin",
        "user": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=60),
    }

    # Encode the token and the signing-key
    encoded_jwt = jwt.encode(payload, signing_key, algorithm=ENCODING_ALGORITHM)
    signing_key_encoded = encode_str_as_base64(signing_key)

    # Test if valid JWT
    try:
        jwt.decode(encoded_jwt, signing_key, algorithms=[ENCODING_ALGORITHM])
        logging.info("JWT successfully generated")
        return {"token": encoded_jwt, "signing-key": signing_key_encoded}
    except jwt.InvalidTokenError:
        raise
