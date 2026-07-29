#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging
import re

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from opensearch_single_kernel.common.constants import CLIENT_RELATION
from tests.integration.conftest import APP_NAME as OPENSEARCH_APP_NAME
from tests.integration.conftest import (
    CONFIG_OPTS,
    MODEL_CONFIG,
    SERIES,
)
from tests.integration.helpers import (
    EmptyBlockedStatus,
    get_application_unit_ids,
    get_leader_unit_id,
    get_leader_unit_ip,
    http_request,
    run_action,
    wait_until,
)
from tests.integration.relations.helpers import (
    get_application_relation_data,
    get_endpoints_from_relation,
    get_secret_data,
    get_secret_uri_from_relation,
    get_version_from_relation,
    ip_to_url,
    run_request,
    wait_for_relation_joined_between,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)

CLIENT_APP_NAME = "application"
SECONDARY_CLIENT_APP_NAME = "secondary-application"
DASHBOARDS_APP_NAME = "opensearch-dashboards"
V1_SECONDARY_CLIENT_APP_NAME = "v1-secondary-application"
V1_CLIENT_APP_NAME = "v1-application"
ALL_APPS = [
    OPENSEARCH_APP_NAME,
    TLS_CERTIFICATES_APP_NAME,
    V1_CLIENT_APP_NAME,
    CLIENT_APP_NAME,
    DASHBOARDS_APP_NAME,
]

NUM_UNITS = 3

FIRST_RELATION_NAME = "first-index"
SECOND_RELATION_NAME = "second-index"
V1_FIRST_RELATION_NAME = "v1-first-index"
V1_SECOND_RELATION_NAME = "v1-second-index"
DASHBOARDS_RELATION_NAME = "opensearch-client"
ADMIN_RELATION_NAME = "admin"
V1_ADMIN_RELATION_NAME = "v1-admin"
PROTECTED_INDICES = [
    ".opendistro_security",
    ".opendistro-alerting-config",
    ".opendistro-alerting-alert",
    ".opendistro-anomaly-results",
    ".opendistro-anomaly-detector",
    ".opendistro-anomaly-checkpoints",
    ".opendistro-anomaly-detection-state",
]


@pytest.mark.abort_on_fail
async def test_create_relation(
    ops_test: OpsTest,
    application_charm,
    v1_application_charm,
    charm,
    series,
    charm_resources,
    substrate,
):
    """Test basic functionality of relation interface."""
    # Deploy both charms (multiple units for each application to test that later they correctly
    # set data in the relation application databag using only the leader unit).
    new_model_conf = MODEL_CONFIG.copy()
    new_model_conf["update-status-hook-interval"] = "1m"

    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
    )

    await ops_test.model.set_config(new_model_conf)
    await asyncio.gather(
        ops_test.model.deploy(
            application_charm,
            application_name=CLIENT_APP_NAME,
        ),
        ops_test.model.deploy(v1_application_charm, application_name=V1_CLIENT_APP_NAME),
        ops_test.model.deploy(
            charm,
            application_name=OPENSEARCH_APP_NAME,
            num_units=NUM_UNITS,
            series=series,
            config=CONFIG_OPTS,
            resources=charm_resources,
            trust=substrate == "k8s",
        ),
    )
    if substrate == "vm":
        await ops_test.model.deploy(
            DASHBOARDS_APP_NAME,
            application_name=DASHBOARDS_APP_NAME,
            channel="2/edge",
            series=SERIES,
        )
    await ops_test.model.integrate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, OPENSEARCH_APP_NAME], status="active", timeout=1600
    )

    global client_relation
    global v1_client_relation
    client_relation = await ops_test.model.integrate(
        f"{OPENSEARCH_APP_NAME}:{CLIENT_RELATION}", f"{CLIENT_APP_NAME}:{FIRST_RELATION_NAME}"
    )
    v1_client_relation = await ops_test.model.integrate(
        f"{OPENSEARCH_APP_NAME}:{CLIENT_RELATION}",
        f"{V1_CLIENT_APP_NAME}:{V1_FIRST_RELATION_NAME}",
    )

    # This test shouldn't take so long
    await ops_test.model.wait_for_idle(
        apps=[OPENSEARCH_APP_NAME, CLIENT_APP_NAME, V1_CLIENT_APP_NAME],
        timeout=1600,
        status="active",
    )
    if substrate == "vm":
        await ops_test.model.wait_for_idle(
            apps=[DASHBOARDS_APP_NAME],
            timeout=1600,
        )


def _all_apps(substrate: str) -> list:
    """Return ALL_APPS, dropping dashboards on k8s where it's never deployed."""
    if substrate == "k8s":
        return [app for app in ALL_APPS if app != DASHBOARDS_APP_NAME]
    return ALL_APPS


def _get_client_relation(ops_test, endpoint_name: str = FIRST_RELATION_NAME):
    """Helper function to retrieve the client relation from the model."""
    for relation in ops_test.model.relations:
        if {CLIENT_APP_NAME, OPENSEARCH_APP_NAME} == {
            app.name for app in relation.applications
        } and endpoint_name in {end.name for end in relation.endpoints}:
            return relation
    raise Exception("Couldn't find client relation")


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_index_usage(ops_test: OpsTest, app_name: str):
    """Check we can update and delete things for both v0 and v1 client apps.

    The client application authenticates using the cert provided in the index; if this is
    invalid for any reason, the test will fail, so this test implicitly verifies that TLS works.
    """
    client_relation = _get_client_relation(ops_test)
    album = "albums" if app_name == CLIENT_APP_NAME else "albums_v1"
    relation_id = client_relation.id if app_name == CLIENT_APP_NAME else v1_client_relation.id
    relation_name = FIRST_RELATION_NAME if app_name == CLIENT_APP_NAME else V1_FIRST_RELATION_NAME

    await run_request(
        ops_test,
        unit_name=ops_test.model.applications[app_name].units[0].name,
        relation_name=relation_name,
        relation_id=relation_id,
        method="PUT",
        endpoint=f"/{album}/_doc/1?refresh=true",
        payload=re.escape(
            '{"artist": "Vulfpeck", "genre": ["Funk", "Jazz"], "title": "Thrill of the Arts"}'
        ),
    )

    run_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[app_name].units[0].name,
        endpoint=f"/{album}/_search?q=Jazz",
        method="GET",
        relation_id=relation_id,
        relation_name=relation_name,
    )
    results = json.loads(run_read_index["results"])
    logging.info(results)
    assert results.get("timed_out") is False
    assert results.get("hits", {}).get("total", {}).get("value") == 1
    assert (
        results.get("hits", {}).get("hits", [{}])[0].get("_source", {}).get("artist") == "Vulfpeck"
    )


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_bulk_index_usage(ops_test: OpsTest, app_name: str):
    """Check we can update and delete things using bulk api for both v0 and v1 client apps."""
    album = "albums" if app_name == CLIENT_APP_NAME else "albums_v1"
    data = [
        {"index": {"_index": album, "_id": "2"}},
        {"artist": "Herbie Hancock", "genre": ["Jazz"], "title": "Head Hunters"},
        {"index": {"_index": album, "_id": "3"}},
        {"artist": "Lydian Collective", "genre": ["Jazz"], "title": "Adventure"},
        {"index": {"_index": album, "_id": "4"}},
        {
            "artist": "Liquid Tension Experiment",
            "genre": ["Prog", "Metal"],
            "title": "Liquid Tension Experiment 2",
        },
    ]
    client_relation = _get_client_relation(ops_test)
    bulk_payload = "\n".join([json.dumps(line) for line in data]) + "\n"

    relation_id = client_relation.id if app_name == CLIENT_APP_NAME else v1_client_relation.id

    relation_name = FIRST_RELATION_NAME if app_name == CLIENT_APP_NAME else V1_FIRST_RELATION_NAME

    await run_request(
        ops_test,
        unit_name=ops_test.model.applications[app_name].units[0].name,
        relation_name=relation_name,
        relation_id=relation_id,
        method="POST",
        endpoint="/_bulk?refresh=true",
        payload=bulk_payload,
    )

    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[app_name].units[0].name,
        endpoint=f"/{album}/_search?q=Jazz",
        method="GET",
        relation_id=relation_id,
        relation_name=relation_name,
    )
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    assert results.get("timed_out") is False
    assert results.get("hits", {}).get("total", {}).get("value") == 3
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_version(ops_test: OpsTest, app_name: str):
    """Check version reported in the databag is consistent with the version on the charm."""
    client_relation = _get_client_relation(ops_test)
    v0 = True if app_name == CLIENT_APP_NAME else False
    relation_id = client_relation.id if v0 else v1_client_relation.id
    relation_name = FIRST_RELATION_NAME if v0 else V1_FIRST_RELATION_NAME

    run_version_request = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[app_name].units[0].name,
        method="GET",
        endpoint="/",
        relation_id=relation_id,
        relation_name=relation_name,
    )
    version = await get_version_from_relation(ops_test, f"{app_name}/0", relation_name, v0)
    logging.info(run_version_request)
    logging.info(version)
    results = json.loads(run_version_request["results"])
    assert version == results.get("version", {}).get("number"), results


# TODO add for k8s once k8s dashboards is available
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("k8s")
async def test_dashboard_relation(ops_test: OpsTest):
    """Test we can create relations with admin permissions."""
    # Add a dashboard relation and wait for them to exchange data
    await ops_test.model.integrate(OPENSEARCH_APP_NAME, DASHBOARDS_APP_NAME)
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, DASHBOARDS_APP_NAME)

    await wait_until(
        ops_test,
        apps=ALL_APPS,
        idle_period=70,
    )

    # On this request, kibanaserver user with its own password should be exposed
    secret_uri = await get_application_relation_data(
        ops_test, f"{DASHBOARDS_APP_NAME}/0", DASHBOARDS_RELATION_NAME, "secret-user"
    )
    relation_user_data = await get_secret_data(ops_test, secret_uri)
    relation_user_name = relation_user_data.get("username")
    relation_user_pwd = relation_user_data.get("password")

    assert relation_user_name == "kibanaserver"

    leader_id = await get_leader_unit_id(ops_test)
    result = await run_action(ops_test, leader_id, "get-password", {"username": "kibanaserver"})
    assert relation_user_pwd == result.response.get("password")


# TODO add for k8s once k8s dashboards is available
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("k8s")
async def test_dashboard_relation_password_change(ops_test: OpsTest):
    """Test we can create relations with admin permissions."""
    # Changing Opensearch kibanaserver password
    leader_id = await get_leader_unit_id(ops_test)
    result = await run_action(ops_test, leader_id, "get-password", {"username": "kibanaserver"})
    orig_pwd = result.response.get("password")
    result = await run_action(ops_test, leader_id, "set-password", {"username": "kibanaserver"})
    result = await run_action(ops_test, leader_id, "get-password", {"username": "kibanaserver"})
    new_pwd = result.response.get("password")
    assert orig_pwd != new_pwd

    # Checking if password also changed for the relation
    secret_uri = await get_application_relation_data(
        ops_test, f"{DASHBOARDS_APP_NAME}/0", DASHBOARDS_RELATION_NAME, "secret-user"
    )
    relation_user_data = await get_secret_data(ops_test, secret_uri)
    relation_user_name = relation_user_data.get("username")
    relation_user_pwd = relation_user_data.get("password")

    assert relation_user_name == "kibanaserver"
    assert relation_user_pwd == new_pwd

    # Double-checking
    result = await run_action(ops_test, leader_id, "get-password", {"username": "kibanaserver"})
    assert relation_user_pwd == result.response.get("password")


@pytest.mark.abort_on_fail
async def test_scaling(ops_test: OpsTest, substrate):
    """Test that scaling correctly updates endpoints in databag.

    scale_application also contains a wait_for_idle check, including checking for active status.
    Idle_period checks must be greater than 1 minute to guarantee update_status fires correctly.
    """

    async def _is_endpoint_count_valid(app: str) -> bool:
        units = get_application_unit_ids(ops_test, OPENSEARCH_APP_NAME)
        relation_name = FIRST_RELATION_NAME if app == CLIENT_APP_NAME else V1_FIRST_RELATION_NAME
        endpoints = await get_endpoints_from_relation(
            ops_test, f"{app}/0", relation_name, is_v0=(app == CLIENT_APP_NAME)
        )
        return len(units) == len(endpoints.split(","))

    for app_name in [CLIENT_APP_NAME, V1_CLIENT_APP_NAME]:
        assert await _is_endpoint_count_valid(app_name)

    await wait_until(ops_test, apps=_all_apps(substrate), idle_period=70)

    # Test scale down
    opensearch_unit_ids = get_application_unit_ids(ops_test, OPENSEARCH_APP_NAME)
    if substrate == "k8s":
        await ops_test.model.applications[OPENSEARCH_APP_NAME].scale(scale_change=-1)
    else:
        await ops_test.model.applications[OPENSEARCH_APP_NAME].destroy_unit(
            f"{OPENSEARCH_APP_NAME}/{max(opensearch_unit_ids)}"
        )
    await wait_until(
        ops_test,
        apps=[OPENSEARCH_APP_NAME, CLIENT_APP_NAME],
        wait_for_exact_units={OPENSEARCH_APP_NAME: len(opensearch_unit_ids) - 1},
        idle_period=70,
    )
    for app_name in [CLIENT_APP_NAME, V1_CLIENT_APP_NAME]:
        assert await _is_endpoint_count_valid(app_name)

    # test scale back up again
    await ops_test.model.applications[OPENSEARCH_APP_NAME].add_unit(count=1)
    await wait_until(
        ops_test,
        apps=[OPENSEARCH_APP_NAME, CLIENT_APP_NAME],
        wait_for_exact_units={OPENSEARCH_APP_NAME: len(opensearch_unit_ids)},
        idle_period=50,  # slightly less than update-status-interval period
    )
    # Now, we want to sleep until an update-status happens
    await asyncio.sleep(30)
    for app_name in [CLIENT_APP_NAME, V1_CLIENT_APP_NAME]:
        assert await _is_endpoint_count_valid(app_name)


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_multiple_relations(
    ops_test: OpsTest,
    application_charm,
    v1_application_charm,
    substrate,
    app_name,
):
    """Test that two different applications can connect to the database."""
    # scale-down for CI
    logger.info("Removing 1 unit for CI..")
    opensearch_unit_ids = get_application_unit_ids(ops_test, app=OPENSEARCH_APP_NAME)
    expected_opensearch_units = len(opensearch_unit_ids) - 1
    if substrate == "k8s":
        await ops_test.model.applications[OPENSEARCH_APP_NAME].scale(scale_change=-1)
    else:
        await ops_test.model.applications[OPENSEARCH_APP_NAME].destroy_unit(
            f"{OPENSEARCH_APP_NAME}/{max(opensearch_unit_ids)}"
        )

    # Wait for the scale-down to actually complete before moving on: a fixed sleep here is
    # racy since k8s pod removal (and any shard relocation) isn't guaranteed to finish within it.
    await wait_until(
        ops_test,
        apps=[OPENSEARCH_APP_NAME],
        wait_for_exact_units={OPENSEARCH_APP_NAME: expected_opensearch_units},
        idle_period=70,
    )

    # Deploy secondary application.
    v0 = True if app_name == CLIENT_APP_NAME else False
    charm = application_charm if v0 else v1_application_charm
    name = SECONDARY_CLIENT_APP_NAME if v0 else V1_SECONDARY_CLIENT_APP_NAME
    relation_name = SECOND_RELATION_NAME if v0 else V1_SECOND_RELATION_NAME
    logger.info(f"Deploying 1 unit of {app_name} with name {name}")
    await ops_test.model.deploy(charm, num_units=1, application_name=name)

    # Relate the new application and wait for them to exchange connection data.
    logger.info(f"Adding relation {name}:{relation_name} with {OPENSEARCH_APP_NAME}")

    relation = await ops_test.model.integrate(OPENSEARCH_APP_NAME, f"{name}:{relation_name}")

    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, name)
    units = {
        OPENSEARCH_APP_NAME: expected_opensearch_units,
        CLIENT_APP_NAME: 1,
        SECONDARY_CLIENT_APP_NAME: 1,
        TLS_CERTIFICATES_APP_NAME: 1,
        V1_CLIENT_APP_NAME: 1,
    }
    if not v0:
        units[V1_SECONDARY_CLIENT_APP_NAME] = 1

    await wait_until(
        ops_test,
        apps=_all_apps(substrate) + [name],
        wait_for_exact_units=units,
        idle_period=70,
        timeout=2000,
    )

    # Test that the permissions are respected between relations by running the same request as
    # before, but expecting it to fail. SECOND_RELATION_NAME doesn't contain permissions for the
    # `albums` index, so we are expecting a 403 forbidden error.
    album = "albums" if v0 else "albums_v1"
    unit = ops_test.model.applications[name].units[0]

    run_read_index = await run_request(
        ops_test,
        unit_name=unit.name,
        endpoint=f"/{album}/_search?q=Jazz",
        method="GET",
        relation_id=relation.id,
        relation_name=relation_name,
    )

    results = json.loads(run_read_index["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results

    # Restore the unit removed above so OpenSearch returns to full size before the next test.
    # This test is parametrized over [application, v1-application] and the scale-down has no
    # matching scale-up, so without this the removals stack across parameters and leave OpenSearch
    # on a single node. On one node every client index (default number_of_replicas=1) has an
    # unassignable replica, so the cluster stays yellow/blocked and later relation provisioning
    # races against run_request's retry budget.
    logger.info("Restoring 1 unit after CI scale-down..")
    if substrate == "k8s":
        await ops_test.model.applications[OPENSEARCH_APP_NAME].scale(scale_change=1)
    else:
        await ops_test.model.applications[OPENSEARCH_APP_NAME].add_unit(count=1)

    # No SCALE_DOWN_STATUSES override here: wait for OpenSearch to return to *active* (green) with
    # replicas reassigned, so the next test starts from a healthy cluster.
    await wait_until(
        ops_test,
        apps=_all_apps(substrate) + [name],
        wait_for_exact_units={OPENSEARCH_APP_NAME: len(opensearch_unit_ids)},
        idle_period=70,
        timeout=2000,
    )


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_multiple_relations_accessing_same_index(ops_test: OpsTest, app_name, substrate):
    """Test that two different applications can connect to the database."""
    # Relate the new application and wait for them to exchange connection data.
    v0 = True if app_name == CLIENT_APP_NAME else False
    name = SECONDARY_CLIENT_APP_NAME if v0 else V1_SECONDARY_CLIENT_APP_NAME
    relation_name = FIRST_RELATION_NAME if v0 else V1_FIRST_RELATION_NAME

    relation = await ops_test.model.integrate(OPENSEARCH_APP_NAME, f"{name}:{relation_name}")

    # test_multiple_relations restores OpenSearch to full size, so require *active* (green) here
    # rather than tolerating scale-down statuses: only proceed once the cluster is healthy and the
    # new relation's credentials are actually provisioned.
    await wait_until(
        ops_test,
        apps=_all_apps(substrate) + [name],
        idle_period=70,
    )

    # Test that different applications can access the same index if they present it in their
    # relation databag. FIRST_RELATION_NAME contains `albums` in its databag, so we should be able
    # to query that index if we want.
    unit = ops_test.model.applications[name].units[0]
    album = "albums" if v0 else "albums_v1"
    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=unit.name,
        endpoint=f"/{album}/_search?q=Jazz",
        method="GET",
        relation_id=relation.id,
        relation_name=relation_name,
    )
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_admin_relation(ops_test: OpsTest, app_name, substrate):
    """Test we can create relations with admin permissions."""
    # Add an admin relation and wait for them to exchange data
    global admin_relation
    global v1_admin_relation

    v0 = True if app_name == CLIENT_APP_NAME else False
    name = CLIENT_APP_NAME if v0 else V1_CLIENT_APP_NAME
    secondary_name = SECONDARY_CLIENT_APP_NAME if v0 else V1_SECONDARY_CLIENT_APP_NAME
    relation_name = ADMIN_RELATION_NAME if v0 else V1_ADMIN_RELATION_NAME

    relation = await ops_test.model.integrate(OPENSEARCH_APP_NAME, f"{name}:{relation_name}")

    if v0:
        admin_relation = relation
        relation_id = admin_relation.id
    else:
        v1_admin_relation = relation
        relation_id = v1_admin_relation.id

    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, name)
    await wait_until(
        ops_test,
        apps=_all_apps(substrate) + [secondary_name],
        idle_period=70,
    )

    # Verify we can access whatever data we like as admin
    album = "albums" if v0 else "albums_v1"
    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[name].units[0].name,
        endpoint=f"/{album}/_search?q=Jazz",
        method="GET",
        relation_id=relation_id,
        relation_name=relation_name,
    )
    logging.info(f"{run_bulk_read_index=}")
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_admin_permissions(ops_test: OpsTest, app_name: str):
    """Test admin permissions behave the way we want for both v0 and v1 client apps.

    admin-only actions include:
    - creating multiple indices
    - removing indices they've created
    - set cluster roles.

    verify that:
    - we can't remove .opendistro_security index
      - otherwise create client-admin-role
    - verify neither admin nor default users can access user api
      - otherwise create client-default-role
    """
    v0 = True if app_name == CLIENT_APP_NAME else False
    admin_rel_name = ADMIN_RELATION_NAME if v0 else V1_ADMIN_RELATION_NAME
    admin_rel_id = admin_relation.id if v0 else v1_admin_relation.id
    first_rel_name = FIRST_RELATION_NAME if v0 else V1_FIRST_RELATION_NAME
    test_unit = ops_test.model.applications[app_name].units[0]

    # Verify admin can't access security API
    run_dump_users = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint="/_plugins/_security/api/internalusers",
        method="GET",
        relation_id=admin_rel_id,
        relation_name=admin_rel_name,
    )
    results = json.loads(run_dump_users["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results

    # verify admin can't delete users
    secret_uri = await get_secret_uri_from_relation(
        ops_test, f"{app_name}/0", first_rel_name, is_v0=v0
    )

    user_data = await get_secret_data(ops_test, secret_uri)
    relation_user = user_data.get("username")

    run_delete_users = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint=f"/_plugins/_security/api/internalusers/{relation_user}",
        method="DELETE",
        relation_id=admin_rel_id,
        relation_name=admin_rel_name,
    )
    results = json.loads(run_delete_users["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results

    # verify admin can't modify protected indices
    for protected_index in PROTECTED_INDICES:
        run_remove_distro = await run_request(
            ops_test,
            unit_name=test_unit.name,
            endpoint=f"/{protected_index}",
            method="DELETE",
            relation_id=admin_rel_id,
            relation_name=admin_rel_name,
        )
        results = json.loads(run_remove_distro["results"])
        logging.info(results)
        assert "Error:" in results[0], results


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_normal_user_permissions(ops_test: OpsTest, app_name: str):
    """Test normal user permissions behave the way we want for both v0 and v1 client apps."""
    v0 = True if app_name == CLIENT_APP_NAME else False
    relation_id = client_relation.id if v0 else v1_client_relation.id
    relation_name = FIRST_RELATION_NAME if v0 else V1_FIRST_RELATION_NAME
    test_unit = ops_test.model.applications[app_name].units[0]

    run_dump_users = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint="/_plugins/_security/api/internalusers",
        method="GET",
        relation_id=relation_id,
        relation_name=relation_name,
    )
    results = json.loads(run_dump_users["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results

    secret_uri = await get_secret_uri_from_relation(
        ops_test, f"{app_name}/0", relation_name, is_v0=v0
    )
    user_data = await get_secret_data(ops_test, secret_uri)
    relation_user = user_data.get("username")

    run_delete_users = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint=f"/_plugins/_security/api/internalusers/{relation_user}",
        method="DELETE",
        relation_id=relation_id,
        relation_name=relation_name,
    )
    results = json.loads(run_delete_users["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results

    # verify user can't modify protected indices
    for protected_index in PROTECTED_INDICES:
        run_remove_index = await run_request(
            ops_test,
            unit_name=test_unit.name,
            endpoint=f"/{protected_index}",
            method="DELETE",
            relation_id=relation_id,
            relation_name=relation_name,
        )
        results = json.loads(run_remove_index["results"])
        logging.info(results)
        assert "Error:" in results[0], results


@pytest.mark.abort_on_fail
async def test_relation_broken(ops_test: OpsTest):
    """Test that the user is removed when the relation is broken for both v0 and v1 clients."""
    users_to_check = []
    for app_name in [CLIENT_APP_NAME, V1_CLIENT_APP_NAME]:
        v0 = True if app_name == CLIENT_APP_NAME else False
        relation_name = FIRST_RELATION_NAME if v0 else V1_FIRST_RELATION_NAME
        secret_uri = await get_secret_uri_from_relation(
            ops_test, f"{app_name}/0", relation_name, is_v0=v0
        )
        user_data = await get_secret_data(ops_test, secret_uri)
        users_to_check.append(user_data.get("username"))

    await wait_until(
        ops_test,
        apps=[OPENSEARCH_APP_NAME, CLIENT_APP_NAME],
        idle_period=70,
    )

    # Break both relations simultaneously.
    await asyncio.gather(
        ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
            f"{OPENSEARCH_APP_NAME}:{CLIENT_RELATION}", f"{CLIENT_APP_NAME}:{FIRST_RELATION_NAME}"
        ),
        ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
            f"{OPENSEARCH_APP_NAME}:{CLIENT_RELATION}", f"{CLIENT_APP_NAME}:{ADMIN_RELATION_NAME}"
        ),
        ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
            f"{OPENSEARCH_APP_NAME}:{CLIENT_RELATION}",
            f"{V1_CLIENT_APP_NAME}:{V1_FIRST_RELATION_NAME}",
        ),
        ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
            f"{OPENSEARCH_APP_NAME}:{CLIENT_RELATION}",
            f"{V1_CLIENT_APP_NAME}:{V1_ADMIN_RELATION_NAME}",
        ),
    )

    await asyncio.gather(
        wait_until(
            ops_test,
            apps=[CLIENT_APP_NAME, V1_CLIENT_APP_NAME],
            apps_statuses={
                CLIENT_APP_NAME: [EmptyBlockedStatus],
                V1_CLIENT_APP_NAME: [EmptyBlockedStatus],
            },
            units_statuses={
                CLIENT_APP_NAME: [EmptyBlockedStatus],
                V1_CLIENT_APP_NAME: [EmptyBlockedStatus],
            },
            idle_period=70,
        ),
        wait_until(
            ops_test,
            apps=[
                OPENSEARCH_APP_NAME,
                TLS_CERTIFICATES_APP_NAME,
                SECONDARY_CLIENT_APP_NAME,
                V1_SECONDARY_CLIENT_APP_NAME,
            ],
            idle_period=70,
        ),
    )

    # The leader removes client users asynchronously in its relation-broken handler (and, as a
    # backstop, on update-status). A juju-idle wait does not guarantee that cleanup has completed,
    # so poll OpenSearch until the users are actually gone rather than asserting on a single
    # snapshot. The timeout covers the ~5-min update-status backstop in case relation-broken was
    # skipped (e.g. the leader's node was briefly down during the break).
    leader_ip = await get_leader_unit_ip(ops_test)
    for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(15)):
        with attempt:
            users = await http_request(
                ops_test,
                "GET",
                f"https://{ip_to_url(leader_ip)}:9200/_plugins/_security/api/internalusers/",
                verify=False,
            )
            lingering = [user for user in users_to_check if user in users.keys()]
            logger.info(f"Checking removal of users {users_to_check}; still present: {lingering}")
            assert not lingering, f"Users {lingering!r} were not removed after relation break"


@pytest.mark.abort_on_fail
@pytest.mark.parametrize("app_name", [CLIENT_APP_NAME, V1_CLIENT_APP_NAME])
async def test_data_persists_on_relation_rejoin(ops_test: OpsTest, app_name: str, substrate):
    """Verify that if we recreate a relation, we can access the same index for both v0 and v1."""
    v0 = True if app_name == CLIENT_APP_NAME else False
    relation_name = FIRST_RELATION_NAME if v0 else V1_FIRST_RELATION_NAME
    album = "albums" if v0 else "albums_v1"

    new_relation = await ops_test.model.integrate(
        f"{OPENSEARCH_APP_NAME}:{CLIENT_RELATION}", f"{app_name}:{relation_name}"
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, app_name)

    apps_to_wait = [
        OPENSEARCH_APP_NAME,
        TLS_CERTIFICATES_APP_NAME,
        app_name,
        SECONDARY_CLIENT_APP_NAME,
        V1_SECONDARY_CLIENT_APP_NAME,
    ]
    if substrate == "vm":
        apps_to_wait.append(DASHBOARDS_APP_NAME)

    await wait_until(
        ops_test,
        apps=apps_to_wait,
        idle_period=70,
    )

    expected_artists = {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}

    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[app_name].units[0].name,
        endpoint=f"/{album}/_search?q=Jazz",
        method="GET",
        relation_id=new_relation.id,
        relation_name=relation_name,
    )
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    assert results.get("timed_out") is False
    assert results.get("hits", {}).get("total", {}).get("value") == 3
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == expected_artists
