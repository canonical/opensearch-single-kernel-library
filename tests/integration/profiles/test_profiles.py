# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.


import logging

import jubilant
import pytest
from requests import request

from opensearch_single_kernel.common.constants import (
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
)
from opensearch_single_kernel.common.statuses import (
    PeerClusterStatuses,
    ProfileStatuses,
)
from opensearch_single_kernel.utils.status import format_status
from tests.integration.conftest import (
    APP_NAME,
    MODEL_CONFIG,
)
from tests.integration.helpers import (
    deploy_opensearch,
    get_cloud_type,
    get_leader_unit_ip,
    get_secrets,
    wait_until,
)
from tests.integration.tls.conftest import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)

THREE_CM_THREE_DATA_STATUS = format_status(
    ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value,
    {"requirements": "At least 3 cluster manager nodes and 3 data nodes are required."},
)

MEMORY_NOT_ENOUGH_STATUS = format_status(
    ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value,
    {"requirements": "Insufficient memory: 3145728.0 < 8388608"},
)


async def check_heap_size(juju: jubilant.Juju, heap_size_in_gb: int, app_name: str = APP_NAME):
    """A dummy test to make pytest happy when all other tests are skipped."""
    unit_ip = await get_leader_unit_ip(juju, app=app_name)

    secrets = await get_secrets(juju, app=app_name)
    assert secrets is not None
    password = secrets.get("password")
    assert password is not None, "Password should not be None"

    # request the OpenSearch endpoint to get the JVM settings
    jvm_response = request(
        "GET",
        f"https://{unit_ip}:9200/_nodes/stats/jvm",
        verify=False,
        auth=("admin", password),
    )
    assert jvm_response.status_code == 200, f"Failed to get JVM stats: {jvm_response.text}"
    jvm_info = jvm_response.json()
    assert "nodes" in jvm_info, "No nodes information in JVM stats"
    for node_id, node_info in jvm_info["nodes"].items():
        assert "jvm" in node_info, f"No JVM information for node {node_id}"
        jvm_mem = node_info["jvm"]["mem"]
        heap_max_in_bytes = jvm_mem["heap_max_in_bytes"]
        # Check that the heap size is set to 4GB (in bytes)
        assert (
            heap_max_in_bytes == heap_size_in_gb * 1024 * 1024 * 1024
        ), f"Heap size is not {heap_size_in_gb}GB: {heap_max_in_bytes}"


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    juju: jubilant.Juju, charm, series, substrate, charm_resources
) -> None:
    """Build and deploy one unit of OpenSearch."""
    juju.model_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    juju.deploy(TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config)
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        APP_NAME,
        1,
        series=series,
        constraints="mem=8G",
        config={"profile": "production"},
        resources=charm_resources,
    )

    # Relate it to OpenSearch to set up TLS.
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)


@pytest.mark.abort_on_fail
async def test_wait_blocked_cluster_topology(juju: jubilant.Juju) -> None:
    """Wait for blocked cluster with cluster topology error."""
    await wait_until(
        juju,
        apps=[APP_NAME],
        units_statuses={APP_NAME: [THREE_CM_THREE_DATA_STATUS]},
        wait_for_exact_units=1,
    )


@pytest.mark.abort_on_fail
async def test_scale_to_active(juju: jubilant.Juju) -> None:
    """Scale the OpenSearch cluster to the active state."""
    juju.add_unit(APP_NAME, num_units=2)
    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=3,
    )

    await check_heap_size(juju, 4)


@pytest.mark.abort_on_fail
async def test_insufficient_memory(
    juju: jubilant.Juju, charm: str, series: str, substrate, charm_resources
) -> None:
    """Test insufficient memory scenario."""
    cloud_name = await get_cloud_type(juju)
    if cloud_name not in {"kubernetes", "lxd"}:
        pytest.skip("This test is only applicable for Kubernetes and LXD cloud types")

    if APP_NAME in juju.status().apps:
        juju.remove_application(APP_NAME)

    await deploy_opensearch(
        juju,
        charm,
        substrate,
        APP_NAME,
        3,
        series=series,
        constraints="mem=3G",
        config={"profile": "production"},
        resources=charm_resources,
    )
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    # we do not wait for idle in this wait because the 3 units will keep trying
    # to acquire the lock but it will always be given to leader who cannot start
    # because it is blocked and deferring
    await wait_until(
        juju,
        apps=[APP_NAME],
        units_statuses={APP_NAME: [MEMORY_NOT_ENOUGH_STATUS]},
        wait_for_exact_units=3,
    )


@pytest.mark.abort_on_fail
async def test_testing_profile(
    juju: jubilant.Juju, charm: str, series: str, substrate, charm_resources
) -> None:
    """Test testing profile"""
    if APP_NAME in juju.status().apps:
        juju.remove_application(APP_NAME)

    await deploy_opensearch(
        juju,
        charm,
        substrate,
        APP_NAME,
        1,
        series=series,
        config={"profile": "testing"},
        resources=charm_resources,
    )
    juju.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        juju,
        apps=[APP_NAME],
        wait_for_exact_units=1,
    )
    await check_heap_size(juju, 1)


@pytest.mark.abort_on_fail
async def test_config_changed_to_production(juju: jubilant.Juju) -> None:
    """Switch to production profile and expect blocked."""
    juju.config(APP_NAME, {"profile": "production"})
    await wait_until(
        juju,
        apps=[APP_NAME],
        units_statuses={APP_NAME: [THREE_CM_THREE_DATA_STATUS]},
        wait_for_exact_units=1,
    )


@pytest.mark.abort_on_fail
# TODO add when LD is on for K8S
@pytest.mark.skip(reason="Skipping large deployment")
async def test_large_deployment_cluster(
    juju: jubilant.Juju, charm: str, series: str, substrate, charm_resources
) -> None:
    """Test large deployment cluster scenario."""
    if APP_NAME in juju.status().apps:
        juju.remove_application(APP_NAME)
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        "main",
        1,
        series=series,
        constraints="mem=8G",
        config={"cluster_name": "test", "roles": "cluster_manager", "profile": "production"},
        resources=charm_resources,
    )
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        "data",
        1,
        series=series,
        constraints="mem=8G",
        config={
            "cluster_name": "test",
            "init_hold": True,
            "roles": "data",
            "profile": "production",
        },
        resources=charm_resources,
    )

    # integrate TLS to all applications
    for app in ["main", "data"]:
        juju.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # create the peer-cluster-relation
    juju.integrate(f"data:{PEER_CLUSTER_RELATION}", f"main:{PEER_CLUSTER_ORCHESTRATOR_RELATION}")

    await wait_until(
        juju,
        apps=["main", "data"],
        units_statuses={
            "main": [ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value],
            "data": [ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value],
        },
        wait_for_exact_units={"main": 1, "data": 1},
    )

    juju.add_unit("main", num_units=2)

    await wait_until(
        juju,
        apps=["main", "data"],
        units_statuses={
            "main": [
                ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value,
                PeerClusterStatuses.PEER_CLUSTER_NO_DATA_NODE.value,
            ],
            "data": [ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value],
        },
        wait_for_exact_units={"main": 3, "data": 1},
    )
    juju.add_unit("data", num_units=2)
    await wait_until(juju, apps=["main", "data"], wait_for_exact_units=3, timeout=2000)

    await check_heap_size(juju, 4, app_name="main")
