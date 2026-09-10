# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from asyncio import gather
from pathlib import Path

import pytest
import requests
from juju.client.client import Action
from juju.model import Model
from oauth_tools import (
    deploy_identity_bundle,
)
from pytest_operator.plugin import OpsTest

from opensearch_single_kernel.common.statuses import (
    OAuthStatuses,
)
from tests.integration.conftest import APP_NAME, CONFIG_OPTS
from tests.integration.helpers import get_leader_unit_ip, wait_until

pytest_plugins = ["oauth_tools.fixtures"]

IDENTITY_PLATFORM_NAME = "identity-platform"
DATA_INTEGRATOR_NAME = "data-integrator"
SECOND_DATA_INTEGRATOR_NAME = "second-data-integrator"

DATA_INTEGRATOR_CONFIG = {
    "index-name": "admin-index",
    "extra-user-roles": "admin",
}
SECOND_DATA_INTEGRATOR_CONFIG = {
    "index-name": "dev-index",
}
MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"
CLUSTER_NAME = "log-app"
REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"
APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 1, DATA_APP: 3}

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy(
    ops_test: OpsTest,
    charm,
    series,
    ops_test_k8s: OpsTest,
    charm_resources,
    substrate,
    architecture,
):
    """Deploy OpenSearch, data integrator and identity platform (K8s) simultaneously."""
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    k8s_ops = ops_test_k8s if substrate == "vm" else ops_test
    await gather(
        ops_test.model.deploy(
            charm,
            application_name=APP_NAME,
            num_units=2,
            series=series,
            config=CONFIG_OPTS,
            resources=charm_resources,
            trust=substrate == "k8s",
        ),
        ops_test.model.deploy(
            DATA_INTEGRATOR_NAME,
            config=DATA_INTEGRATOR_CONFIG,
        ),
    )
    await deploy_identity_bundle(
        ops_test=k8s_ops,
        bundle_url="./tests/integration/bundle-iam.yaml",
    )
    await gather(
        ops_test.model.wait_for_idle(timeout=1000),
        k8s_ops.model.wait_for_idle(timeout=1000),
    )


@pytest.mark.abort_on_fail
async def test_setup_relations(ops_test: OpsTest, k8s_model: Model, substrate, architecture: str):
    """Establish all the required relations.

    Connects OpenSearch, data integrator and identity platform (cross-model).
    """
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    if substrate == "k8s":
        # if we're on k8s, we already have identity platform deployed in the same model,
        # so we just relate to it
        await ops_test.model.integrate(f"{APP_NAME}:certificates", "self-signed-certificates")
        await ops_test.model.integrate(f"{APP_NAME}:oauth", "hydra")
    else:
        await k8s_model.create_offer("certificates", "certificates", "self-signed-certificates")
        await ops_test.model.consume(f"admin/{k8s_model.name}.certificates")
        await ops_test.model.integrate("opensearch:certificates", "certificates")

        await k8s_model.create_offer("oauth", "oauth", "hydra")
        await ops_test.model.consume(f"admin/{k8s_model.name}.oauth")
        await ops_test.model.integrate("opensearch:oauth", "oauth")

    await ops_test.model.integrate(
        "opensearch:opensearch-client", f"{DATA_INTEGRATOR_NAME}:opensearch"
    )

    # Require identity platform to be active so OAuth setup can succeed
    await gather(
        ops_test.model.wait_for_idle(apps=[APP_NAME, DATA_INTEGRATOR_NAME], status="active"),
        # we can get a blocked status on kratos-external-idp-integrator
        # but setup can still proceed, so we don't check for active status on k8s model
        k8s_model.wait_for_idle(timeout=1200),
    )


@pytest.mark.abort_on_fail
async def test_setup_oauth(ops_test: OpsTest, k8s_model: Model, architecture: str):
    """Configure new OAuth client on Hydra (identity platform).

    Also, acquire corresponding access token for the further testing.
    """
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    # Ensure Hydra is active before running the action
    await k8s_model.wait_for_idle(apps=["hydra"], status="active", timeout=300)

    action: Action = (
        await k8s_model.applications["hydra"]
        .units[0]
        .run_action(
            "create-oauth-client",
            **{
                "scope": ["openid", "profile", "email", "phone", "offline"],
                "grant-types": ["client_credentials"],
                "audience": ["opensearch"],
            },
        )
    )
    await action.wait()
    global oauth_client_id
    oauth_client_id = action.results.get("client-id")
    oauth_client_secret = action.results.get("client-secret")
    if not (oauth_client_id and oauth_client_secret):
        msg = (
            "failed to retrieve oauth client id and secret from hydra; "
            f"action status={getattr(action, 'status', 'unknown')}, "
            f"results={action.results}"
        )
        raise AssertionError(msg)

    action = (
        await k8s_model.applications["traefik-public"]
        .units[0]
        .run_action("show-proxied-endpoints")
    )
    await action.wait()
    result = json.loads(action.results.get("proxied-endpoints", "{}"))
    hydra_url = result.get("hydra", {}).get("url")
    assert hydra_url, "failed to retrieve hydra url from traefik"

    result = requests.post(
        f"{hydra_url}/oauth2/token",
        {
            "scope": "openid",
            "grant_type": "client_credentials",
            "audience": "opensearch",
        },
        auth=requests.auth.HTTPBasicAuth(oauth_client_id, oauth_client_secret),
        verify=False,
    )

    global oauth_access_token
    oauth_access_token = result.json().get("access_token")
    logger.info(f"Retrieved access token from Hydra: {oauth_access_token}")
    Path("oauth_info.json").write_text(
        json.dumps(
            {
                "client_id": oauth_client_id,
                "client_secret": oauth_client_secret,
                "access_token": oauth_access_token,
                "hydra_url": hydra_url,
            },
            indent=2,
        )
    )
    assert oauth_access_token, "failed to retrieve access token from hydra"


@pytest.mark.abort_on_fail
async def test_oauth_access(ops_test: OpsTest, k8s_model: Model, architecture: str):
    """Check access to the OpenSearch with an access token, acquired earlier.

    Ensure that roles mapping works correctly by elevating user
    to the admin role and checking access to the admin endpoint.
    """
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    # read oauth info from file if it was written in the previous test, so we can run
    # this test independently
    if Path("oauth_info.json").exists():
        oauth_info = json.loads(Path("oauth_info.json").read_text())
        oauth_access_token = oauth_info.get("access_token")
        oauth_client_id = oauth_info.get("client_id")

    global opensearch_address
    opensearch_address = await get_leader_unit_ip(ops_test, "opensearch")
    opensearch_url = f"https://{opensearch_address}:9200/_cat/indices"
    result = requests.get(
        opensearch_url,
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.json().get("status") == 403, "no permissions error expected"

    action = (
        await ops_test.model.applications[DATA_INTEGRATOR_NAME]
        .units[0]
        .run_action("get-credentials")
    )
    await action.wait()
    data_integrator_user = action.results.get("opensearch", {}).get("username")
    assert data_integrator_user, "failed to retrieve data integrator user"

    global original_opensearch_config
    original_opensearch_config = await ops_test.model.applications["opensearch"].get_config()
    config_with_roles = original_opensearch_config.copy()
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: data_integrator_user})
    await ops_test.model.applications["opensearch"].set_config(config_with_roles)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active")

    result = requests.get(
        opensearch_url,
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.status_code == 200, "request expected to succeed with roles mapping"


@pytest.mark.abort_on_fail
async def test_deploy_second_client(ops_test: OpsTest, k8s_model: Model, architecture: str):
    """Deploy and configure second data integrator."""
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    await ops_test.model.deploy(
        DATA_INTEGRATOR_NAME,
        application_name=SECOND_DATA_INTEGRATOR_NAME,
        config=SECOND_DATA_INTEGRATOR_CONFIG,
    )
    await ops_test.model.wait_for_idle()
    await ops_test.model.integrate(SECOND_DATA_INTEGRATOR_NAME, "opensearch")
    await ops_test.model.wait_for_idle()


@pytest.mark.abort_on_fail
async def test_oauth_access_second_client(ops_test: OpsTest, k8s_model: Model, architecture: str):
    """Change roles mapping from first data integrator user to second one.

    Ensure, that admin permissions from the first one is removed, while role
    from the second one is added.
    """
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    action = (
        await ops_test.model.applications[SECOND_DATA_INTEGRATOR_NAME]
        .units[0]
        .run_action("get-credentials")
    )
    await action.wait()
    second_data_integrator_user = action.results.get("opensearch", {}).get("username")
    assert second_data_integrator_user, "failed to retrieve second data integrator user"

    oauth_info = json.loads(Path("oauth_info.json").read_text())
    oauth_access_token = oauth_info.get("access_token")
    oauth_client_id = oauth_info.get("client_id")

    original_opensearch_config = await ops_test.model.applications["opensearch"].get_config()
    config_with_roles = original_opensearch_config.copy()
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: second_data_integrator_user})
    await ops_test.model.applications["opensearch"].set_config(config_with_roles)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active")

    opensearch_address = await get_leader_unit_ip(ops_test, "opensearch")
    # Ensure first data integrator admin role is removed
    result = requests.get(
        f"https://{opensearch_address}:9200/_cat/indices",
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.json().get("status") == 403, (
        "no permissions error expected as admin role should be removed"
    )

    # Ensure second data integrator role is configured
    result = requests.get(
        f"https://{opensearch_address}:9200/_plugins/_security/authinfo",
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.status_code == 200, "request for authinfo should success"
    assert sorted(result.json().get("roles")) == sorted(
        [
            "own_index",
            second_data_integrator_user,
        ]
    ), "second data integrator role should be enabled"


@pytest.mark.abort_on_fail
async def test_oauth_access_cleanup(ops_test: OpsTest, k8s_model: Model, architecture: str):
    """Ensure that all of the oauth clients permissions are removed with clean roles mapping."""
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    await ops_test.model.applications["opensearch"].set_config(original_opensearch_config)
    await ops_test.model.wait_for_idle(apps=["opensearch"], status="active")

    result = requests.get(
        f"https://{opensearch_address}:9200/_plugins/_security/authinfo",
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.status_code == 200, "request for authinfo should success"
    assert result.json().get("roles") == ["own_index"], "all the mapped roles should be removed"


@pytest.mark.abort_on_fail
async def test_setup_large_cluster(
    ops_test: OpsTest,
    charm,
    series,
    k8s_model: Model,
    substrate,
    charm_resources,
    architecture: str,
):
    """Replace the Opensearch application with a large deployment cluster."""
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    logger.info("Remove Opensearch application")
    await ops_test.model.remove_application("opensearch", block_until_done=True)
    await ops_test.model.remove_application(SECOND_DATA_INTEGRATOR_NAME, block_until_done=True)

    logger.info("Create large deployment cluster of Opensearch")
    await asyncio.gather(
        ops_test.model.deploy(
            charm,
            application_name=MAIN_APP,
            num_units=APP_UNITS[MAIN_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager"} | CONFIG_OPTS,
            trust=substrate == "k8s",
            resources=charm_resources,
        ),
        ops_test.model.deploy(
            charm,
            application_name=FAILOVER_APP,
            num_units=APP_UNITS[FAILOVER_APP],
            series=series,
            config={
                "cluster_name": CLUSTER_NAME,
                "init_hold": True,
                "roles": "cluster_manager",
            }
            | CONFIG_OPTS,
            trust=substrate == "k8s",
            resources=charm_resources,
        ),
        ops_test.model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=APP_UNITS[DATA_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data"}
            | CONFIG_OPTS,
            trust=substrate == "k8s",
            resources=charm_resources,
        ),
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP]:
        if substrate == "k8s":
            await ops_test.model.integrate(app, "self-signed-certificates")
        else:
            await ops_test.model.integrate(app, "certificates")

    # integrate large deployment cluster
    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{FAILOVER_APP}:{REL_ORCHESTRATOR}")

    # integrate with Data integrator
    await ops_test.model.integrate(
        f"{DATA_APP}:opensearch-client", f"{DATA_INTEGRATOR_NAME}:opensearch"
    )

    # Let Juju settle while the cluster forms TLS + security index + peer orchestration
    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_INTEGRATOR_NAME],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
    )


@pytest.mark.abort_on_fail
async def test_oauth_relation_restricted(
    ops_test: OpsTest, charm, series, k8s_model: Model, substrate, architecture: str
):
    """Ensure OAuth cannot be enabled if related to non-main-orchestrator."""
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    logger.info(f"Integrating {DATA_APP} with OAuth - this will result in blocked status")
    if substrate == "k8s":
        await ops_test.model.integrate(f"{DATA_APP}:oauth", "hydra")
    else:
        await ops_test.model.integrate(f"{DATA_APP}:oauth", "oauth")
    await wait_until(
        ops_test,
        apps=[DATA_APP],
        apps_statuses={
            DATA_APP: [OAuthStatuses.OAUTH_RELATION_INVALID.value],
        },
        wait_for_exact_units={DATA_APP: 3},
    )

    logger.info("Verifying access is not possible")
    opensearch_address = await get_leader_unit_ip(ops_test, DATA_APP)
    opensearch_url = f"https://{opensearch_address}:9200/_cat/indices"
    result = requests.get(
        opensearch_url,
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.status_code == 401, "`Unauthorized` error expected"
    logger.info("Access with OAuth Token failed as expected")

    logger.info(f"Remove relation with {DATA_APP}")
    if substrate == "k8s":
        remove_relation_cmd = f"remove-relation {DATA_APP}:oauth hydra"
    else:
        remove_relation_cmd = f"remove-relation {DATA_APP}:oauth oauth"
    await ops_test.juju(*remove_relation_cmd.split(), check=True)

    await wait_until(
        ops_test,
        apps=[DATA_APP],
        wait_for_exact_units={DATA_APP: 3},
    )


@pytest.mark.abort_on_fail
async def test_oauth_access_large_cluster(
    ops_test: OpsTest, charm, series, k8s_model: Model, substrate, architecture: str
):
    """Relate to main orchestrator and verify access with OAuth."""
    if architecture == "arm64":
        pytest.skip(
            "Skipping test on arm64 architecture since kratos-external-idp-integrator is not available for arm64"
        )
    logger.info(f"Integrating {MAIN_APP} with oauth")
    if substrate == "k8s":
        await ops_test.model.integrate(f"{MAIN_APP}:oauth", "hydra")
    else:
        await ops_test.model.integrate(f"{MAIN_APP}:oauth", "oauth")
    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
    )

    action = (
        await ops_test.model.applications[DATA_INTEGRATOR_NAME]
        .units[0]
        .run_action("get-credentials")
    )
    await action.wait()
    data_integrator_user = action.results.get("opensearch", {}).get("username")
    assert data_integrator_user, "failed to retrieve data integrator user"

    original_opensearch_config = await ops_test.model.applications[DATA_APP].get_config()
    config_with_roles = original_opensearch_config.copy()
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: data_integrator_user})
    await ops_test.model.applications[DATA_APP].set_config(config_with_roles)
    await ops_test.model.wait_for_idle(apps=[MAIN_APP, DATA_APP, FAILOVER_APP], status="active")

    opensearch_address = await get_leader_unit_ip(ops_test, DATA_APP)
    opensearch_url = f"https://{opensearch_address}:9200/_cat/indices"
    result = requests.get(
        opensearch_url,
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.status_code == 200, "request expected to succeed with roles mapping"
