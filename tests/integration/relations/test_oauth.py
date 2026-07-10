# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from pathlib import Path

import jubilant
import pytest
import requests
from oauth_tools import (
    deploy_identity_bundle,
)

from opensearch_single_kernel.common.statuses import (
    OAuthStatuses,
)
from tests.integration.conftest import APP_NAME, CONFIG_OPTS
from tests.integration.helpers import deploy_opensearch, get_leader_unit_ip, wait_until

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
    juju: jubilant.Juju,
    charm,
    series,
    ops_test_microk8s: jubilant.Juju,
    charm_resources,
    substrate,
):
    """Deploy OpenSearch, data integrator and identity platform (K8s) simultaneously."""
    k8s_ops = ops_test_microk8s if substrate == "vm" else juju
    await deploy_opensearch(
        juju,
        charm,
        substrate,
        APP_NAME,
        2,
        series=series,
        config=CONFIG_OPTS,
        resources=charm_resources,
    )
    juju.deploy(DATA_INTEGRATOR_NAME, config=DATA_INTEGRATOR_CONFIG)
    # TODO: oauth_tools.deploy_identity_bundle still expects OpsTest; update when
    # the library adds jubilant support.
    await deploy_identity_bundle(
        ops_test=k8s_ops,
        bundle_url="./tests/integration/bundle-iam.yaml",
    )
    await wait_until(juju, apps=[APP_NAME], timeout=1000)


@pytest.mark.abort_on_fail
async def test_setup_relations(juju: jubilant.Juju, microk8s_model: jubilant.Juju, substrate):
    """Establish all the required relations.

    Connects OpenSearch, data integrator and identity platform (cross-model).
    """
    if substrate == "k8s":
        # if we're on k8s, we already have identity platform deployed in the same model,
        # so we just relate to it
        juju.integrate(f"{APP_NAME}:certificates", "self-signed-certificates")
        juju.integrate(f"{APP_NAME}:oauth", "hydra")
    else:
        microk8s_model.offer(
            "self-signed-certificates", endpoint="certificates", name="certificates"
        )
        juju.consume(f"admin/{microk8s_model.model}.certificates")
        juju.integrate("opensearch:certificates", "certificates")

        microk8s_model.offer("hydra", endpoint="oauth", name="oauth")
        juju.consume(f"admin/{microk8s_model.model}.oauth")
        juju.integrate("opensearch:oauth", "oauth")

    juju.integrate("opensearch:opensearch-client", f"{DATA_INTEGRATOR_NAME}:opensearch")

    # Require identity platform to be active so OAuth setup can succeed
    await wait_until(juju, apps=[APP_NAME, DATA_INTEGRATOR_NAME])
    # we can get a blocked status on kratos-external-idp-integrator
    # but setup can still proceed, so we don't check for active status on microk8s model
    if substrate == "vm":
        await wait_until(microk8s_model, apps=["hydra"], timeout=1200)


@pytest.mark.abort_on_fail
async def test_setup_oauth(juju: jubilant.Juju, microk8s_model: jubilant.Juju):
    """Configure new OAuth client on Hydra (identity platform).

    Also, acquire corresponding access token for the further testing.
    """
    # Ensure Hydra is active before running the action
    await wait_until(microk8s_model, apps=["hydra"], timeout=300)

    hydra_unit = next(iter(microk8s_model.status().apps["hydra"].units))
    task = microk8s_model.run(
        hydra_unit,
        "create-oauth-client",
        {
            "scope": ["openid", "profile", "email", "phone", "offline"],
            "grant-types": ["client_credentials"],
            "audience": ["opensearch"],
        },
    )
    global oauth_client_id
    oauth_client_id = task.results.get("client-id")
    oauth_client_secret = task.results.get("client-secret")
    if not (oauth_client_id and oauth_client_secret):
        msg = (
            "failed to retrieve oauth client id and secret from hydra; "
            f"action status={task.status}, "
            f"results={task.results}"
        )
        raise AssertionError(msg)

    traefik_unit = next(iter(microk8s_model.status().apps["traefik-public"].units))
    task = microk8s_model.run(traefik_unit, "show-proxied-endpoints")
    result = json.loads(task.results.get("proxied-endpoints", "{}"))
    hydra_url = result.get("hydra", {}).get("url")
    assert hydra_url, "failed to retrieve hydra url from traefik"

    result = requests.post(
        f"{hydra_url}/oauth2/token",
        {"scope": "openid", "grant_type": "client_credentials", "audience": "opensearch"},
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
async def test_oauth_access(juju: jubilant.Juju, microk8s_model: jubilant.Juju):
    """Check access to the OpenSearch with an access token, acquired earlier.

    Ensure that roles mapping works correctly by elevating user
    to the admin role and checking access to the admin endpoint.
    """
    # read oauth info from file if it was written in the previous test, so we can run
    # this test independently
    if Path("oauth_info.json").exists():
        oauth_info = json.loads(Path("oauth_info.json").read_text())
        oauth_access_token = oauth_info.get("access_token")
        oauth_client_id = oauth_info.get("client_id")

    global opensearch_address
    opensearch_address = await get_leader_unit_ip(juju, "opensearch")
    opensearch_url = f"https://{opensearch_address}:9200/_cat/indices"
    result = requests.get(
        opensearch_url, headers={"Authorization": f"Bearer {oauth_access_token}"}, verify=False
    )
    assert result.json().get("status") == 403, "no permissions error expected"

    di_unit = next(iter(juju.status().apps[DATA_INTEGRATOR_NAME].units))
    task = juju.run(di_unit, "get-credentials")
    data_integrator_user = task.results.get("opensearch", {}).get("username")
    assert data_integrator_user, "failed to retrieve data integrator user"

    global original_opensearch_config
    original_opensearch_config = juju.config("opensearch")
    config_with_roles = dict(original_opensearch_config)
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: data_integrator_user})
    juju.config("opensearch", config_with_roles)
    await wait_until(juju, apps=[APP_NAME])

    result = requests.get(
        opensearch_url, headers={"Authorization": f"Bearer {oauth_access_token}"}, verify=False
    )
    assert result.status_code == 200, "request expected to succeed with roles mapping"


@pytest.mark.abort_on_fail
async def test_deploy_second_client(juju: jubilant.Juju, microk8s_model: jubilant.Juju):
    """Deploy and configure second data integrator."""
    juju.deploy(
        DATA_INTEGRATOR_NAME,
        app=SECOND_DATA_INTEGRATOR_NAME,
        config=SECOND_DATA_INTEGRATOR_CONFIG,
    )
    await wait_until(juju, apps=[SECOND_DATA_INTEGRATOR_NAME])
    juju.integrate(SECOND_DATA_INTEGRATOR_NAME, "opensearch")
    await wait_until(juju, apps=[SECOND_DATA_INTEGRATOR_NAME, "opensearch"])


@pytest.mark.abort_on_fail
async def test_oauth_access_second_client(juju: jubilant.Juju, microk8s_model: jubilant.Juju):
    """Change roles mapping from first data integrator user to second one.

    Ensure, that admin permissions from the first one is removed, while role
    from the second one is added.
    """
    di_unit = next(iter(juju.status().apps[SECOND_DATA_INTEGRATOR_NAME].units))
    task = juju.run(di_unit, "get-credentials")
    second_data_integrator_user = task.results.get("opensearch", {}).get("username")
    assert second_data_integrator_user, "failed to retrieve second data integrator user"

    oauth_info = json.loads(Path("oauth_info.json").read_text())
    oauth_access_token = oauth_info.get("access_token")
    oauth_client_id = oauth_info.get("client_id")

    original_opensearch_config = juju.config("opensearch")
    config_with_roles = dict(original_opensearch_config)
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: second_data_integrator_user})
    juju.config("opensearch", config_with_roles)
    await wait_until(juju, apps=[APP_NAME])

    opensearch_address = await get_leader_unit_ip(juju, "opensearch")
    # Ensure first data integrator admin role is removed
    result = requests.get(
        f"https://{opensearch_address}:9200/_cat/indices",
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert (
        result.json().get("status") == 403
    ), "no permissions error expected as admin role should be removed"

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
async def test_oauth_access_cleanup(juju: jubilant.Juju, microk8s_model: jubilant.Juju):
    """Ensure that all of the oauth clients permissions are removed with clean roles mapping."""
    juju.config("opensearch", original_opensearch_config, reset="roles_mapping")
    await wait_until(juju, apps=["opensearch"])

    result = requests.get(
        f"https://{opensearch_address}:9200/_plugins/_security/authinfo",
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.status_code == 200, "request for authinfo should success"
    assert result.json().get("roles") == ["own_index"], "all the mapped roles should be removed"


@pytest.mark.abort_on_fail
@pytest.mark.skip(reason="https://warthogs.atlassian.net/browse/DPE-9182")
async def test_setup_large_cluster(
    juju: jubilant.Juju, charm, series, microk8s_model: jubilant.Juju, substrate
):
    """Replace the Opensearch application with a large deployment cluster."""
    logger.info("Remove Opensearch application")
    juju.remove_application("opensearch")
    juju.remove_application(SECOND_DATA_INTEGRATOR_NAME)
    juju.wait(
        lambda status: "opensearch" not in status.apps
        and SECOND_DATA_INTEGRATOR_NAME not in status.apps
    )

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
        config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "cluster_manager"}
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
        juju.integrate(app, "certificates")

    # integrate large deployment cluster
    juju.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    juju.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    juju.integrate(f"{DATA_APP}:{REL_PEER}", f"{FAILOVER_APP}:{REL_ORCHESTRATOR}")

    # integrate with Data integrator
    juju.integrate(f"{DATA_APP}:opensearch-client", f"{DATA_INTEGRATOR_NAME}:opensearch")

    # Let Juju settle while the cluster forms TLS + security index + peer orchestration
    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_INTEGRATOR_NAME],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
    )


@pytest.mark.abort_on_fail
@pytest.mark.skip(reason="https://warthogs.atlassian.net/browse/DPE-9182")
async def test_oauth_relation_restricted(
    juju: jubilant.Juju, charm, series, microk8s_model: jubilant.Juju
):
    """Ensure OAuth cannot be enabled if related to non-main-orchestrator."""
    logger.info(f"Integrating {DATA_APP} with OAuth - this will result in blocked status")
    juju.integrate(f"{DATA_APP}:oauth", "oauth")
    await wait_until(
        juju,
        apps=[DATA_APP],
        apps_statuses={
            DATA_APP: [OAuthStatuses.OAUTH_RELATION_INVALID.value],
        },
        wait_for_exact_units={DATA_APP: 3},
    )

    logger.info("Verifying access is not possible")
    opensearch_address = await get_leader_unit_ip(juju, DATA_APP)
    opensearch_url = f"https://{opensearch_address}:9200/_cat/indices"
    result = requests.get(
        opensearch_url, headers={"Authorization": f"Bearer {oauth_access_token}"}, verify=False
    )
    assert result.status_code == 401, "`Unauthorized` error expected"
    logger.info("Access with OAuth Token failed as expected")

    logger.info(f"Remove relation with {DATA_APP}")
    juju.remove_relation(f"{DATA_APP}:oauth", "oauth")

    await wait_until(
        juju,
        apps=[DATA_APP],
        wait_for_exact_units={DATA_APP: 3},
    )


@pytest.mark.abort_on_fail
@pytest.mark.skip(reason="https://warthogs.atlassian.net/browse/DPE-9182")
async def test_oauth_access_large_cluster(
    juju: jubilant.Juju, charm, series, microk8s_model: jubilant.Juju
):
    """Relate to main orchestrator and verify access with OAuth."""
    logger.info(f"Integrating {MAIN_APP} with oauth")
    juju.integrate(f"{MAIN_APP}:oauth", "oauth")
    await wait_until(
        juju,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
    )

    di_unit = next(iter(juju.status().apps[DATA_INTEGRATOR_NAME].units))
    task = juju.run(di_unit, "get-credentials")
    data_integrator_user = task.results.get("opensearch", {}).get("username")
    assert data_integrator_user, "failed to retrieve data integrator user"

    original_opensearch_config = juju.config(DATA_APP)
    config_with_roles = dict(original_opensearch_config)
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: data_integrator_user})
    juju.config(DATA_APP, config_with_roles)
    await wait_until(juju, apps=[MAIN_APP, DATA_APP, FAILOVER_APP])

    opensearch_address = await get_leader_unit_ip(juju, DATA_APP)
    opensearch_url = f"https://{opensearch_address}:9200/_cat/indices"
    result = requests.get(
        opensearch_url, headers={"Authorization": f"Bearer {oauth_access_token}"}, verify=False
    )
    assert result.status_code == 200, "request expected to succeed with roles mapping"
