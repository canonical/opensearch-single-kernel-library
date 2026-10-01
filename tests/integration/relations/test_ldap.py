# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from asyncio import gather
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

import pytest
import requests
from juju.model import Model
from kubernetes import client
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from opensearch_single_kernel.common.statuses import LdapStatuses
from tests.helpers import Substrate
from tests.integration.conftest import CONFIG_OPTS
from tests.integration.ha.k8s_helpers.helpers import delete_pod
from tests.integration.helpers import (
    NO_TTY_STDIN,
    get_application_unit_ids_ips,
    get_application_unit_ips,
    get_leader_unit_id,
    get_leader_unit_ip,
    get_secret_by_label,
    run_action,
    wait_until,
)
from tests.integration.relations.authentik import API_TOKEN_SECRET_LABEL, provision_directory
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

ROLE_PASSWORD = "password"

DATA_INTEGRATOR_NAME = "data-integrator"
# Revisions are built per architecture; both come from the same latest/edge release
DATA_INTEGRATOR_REVISIONS = {"amd64": 500, "arm64": 501}
DATA_INTEGRATOR_CONFIG = {
    "index-name": "search-index",
}

SEARCH_ADMIN_DATA_INTEGRATOR_NAME = "search-admin-data-integrator"
SEARCH_ADMIN_DATA_INTEGRATOR_CONFIG = {
    "index-name": "search-admin-index",
    "entity-type": "GROUP",
    "entity-permissions": '[{"resource_name":"search-index","resource_type":"index_permissions","privileges":["read","search","get","write"]}]',
}
SEARCH_ADMIN_ROLE = "search-admin"
SEARCH_ADMIN_LDAP_AUTHORIZATION = "Basic YWxpY2U6YWxpY2VwYXNzd29yZA=="  # alice:alicepassword

SEARCH_READONLY_DATA_INTEGRATOR_NAME = "search-readonly-data-integrator"
SEARCH_READONLY_DATA_INTEGRATOR_CONFIG = {
    "index-name": "search-readonly-index",
    "entity-type": "GROUP",
    "entity-permissions": '[{"resource_name":"search-index","resource_type":"index_permissions","privileges":["read","search","get"]}]',
}
SEARCH_READONLY_ROLE = "search-readonly"
SEARCH_READONLY_LDAP_AUTHORIZATION = "Basic Ym9iOmJvYnBhc3N3b3Jk"  # bob:bobpassword

# LDAP authorization header -> the backend role OpenSearch must resolve for that user.
# The role name comes from the `ou` (GLAuth, see ldap.ldif) or `cn` (Authentik) of the user's
# LDAP group.
LDAP_BACKEND_ROLES = {
    SEARCH_ADMIN_LDAP_AUTHORIZATION: SEARCH_ADMIN_ROLE,
    SEARCH_READONLY_LDAP_AUTHORIZATION: SEARCH_READONLY_ROLE,
}

MAIN_APP = "opensearch-main"
DATA_APP = "opensearch-data"
POSTGRESQL_K8S = "postgresql-k8s"
LDAP_APP_NAME = "glauth-k8s"
LDAP_UTILS_APP_NAME = "glauth-utils"
# GLAuth publishes arm64 builds on latest/edge only
GLAUTH_CHANNELS = {"amd64": "latest/stable", "arm64": "latest/edge"}
TRAEFIK_CHARM = "traefik-k8s"

AUTHENTIK_CHANNEL = "latest/edge"
AUTHENTIK_SERVER = "authentik-server"
AUTHENTIK_WORKER = "authentik-worker"
AUTHENTIK_LDAP_OUTPOST = "authentik-ldap-outpost"
AUTHENTIK_BASE_DN = "dc=ldap,dc=authentik,dc=io"
# username -> (password, group); mirrors the users and groups of ldap.ldif
AUTHENTIK_USERS = {
    "alice": ("alicepassword", SEARCH_ADMIN_ROLE),
    "bob": ("bobpassword", SEARCH_READONLY_ROLE),
}

LDAP_OFFER = "ldap"
LDAP_CERT_OFFER = "ldap-cert"
CERT_OFFER = "certificates"

logger = logging.getLogger(__name__)


async def _apply_ldif(ops_test_k8s: OpsTest, k8s_model: Model) -> None:
    """Apply an LDIF on glauth-utils."""
    source_path = "./tests/integration/relations/ldap.ldif"
    target_path = "/var/tmp/ldap.ldif"
    app = k8s_model.applications[LDAP_UTILS_APP_NAME]
    scp_cmd = f"scp {source_path} {app.units[0].name}:{target_path}".split()
    await ops_test_k8s.juju(*scp_cmd)
    await run_action(
        ops_test_k8s,
        0,
        "apply-ldif",
        {"path": target_path},
        LDAP_UTILS_APP_NAME,
    )


async def _configure_data_integrators(model: Model) -> None:
    search_admin_secret = await model.add_secret(
        SEARCH_ADMIN_ROLE, [f"{SEARCH_ADMIN_ROLE}={ROLE_PASSWORD}"]
    )
    search_readonly_secret = await model.add_secret(
        SEARCH_READONLY_ROLE, [f"{SEARCH_READONLY_ROLE}={ROLE_PASSWORD}"]
    )

    await asyncio.gather(
        model.grant_secret(SEARCH_ADMIN_ROLE, SEARCH_ADMIN_DATA_INTEGRATOR_NAME),
        model.grant_secret(SEARCH_READONLY_ROLE, SEARCH_READONLY_DATA_INTEGRATOR_NAME),
    )

    await asyncio.gather(
        model.applications[SEARCH_ADMIN_DATA_INTEGRATOR_NAME].set_config(
            SEARCH_ADMIN_DATA_INTEGRATOR_CONFIG
            | {"requested-entities-secret": search_admin_secret}
        ),
        model.applications[SEARCH_READONLY_DATA_INTEGRATOR_NAME].set_config(
            SEARCH_READONLY_DATA_INTEGRATOR_CONFIG
            | {"requested-entities-secret": search_readonly_secret}
        ),
    )


async def _deploy_glauth(ops_test_k8s: OpsTest, k8s_model: Model, architecture: str) -> None:
    """Deploy glauth and all required charms coming with glauth, relate them and add users."""
    await asyncio.gather(
        k8s_model.deploy(
            POSTGRESQL_K8S,
            channel="14/stable",
            trust=True,
            series="jammy",
            config={"profile": "testing"},
        ),
        k8s_model.deploy(
            LDAP_APP_NAME,
            channel=GLAUTH_CHANNELS[architecture],
            trust=True,
        ),
        k8s_model.deploy(LDAP_UTILS_APP_NAME, channel=GLAUTH_CHANNELS[architecture], trust=True),
        k8s_model.deploy(
            TLS_CERTIFICATES_APP_NAME,
            channel=TLS_STABLE_CHANNEL,
        ),
        k8s_model.deploy(TRAEFIK_CHARM, channel="latest/stable", trust=True),
    )

    await k8s_model.wait_for_idle(
        apps=[LDAP_APP_NAME, POSTGRESQL_K8S, TLS_CERTIFICATES_APP_NAME, LDAP_UTILS_APP_NAME],
        raise_on_blocked=False,
    )

    await asyncio.gather(
        k8s_model.integrate(f"{LDAP_APP_NAME}:ldaps-ingress", f"{TRAEFIK_CHARM}:ingress-per-unit"),
        k8s_model.integrate(f"{LDAP_APP_NAME}:pg-database", f"{POSTGRESQL_K8S}:database"),
        k8s_model.integrate(LDAP_APP_NAME, TLS_CERTIFICATES_APP_NAME),
        k8s_model.integrate(LDAP_APP_NAME, LDAP_UTILS_APP_NAME),
    )

    # PostgreSQL is left out: once related its agent flips executing/idle every ~10s, so no idle
    # period it takes part in ever elapses. An active glauth-k8s already implies a working
    # database.
    await wait_until(
        ops_test_k8s,
        apps=[LDAP_APP_NAME, TLS_CERTIFICATES_APP_NAME, LDAP_UTILS_APP_NAME],
    )

    await _apply_ldif(ops_test_k8s, k8s_model)


async def _deploy_authentik(ops_test_k8s: OpsTest, k8s_model: Model, architecture: str) -> None:
    """Deploy the Authentik LDAP stack, relate it and add users through the Authentik API."""
    await asyncio.gather(
        k8s_model.deploy(
            POSTGRESQL_K8S,
            channel="14/stable",
            trust=True,
            series="jammy",
            config={"profile": "testing"},
        ),
        k8s_model.deploy(AUTHENTIK_SERVER, channel=AUTHENTIK_CHANNEL, trust=True),
        k8s_model.deploy(AUTHENTIK_WORKER, channel=AUTHENTIK_CHANNEL, trust=True),
        # `direct` reads the live Authentik state; the default `cached` modes would serve a
        # directory snapshot taken before the users are created
        k8s_model.deploy(
            AUTHENTIK_LDAP_OUTPOST,
            channel=AUTHENTIK_CHANNEL,
            trust=True,
            config={
                "base_dn": AUTHENTIK_BASE_DN,
                "search_mode": "direct",
                "bind_mode": "direct",
            },
        ),
        k8s_model.deploy(
            TLS_CERTIFICATES_APP_NAME,
            channel=TLS_STABLE_CHANNEL,
        ),
        # Traefik terminates LDAPS for the outpost, which never provisions a certificate itself
        k8s_model.deploy(TRAEFIK_CHARM, channel="latest/stable", trust=True),
    )

    await asyncio.gather(
        k8s_model.integrate(f"{AUTHENTIK_SERVER}:pg-database", f"{POSTGRESQL_K8S}:database"),
        k8s_model.integrate(f"{AUTHENTIK_SERVER}:authentik-cluster", AUTHENTIK_WORKER),
        k8s_model.integrate(f"{AUTHENTIK_SERVER}:authentik-server-info", AUTHENTIK_LDAP_OUTPOST),
        k8s_model.integrate(f"{AUTHENTIK_SERVER}:traefik-route", TRAEFIK_CHARM),
        k8s_model.integrate(f"{AUTHENTIK_LDAP_OUTPOST}:traefik-route", TRAEFIK_CHARM),
        k8s_model.integrate(f"{TRAEFIK_CHARM}:certificates", TLS_CERTIFICATES_APP_NAME),
    )

    # PostgreSQL is left out: once related its agent flips executing/idle every ~10s, so no idle
    # period it takes part in ever elapses. An active authentik-server already implies a working
    # database.
    await wait_until(
        ops_test_k8s,
        apps=[
            AUTHENTIK_SERVER,
            AUTHENTIK_WORKER,
            AUTHENTIK_LDAP_OUTPOST,
            TLS_CERTIFICATES_APP_NAME,
            TRAEFIK_CHARM,
        ],
        timeout=1800,
    )

    token = (await get_secret_by_label(ops_test_k8s, API_TOKEN_SECRET_LABEL))["api-token"]
    host = (await get_application_unit_ips(ops_test_k8s, AUTHENTIK_SERVER))[0]
    provision_directory(
        host,
        token,
        groups=[SEARCH_ADMIN_ROLE, SEARCH_READONLY_ROLE],
        users=AUTHENTIK_USERS,
    )


@dataclass(frozen=True)
class LdapProvider:
    """An LDAP server flavor the test module runs against."""

    name: str
    # Application providing the `ldap` endpoint
    app: str
    deploy: Callable[[OpsTest, Model, str], Awaitable[None]]
    # Extra OpenSearch config needed to find users and resolve their roles in this directory
    opensearch_config: dict[str, str] = field(default_factory=dict)
    # GLAuth starts with LDAPS disabled and has it enabled by the test
    ldaps_enabled_by_default: bool = True


GLAUTH = LdapProvider(
    name="glauth",
    app=LDAP_APP_NAME,
    deploy=_deploy_glauth,
    ldaps_enabled_by_default=False,
)
AUTHENTIK = LdapProvider(
    name="authentik",
    app=AUTHENTIK_LDAP_OUTPOST,
    deploy=_deploy_authentik,
    opensearch_config={
        "ldap_user_base": f"ou=users,{AUTHENTIK_BASE_DN}",
        "ldap_role_name_attr": "cn",
    },
)


@pytest.fixture(
    scope="module",
    autouse=True,
    params=[
        pytest.param(provider, id=provider.name, marks=pytest.mark.group(id=provider.name))
        for provider in (GLAUTH, AUTHENTIK)
    ],
)
def ldap_provider(request: pytest.FixtureRequest) -> LdapProvider:
    """The LDAP server flavor; select one with `-m 'group(id="<name>")'`."""
    return request.param


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_ldap_provider(
    ops_test_k8s: OpsTest,
    k8s_model: Model,
    substrate: Substrate,
    architecture: str,
    ldap_provider: LdapProvider,
) -> None:
    """Deploy the LDAP provider with its required charms and add the test users.

    Then it offers the relations OpenSearch needs on the VM substrate.
    """
    await ldap_provider.deploy(ops_test_k8s, k8s_model, architecture)

    if substrate == "vm":
        await asyncio.gather(
            k8s_model.create_offer(f"{ldap_provider.app}:ldap", LDAP_OFFER),
            # Neither GLAuth (certificate-transfer v0 only) nor the Authentik outpost (no
            # `send-ca-cert`) can send their CA; take it from the provider that issued the
            # LDAPS certificate instead
            k8s_model.create_offer(f"{TLS_CERTIFICATES_APP_NAME}:send-ca-cert", LDAP_CERT_OFFER),
            k8s_model.create_offer(f"{TLS_CERTIFICATES_APP_NAME}:certificates", CERT_OFFER),
        )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy(
    ops_test: OpsTest,
    charm: str,
    series: str,
    k8s_model: Model,
    charm_resources: dict[str, str],
    substrate: Substrate,
    architecture: str,
    ldap_provider: LdapProvider,
):
    """Deploy OpenSearch, data integrator and identity platform (K8s) simultaneously."""
    assert (model := ops_test.model)

    if substrate == "vm":
        await asyncio.gather(
            model.consume(f"admin/{k8s_model.info.name}.{LDAP_OFFER}"),
            model.consume(f"admin/{k8s_model.info.name}.{LDAP_CERT_OFFER}"),
            model.consume(f"admin/{k8s_model.info.name}.{CERT_OFFER}"),
        )

    await gather(
        model.deploy(
            charm,
            application_name=MAIN_APP,
            num_units=3,
            series=series,
            config=CONFIG_OPTS | ldap_provider.opensearch_config,
            resources=charm_resources,
            trust=True,
        ),
        model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=1,
            series=series,
            config=CONFIG_OPTS
            | ldap_provider.opensearch_config
            | {"roles": "data", "init_hold": True},
            resources=charm_resources,
            trust=True,
        ),
        model.deploy(
            DATA_INTEGRATOR_NAME,
            revision=DATA_INTEGRATOR_REVISIONS[architecture],
            channel="latest/edge",
            application_name=DATA_INTEGRATOR_NAME,
            config=DATA_INTEGRATOR_CONFIG,
        ),
        model.deploy(
            DATA_INTEGRATOR_NAME,
            revision=DATA_INTEGRATOR_REVISIONS[architecture],
            channel="latest/edge",
            application_name=SEARCH_ADMIN_DATA_INTEGRATOR_NAME,
        ),
        model.deploy(
            DATA_INTEGRATOR_NAME,
            revision=DATA_INTEGRATOR_REVISIONS[architecture],
            channel="latest/edge",
            application_name=SEARCH_READONLY_DATA_INTEGRATOR_NAME,
        ),
    )

    await model.wait_for_idle(timeout=1800)

    await _configure_data_integrators(model)

    await asyncio.gather(
        model.integrate(
            f"{MAIN_APP}:certificates",
            CERT_OFFER if substrate == "vm" else f"{TLS_CERTIFICATES_APP_NAME}:certificates",
        ),
        model.integrate(
            f"{DATA_APP}:certificates",
            CERT_OFFER if substrate == "vm" else f"{TLS_CERTIFICATES_APP_NAME}:certificates",
        ),
    )

    await model.wait_for_idle(timeout=300)

    await asyncio.gather(
        model.integrate(f"{MAIN_APP}:peer-cluster-orchestrator", f"{DATA_APP}:peer-cluster"),
        model.integrate(MAIN_APP, DATA_INTEGRATOR_NAME),
    )

    await wait_until(ops_test, apps=[MAIN_APP, DATA_APP])


@pytest.mark.abort_on_fail
async def test_ldap_unauthenticated(ops_test: OpsTest) -> None:
    ip = await get_leader_unit_ip(ops_test, app=MAIN_APP)
    result = requests.get(
        f"https://{ip}:9200/_plugins/_security/authinfo",
        headers={"Authorization": SEARCH_ADMIN_LDAP_AUTHORIZATION},
        verify=False,
    )
    assert result.status_code == 401


@pytest.mark.abort_on_fail
async def test_ldap_invalid_relation(
    ops_test: OpsTest, substrate: Substrate, ldap_provider: LdapProvider
) -> None:
    assert (model := ops_test.model)

    await model.integrate(
        DATA_APP, LDAP_OFFER if substrate == "vm" else f"{ldap_provider.app}:ldap"
    )

    await wait_until(
        ops_test, apps=[DATA_APP], apps_statuses={DATA_APP: [LdapStatuses.RELATION_INVALID.value]}
    )

    await model.applications[DATA_APP].remove_relation(
        "ldap", LDAP_OFFER if substrate == "vm" else ldap_provider.app, True
    )

    await wait_until(ops_test, apps=[DATA_APP])


@pytest.mark.abort_on_fail
async def test_ldaps_not_enabled(
    ops_test: OpsTest, substrate: Substrate, ldap_provider: LdapProvider
) -> None:
    assert (model := ops_test.model)

    await model.integrate(
        MAIN_APP, LDAP_OFFER if substrate == "vm" else f"{ldap_provider.app}:ldap"
    )

    # A provider serving LDAPS from the start goes straight to the missing CA status
    expected_status = (
        LdapStatuses.CERT_NOT_CONNECTED
        if ldap_provider.ldaps_enabled_by_default
        else LdapStatuses.LDAPS_NOT_ENABLED
    )
    await wait_until(ops_test, apps=[MAIN_APP], apps_statuses={MAIN_APP: [expected_status.value]})


@pytest.mark.abort_on_fail
async def test_ldap_cert_not_connected(
    ops_test: OpsTest, k8s_model: Model, ldap_provider: LdapProvider
) -> None:
    if not ldap_provider.ldaps_enabled_by_default:
        await k8s_model.applications[ldap_provider.app].set_config({"ldaps_enabled": "true"})

    await wait_until(
        ops_test,
        apps=[MAIN_APP],
        apps_statuses={MAIN_APP: [LdapStatuses.CERT_NOT_CONNECTED.value]},
    )


@pytest.mark.abort_on_fail
async def test_ldap_authenticated(ops_test: OpsTest, substrate: Substrate) -> None:
    assert (model := ops_test.model)

    # Neither LDAP provider can send its CA; take it from the provider that issued the LDAPS
    # certificate instead
    await asyncio.gather(
        model.integrate(
            f"{MAIN_APP}:ldap-certificate-transfer",
            LDAP_CERT_OFFER if substrate == "vm" else f"{TLS_CERTIFICATES_APP_NAME}:send-ca-cert",
        ),
        model.integrate(
            f"{DATA_APP}:ldap-certificate-transfer",
            LDAP_CERT_OFFER if substrate == "vm" else f"{TLS_CERTIFICATES_APP_NAME}:send-ca-cert",
        ),
    )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP],
    )

    main_app_ips = await get_application_unit_ips(ops_test, MAIN_APP)
    data_app_ips = await get_application_unit_ips(ops_test, DATA_APP)
    for ip in [*main_app_ips, *data_app_ips]:
        for authorization, backend_role in LDAP_BACKEND_ROLES.items():
            # Wait for LDAP propagation over the cluster
            for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(10)):
                with attempt:
                    result = requests.get(
                        f"https://{ip}:9200/_plugins/_security/authinfo",
                        headers={"Authorization": authorization},
                        verify=False,
                    )
                    assert result.status_code == 200
                    # The LDAP authz backend must resolve the user's group into a
                    # backend role, even before any role mapping exists for it.
                    authinfo = result.json()
                    assert backend_role in authinfo["backend_roles"], authinfo

            result = requests.get(
                f"https://{ip}:9200/search-index/_search",
                headers={"Authorization": authorization},
                verify=False,
            )
            assert result.status_code == 403


@pytest.mark.abort_on_fail
async def test_ldap_access(ops_test: OpsTest) -> None:
    assert (model := ops_test.model)

    await asyncio.gather(
        model.integrate(MAIN_APP, SEARCH_ADMIN_DATA_INTEGRATOR_NAME),
        model.integrate(MAIN_APP, SEARCH_READONLY_DATA_INTEGRATOR_NAME),
    )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, SEARCH_ADMIN_DATA_INTEGRATOR_NAME, SEARCH_READONLY_DATA_INTEGRATOR_NAME],
    )

    main_app_ips = await get_application_unit_ips(ops_test, MAIN_APP)
    data_app_ips = await get_application_unit_ips(ops_test, DATA_APP)
    for ip in [*main_app_ips, *data_app_ips]:
        for authorization in (SEARCH_ADMIN_LDAP_AUTHORIZATION, SEARCH_READONLY_LDAP_AUTHORIZATION):
            result = requests.get(
                f"https://{ip}:9200/search-index/_search",
                headers={"Authorization": authorization},
                verify=False,
            )
            assert result.status_code == 200

        result = requests.post(
            f"https://{ip}:9200/search-index/_doc",
            headers={"Authorization": SEARCH_ADMIN_LDAP_AUTHORIZATION},
            verify=False,
            json={"field": "test_value"},
        )
        assert result.status_code == 201

        result = requests.post(
            f"https://{ip}:9200/search-index/_doc",
            headers={"Authorization": SEARCH_READONLY_LDAP_AUTHORIZATION},
            verify=False,
            json={"field": "test_value"},
        )
        assert result.status_code == 403


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("vm")
async def test_ldap_certificates_restored_after_pod_deletion(ops_test: OpsTest) -> None:
    """The LDAP CA file lives on the ephemeral pod filesystem and must be restored on start.

    The leader is recreated as it is the unit applying the security config cluster-wide.
    """
    assert (model := ops_test.model)

    leader_id = await get_leader_unit_id(ops_test, app=MAIN_APP)
    unit_name = f"{MAIN_APP}/{leader_id}"
    pod_name = f"{MAIN_APP}-{leader_id}"

    deleted_at = datetime.now(timezone.utc)
    delete_pod(pod_name, namespace=model.name)

    # Wait for the replacement pod, otherwise Juju may still report the stale active status
    for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(10)):
        with attempt:
            pod = client.CoreV1Api().read_namespaced_pod(pod_name, model.name)
            assert pod.metadata.creation_timestamp > deleted_at
            assert pod.status.phase == "Running"

    await wait_until(ops_test, apps=[MAIN_APP, DATA_APP])

    _, ldap_chain, _ = await ops_test.juju(
        "ssh",
        "--container",
        "opensearch",
        unit_name,
        "cat",
        "/etc/opensearch/certificates/ldap.pem",
        stdin=NO_TTY_STDIN,
    )
    assert "BEGIN CERTIFICATE" in ldap_chain

    # The security plugin authenticates on the node receiving the request, so query the
    # recreated unit directly. Its IP changes on recreation.
    ip = (await get_application_unit_ids_ips(ops_test, MAIN_APP))[leader_id]
    for authorization, backend_role in LDAP_BACKEND_ROLES.items():
        for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(10)):
            with attempt:
                result = requests.get(
                    f"https://{ip}:9200/_plugins/_security/authinfo",
                    headers={"Authorization": authorization},
                    verify=False,
                )
                assert result.status_code == 200
                assert backend_role in result.json()["backend_roles"], result.json()


@pytest.mark.abort_on_fail
async def test_remove_ldap_relation(
    ops_test: OpsTest, substrate: Substrate, ldap_provider: LdapProvider
) -> None:
    """Removing the LDAP relation on its own switches LDAP authentication off."""
    assert (model := ops_test.model)

    await model.applications[MAIN_APP].remove_relation(
        "ldap", LDAP_OFFER if substrate == "vm" else ldap_provider.app, True
    )

    # No LDAP relation is left to complain about, so the apps go back to active/idle.
    await wait_until(ops_test, apps=[MAIN_APP, DATA_APP])

    main_app_ips = await get_application_unit_ips(ops_test, MAIN_APP)
    data_app_ips = await get_application_unit_ips(ops_test, DATA_APP)
    for ip in [*main_app_ips, *data_app_ips]:
        for authorization in (SEARCH_ADMIN_LDAP_AUTHORIZATION, SEARCH_READONLY_LDAP_AUTHORIZATION):
            # Wait for LDAP propagation over the cluster
            for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(10)):
                with attempt:
                    result = requests.get(
                        f"https://{ip}:9200/_plugins/_security/authinfo",
                        headers={"Authorization": authorization},
                        verify=False,
                    )
                    assert result.status_code == 401


@pytest.mark.abort_on_fail
async def test_readd_ldap_relation(
    ops_test: OpsTest, substrate: Substrate, ldap_provider: LdapProvider
) -> None:
    """Reconnecting the LDAP relation restores authentication and index access."""
    assert (model := ops_test.model)

    await model.integrate(
        f"{MAIN_APP}:ldap", LDAP_OFFER if substrate == "vm" else f"{ldap_provider.app}:ldap"
    )

    await wait_until(ops_test, apps=[MAIN_APP, DATA_APP])

    main_app_ips = await get_application_unit_ips(ops_test, MAIN_APP)
    data_app_ips = await get_application_unit_ips(ops_test, DATA_APP)
    for ip in [*main_app_ips, *data_app_ips]:
        for authorization, backend_role in LDAP_BACKEND_ROLES.items():
            # Wait for LDAP propagation over the cluster
            for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(10)):
                with attempt:
                    result = requests.get(
                        f"https://{ip}:9200/_plugins/_security/authinfo",
                        headers={"Authorization": authorization},
                        verify=False,
                    )
                    assert result.status_code == 200
                    authinfo = result.json()
                    assert backend_role in authinfo["backend_roles"], authinfo

            result = requests.get(
                f"https://{ip}:9200/search-index/_search",
                headers={"Authorization": authorization},
                verify=False,
            )
            assert result.status_code == 200

        result = requests.post(
            f"https://{ip}:9200/search-index/_doc",
            headers={"Authorization": SEARCH_ADMIN_LDAP_AUTHORIZATION},
            verify=False,
            json={"field": "test_value"},
        )
        assert result.status_code == 201

        result = requests.post(
            f"https://{ip}:9200/search-index/_doc",
            headers={"Authorization": SEARCH_READONLY_LDAP_AUTHORIZATION},
            verify=False,
            json={"field": "test_value"},
        )
        assert result.status_code == 403


@pytest.mark.abort_on_fail
async def test_remove_ldap_cert_relation(ops_test: OpsTest, substrate: Substrate) -> None:
    """Removing the certificate transfer relation on its own blocks and disables LDAP."""
    assert (model := ops_test.model)

    await model.applications[MAIN_APP].remove_relation(
        "ldap-certificate-transfer",
        LDAP_CERT_OFFER if substrate == "vm" else TLS_CERTIFICATES_APP_NAME,
        True,
    )

    # Without the CA the charm cannot verify the LDAPS endpoint.
    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP],
        apps_statuses={MAIN_APP: [LdapStatuses.CERT_NOT_CONNECTED.value]},
    )

    main_app_ips = await get_application_unit_ips(ops_test, MAIN_APP)
    data_app_ips = await get_application_unit_ips(ops_test, DATA_APP)
    for ip in [*main_app_ips, *data_app_ips]:
        for authorization in (SEARCH_ADMIN_LDAP_AUTHORIZATION, SEARCH_READONLY_LDAP_AUTHORIZATION):
            # Wait for LDAP propagation over the cluster
            for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(10)):
                with attempt:
                    result = requests.get(
                        f"https://{ip}:9200/_plugins/_security/authinfo",
                        headers={"Authorization": authorization},
                        verify=False,
                    )
                    assert result.status_code == 401


@pytest.mark.abort_on_fail
async def test_readd_ldap_cert_relation(ops_test: OpsTest, substrate: Substrate) -> None:
    """Reconnecting the certificate transfer relation restores auth and index access."""
    assert (model := ops_test.model)

    # Neither LDAP provider can send its CA; take it from the provider that issued the LDAPS
    # certificate instead
    await model.integrate(
        f"{MAIN_APP}:ldap-certificate-transfer",
        LDAP_CERT_OFFER if substrate == "vm" else f"{TLS_CERTIFICATES_APP_NAME}:send-ca-cert",
    )

    await wait_until(ops_test, apps=[MAIN_APP, DATA_APP])

    main_app_ips = await get_application_unit_ips(ops_test, MAIN_APP)
    data_app_ips = await get_application_unit_ips(ops_test, DATA_APP)
    for ip in [*main_app_ips, *data_app_ips]:
        for authorization, backend_role in LDAP_BACKEND_ROLES.items():
            # Wait for LDAP propagation over the cluster
            for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(10)):
                with attempt:
                    result = requests.get(
                        f"https://{ip}:9200/_plugins/_security/authinfo",
                        headers={"Authorization": authorization},
                        verify=False,
                    )
                    assert result.status_code == 200
                    authinfo = result.json()
                    assert backend_role in authinfo["backend_roles"], authinfo

            result = requests.get(
                f"https://{ip}:9200/search-index/_search",
                headers={"Authorization": authorization},
                verify=False,
            )
            assert result.status_code == 200

        result = requests.post(
            f"https://{ip}:9200/search-index/_doc",
            headers={"Authorization": SEARCH_ADMIN_LDAP_AUTHORIZATION},
            verify=False,
            json={"field": "test_value"},
        )
        assert result.status_code == 201

        result = requests.post(
            f"https://{ip}:9200/search-index/_doc",
            headers={"Authorization": SEARCH_READONLY_LDAP_AUTHORIZATION},
            verify=False,
            json={"field": "test_value"},
        )
        assert result.status_code == 403


@pytest.mark.abort_on_fail
async def test_kibana(ops_test: OpsTest) -> None:
    assert (model := ops_test.model)

    ip = await get_leader_unit_ip(ops_test, app=MAIN_APP)

    result = requests.put(
        f"https://{ip}:9200/.kibana",
        headers={"Authorization": SEARCH_ADMIN_LDAP_AUTHORIZATION},
        verify=False,
        json={"settings": {"number_of_shards": 1, "number_of_replicas": 0}},
    )
    assert result.status_code == 403

    await model.applications[MAIN_APP].remove_relation(
        "opensearch-client", SEARCH_ADMIN_DATA_INTEGRATOR_NAME, True
    )

    await wait_until(
        ops_test,
        apps=[MAIN_APP],
    )

    await model.applications[SEARCH_ADMIN_DATA_INTEGRATOR_NAME].set_config(
        {"extra-group-roles": "kibana_user"}
    )

    await model.integrate(MAIN_APP, SEARCH_ADMIN_DATA_INTEGRATOR_NAME)
    await wait_until(
        ops_test,
        apps=[MAIN_APP, SEARCH_ADMIN_DATA_INTEGRATOR_NAME],
    )

    result = requests.put(
        f"https://{ip}:9200/.kibana",
        headers={"Authorization": SEARCH_ADMIN_LDAP_AUTHORIZATION},
        verify=False,
        json={"settings": {"number_of_shards": 1, "number_of_replicas": 0}},
    )
    assert result.status_code == 200


@pytest.mark.abort_on_fail
async def test_remove_ldap_access(ops_test: OpsTest) -> None:
    assert (model := ops_test.model)

    await asyncio.gather(
        model.applications[MAIN_APP].remove_relation(
            "opensearch-client", SEARCH_ADMIN_DATA_INTEGRATOR_NAME, True
        ),
        model.applications[MAIN_APP].remove_relation(
            "opensearch-client", SEARCH_READONLY_DATA_INTEGRATOR_NAME, True
        ),
    )

    await wait_until(
        ops_test,
        apps=[MAIN_APP],
    )

    main_app_ips = await get_application_unit_ips(ops_test, MAIN_APP)
    data_app_ips = await get_application_unit_ips(ops_test, DATA_APP)
    for ip in [*main_app_ips, *data_app_ips]:
        for authorization in (SEARCH_ADMIN_LDAP_AUTHORIZATION, SEARCH_READONLY_LDAP_AUTHORIZATION):
            # Wait for LDAP propagation over the cluster
            for attempt in Retrying(stop=stop_after_delay(600), wait=wait_fixed(10)):
                with attempt:
                    result = requests.get(
                        f"https://{ip}:9200/search-index/_search",
                        headers={"Authorization": authorization},
                        verify=False,
                    )
                    assert result.status_code == 403
