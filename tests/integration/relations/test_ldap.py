# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from asyncio import gather

import pytest
import requests
from juju.model import Model
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from opensearch_single_kernel.common.statuses import LdapStatuses
from tests.helpers import Substrate
from tests.integration.conftest import CONFIG_OPTS
from tests.integration.helpers import (
    EmptyActiveStatus,
    EmptyBlockedStatus,
    get_application_unit_ips,
    get_leader_unit_ip,
    run_action,
    wait_until,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

ROLE_PASSWORD = "password"

DATA_INTEGRATOR_NAME = "data-integrator"
DATA_INTEGRATOR_CONFIG = {
    "index-name": "search-index",
}

SEARCH_ADMIN_DATA_INTEGRATOR_NAME = "search-admin-data-integrator"
SEARCH_ADMIN_DATA_INTEGRATOR_CONFIG = {
    "index-name": "search-admin-index",
    "entity-type": "GROUP",
    "entity-permissions": '[{"resource_name":["search-index"],"resource_type":"index_permissions","privileges":["read","search","get","write"]}]',
}
SEARCH_ADMIN_ROLE = "search-admin"
SEARCH_ADMIN_LDAP_AUTHORIZATION = "Basic YWxpY2U6YWxpY2VwYXNzd29yZA=="  # alice:alicepassword

SEARCH_READONLY_DATA_INTEGRATOR_NAME = "search-readonly-data-integrator"
SEARCH_READONLY_DATA_INTEGRATOR_CONFIG = {
    "index-name": "search-readonly-index",
    "entity-type": "GROUP",
    "entity-permissions": '[{"resource_name":["search-index"],"resource_type":"index_permissions","privileges":["read","search","get"]}]',
}
SEARCH_READONLY_ROLE = "search-readonly"
SEARCH_READONLY_LDAP_AUTHORIZATION = "Basic Ym9iOmJvYnBhc3N3b3Jk"  # bob:bobpassword

MAIN_APP = "opensearch-main"
DATA_APP = "opensearch-data"
POSTGRESQL_K8S = "postgresql-k8s"
LDAP_APP_NAME = "glauth-k8s"
LDAP_UTILS_APP_NAME = "glauth-utils"
TRAEFIK_CHARM = "traefik-k8s"

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


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_glauth(
    ops_test_k8s: OpsTest, k8s_model: Model, substrate: Substrate
) -> None:
    """Deploys glauth and all required charms coming with glauth and relate them.

    Then it offers the two relations provided by glauth.
    """
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
            channel="latest/edge",
            revision=56,
            trust=True,
        ),
        k8s_model.deploy(LDAP_UTILS_APP_NAME, channel="latest/edge", trust=True),
        k8s_model.deploy(
            TLS_CERTIFICATES_APP_NAME,
            channel=TLS_STABLE_CHANNEL,
            trust=True,
        ),
        k8s_model.deploy(TRAEFIK_CHARM, trust=True),
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

    await wait_until(
        ops_test_k8s,
        apps=[LDAP_APP_NAME, POSTGRESQL_K8S, TLS_CERTIFICATES_APP_NAME, LDAP_UTILS_APP_NAME],
        units_statuses={
            POSTGRESQL_K8S: [EmptyActiveStatus, EmptyBlockedStatus]
        },  # postgresql can be in Blocked State because of low free space
    )

    await _apply_ldif(ops_test_k8s, k8s_model)

    if substrate == "vm":
        await asyncio.gather(
            k8s_model.create_offer(f"{LDAP_APP_NAME}:ldap", LDAP_OFFER),
            k8s_model.create_offer(f"{LDAP_APP_NAME}:send-ca-cert", LDAP_CERT_OFFER),
            k8s_model.create_offer(f"{TLS_CERTIFICATES_APP_NAME}:certificates", CERT_OFFER),
        )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy(
    ops_test: OpsTest,
    charm: str,
    series: str,
    k8s_model: Model,
    data_integrator_charm: str,
    charm_resources: dict[str, str],
    substrate: Substrate,
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
            config=CONFIG_OPTS,
            resources=charm_resources,
            trust=True,
        ),
        model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=1,
            series=series,
            config=CONFIG_OPTS | {"roles": "data", "init_hold": True},
            resources=charm_resources,
            trust=True,
        ),
        model.deploy(
            data_integrator_charm,
            application_name=DATA_INTEGRATOR_NAME,
            config=DATA_INTEGRATOR_CONFIG,
        ),
        model.deploy(
            data_integrator_charm,
            application_name=SEARCH_ADMIN_DATA_INTEGRATOR_NAME,
        ),
        model.deploy(
            data_integrator_charm,
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
async def test_ldap_invalid_relation(ops_test: OpsTest, substrate: Substrate) -> None:
    assert (model := ops_test.model)

    await model.integrate(DATA_APP, LDAP_OFFER if substrate == "vm" else f"{LDAP_APP_NAME}:ldap")

    await wait_until(
        ops_test, apps=[DATA_APP], apps_statuses={DATA_APP: [LdapStatuses.RELATION_INVALID.value]}
    )

    await model.applications[DATA_APP].remove_relation(
        "ldap", LDAP_OFFER if substrate == "vm" else LDAP_APP_NAME, True
    )

    await wait_until(ops_test, apps=[DATA_APP])


@pytest.mark.abort_on_fail
async def test_ldaps_not_enabled(ops_test: OpsTest, substrate: Substrate) -> None:
    assert (model := ops_test.model)

    await model.integrate(MAIN_APP, LDAP_OFFER if substrate == "vm" else f"{LDAP_APP_NAME}:ldap")

    await wait_until(
        ops_test, apps=[MAIN_APP], apps_statuses={MAIN_APP: [LdapStatuses.LDAPS_NOT_ENABLED.value]}
    )


@pytest.mark.abort_on_fail
async def test_ldap_cert_not_connected(ops_test: OpsTest, k8s_model: Model) -> None:
    await k8s_model.applications[LDAP_APP_NAME].set_config({"ldaps_enabled": "true"})

    await wait_until(
        ops_test,
        apps=[MAIN_APP],
        apps_statuses={MAIN_APP: [LdapStatuses.CERT_NOT_CONNECTED.value]},
    )


@pytest.mark.abort_on_fail
async def test_ldap_authenticated(ops_test: OpsTest, substrate: Substrate) -> None:
    assert (model := ops_test.model)

    await asyncio.gather(
        model.integrate(
            f"{MAIN_APP}:ldap-certificate-transfer",
            LDAP_CERT_OFFER if substrate == "vm" else f"{LDAP_APP_NAME}:send-ca-cert",
        ),
        model.integrate(
            f"{DATA_APP}:ldap-certificate-transfer",
            LDAP_CERT_OFFER if substrate == "vm" else f"{LDAP_APP_NAME}:send-ca-cert",
        ),
    )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP],
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
                    assert result.status_code == 200

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
