# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests of the nodes_dn lists, static in opensearch.yml and dynamic in the security index."""

import fnmatch
from pathlib import Path
from unittest.mock import PropertyMock

import pytest
from charmlibs.pathops import LocalPath

from opensearch_single_kernel.common.constants import CertType
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.core.models import App, PeerClusterApp
from opensearch_single_kernel.managers.config import ConfigManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from tests.unit.helpers import deployment_descriptions

STATE = "opensearch_single_kernel.core.state"
CLUSTER_NAME = deployment_descriptions["ok"].config.cluster_name


@pytest.fixture
def deployment(mocker):
    """The deployment description of a small deployment."""
    return mocker.patch(
        f"{STATE}.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )


@pytest.fixture
def fleet(mocker, deployment):
    """The unit names of the cluster fleet."""
    return mocker.patch(
        f"{STATE}.ClusterState.fleet_unit_names",
        new_callable=PropertyMock,
        return_value={"main-0.abc", "data-1.def"},
    )


@pytest.fixture
def yaml_setter(harness, mocker, tmp_path: Path) -> YamlConfigSetter:
    """A YAML config setter working on real files in a temporary directory."""
    setter = YamlConfigSetter(harness.charm.workload)
    setter.base_path = LocalPath(str(tmp_path))
    (tmp_path / ConfigManager.CONFIG_YML).write_text(
        "cluster.name: dev\nplugins.security.nodes_dn:\n- CN=old.abc\n"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.yaml_setter",
        new_callable=PropertyMock,
        return_value=setter,
    )
    return setter


def test_fleet_unit_names_include_the_units_of_all_apps(harness, mocker, deployment):
    """The fleet is the units of the current app and of every app in the cluster fleet."""
    mocker.patch(
        f"{STATE}.ClusterState.all_unit_names",
        new_callable=PropertyMock,
        return_value=["main-0.abc", "main-1.abc"],
    )
    app = App(model_uuid="model", name="data")
    current = deployment_descriptions["ok"].app
    mocker.patch(
        f"{STATE}.OpenSearchApplication.cluster_fleet_apps",
        new_callable=PropertyMock,
        return_value={
            app.id: PeerClusterApp(app=app, planned_units=1, units=["data-0.def"], roles=[]),
            # a stale snapshot of the current app: its removed units are not listed
            current.id: PeerClusterApp(
                app=current, planned_units=3, units=["main-2.abc"], roles=[]
            ),
        },
    )

    assert harness.charm.state.fleet_unit_names == {"main-0.abc", "main-1.abc", "data-0.def"}


def test_nodes_dn_list_the_cn_of_every_unit_of_the_fleet(harness, fleet):
    """Each unit is listed by its CN, alone or with the attributes an issuer adds around it."""
    assert harness.charm.config_manager.nodes_dn() == [
        "*,CN=data-1.def",
        "*,CN=data-1.def,*",
        "*,CN=main-0.abc",
        "*,CN=main-0.abc,*",
        "CN=data-1.def",
        "CN=data-1.def,*",
        "CN=main-0.abc",
        "CN=main-0.abc,*",
    ]


@pytest.mark.parametrize(
    "subject",
    [
        "CN=main-0.abc",
        "O=opensearch-dev,CN=main-0.abc",
        "CN=main-0.abc,O=acme",
        "C=FR,CN=main-0.abc,O=acme",
    ],
    ids=["cn-only", "self-signed", "vault-organization", "both-sides"],
)
def test_nodes_dn_match_the_subjects_of_the_issuers(harness, fleet, subject):
    """The subject of a unit certificate, as OpenSearch compares it, matches one of its patterns."""
    patterns = harness.charm.config_manager.nodes_dn()

    assert any(fnmatch.fnmatchcase(subject, pattern) for pattern in patterns)
    assert not any(fnmatch.fnmatchcase("CN=main-01.abc", pattern) for pattern in patterns)


def test_nodes_dn_empty_before_the_deployment_is_set_up(harness, mocker):
    """Without a deployment description, there is no fleet to list."""
    mocker.patch(
        f"{STATE}.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=None,
    )

    assert harness.charm.config_manager.nodes_dn() == []


@pytest.mark.real_fs
def test_rewrite_does_not_report_the_ignored_keys(harness, yaml_setter):
    """A change of an ignored key is written, but not reported."""
    nodes_dn = ConfigManager.NODES_DN_KEY
    ignored = (nodes_dn,)

    assert not yaml_setter.rewrite(
        ConfigManager.CONFIG_YML,
        {"cluster.name": "dev", nodes_dn: ["CN=new.abc"]},
        ignored_keys=ignored,
    )
    assert yaml_setter.load(ConfigManager.CONFIG_YML)[nodes_dn] == ["CN=new.abc"]

    assert yaml_setter.rewrite(
        ConfigManager.CONFIG_YML,
        {"cluster.name": "prod", nodes_dn: ["CN=new.abc"]},
        ignored_keys=ignored,
    )


@pytest.fixture
def listed_check(harness, mocker, deployment):
    """The running nodes, and the dynamic nodes_dn list they serve."""
    mocker.patch(
        "opensearch_single_kernel.managers.base.BaseManager.alt_hosts",
        new_callable=PropertyMock,
        return_value=["10.0.0.2"],
    )
    mocker.patch(
        f"{STATE}.ClusterState.unit_name",
        new_callable=PropertyMock,
        return_value="main-0.abc",
    )
    mocker.patch(
        f"{STATE}.OpenSearchApplication.admin_secrets",
        new_callable=PropertyMock,
        return_value={"cert": "admin-cert", "key": "admin-key"},
    )
    admin_cert_files = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager._admin_cert_files"
    )
    admin_cert_files.return_value.__enter__.return_value = ("admin.pem", "admin.key")
    return mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_nodes_dn",
        return_value=["CN=main-0.abc", "CN=main-0.abc,*"],
    )


def test_unit_listed_in_dynamic_nodes_dn(harness, listed_check):
    """The unit is listed by its CN in the entry of the cluster."""
    assert harness.charm.tls_manager.is_listed_in_nodes_dn()

    listed_check.assert_called_once_with(CLUSTER_NAME, ["10.0.0.2"], ("admin.pem", "admin.key"))


def test_unit_not_listed_in_dynamic_nodes_dn(harness, listed_check):
    """The unit waits while the running nodes list other units only."""
    listed_check.return_value = ["CN=main-1.abc", "CN=main-1.abc,*"]

    assert not harness.charm.tls_manager.is_listed_in_nodes_dn()


@pytest.mark.parametrize("served", [None, []], ids=["not-served", "no-entry"])
def test_listed_check_passes_without_a_dynamic_list(harness, listed_check, served):
    """Without a dynamic list yet (e.g. during an upgrade), no node relies on it."""
    listed_check.return_value = served

    assert harness.charm.tls_manager.is_listed_in_nodes_dn()


def test_listed_check_fails_without_the_admin_certificate(harness, mocker, listed_check):
    """The unit waits for the admin certificate to check the list."""
    mocker.patch(
        f"{STATE}.OpenSearchApplication.admin_secrets",
        new_callable=PropertyMock,
        return_value={},
    )

    assert not harness.charm.tls_manager.is_listed_in_nodes_dn()
    listed_check.assert_not_called()


def test_listed_check_passes_when_no_other_node_is_online(harness, mocker, listed_check):
    """With no other node running, no node needs to accept the unit."""
    mocker.patch(
        "opensearch_single_kernel.managers.base.BaseManager.alt_hosts",
        new_callable=PropertyMock,
        return_value=[],
    )

    assert harness.charm.tls_manager.is_listed_in_nodes_dn()
    listed_check.assert_not_called()


def test_listed_check_raises_when_the_list_cannot_be_read(harness, listed_check):
    """Other errors are raised, for the start to be retried."""
    listed_check.side_effect = OpenSearchHttpError(response_text="boom", response_code=500)

    with pytest.raises(OpenSearchHttpError):
        harness.charm.tls_manager.is_listed_in_nodes_dn()


def test_certificate_cn_is_the_unit_name(harness, mocker):
    """The CN of the node certificates is the unit name, on both substrates."""
    mocker.patch(
        f"{STATE}.ClusterState.unit_name",
        new_callable=PropertyMock,
        return_value="opensearch-0.a03",
    )

    tls_manager = harness.charm.tls_manager
    assert tls_manager._get_certificate_subject(CertType.UNIT_TRANSPORT) == "opensearch-0.a03"
    assert tls_manager._get_certificate_subject(CertType.UNIT_HTTP) == "opensearch-0.a03"
    assert tls_manager._get_certificate_subject(CertType.APP_ADMIN) == "admin"


def test_dynamic_list_applied_when_it_differs(harness, mocker, listed_check):
    """The writer replaces the entry of the cluster when it does not hold the list."""
    put = mocker.patch("opensearch_single_kernel.common.client.OpenSearchClient.put_nodes_dn")
    nodes_dn = ["CN=main-0.abc", "CN=main-0.abc,*", "CN=main-1.abc", "CN=main-1.abc,*"]

    harness.charm.tls_manager.apply_nodes_dn(nodes_dn)

    listed_check.assert_called_once_with(CLUSTER_NAME, [], ("admin.pem", "admin.key"))
    put.assert_called_once_with(CLUSTER_NAME, nodes_dn, [], ("admin.pem", "admin.key"))


@pytest.mark.parametrize(
    "served", [["CN=main-0.abc,*", "CN=main-0.abc"], None], ids=["same-list", "not-served"]
)
def test_dynamic_list_not_applied_when_not_needed(harness, mocker, listed_check, served):
    """Nothing is written when the nodes serve the list already, or serve none."""
    listed_check.return_value = served
    put = mocker.patch("opensearch_single_kernel.common.client.OpenSearchClient.put_nodes_dn")

    harness.charm.tls_manager.apply_nodes_dn(["CN=main-0.abc", "CN=main-0.abc,*"])

    put.assert_not_called()


def test_dynamic_list_created_when_the_cluster_has_no_entry(harness, mocker, listed_check):
    """The entry of the cluster is created when missing."""
    listed_check.return_value = []
    put = mocker.patch("opensearch_single_kernel.common.client.OpenSearchClient.put_nodes_dn")

    harness.charm.tls_manager.apply_nodes_dn(["CN=main-0.abc", "CN=main-0.abc,*"])

    put.assert_called_once()


def test_dynamic_list_failure_does_not_raise(harness, mocker, listed_check):
    """Applying the list is best effort: a later call retries it."""
    put = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.put_nodes_dn",
        side_effect=OpenSearchHttpError(response_text="boom", response_code=500),
    )

    harness.charm.tls_manager.apply_nodes_dn(["CN=main-1.abc"])

    put.assert_called_once()


@pytest.mark.parametrize("initialised", [True, False], ids=["security-index", "no-index"])
def test_static_list_change_restarts_only_before_the_security_index_exists(
    harness, mocker, deployment, initialised
):
    """Once the security index exists, the running nodes get the new list dynamically."""
    mocker.patch(
        f"{STATE}.OpenSearchApplication.is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=initialised,
    )
    mocker.patch.object(ConfigManager, "_update_static_jvm_options")
    mocker.patch.object(ConfigManager, "update_seeds_config")
    rewrite = mocker.patch.object(YamlConfigSetter, "rewrite", return_value=True)

    harness.charm.config_manager.update_opensearch_config()

    expected = (ConfigManager.NODES_DN_KEY,) if initialised else ()
    assert rewrite.call_args.kwargs["ignored_keys"] == expected


@pytest.fixture
def reconfigure(harness, mocker, fleet):
    """A unit reconfiguring opensearch.yml, with a security index."""
    mocker.patch.object(ConfigManager, "update_opensearch_config", return_value=False)
    mocker.patch(
        f"{STATE}.OpenSearchApplication.is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch(f"{STATE}.ClusterState.is_main_orchestrator", True)
    return mocker.patch("opensearch_single_kernel.managers.tls.TlsManager.apply_nodes_dn")


@pytest.mark.parametrize("is_leader", [True, False], ids=["leader", "non-leader"])
def test_only_the_main_orchestrator_leader_applies_the_dynamic_list(
    harness, reconfigure, is_leader
):
    """The dynamic list follows opensearch.yml, applied by a single unit of the fleet."""
    with harness.hooks_disabled():
        harness.set_leader(is_leader)

    assert harness.charm.opensearch_events._reconfigure_and_restart_if_needed()

    if is_leader:
        reconfigure.assert_called_once_with(harness.charm.config_manager.nodes_dn())
    else:
        reconfigure.assert_not_called()


def test_dynamic_list_not_applied_without_the_admin_certificate(harness, mocker, listed_check):
    """The admin certificate is required: the list is applied once it is available."""
    mocker.patch(
        f"{STATE}.OpenSearchApplication.admin_secrets",
        new_callable=PropertyMock,
        return_value={"truststore-password": "pwd"},
    )

    harness.charm.tls_manager.apply_nodes_dn(["CN=main-0.abc"])
    listed_check.assert_not_called()


@pytest.mark.parametrize(
    "error,served",
    [
        (
            OpenSearchHttpError(
                response_text='{"error":"no handler found for uri [/_plugins/_security/api/nodesdn/x]"}',
                response_code=400,
            ),
            None,
        ),
        (OpenSearchHttpError(response_text='{"status":"NOT_FOUND"}', response_code=404), []),
    ],
    ids=["not-served", "no-entry"],
)
def test_client_maps_the_nodesdn_api_errors(harness, mocker, deployment, error, served):
    """The client tells a missing entry from a disabled dynamic config."""
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.request", side_effect=error
    )

    client = harness.charm.tls_manager.opensearch_client
    assert client.get_nodes_dn("x", ["10.0.0.2"], ("admin.pem", "admin.key")) == served
