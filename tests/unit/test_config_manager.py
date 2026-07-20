# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit Tests for config Manager functions."""

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import PropertyMock

import pytest
from charmlibs.pathops import LocalPath

from opensearch_single_kernel.common.constants import DeploymentType, StartMode, State
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
)
from opensearch_single_kernel.utils.config import YamlConfigSetter
from tests.unit.helpers import (
    config_path,
    jvm_options,
    opensearch_yml,
    sec_conf_yml,
    seed_unicast_hosts,
)


def get_nested_value(config: dict, key_path: str) -> Any | None:
    """Get a nested value from config dict using dotted key path."""
    if not isinstance(config, dict):
        return None
    if key_path in config:
        return config.get(key_path)
    keys = key_path.split(".")
    value: Any = config
    for idx, key in enumerate(keys):
        if not isinstance(value, dict):
            return None
        remaining = ".".join(keys[idx:])
        if remaining in value:
            return value.get(remaining)
        value = value.get(key)
        if value is None:
            return None
    return value


@pytest.fixture
def tmp_config_path(tmp_path: Path) -> LocalPath:
    """Create an isolated OpenSearch config tree for a test."""
    base_path = Path(config_path.as_posix())
    target_path = tmp_path / "config"

    for relative_path in [
        opensearch_yml,
        seed_unicast_hosts,
        jvm_options,
        sec_conf_yml,
    ]:
        source = base_path / relative_path
        target = target_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    return LocalPath(str(target_path))


@pytest.mark.real_fs
def test_set_client_auth(harness, mocker, substrate, tmp_config_path):
    """Test setting the client authentication config."""
    yaml_conf_setter = YamlConfigSetter(harness.charm.workload)
    yaml_conf_setter.base_path = tmp_config_path

    def authc() -> dict[str, Any]:
        return security_conf["config"]["dynamic"]["authc"]

    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    security_conf = yaml_conf_setter.load(sec_conf_yml)

    # Fixture opensearch.yml does not define plugins.security.ssl.http.clientauth_mode.
    assert (
        get_nested_value(opensearch_conf, "plugins.security.ssl.http.clientauth_mode")
        is None
    )
    assert authc()["basic_internal_auth_domain"]["http_enabled"]
    assert authc()["clientcert_auth_domain"]["http_enabled"] is False
    assert authc()["clientcert_auth_domain"]["transport_enabled"] is False

    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.seed_hosts",
        return_value=tmp_config_path / seed_unicast_hosts,
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.opensearch_config",
        return_value=tmp_config_path / opensearch_yml,
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.yaml_setter",
        return_value=yaml_conf_setter,
        new_callable=PropertyMock,
    )
    # configure host and network hosts
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.network_hosts",
        return_value=["10.10.10.10"],
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.host_ip",
        return_value="20.20.20.20",
        new_callable=PropertyMock,
    )
    deployment_desc_mock = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    app = App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name)
    deployment_desc_mock.return_value = DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="opensearch-dev", init_hold=False, roles=[]
        ),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        app=app,
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        state=DeploymentState(value=State.ACTIVE),
    )
    # call method
    harness.charm.config_manager.update_opensearch_config()

    # check the changes
    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    security_conf = yaml_conf_setter.load(sec_conf_yml)

    assert (
        get_nested_value(opensearch_conf, "plugins.security.ssl.http.clientauth_mode")
        == "OPTIONAL"
    )
    assert authc()["basic_internal_auth_domain"]["http_enabled"]
    assert authc()["clientcert_auth_domain"]["http_enabled"]
    assert authc()["clientcert_auth_domain"]["transport_enabled"]


# TODO: Add tests related to configuring tls


@pytest.mark.real_fs
def test_set_node_and_cleanup_if_bootstrapped(
    harness, mocker, substrate, tmp_config_path
):
    """Test setting the core config of a node."""
    yaml_conf_setter = YamlConfigSetter(harness.charm.workload)
    yaml_conf_setter.base_path = tmp_config_path

    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    app = App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name)
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="opensearch-dev",
            init_hold=False,
            roles=["cluster_manager", "data"],
            data_temperature="hot",
        ),
        start=StartMode.WITH_PROVIDED_ROLES,
        pending_directives=[],
        app=app,
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        state=DeploymentState(value=State.ACTIVE),
        promotion_time=None,
    )
    if substrate != "vm":
        mocker.patch(
            "opensearch_single_kernel.core.state.ClusterState.fqdn",
            return_value="opensearch-0.opensearch-endpoints.namespace.svc.cluster.local",
            new_callable=PropertyMock,
        )

    mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.yaml_setter",
        return_value=yaml_conf_setter,
        new_callable=PropertyMock,
    )
    # configure host and network hosts
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.network_hosts",
        return_value=["10.10.10.10"],
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.seed_hosts",
        return_value=tmp_config_path / seed_unicast_hosts,
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.opensearch_config",
        return_value=tmp_config_path / opensearch_yml,
        new_callable=PropertyMock,
    )
    is_bootstrap_contributor = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchServer.is_bootstrap_contributor",
        return_value=True,
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.host_ip",
        return_value="20.20.20.20",
        new_callable=PropertyMock,
    )

    harness.charm.config_manager.update_opensearch_config(
        roles=["cluster_manager", "data"],
        cm_names=["cm1"],
    )
    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    assert opensearch_conf["cluster.name"] == "opensearch-dev"

    expected_node_name = harness.charm.state.unit_name
    assert opensearch_conf["node.name"] == expected_node_name

    assert opensearch_conf["node.attr.temp"] == "hot"
    assert opensearch_conf["node.attr.app_id"] == app.id
    expected_publish_host = (
        "20.20.20.20"
        if substrate == "vm"
        else "opensearch-0.opensearch-endpoints.namespace.svc.cluster.local"
    )
    expected_network_host = ["10.10.10.10"]
    assert opensearch_conf["network.host"] == expected_network_host
    assert opensearch_conf["network.publish_host"] == expected_publish_host
    assert opensearch_conf["http.publish_host"] == [expected_publish_host]
    assert opensearch_conf["node.roles"] == ["cluster_manager", "data"]
    assert opensearch_conf["discovery.seed_providers"] == "file"

    assert opensearch_conf["cluster.initial_cluster_manager_nodes"] == ["cm1"]

    # test cleanup_conf_if_bootstrapped
    is_bootstrap_contributor.return_value = False
    harness.charm.config_manager.update_opensearch_config()
    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    # Base security stuff set by set_node()
    assert get_nested_value(opensearch_conf, "plugins.security.disabled") is False
    assert (
        get_nested_value(opensearch_conf, "plugins.security.ssl_cert_reload_enabled")
        is True
    )
    assert get_nested_value(
        opensearch_conf, "plugins.security.restapi.roles_enabled"
    ) == [
        "all_access",
        "security_rest_api_access",
    ]
    assert (
        get_nested_value(
            opensearch_conf,
            "plugins.security.unsupported.restapi.allow_securityconfig_modification",
        )
        is True
    )

    # unicast_hosts content
    with open(tmp_config_path / seed_unicast_hosts, "r") as f:
        stored = set([line.strip() for line in f])
        expected = {"20.20.20.20"}
        assert stored == expected
