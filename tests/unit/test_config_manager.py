# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit Tests for config Manager functions."""

from typing import Any
from unittest.mock import PropertyMock

from opensearch_single_kernel.common.constants import DeploymentType, StartMode, State
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.utils.config import YamlConfigSetter, get_nested_value
from tests.helpers import patch_workload_meminfo
from tests.unit.helpers import (
    config_path,
    opensearch_yml,
    sec_conf_yml,
    seed_unicast_hosts,
)


def test_set_client_auth(harness, mocker, substrate):
    """Test setting the client authentication config."""
    yaml_conf_setter = YamlConfigSetter(harness.charm.workload)
    yaml_conf_setter.base_path = config_path / "tmp"

    def authc() -> dict[str, Any]:
        return security_conf["config"]["dynamic"]["authc"]

    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    security_conf = yaml_conf_setter.load(sec_conf_yml)

    # Fixture opensearch.yml does not define plugins.security.ssl.http.clientauth_mode.
    assert get_nested_value(opensearch_conf, "plugins.security.ssl.http.clientauth_mode") is None
    assert authc()["basic_internal_auth_domain"]["http_enabled"]
    assert authc()["clientcert_auth_domain"]["http_enabled"] is False
    assert authc()["clientcert_auth_domain"]["transport_enabled"] is False

    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.seed_hosts",
        return_value=config_path / "tmp" / seed_unicast_hosts,
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.opensearch_config",
        return_value=config_path / "tmp" / opensearch_yml,
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


def test_set_node_and_cleanup_if_bootstrapped(harness, mocker, substrate):
    """Test setting the core config of a node (base config)."""
    yaml_conf_setter = YamlConfigSetter(harness.charm.workload)
    yaml_conf_setter.base_path = config_path / "tmp"

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
    if substrate == "vm":
        mocker.patch(
            "opensearch_single_kernel.workload.vm.VMWorkload.get_publish_host",
            return_value="30.30.30.30",
        )
    else:
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
        return_value=config_path / "tmp" / seed_unicast_hosts,
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.opensearch_config",
        return_value=config_path / "tmp" / opensearch_yml,
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
        seed_hosts=["20.20.20.20"],
    )
    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    assert opensearch_conf["cluster.name"] == "opensearch-dev"

    expected_node_name = harness.charm.state.unit_name
    assert opensearch_conf["node.name"] == expected_node_name

    assert opensearch_conf["node.attr.temp"] == "hot"
    assert opensearch_conf["node.attr.app_id"] == app.id
    assert opensearch_conf["network.host"] == (
        ["_site_", "_local_", "10.10.10.10"] if substrate == "vm" else ["_local_", "10.10.10.10"]
    )
    expected_network_publish = (
        "20.20.20.20"
        if substrate == "vm"
        else "opensearch-0.opensearch-endpoints.namespace.svc.cluster.local"
    )
    assert opensearch_conf["network.publish_host"] == expected_network_publish
    if substrate != "vm":
        assert opensearch_conf["transport.publish_host"] == expected_network_publish
    expected_publish_host = (
        "30.30.30.30"
        if substrate == "vm"
        else "opensearch-0.opensearch-endpoints.namespace.svc.cluster.local"
    )
    assert opensearch_conf["http.publish_host"] == expected_publish_host
    assert opensearch_conf["node.roles"] == ["cluster_manager", "data"]
    assert opensearch_conf["discovery.seed_providers"] == "file"

    assert opensearch_conf["cluster.initial_cluster_manager_nodes"] == ["cm1"]

    # test cleanup_conf_if_bootstrapped
    is_bootstrap_contributor.return_value = False
    harness.charm.config_manager.update_opensearch_config()
    opensearch_conf = yaml_conf_setter.load(opensearch_yml)
    # Base security stuff set by set_node()
    assert get_nested_value(opensearch_conf, "plugins.security.disabled") is False
    assert get_nested_value(opensearch_conf, "plugins.security.ssl_cert_reload_enabled") is True
    assert get_nested_value(opensearch_conf, "plugins.security.restapi.roles_enabled") == [
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
    with open(config_path / ("tmp/" + seed_unicast_hosts), "r") as f:
        stored = {line.strip() for line in f.readlines()}
    assert stored == {"20.20.20.20"}


def test_update_profile_configuration_updates_heap_and_state(harness, mocker, substrate):
    """Changing profile should update JVM heap and persist the new runtime profile."""
    update_heap = mocker.patch.object(harness.charm.config_manager, "_update_jvm_heap_size")
    # MemTotal is in kB; 8 GiB → heap 50% capped by MAX_HEAP (here 4 GiB = 4194304 kB).
    patch_workload_meminfo(mocker, substrate, {"MemTotal": 8 * 1024 * 1024})
    server_profile = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchServer.profile",
        new_callable=PropertyMock,
        return_value=None,
    )

    restart_needed = harness.charm.config_manager.update_profile_configuration(ProductionProfile())

    assert restart_needed is True
    update_heap.assert_called_once_with(4194304)
    server_profile.assert_called()
    server_profile.return_value = ProductionProfile()


def test_update_profile_configuration_is_noop_when_profile_unchanged(harness, mocker):
    """Reapplying the same profile should not rewrite JVM settings."""
    update_heap = mocker.patch.object(harness.charm.config_manager, "_update_jvm_heap_size")
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchServer.profile",
        new_callable=PropertyMock,
        return_value=TestingProfile(),
    )

    restart_needed = harness.charm.config_manager.update_profile_configuration(TestingProfile())

    assert restart_needed is False
    update_heap.assert_not_called()


def test_update_profile_configuration_skips_when_memtotal_missing(harness, mocker, substrate):
    """Profile updates should be skipped when memory information is unavailable."""
    update_heap = mocker.patch.object(harness.charm.config_manager, "_update_jvm_heap_size")
    patch_workload_meminfo(mocker, substrate, {})
    server_profile = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchServer.profile",
        new_callable=PropertyMock,
        return_value=None,
    )

    restart_needed = harness.charm.config_manager.update_profile_configuration(ProductionProfile())

    assert restart_needed is False
    update_heap.assert_not_called()
    server_profile.assert_called()
