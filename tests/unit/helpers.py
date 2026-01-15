# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import shutil
from pathlib import Path
from unittest.mock import PropertyMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from opensearch_single_kernel.common.constants import (
    DeploymentType,
    Directive,
    StartMode,
    State,
)
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
)
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.workload.base import Paths

deployment_descriptions = {
    "ok": DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        app=App(model_uuid="model-uuid", name="opensearch"),
        state=DeploymentState(value=State.ACTIVE),
    ),
    "ko": DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="logs", init_hold=True, roles=["ml"], profile="production"
        ),
        start=StartMode.WITH_PROVIDED_ROLES,
        pending_directives=[Directive.WAIT_FOR_PEER_CLUSTER_RELATION],
        typ=DeploymentType.OTHER,
        app=App(model_uuid="model-uuid", name="opensearch"),
        state=DeploymentState(value=State.BLOCKED_CANNOT_START_WITH_ROLES, message="error"),
    ),
    "cm-only": DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="", init_hold=False, roles=["cluster-manager"], profile="production"
        ),
        start=StartMode.WITH_PROVIDED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        app=App(model_uuid="model-uuid", name="opensearch"),
        state=DeploymentState(value=State.ACTIVE),
    ),
    "data-only": DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="", init_hold=False, roles=["data"], profile="production"
        ),
        start=StartMode.WITH_PROVIDED_ROLES,
        pending_directives=[],
        typ=DeploymentType.OTHER,
        app=App(model_uuid="model-uuid", name="opensearch"),
        state=DeploymentState(value=State.ACTIVE),
    ),
}


def copy_file_content_to_tmp(config_dir_path: str, source_path: str) -> str:
    """Copy the content of a file into a temporary file and return it."""
    relative_dir = ""
    if "/" in source_path:
        relative_dir = "/".join(source_path.split("/")[:-1])

    target_dir = f"{config_dir_path}/tmp/{relative_dir}"
    Path(target_dir).mkdir(parents=True, exist_ok=True)

    dest_path = f"{target_dir}/{source_path.split('/')[-1]}"
    shutil.copyfile(f"{config_dir_path}/{source_path}", dest_path)

    return dest_path


config_path = "tests/unit/resources/config"
opensearch_yml = copy_file_content_to_tmp(config_path, "opensearch.yml")
seed_unicast_hosts = copy_file_content_to_tmp(config_path, "unicast_hosts.txt")
jvm_options = copy_file_content_to_tmp(config_path, "jvm.options")
sec_conf_yml = copy_file_content_to_tmp(config_path, "opensearch-security/config.yml")


def configure_opensearch_config(harness, mocker):
    """Configure opensearch config with mocks to initiate for unit testing."""
    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.seed_hosts",
        return_value=seed_unicast_hosts,
        new_callable=PropertyMock,
    )

    mocker.patch(
        "opensearch_single_kernel.workload.base.Paths.seed_hosts",
        return_value=seed_unicast_hosts,
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.workload.vm.VMWorkload.paths",
        return_value=Paths(conf="", data="data", logs="logs", home="", jdk="", tmp="", bin=""),
        new_callable=PropertyMock,
    )
    harness.charm.config_manager.yaml_setter = YamlConfigSetter(f"{config_path}/tmp")

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


def create_utf8_encoded_private_key() -> str:
    """Creates a private key."""
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("utf-8")
    )
