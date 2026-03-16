# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import os
from logging import getLogger
from pathlib import Path

import pytest
import yaml

from tests.helpers import Substrate

logger = getLogger(__name__)


CONFIG = str(yaml.safe_load(Path("./tests/charms/opensearch_test_charm/config.yaml").read_text()))
ACTIONS = str(
    yaml.safe_load(Path("./tests/charms/opensearch_test_charm/actions.yaml").read_text())
)
METADATA = yaml.safe_load(Path("./tests/charms/opensearch_test_charm/metadata.yaml").read_text())
K8S_METADATA = yaml.safe_load(
    Path("./tests/charms/opensearch_k8s_test_charm/metadata.yaml").read_text()
)


APP_NAME = METADATA["name"]

SERIES = "jammy"
# TODO: restore multi-unit tests when charm scale up and scale down are implemented
# UNIT_IDS = [0, 1, 2]
UNIT_IDS = [0]
IDLE_PERIOD = 75


CONFIG_OPTS = {"profile": "testing"}
PRODUCTION_CONFIG_OPTS = {"profile": "production"}


def config_opts_for_deployment(substrate: str, num_units: int) -> dict[str, str]:
    """Return profile config matching the intended deployment topology."""
    if substrate == "k8s":
        return CONFIG_OPTS.copy()
    if num_units >= 3:
        return PRODUCTION_CONFIG_OPTS.copy()
    return CONFIG_OPTS.copy()


MODEL_CONFIG = {
    "logging-config": "<root>=INFO;unit=DEBUG",
    "update-status-hook-interval": "5m",
    "cloudinit-userdata": """postruncmd:
        - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
        - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
        - [ 'sysctl', '-w', 'vm.swappiness=0' ]
        - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    """,
}


@pytest.fixture
def ubuntu_base() -> str:
    """Charm base version to use for testing."""
    return os.environ["CHARM_UBUNTU_BASE"]


@pytest.fixture
def series(ubuntu_base) -> str:
    """Workaround: python-libjuju does not support deploy base="ubuntu@22.04"; use series"""
    if ubuntu_base == "22.04":
        return "jammy"
    elif ubuntu_base == "24.04":
        return "noble"
    else:
        raise NotImplementedError


@pytest.fixture
def charm(substrate: Substrate, opensearch_base_path: str, ubuntu_base: str) -> str:
    """The OpenSearch charm path, to deploy charms, according to the substrate."""
    if substrate == "k8s":
        return f"./{opensearch_base_path}/opensearch-k8s_ubuntu@{ubuntu_base}-amd64.charm"
    return f"./{opensearch_base_path}/opensearch_ubuntu@{ubuntu_base}-amd64.charm"


@pytest.fixture
def charm_resources(substrate: Substrate, ubuntu_base: str) -> dict[str, str]:
    """Resources to pass to `juju deploy` for the OpenSearch charm.

    Juju does not reliably auto-populate OCI image resources for locally packed charms in all
    environments. For the K8s substrate, explicitly provide the `opensearch-image` resource so the
    controller can fetch the image. The K8s workload image is published independently from the
    charm base variants, so we always use the upstream image declared in metadata.
    """
    if substrate != "k8s":
        return {}

    upstream = (
        (K8S_METADATA.get("resources") or {}).get("opensearch-image", {}).get("upstream-source")
    )
    if not upstream:
        raise RuntimeError(
            "K8s test charm metadata is missing resources.opensearch-image.upstream-source"
        )

    return {"opensearch-image": upstream}
