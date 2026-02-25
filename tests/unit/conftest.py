# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
import yaml
from ops.testing import Harness

from opensearch_single_kernel.common.constants import PEER_RELATION, TLS_RELATION
from tests.helpers import Substrate

CONFIG = yaml.safe_load(Path("./tests/charms/opensearch_test_charm/config.yaml").read_text())
ACTIONS = yaml.safe_load(Path("./tests/charms/opensearch_test_charm/actions.yaml").read_text())
METADATA = yaml.safe_load(Path("./tests/charms/opensearch_test_charm/metadata.yaml").read_text())


@pytest.fixture
def harness(substrate: Substrate, opensearch_base_path: Path, mocker) -> Harness:
    if substrate == "vm":
        from tests.charms.opensearch_test_charm.src.charm import (
            OpenSearchVMCharm as TestCharm,
        )
    else:
        from tests.charms.opensearch_k8s_test_charm.src.charm import (
            OpenSearchK8sCharm as TestCharm,
        )

    # In real K8s, the container hostname is the Pod name (e.g. "opensearch-0").
    # When running unit tests on a local machine, socket.gethostname() would
    # return the host machine name which breaks node.name-dependent logic.
    if substrate != "vm":
        mocker.patch("socket.gethostname", return_value="opensearch-0")
        mocker.patch("socket.getfqdn", return_value="opensearch-0")

    config = str(yaml.safe_load((opensearch_base_path / "config.yaml").read_text()))
    actions = str(yaml.safe_load((opensearch_base_path / "actions.yaml").read_text()))
    metadata = str(yaml.safe_load((opensearch_base_path / "metadata.yaml").read_text()))

    harness = Harness(TestCharm, meta=metadata, actions=actions, config=config)
    harness.add_network("1.1.1.1")
    harness.add_network("1.1.1.1", endpoint=TLS_RELATION)
    harness.begin()
    # Most unit tests assume the workload container is connectable so charm logic can
    # proceed past "container not ready" gating (pebble/files/exec operations are mocked).
    if substrate != "vm":
        harness.set_can_connect("opensearch", True)
    rel_id = harness.add_relation(PEER_RELATION, harness.charm.app.name)
    harness.add_relation_unit(rel_id, f"{harness.charm.app.name}/0")
    harness.add_relation(TLS_RELATION, harness.charm.app.name),

    return harness


@pytest.fixture
def mock_fs_interactions(mocker, substrate: Substrate) -> None:
    """Mock Filesystem interactions."""
    mocker.patch("charmlibs.pathops.PathProtocol.read_text")
    mocker.patch("charmlibs.pathops.PathProtocol.write_text")
    mocker.patch("charmlibs.pathops.PathProtocol.mkdir")
    mocker.patch("charmlibs.pathops.PathProtocol.unlink")
    mocker.patch("charmlibs.pathops.PathProtocol.exists", return_value=True)
