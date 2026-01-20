# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
import yaml
from ops.testing import Harness

from tests.helpers import Substrate

CONFIG = yaml.safe_load(Path("./tests/charms/opensearch_test_charm/config.yaml").read_text())
ACTIONS = yaml.safe_load(Path("./tests/charms/opensearch_test_charm/actions.yaml").read_text())
METADATA = yaml.safe_load(Path("./tests/charms/opensearch_test_charm/metadata.yaml").read_text())


@pytest.fixture
def harness(substrate: Substrate, opensearch_base_path: Path) -> Harness:
    if substrate == "lxd":
        from tests.charms.opensearch_test_charm.src.charm import (
            OpenSearchVMCharm as TestCharm,
        )
    else:
        from tests.charms.opensearch_k8s_test_charm.src.charm import (
            OpenSearchK8sCharm as TestCharm,
        )

    config = str(yaml.safe_load((opensearch_base_path / "config.yaml").read_text()))
    actions = str(yaml.safe_load((opensearch_base_path / "actions.yaml").read_text()))
    metadata = str(yaml.safe_load((opensearch_base_path / "metadata.yaml").read_text()))

    harness = Harness(TestCharm, meta=metadata, actions=actions, config=config)
    harness.add_network("1.1.1.1")
    harness.add_relation("opensearch-peers", "opensearch-peers")
    harness.begin()

    return harness
