# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from ops import testing
from ops.testing import Harness

from opensearch_single_kernel.charms.k8s import OpenSearchK8sCharm
from opensearch_single_kernel.charms.vm import OpenSearchVMCharm
from opensearch_single_kernel.common.constants import (
    AZURE_RELATION,
    GCS_RELATION,
    PEER_RELATION,
    S3_RELATION,
    TLS_RELATION,
)
from tests.helpers import Substrate
from tests.integration.conftest import ACTIONS, CONFIG, METADATA
from tests.unit.constants import DEFAULT_AZURE_INFO, DEFAULT_GCS_INFO, DEFAULT_S3_INFO


@pytest.fixture
def harness(substrate: Substrate, opensearch_base_path: Path, mocker) -> Harness:
    if substrate == "vm":
        mocker.patch("opensearch_single_kernel.lib.charms.operator_libs_linux.v2.snap.SnapCache")
        from tests.charms.opensearch_test_charm.src.charm import (
            OpenSearchVMCharm as TestCharm,
        )

        # unit tests should not depend on a running snapd daemon.
        fake_snap = MagicMock()
        fake_snap.present = True
        fake_snap.held = True
        mocker.patch(
            "opensearch_single_kernel.workload.vm.snap.SnapCache",
            return_value={"opensearch": fake_snap},
        )
        # Unit tests should not run Juju CLI (such as unit-get public-address).
        # VM workload callers can fall back to state.host_ip populated by harness.add_network.
        mocker.patch(
            "opensearch_single_kernel.workload.vm.VMWorkload.get_host_public_ip",
            return_value=None,
        )
        mocker.patch(
            "opensearch_single_kernel.workload.vm.VMWorkload.check_missing_system_requirements",
            return_value=[],
        )
    else:
        from tests.charms.opensearch_k8s_test_charm.src.charm import (
            OpenSearchK8sCharm as TestCharm,
        )

    # In K8s, the container hostname is the Pod name ("opensearch-0").
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
    harness.add_relation(TLS_RELATION, harness.charm.app.name)
    with harness.hooks_disabled():
        upgrade_rel_id = harness.add_relation(UPGRADE_RELATION, harness.charm.app.name)
        harness.add_relation_unit(upgrade_rel_id, f"{harness.charm.app.name}/0")

    return harness


@pytest.fixture(autouse=True)
def context(substrate):
    charm_type = OpenSearchVMCharm if substrate == "vm" else OpenSearchK8sCharm
    return testing.Context(charm_type=charm_type, config=CONFIG, meta=METADATA, actions=ACTIONS)


@pytest.fixture(autouse=True)
def mock_fs_interactions(mocker, substrate: Substrate, request) -> None:
    """Mock Filesystem interactions."""
    if request.node.get_closest_marker("real_fs"):
        return
    mocker.patch("charmlibs.pathops.PathProtocol.read_text")
    mocker.patch("charmlibs.pathops.PathProtocol.write_text")
    mocker.patch("charmlibs.pathops.PathProtocol.mkdir")
    mocker.patch("charmlibs.pathops.PathProtocol.unlink")
    mocker.patch("charmlibs.pathops.PathProtocol.exists", return_value=True)
    # VM workload paths are LocalPath,
    # patch those too to avoid touching `/var/snap/...` on dev machines.
    mocker.patch("charmlibs.pathops.LocalPath.exists", return_value=True)
    mocker.patch("charmlibs.pathops.LocalPath.mkdir")
    mocker.patch("charmlibs.pathops.LocalPath.read_text")
    mocker.patch("charmlibs.pathops.LocalPath.write_text")
    mocker.patch("charmlibs.pathops.LocalPath.unlink")
    # Some code paths instantiate LocalPath from the implementation module directly.
    mocker.patch("charmlibs.pathops._local_path.LocalPath.exists", return_value=True)
    mocker.patch("charmlibs.pathops._local_path.LocalPath.mkdir")
    mocker.patch("charmlibs.pathops._local_path.LocalPath.read_text")
    mocker.patch("charmlibs.pathops._local_path.LocalPath.write_text")
    mocker.patch("charmlibs.pathops._local_path.LocalPath.unlink")

    mocker.patch("charmlibs.pathops.LocalPath.read_text")
    mocker.patch("charmlibs.pathops.LocalPath.write_text")
    mocker.patch("charmlibs.pathops.LocalPath.mkdir")
    mocker.patch("charmlibs.pathops.LocalPath.unlink")


# ---- Backup and Restore related fixtures ---- #


def use_s3(mocker, *, ca: str | None = None, info: dict[str, str] | None = None) -> None:
    """Configure fixture to behave as if S3 is connected, optionally inject a CA."""
    mock_s3_conn = mocker.patch(
        "opensearch_single_kernel.lib.charms.data_platform_libs.v0.s3.S3Requirer.get_s3_connection_info",
        return_value=DEFAULT_S3_INFO,
    )

    info = info or DEFAULT_S3_INFO
    if ca is not None:
        info["tls_ca_chain"] = ca
    mock_s3_conn.return_value = info


def use_azure(mocker, info: dict | None = None) -> None:
    """Configure fixture to behave as if Azure is connected."""
    mock_azure_conn = mocker.patch(
        "opensearch_single_kernel.lib.charms.data_platform_libs.v0.azure_storage.AzureStorageRequires.get_azure_storage_connection_info",
        return_value=DEFAULT_AZURE_INFO,
    )
    info = info or DEFAULT_AZURE_INFO
    mock_azure_conn.return_value = info


def use_gcs(mocker, info: dict | None = None) -> None:
    """Configure fixture to behave as if GCS is connected."""
    mock_gcs_conn = mocker.patch(
        "opensearch_single_kernel.lib.charms.data_platform_libs.v0.gcs_storage.GcsStorageRequires.get_storage_connection_info",
        return_value=DEFAULT_GCS_INFO,
    )
    info = info or DEFAULT_GCS_INFO
    mock_gcs_conn.return_value = info


def s3_relation() -> testing.Relation:
    return testing.Relation(endpoint=S3_RELATION, interface="s3", remote_app_name="s3-integrator")


def azure_relation() -> testing.Relation:
    return testing.Relation(
        endpoint=AZURE_RELATION, interface="azure", remote_app_name="azure-integrator"
    )


def gcs_relation() -> testing.Relation:
    return testing.Relation(
        endpoint=GCS_RELATION, interface="gcs", remote_app_name="gcs-integrator"
    )


@pytest.fixture(params=["s3", "azure", "gcs"])
def backend_setup(request, mocker):
    backend = request.param

    mapping = {
        "s3": (use_s3, s3_relation),
        "azure": (use_azure, azure_relation),
        "gcs": (use_gcs, gcs_relation),
    }

    try:
        use_fn, rel_fn = mapping[backend]
    except KeyError as exc:
        raise AssertionError(f"Unknown backend {backend}") from exc

    use_fn(mocker=mocker)
    return backend, {rel_fn()}
