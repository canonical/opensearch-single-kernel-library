# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import subprocess
from pathlib import Path

import pytest
from _pytest.config.argparsing import Parser

from tests.helpers import Substrate

# Repo root is the parent of this file's directory (tests/).
_TESTS_DIR = Path(__file__).resolve().parent


def pytest_addoption(parser: Parser):
    parser.addoption(
        "--substrate",
        action="store",
        help="Substrate to test, either vm or k8s",
        choices=("vm", "k8s"),
        default="vm",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "skip_if_substrate(substrate): skip test for the given substrate"
    )
    config.addinivalue_line(
        "markers",
        "skip_if_deployed: skip bootstrap deploy tests when an OpenSearch app already exists",
    )
    config.addinivalue_line("markers", "group(id): mark grouped integration scenarios")


@pytest.fixture(scope="session")
def substrate(request) -> Substrate:
    """The substrate that we are testing."""
    return request.config.option.substrate


@pytest.fixture(autouse=True)
def skip_for_substrate(request, substrate: Substrate):
    if mark := request.node.get_closest_marker("skip_if_substrate"):
        if mark.args[0] == substrate:
            pytest.skip(f"This test does not run on {substrate}")


@pytest.fixture(autouse=True)
def skip_if_deployed(request):
    if not request.node.get_closest_marker("skip_if_deployed"):
        return

    ops_test = request.getfixturevalue("ops_test")
    model_name = ops_test.model.info.name
    status = json.loads(
        subprocess.check_output(
            ["juju", "status", "--model", model_name, "--format", "json"],
            text=True,
        )
    )

    opensearch_charm_names = {"opensearch", "opensearch-k8s"}
    for app in status.get("applications", {}).values():
        if app.get("charm-name") in opensearch_charm_names:
            pytest.skip("OpenSearch is already deployed in this model")


@pytest.fixture
def opensearch_base_path(substrate) -> Path:
    """The base path for the files of the opensearch charms, according to the substrate."""
    if substrate == "k8s":
        return _TESTS_DIR / "charms/opensearch_k8s_test_charm"
    return _TESTS_DIR / "charms/opensearch_test_charm"
