# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from _pytest.config.argparsing import Parser


def pytest_addoption(parser: Parser):
    parser.addoption(
        "--substrate",
        action="store",
        help="Substrate to test, either lxd or microk8s",
        choices=("lxd", "microk8s"),
        default="lxd",
    )
