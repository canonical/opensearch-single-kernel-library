# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the LDAP manager."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from opensearch_single_kernel.common.constants import Substrates
from opensearch_single_kernel.common.statuses import GeneralStatuses, LdapStatuses
from opensearch_single_kernel.managers.ldap import LdapManager

LDAPS_DATA = SimpleNamespace(ldaps_urls=["ldaps://ldap.local:636"])
CERTIFICATES = {"cert-b", "cert-a"}


def make_state(
    substrate: Substrates = Substrates.VM,
    is_main_orchestrator: bool = True,
    ldap_relation: bool = True,
    ldap_data: SimpleNamespace | None = LDAPS_DATA,
    ldap_certificates: set[str] = CERTIFICATES,
) -> MagicMock:
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.substrate = substrate
    state.is_main_orchestrator = is_main_orchestrator
    state.ldap_relation = MagicMock() if ldap_relation else None
    state.ldap_data = ldap_data
    state.ldap_certificates = ldap_certificates
    return state


def make_workload(chain_content: str | None) -> MagicMock:
    workload = MagicMock()
    workload.exists.return_value = chain_content is not None
    workload.read_text.return_value = chain_content
    return workload


def test_idle_without_ldap_relation():
    manager = LdapManager(make_state(ldap_relation=False, ldap_data=None), MagicMock())

    assert manager.get_statuses("app") == [GeneralStatuses.ACTIVE_IDLE.value]


def test_ldap_statuses_are_app_scoped_only():
    manager = LdapManager(make_state(is_main_orchestrator=False, ldap_data=None), MagicMock())

    assert manager.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]


@pytest.mark.parametrize(
    "state, expected_statuses",
    [
        (make_state(), [GeneralStatuses.ACTIVE_IDLE]),
        (make_state(is_main_orchestrator=False), [LdapStatuses.RELATION_INVALID]),
        (make_state(ldap_data=None), [LdapStatuses.LDAP_DATA_UNAVAILABLE]),
        (
            make_state(ldap_data=SimpleNamespace(ldaps_urls=[])),
            [LdapStatuses.LDAPS_NOT_ENABLED],
        ),
        (make_state(ldap_certificates=set()), [LdapStatuses.CERT_NOT_CONNECTED]),
        (
            make_state(ldap_data=None, ldap_certificates=set()),
            [LdapStatuses.LDAP_DATA_UNAVAILABLE, LdapStatuses.CERT_NOT_CONNECTED],
        ),
    ],
    ids=[
        "fully-configured",
        "not-main-orchestrator",
        "no-provider-data",
        "ldaps-disabled",
        "no-certificates",
        "no-provider-data-and-no-certificates",
    ],
)
def test_ldap_relation_statuses(state, expected_statuses):
    manager = LdapManager(state, MagicMock())

    assert manager.get_statuses("app") == [status.value for status in expected_statuses]


@pytest.mark.parametrize("chain_content", [None, "cert-old"], ids=["missing", "outdated"])
def test_certificates_restored_on_k8s(chain_content):
    workload = make_workload(chain_content)

    LdapManager(make_state(substrate=Substrates.K8S), workload).restore_ldap_ca()

    workload.write_text.assert_called_once_with("cert-a\ncert-b", workload.paths.ldap_chain)


@pytest.mark.parametrize(
    "state, workload",
    [
        (make_state(substrate=Substrates.VM), make_workload(chain_content=None)),
        (make_state(substrate=Substrates.K8S), make_workload(chain_content="cert-a\ncert-b")),
        (
            make_state(substrate=Substrates.K8S, ldap_certificates=set()),
            make_workload(chain_content=None),
        ),
    ],
    ids=["vm", "k8s-chain-up-to-date", "k8s-no-certificates"],
)
def test_certificates_not_restored(state, workload):
    LdapManager(state, workload).restore_ldap_ca()

    workload.write_text.assert_not_called()
