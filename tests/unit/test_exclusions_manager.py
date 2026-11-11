# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exclusion cleanup should only contact OpenSearch when there is work to do."""

from unittest.mock import Mock, PropertyMock

import pytest

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.core.models import Node
from opensearch_single_kernel.managers.exclusions import NodesExclusionsManager


@pytest.fixture(params=[Scope.APP, Scope.UNIT])
def scope(request):
    return request.param


@pytest.fixture
def manager(harness, patch_deployment_desc):
    with harness.hooks_disabled():
        harness.set_leader(True)
    return harness.charm.exclusions_manager


@pytest.fixture
def client(manager, mocker):
    client = Mock(spec=OpenSearchClient)
    client.fetch_voting_exclusions_config.return_value = set()
    client.remove_voting_exclusions.return_value = True
    client.get_current_node.return_value = Node(
        name=manager.state.unit_name,
        roles=["cluster_manager"],
        ip=manager.state.node_host,
        app=manager.state.application.deployment_desc.app,
        unit_number=0,
    )
    mocker.patch.object(
        NodesExclusionsManager, "opensearch_client", new_callable=PropertyMock, return_value=client
    )
    mocker.patch.object(
        NodesExclusionsManager, "alt_hosts", new_callable=PropertyMock, return_value=[]
    )
    return client


@pytest.fixture
def cleanup_state(manager, scope):
    return manager.state.application if scope == Scope.APP else manager.state.server


@pytest.mark.parametrize("pending_current_unit", [False, True])
def test_cleanup_without_departed_units_makes_no_requests(
    manager, client, cleanup_state, scope, pending_current_unit
):
    pending = {manager.state.unit_name} if pending_current_unit else set()
    cleanup_state.voting_exclusions_to_delete = pending

    manager.cleanup(scope)

    assert client.mock_calls == []
    assert cleanup_state.voting_exclusions_to_delete == pending


@pytest.mark.parametrize("succeeds", [False, True])
def test_allocation_cleanup_runs_without_voting_cleanup(
    manager, client, cleanup_state, scope, succeeds
):
    cleanup_state.allocation_exclusions_to_delete = {"departed-node"}
    client.fetch_allocation_exclusions.return_value = {"departed-node", "other-node"}
    client.add_allocation_exclusions.return_value = succeeds

    manager.cleanup(scope)

    client.fetch_voting_exclusions_config.assert_not_called()
    client.remove_voting_exclusions.assert_not_called()
    client.add_allocation_exclusions.assert_called_once_with(
        client.get_current_node.return_value,
        allocations={"other-node"},
        override=True,
        alt_hosts=[],
    )
    assert cleanup_state.allocation_exclusions_to_delete == (
        set() if succeeds else {"departed-node"}
    )


@pytest.mark.parametrize("succeeds", [False, True])
def test_voting_cleanup_removes_departed_units_and_keeps_pending_work_on_failure(
    manager, client, cleanup_state, scope, succeeds
):
    current = manager.state.unit_name
    cleanup_state.voting_exclusions_to_delete = {"departed-node", current}
    client.fetch_voting_exclusions_config.return_value = {"departed-node", current}
    client.remove_voting_exclusions.return_value = succeeds
    client.add_voting_exclusions.return_value = True

    manager.cleanup(scope)

    client.remove_voting_exclusions.assert_called_once_with(alt_hosts=[])
    if succeeds:
        client.add_voting_exclusions.assert_called_once_with(exclusions={current}, alt_hosts=[])
    else:
        client.add_voting_exclusions.assert_not_called()
    assert cleanup_state.voting_exclusions_to_delete == (
        {current} if succeeds else {"departed-node", current}
    )


def test_explicit_removal_still_clears_current_units_voting_exclusion(
    manager, client, cleanup_state, scope
):
    current = manager.state.unit_name
    cleanup_state.voting_exclusions_to_delete = {current}
    client.fetch_voting_exclusions_config.return_value = {current}

    manager.delete_current(scope, allocation=False)

    client.remove_voting_exclusions.assert_called_once_with(alt_hosts=[])
    assert cleanup_state.voting_exclusions_to_delete == set()
