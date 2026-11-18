# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exclusion cleanup should only contact OpenSearch when there is work to do."""

from unittest.mock import Mock, PropertyMock

import pytest

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
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


def make_node(manager, name):
    return Node(
        name=name,
        roles=["cluster_manager", "data"],
        ip="10.0.0.1",
        app=manager.state.application.deployment_desc.app,
        unit_number=1,
    )


@pytest.fixture
def nodes(client):
    return [client.get_current_node.return_value]


@pytest.mark.parametrize("pending_current_unit", [False, True])
def test_cleanup_without_departed_units_makes_no_requests(
    manager, client, cleanup_state, scope, nodes, pending_current_unit
):
    pending = {manager.state.unit_name} if pending_current_unit else set()
    cleanup_state.voting_exclusions_to_delete = pending

    manager.cleanup(scope, nodes)

    assert client.mock_calls == []
    assert cleanup_state.voting_exclusions_to_delete == pending


@pytest.mark.parametrize("succeeds", [False, True])
def test_allocation_cleanup_runs_without_voting_cleanup(
    manager, client, cleanup_state, scope, nodes, succeeds
):
    cleanup_state.allocation_exclusions_to_delete = {"departed-node"}
    client.fetch_allocation_exclusions.return_value = {"departed-node", "other-node"}
    client.add_allocation_exclusions.return_value = succeeds

    manager.cleanup(scope, nodes)

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
    manager, client, cleanup_state, scope, nodes, succeeds
):
    current = manager.state.unit_name
    cleanup_state.voting_exclusions_to_delete = {"departed-node", current}
    client.fetch_voting_exclusions_config.return_value = {"departed-node", current}
    client.remove_voting_exclusions.return_value = succeeds
    client.add_voting_exclusions.return_value = True

    manager.cleanup(scope, nodes)

    client.remove_voting_exclusions.assert_called_once_with(alt_hosts=[])
    if succeeds:
        client.add_voting_exclusions.assert_called_once_with(exclusions={current}, alt_hosts=[])
    else:
        client.add_voting_exclusions.assert_not_called()
    assert cleanup_state.voting_exclusions_to_delete == (
        {current} if succeeds else {"departed-node", current}
    )


@pytest.mark.parametrize("in_cluster", [True, False], ids=["node-in-cluster", "nodes-unknown"])
def test_voting_cleanup_keeps_departing_unit_until_its_node_leaves(
    manager, client, cleanup_state, scope, nodes, in_cluster
):
    cleanup_state.voting_exclusions_to_delete = {"departing-node"}
    client.fetch_voting_exclusions_config.return_value = {"departing-node"}
    cluster_nodes = [*nodes, make_node(manager, "departing-node")] if in_cluster else []

    manager.cleanup(scope, cluster_nodes)

    client.remove_voting_exclusions.assert_not_called()
    assert cleanup_state.voting_exclusions_to_delete == {"departing-node"}


@pytest.mark.parametrize("in_cluster", [True, False], ids=["node-in-cluster", "nodes-unknown"])
def test_allocation_cleanup_keeps_departing_unit_until_its_node_leaves(
    manager, client, cleanup_state, scope, nodes, in_cluster
):
    cleanup_state.allocation_exclusions_to_delete = {"departing-node"}
    client.fetch_allocation_exclusions.return_value = {"departing-node"}
    cluster_nodes = [*nodes, make_node(manager, "departing-node")] if in_cluster else []

    manager.cleanup(scope, cluster_nodes)

    client.add_allocation_exclusions.assert_not_called()
    assert cleanup_state.allocation_exclusions_to_delete == {"departing-node"}


@pytest.mark.parametrize("succeeds", [False, True])
def test_allocation_cleanup_removes_departed_units_and_keeps_pending_work_on_failure(
    manager, client, cleanup_state, scope, nodes, succeeds
):
    current = manager.state.unit_name
    cleanup_state.allocation_exclusions_to_delete = {"departed-node", current}
    client.fetch_allocation_exclusions.return_value = {"departed-node", current}
    client.add_allocation_exclusions.return_value = succeeds

    manager.cleanup(scope, nodes)

    client.add_allocation_exclusions.assert_called_once_with(
        client.get_current_node.return_value,
        allocations={current},
        override=True,
        alt_hosts=[],
    )
    assert cleanup_state.allocation_exclusions_to_delete == (
        {current} if succeeds else {"departed-node", current}
    )


@pytest.mark.parametrize("excluded", [True, False], ids=["still-excluded", "not-excluded"])
def test_voting_cleanup_removes_own_leftover_once_started(
    manager, client, cleanup_state, scope, nodes, excluded
):
    current = manager.state.unit_name
    manager.state.server.started = "1234.0"
    cleanup_state.voting_exclusions_to_delete = {current}
    client.fetch_voting_exclusions_config.return_value = {current} if excluded else set()

    manager.cleanup(scope, nodes)

    assert client.remove_voting_exclusions.call_count == (1 if excluded else 0)
    assert cleanup_state.voting_exclusions_to_delete == set()


def test_allocation_cleanup_removes_own_leftover_once_started(
    manager, client, cleanup_state, scope, nodes
):
    current = manager.state.unit_name
    manager.state.server.started = "1234.0"
    cleanup_state.allocation_exclusions_to_delete = {current}
    client.fetch_allocation_exclusions.return_value = {current, "other-node"}
    client.add_allocation_exclusions.return_value = True

    manager.cleanup(scope, nodes)

    client.add_allocation_exclusions.assert_called_once_with(
        client.get_current_node.return_value,
        allocations={"other-node"},
        override=True,
        alt_hosts=[],
    )
    assert cleanup_state.allocation_exclusions_to_delete == set()


def test_started_cleanup_without_own_leftover_makes_no_requests(
    manager, client, cleanup_state, scope, nodes
):
    manager.state.server.started = "1234.0"
    cleanup_state.voting_exclusions_to_delete = set()
    cleanup_state.allocation_exclusions_to_delete = set()

    manager.cleanup(scope, nodes)

    assert client.mock_calls == []


@pytest.mark.parametrize("known", [True, False], ids=["node-not-in-cluster", "nodes-unknown"])
def test_cleanup_keeps_own_leftover_until_its_node_is_back(
    manager, client, cleanup_state, scope, known
):
    current = manager.state.unit_name
    manager.state.server.started = "1234.0"
    cleanup_state.voting_exclusions_to_delete = {current}
    cleanup_state.allocation_exclusions_to_delete = {current}
    cluster_nodes = [make_node(manager, "other-node")] if known else []

    manager.cleanup(scope, cluster_nodes)

    assert client.mock_calls == []
    assert cleanup_state.voting_exclusions_to_delete == {current}
    assert cleanup_state.allocation_exclusions_to_delete == {current}


def test_explicit_removal_still_clears_current_units_voting_exclusion(
    manager, client, cleanup_state, scope
):
    current = manager.state.unit_name
    cleanup_state.voting_exclusions_to_delete = {current}
    client.fetch_voting_exclusions_config.return_value = {current}

    manager.delete_current(scope, allocation=False)

    client.remove_voting_exclusions.assert_called_once_with(alt_hosts=[])
    assert cleanup_state.voting_exclusions_to_delete == set()


@pytest.mark.parametrize(
    "current_exclusions", [set(), {"other-node"}], ids=["none", "other-node-only"]
)
def test_delete_current_skips_clear_if_unit_not_excluded(
    manager, client, cleanup_state, scope, current_exclusions
):
    current = manager.state.unit_name
    cleanup_state.voting_exclusions_to_delete = {current}
    client.fetch_voting_exclusions_config.return_value = current_exclusions

    manager.delete_current(scope, allocation=False)

    client.remove_voting_exclusions.assert_not_called()
    assert cleanup_state.voting_exclusions_to_delete == set()


def test_delete_current_skips_clear_if_exclusions_unknown(manager, client, cleanup_state, scope):
    current = manager.state.unit_name
    cleanup_state.voting_exclusions_to_delete = {current}
    client.fetch_voting_exclusions_config.side_effect = OpenSearchHttpError(
        response_text="read timed out"
    )

    manager.delete_current(scope, allocation=False)

    client.remove_voting_exclusions.assert_not_called()
    assert cleanup_state.voting_exclusions_to_delete == {current}
