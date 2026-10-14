# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exclusion cleanup must work after the departing node has stopped."""

from unittest.mock import MagicMock, PropertyMock

import pytest
import responses

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.common.exceptions import (
    OpenSearchExclusionsException,
    OpenSearchHttpError,
)
from opensearch_single_kernel.managers.exclusions import NodesExclusionsManager


@pytest.fixture
def exclusions(mocker):
    state = MagicMock()
    state.unit_name = "departing"
    state.node_config = None
    state.server.voting_exclusions_to_delete = {"departing", "other"}
    state.server.allocation_exclusions_to_delete = set()
    client = MagicMock(spec=OpenSearchClient)
    client.get_current_node.return_value = None
    client.fetch_voting_exclusions_config.return_value = {"departing", "other"}
    client.fetch_allocation_exclusions.return_value = {"departing", "other"}
    client.remove_voting_exclusions.return_value = True
    client.add_voting_exclusions.return_value = True
    client.add_allocation_exclusions.return_value = True
    mocker.patch.object(
        NodesExclusionsManager, "opensearch_client", new_callable=PropertyMock, return_value=client
    )
    mocker.patch.object(
        NodesExclusionsManager, "alt_hosts", new_callable=PropertyMock, return_value=["survivor"]
    )
    return NodesExclusionsManager(state, MagicMock()), client


def test_cleanup_after_node_and_topology_disappear(exclusions):
    manager, client = exclusions
    manager.delete_current(Scope.UNIT, raise_error=True)

    client.add_voting_exclusions.assert_called_once_with(
        exclusions={"other"}, alt_hosts=["survivor"]
    )
    assert client.add_allocation_exclusions.call_args.kwargs["allocations"] == {"other"}
    assert manager.state.server.voting_exclusions_to_delete == {"other"}
    client.get_current_node.assert_not_called()


def test_failed_voting_lookup_does_not_erase_other_exclusions(exclusions):
    manager, client = exclusions
    client.get_current_node.return_value = MagicMock(name="departing")
    client.fetch_voting_exclusions_config.side_effect = OpenSearchHttpError("unavailable", 503)
    with pytest.raises(OpenSearchExclusionsException):
        manager.delete_current(Scope.UNIT, raise_error=True)
    client.remove_voting_exclusions.assert_not_called()
    assert manager.state.server.voting_exclusions_to_delete == {"departing", "other"}


def test_repeated_cleanup_is_idempotent(exclusions):
    manager, client = exclusions
    client.fetch_voting_exclusions_config.return_value = {"other"}
    client.fetch_allocation_exclusions.return_value = {"other"}
    for _ in range(2):
        manager.delete_current(Scope.UNIT, raise_error=True)
    client.remove_voting_exclusions.assert_not_called()
    assert manager.state.server.voting_exclusions_to_delete == {"other"}


def test_allocation_exclusion_requires_positive_acknowledgement(mocker):
    workload = MagicMock()
    workload.chain_path.return_value = "/ca.pem"
    client = OpenSearchClient(workload, "localhost", 9200, "password")
    mocker.patch.object(client, "is_node_up", return_value=True)
    with responses.RequestsMock() as http:
        http.put("https://localhost:9200/_cluster/settings", json={"acknowledged": False})
        assert not client.add_allocation_exclusions(
            "departing", allocations={"departing"}, override=True
        )
