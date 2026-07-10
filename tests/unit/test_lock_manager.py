# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for Lock Manager."""

from unittest.mock import PropertyMock

import pytest
import responses

from opensearch_single_kernel.common.constants import NODE_LOCK_RELATION
from tests.unit.helpers import (
    deployment_descriptions,
    mock_response_lock_not_requested,
    mock_response_nodes,
    mock_response_root,
)


@pytest.fixture
def lock_rel_id(harness):
    lock_rel_id = harness.add_relation(NODE_LOCK_RELATION, harness.charm.app.name)
    harness.add_relation_unit(lock_rel_id, f"{harness.charm.app.name}/1")
    return lock_rel_id


@pytest.fixture
def mock_deployment_desc(mocker):
    """Patch deployment_desc and the file-based internal-user operations it triggers."""
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        return_value=deployment_descriptions["ok"],
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )


def test_node_lock_no_online_hosts_init_leader(harness, lock_rel_id):
    """Initially no one has the lock if there is a leader."""
    harness.set_leader(is_leader=True)

    assert harness.get_relation_data(lock_rel_id, harness.charm.app.name) == {}
    assert harness.get_relation_data(lock_rel_id, harness.charm.unit.name) == {}


@responses.activate
def test_node_lock_has_online_hosts_init_leader(
    harness, lock_rel_id, mock_deployment_desc, mocker
):
    """Initially no one has the lock if there is a leader."""
    mocker.patch("socket.create_connection")
    mock_response_root(harness.charm.state.unit_name, harness.charm.state.host_ip)
    mock_response_nodes(harness.charm.state.unit_name, harness.charm.state.host_ip)

    harness.set_leader(is_leader=True)

    assert harness.get_relation_data(lock_rel_id, harness.charm.app.name) == {}
    assert harness.get_relation_data(lock_rel_id, harness.charm.unit.name) == {}


def test_node_lock_no_online_hosts_leader_acquire_lock_via_databag(
    harness, lock_rel_id, mock_deployment_desc, monkeypatch
):
    """Leader acquires lock via peer databag when no online nodes are present."""
    monkeypatch.setenv("JUJU_CONTEXT_ID", "juju-context-id")

    # The leader does not have the lock at this moment, but starts "queuing up".
    # If the charm code raises an uncaught exception later in the Juju event,
    # the lock will be reverted to its previous value.
    harness.set_leader(is_leader=True)
    harness.update_relation_data(lock_rel_id, harness.charm.app.name, {"unit-with-lock": ""})
    assert not harness.charm.lock_manager.acquire()

    assert (
        harness.get_relation_data(lock_rel_id, harness.charm.unit.name)["lock-requested"] == "True"
    )

    # A new event introduces a new Juju context ID.
    # At this point the leader can take the lock.
    monkeypatch.setenv("JUJU_CONTEXT_ID", "new-context-id")
    assert harness.charm.lock_manager.acquire()


@responses.activate
def test_node_lock_has_online_nodes_leader_acquire_lock_via_document(
    harness, lock_rel_id, mock_deployment_desc, mocker, monkeypatch
):
    """Leader acquires lock via OpenSearch document when online nodes are present."""
    monkeypatch.setenv("JUJU_CONTEXT_ID", "juju-context-id")
    mocker.patch("socket.create_connection")
    create_lock_index_if_needed = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_lock_index_if_needed",
        return_value=True,
    )
    create_lock_document = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_lock_document",
        return_value=True,
    )

    host = harness.charm.state.host_ip
    unit_name = harness.charm.state.unit_name
    mock_response_root(unit_name, host)
    mock_response_nodes(unit_name, host)
    mock_response_lock_not_requested(host)

    harness.set_leader(is_leader=True)
    harness.update_relation_data(lock_rel_id, harness.charm.app.name, {"unit-with-lock": ""})

    # The leader acquires the lock via the OpenSearch document without waiting for another
    # Juju event.
    assert harness.charm.lock_manager.acquire()
    create_lock_index_if_needed.assert_called_once()
    create_lock_document.assert_called_once()


def test_node_lock_no_online_nodes_departing_node_doesnt_break(
    harness, lock_rel_id, mock_deployment_desc, monkeypatch
):
    """Departing unit may be part of the relation while having no entry in the databag.

    https://github.com/canonical/opensearch-operator/issues/323
    """
    monkeypatch.setenv("JUJU_CONTEXT_ID", "juju-context-id")

    harness.set_leader(is_leader=True)
    harness.update_relation_data(lock_rel_id, harness.charm.app.name, {"unit-with-lock": ""})

    # We simulate a departing node by removing it from the relation.
    harness.remove_relation_unit(lock_rel_id, f"{harness.charm.app.name}/1")

    # The property function executes healthy
    # instead of breaking over the departing unit.
    assert not harness.charm.lock_manager.acquire()


@responses.activate
def test_node_lock_has_online_nodes_departing_node_doesnt_break(
    harness, lock_rel_id, mock_deployment_desc, mocker, monkeypatch
):
    """Departing unit may be part of the relation while having no entry in the databag.

    https://github.com/canonical/opensearch-operator/issues/323
    """
    monkeypatch.setenv("JUJU_CONTEXT_ID", "juju-context-id")
    mocker.patch("socket.create_connection")
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_lock_index_if_needed",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_lock_document",
        return_value=True,
    )

    host = harness.charm.state.host_ip
    unit_name = harness.charm.state.unit_name
    mock_response_root(unit_name, host)
    mock_response_nodes(unit_name, host)
    mock_response_lock_not_requested(host)

    harness.set_leader(is_leader=True)
    harness.update_relation_data(lock_rel_id, harness.charm.app.name, {"unit-with-lock": ""})

    # We simulate a departing node by removing it from the relation.
    harness.remove_relation_unit(lock_rel_id, f"{harness.charm.app.name}/1")

    # The lock acquisition executes without breaking over the departing unit.
    assert harness.charm.lock_manager.acquire()
