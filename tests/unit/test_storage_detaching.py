# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exercise removal through the handler, stop logic, health and exclusion managers."""

from itertools import count
from unittest.mock import PropertyMock

import pytest
from ops import StorageDetachingEvent

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import StartMode
from opensearch_single_kernel.common.exceptions import (
    OpenSearchExclusionsException,
    OpenSearchHAError,
    OpenSearchHttpError,
    OpenSearchStopError,
)
from opensearch_single_kernel.core.models import App, Node, PeerClusterApp
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.managers.exclusions import NodesExclusionsManager


@pytest.fixture
def removal(harness, patch_deployment_desc, mocker):
    charm = harness.charm
    harness.set_planned_units(1)
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    client = mocker.Mock(spec=OpenSearchClient)
    client.is_node_up.return_value = True
    node = Node(
        name=charm.state.unit_name,
        roles=["cluster_manager", "data"],
        ip="1.1.1.1",
        app=charm.state.application.deployment_desc.app,
        unit_number=0,
    )
    client.get_nodes.return_value = {
        "nodes": {
            "self": {
                "name": node.name,
                "roles": node.roles,
                "ip": node.ip,
                "host": node.ip,
                "attributes": {"app_id": node.app.id},
            },
            "survivor": {
                "name": "opensearch-1.c1d",
                "roles": node.roles,
                "ip": "2.2.2.2",
                "host": "2.2.2.2",
                "attributes": {"app_id": node.app.id},
            },
        }
    }
    client.get_current_node.return_value = node
    client.get_cluster_node_names = mocker.Mock(return_value={node.name, "survivor"})
    client.get_health.return_value = {
        "status": "green",
        "initializing_shards": 0,
        "relocating_shards": 0,
    }
    client.get_shards.return_value = [
        {
            "index": "data",
            "shard": "0",
            "prirep": "p",
            "state": "STARTED",
            "node": "survivor",
            "in_sync": True,
        }
    ]
    client.get_unit_with_lock.return_value = None
    client.fetch_voting_exclusions_config.return_value = set()
    client.fetch_allocation_exclusions.return_value = set()
    client.add_voting_exclusions.return_value = True
    client.add_allocation_exclusions.return_value = True
    client.remove_voting_exclusions.return_value = True
    mocker.patch.object(
        BaseManager, "opensearch_client", new_callable=PropertyMock, return_value=client
    )
    hosts = mocker.patch.object(
        BaseManager, "alt_hosts", new_callable=PropertyMock, return_value=["2.2.2.2"]
    )
    acquire = mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    stopped = mocker.patch.object(charm.cluster_manager, "stop_workload")
    # Exhaust deadline-based waits in one attempt without changing their production behavior.
    clock = count(step=1000)
    mocker.patch("time.monotonic", side_effect=lambda: next(clock))
    event = mocker.Mock(spec=StorageDetachingEvent)
    return charm, client, stopped, event, hosts, acquire


@pytest.mark.parametrize(
    "failure", ["only-copy-departing", "unavailable-state", "no-survivor", "exclusion-rejected"]
)
def test_unsafe_removal_keeps_workload_running(removal, failure):
    charm, client, stopped, event, hosts, _ = removal
    if failure == "only-copy-departing":
        client.get_shards.return_value[0]["node"] = charm.state.unit_name
    elif failure == "unavailable-state":
        client.get_shards.side_effect = OpenSearchHttpError("unavailable", 503)
    elif failure == "no-survivor":
        hosts.return_value = []
    else:
        client.add_allocation_exclusions.return_value = False

    with pytest.raises((OpenSearchStopError, OpenSearchHAError)):
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)

    stopped.assert_not_called()
    client.remove_voting_exclusions.assert_not_called()


def test_safe_removal_stops_and_cleans_exclusions(removal):
    charm, client, stopped, event, _, _ = removal
    name = charm.state.unit_name
    client.fetch_voting_exclusions_config.return_value = {name, "other"}
    client.fetch_allocation_exclusions.return_value = {name, "other"}

    charm.opensearch_events._on_opensearch_data_storage_detaching(event)

    stopped.assert_called_once()
    client.add_voting_exclusions.assert_called_with(exclusions={"other"}, alt_hosts=["2.2.2.2"])
    assert client.add_allocation_exclusions.call_args.kwargs["allocations"] == {"other"}
    client.get_unit_with_lock.assert_called_once()


@pytest.mark.parametrize("cleanup_failed", [False, True])
def test_release_failure_preserves_removal_error(removal, caplog, cleanup_failed):
    charm, client, stopped, event, _, _ = removal
    if cleanup_failed:
        client.fetch_voting_exclusions_config.side_effect = OpenSearchHttpError(
            "cleanup unavailable", 503
        )
    else:
        client.get_shards.return_value[0]["node"] = charm.state.unit_name
    client.get_unit_with_lock.side_effect = OpenSearchHttpError("lock unavailable", 503)

    with pytest.raises(OpenSearchExclusionsException if cleanup_failed else OpenSearchStopError):
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)

    assert stopped.called == cleanup_failed
    assert "lock unavailable" in caplog.text
    client.delete_lock_document.assert_not_called()


def test_release_failure_after_success_still_fails_hook(removal):
    charm, client, stopped, event, _, _ = removal
    client.get_unit_with_lock.side_effect = OpenSearchHttpError("lock unavailable", 503)
    with pytest.raises(OpenSearchHttpError, match="lock unavailable"):
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)
    stopped.assert_called_once()
    client.delete_lock_document.assert_not_called()


def test_reconciliation_failure_still_releases_lock(removal, harness, mocker):
    charm, client, stopped, event, _, _ = removal
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(
        charm.cluster_manager,
        "reconcile_before_unit_removal",
        side_effect=OpenSearchHAError("topology unavailable"),
    )
    with pytest.raises(OpenSearchHAError, match="topology unavailable"):
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)
    stopped.assert_not_called()
    client.get_unit_with_lock.assert_called_once()


@pytest.mark.parametrize("other_app_survives", [False, True])
def test_last_application_unit_distinguishes_cluster_teardown(
    removal, harness, other_app_survives
):
    charm, client, stopped, event, _, acquire = removal
    harness.set_planned_units(0)
    remote = App(model_uuid="model-uuid", name="remote")
    with harness.hooks_disabled():
        harness.set_leader(True)
        charm.state.application.cluster_fleet_apps = {
            remote.id: PeerClusterApp(
                app=remote,
                planned_units=int(other_app_survives),
                units=["remote/0"] if other_app_survives else [],
                roles=["data", "cluster_manager"],
            )
        }
        harness.set_leader(False)
    client.get_shards.return_value[0]["node"] = charm.state.unit_name
    if other_app_survives:
        with pytest.raises(OpenSearchStopError):
            charm.opensearch_events._on_opensearch_data_storage_detaching(event)
        stopped.assert_not_called()
        acquire.assert_called_once()
    else:
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)
        stopped.assert_called_once()
        acquire.assert_not_called()
        client.get_shards.assert_not_called()


def test_restart_does_not_require_a_surviving_copy(removal):
    charm, client, stopped, _, _, _ = removal
    client.get_shards.return_value[0]["node"] = charm.state.unit_name
    charm.stop_opensearch(restart=True)
    stopped.assert_called_once()
    client.get_shards.assert_not_called()


@pytest.mark.skip_if_substrate("k8s")
def test_vm_teardown_without_deployment_description_can_stop(removal, mocker):
    """Preserve VM teardown after relation state disappears (K8s needs it for its FQDN)."""
    charm, _, stopped, _, _, _ = removal
    mocker.patch.object(
        type(charm.state.application),
        "deployment_desc",
        new_callable=PropertyMock,
        return_value=None,
    )
    charm.stop_opensearch()
    stopped.assert_called_once()


def test_local_http_failure_does_not_bypass_voting_exclusions(removal):
    """The survivor still sees a voting member even if its local HTTP probe fails."""
    charm, client, stopped, event, _, _ = removal
    client.is_node_up.return_value = False
    client.add_voting_exclusions.return_value = False
    with pytest.raises(OpenSearchStopError):
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)
    stopped.assert_not_called()


def test_last_provider_keeps_survivor_discovery_until_lock_release(removal, harness, mocker):
    """Last-app cleanup must not discard the only addresses of surviving fleet nodes."""
    charm, client, stopped, event, hosts, _ = removal
    harness.set_planned_units(0)
    remote = App(model_uuid="model-uuid", name="remote")
    mocker.patch.object(
        type(charm.state.application),
        "deployment_desc",
        new_callable=PropertyMock,
        return_value=charm.state.application.deployment_desc.model_copy(deep=True),
    )
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=True)
    local_node = client.get_current_node.return_value
    remote_node = local_node.model_copy(
        update={"name": "remote-0", "ip": "2.2.2.2", "app": remote}
    )
    with harness.hooks_disabled():
        harness.set_leader(True)
        charm.state.application.is_security_index_initialised = True
        harness.add_relation_unit(charm.state.peer_relation.id, f"{charm.app.name}/1")
        charm.state.application.cluster_fleet_apps = {
            remote.id: PeerClusterApp(
                app=remote, planned_units=1, units=["remote/0"], roles=["data", "cluster_manager"]
            )
        }
        charm.state.application.nodes_config = {
            local_node.name: local_node,
            remote_node.name: remote_node,
        }
    mocker.stop(hosts)
    mocker.patch.object(
        type(charm.state), "peer_unit_hosts", new_callable=PropertyMock, side_effect=lambda: set()
    )
    mocker.patch.object(charm.state, "get_rel_data_from_main_orchestrator", return_value=None)
    mocker.patch.object(charm.peer_cluster_orchestrator_manager, "refresh_relation_data")
    mocker.patch.object(
        charm.peer_cluster_orchestrator_manager, "clean_all_provider_relation_data"
    )

    def stop():
        client.is_node_up.side_effect = lambda host=None: host == "2.2.2.2"

    stopped.side_effect = stop

    def check_release(host, alt_hosts):
        assert host is None
        assert alt_hosts == ["2.2.2.2"]
        return None

    client.get_unit_with_lock.side_effect = check_release

    charm.opensearch_events._on_opensearch_data_storage_detaching(event)

    stopped.assert_called_once()
    client.get_unit_with_lock.assert_called_once()
    assert set(charm.state.application.nodes_config) == {remote_node.name}
    assert charm.cluster_manager.alt_hosts == ["2.2.2.2"]


def test_fresh_removal_retry_after_stop_and_topology_pruning(removal, harness):
    """A fresh manager can finish cleanup after the previous hook already stopped the node."""
    charm, client, stopped, event, _, _ = removal
    with harness.hooks_disabled():
        harness.set_leader(True)
        charm.state.application.is_security_index_initialised = True
    client.fetch_voting_exclusions_config.side_effect = [
        OpenSearchHttpError("unavailable", 503),
        {charm.state.unit_name},
    ]
    with pytest.raises(OpenSearchExclusionsException):
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)
    stopped.assert_called_once()
    assert charm.state.unit_name not in charm.state.application.nodes_config

    charm.exclusions_manager = NodesExclusionsManager(charm.state, charm.workload)
    client.is_node_up.return_value = False
    client.get_current_node.return_value = None
    client.get_current_node.reset_mock()
    del client.get_nodes.return_value["nodes"]["self"]
    client.get_cluster_node_names.return_value = {"survivor"}

    charm.opensearch_events._on_opensearch_data_storage_detaching(event)

    client.get_current_node.assert_not_called()
    client.remove_voting_exclusions.assert_called_once()


def test_partial_node_info_does_not_authorize_removal(removal):
    """A missing node-info response is not evidence that the member has left."""
    charm, client, stopped, event, _, _ = removal
    client.is_node_up.return_value = False
    del client.get_nodes.return_value["nodes"]["self"]
    client.add_voting_exclusions.return_value = False
    with pytest.raises(OpenSearchStopError):
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)
    stopped.assert_not_called()


@pytest.mark.parametrize(
    "health", [None, {"status": "red", "initializing_shards": 0, "relocating_shards": 0}]
)
@pytest.mark.parametrize("data_role", [False, True])
def test_unhealthy_survivor_after_stop_fails_removal(removal, mocker, health, data_role):
    charm, client, stopped, event, _, _ = removal
    if not data_role:
        deployment = charm.state.application.deployment_desc.model_copy(deep=True)
        deployment.start = StartMode.WITH_PROVIDED_ROLES
        deployment.config.roles = ["cluster_manager"]
        mocker.patch.object(
            type(charm.state.application),
            "deployment_desc",
            new_callable=PropertyMock,
            return_value=deployment,
        )
        client.get_current_node.return_value.roles = ["cluster_manager"]
    client.get_health.return_value = health
    with pytest.raises(OpenSearchHAError):
        charm.opensearch_events._on_opensearch_data_storage_detaching(event)
    stopped.assert_called_once()
    client.get_unit_with_lock.assert_called_once()
