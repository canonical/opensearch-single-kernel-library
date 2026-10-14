# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the health manager."""

from collections import Counter
from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest
import requests
import responses
from tenacity import stop_after_attempt

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import HealthColors
from opensearch_single_kernel.common.exceptions import OpenSearchHAError, OpenSearchHttpError
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    HealthStatuses,
)
from opensearch_single_kernel.managers.health import HealthManager
from opensearch_single_kernel.utils.status import format_status


@pytest.fixture
def health_manager(mocker):
    workload = MagicMock()
    workload.chain_path.return_value = "/ca.pem"
    client = OpenSearchClient(workload, "localhost", 9200, "password")
    mocker.patch.object(client, "is_node_up", return_value=True)
    mocker.patch.object(
        HealthManager, "opensearch_client", new_callable=PropertyMock, return_value=client
    )
    mocker.patch.object(HealthManager, "alt_hosts", new_callable=PropertyMock, return_value=None)
    state = MagicMock()
    state.node_host = "localhost"
    state.peer_unit_hosts = set()
    state.application.nodes_config = {}
    state.get_rel_data_from_main_orchestrator.return_value = None
    return HealthManager(state, workload)


@pytest.fixture
def cluster_health_manager(mocker):
    """Keep host discovery and HTTP preflights real; replace only network I/O."""
    workload = MagicMock()
    workload.chain_path.return_value = "/ca.pem"
    workload.is_reachable.return_value = True
    state = MagicMock()
    state.node_host = "node0"
    state.peer_unit_hosts = {"node0", "node1"}
    state.application.nodes_config = {}
    state.get_rel_data_from_main_orchestrator.return_value = None
    state.application.admin_password = "password"
    mocker.patch("random.shuffle", side_effect=lambda hosts: hosts.sort())
    mocker.patch("time.sleep")
    return HealthManager(state, workload)


def test_health_checks_alternative_hosts_only_once(cluster_health_manager):
    """Discover peers from all topology sources, then probe each candidate once."""
    manager = cluster_health_manager
    manager.state.peer_unit_hosts = {"node0", "node1", "node2"}
    manager.state.application.nodes_config = {
        "node2": SimpleNamespace(ip="node2"),
        "node3": SimpleNamespace(ip="node3"),
    }
    manager.state.get_rel_data_from_main_orchestrator.return_value = SimpleNamespace(
        cm_nodes=[SimpleNamespace(ip="node3"), SimpleNamespace(ip="node4")]
    )
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        for i in range(5):
            http.get(f"https://node{i}:9200/", json={})
        http.get(
            "https://node0:9200/_cluster/health",
            json={"status": "green", "initializing_shards": 0, "relocating_shards": 0},
        )

        assert manager.get() == HealthColors.GREEN
        assert Counter(call.request.url for call in http.calls) == Counter(
            {
                "https://node0:9200/": 1,
                "https://node1:9200/": 1,
                "https://node2:9200/": 1,
                "https://node3:9200/": 1,
                "https://node4:9200/": 1,
                "https://node0:9200/_cluster/health": 1,
            }
        )


def test_local_only_topology_has_no_alternative_hosts(cluster_health_manager):
    """Callers can append the local host even when no peers are known."""
    cluster_health_manager.state.peer_unit_hosts = {"node0"}

    assert cluster_health_manager.alt_hosts == []


@pytest.mark.parametrize("property_name", ["peer_hosts", "alt_hosts"])
def test_empty_topology_does_not_require_local_address(
    cluster_health_manager, mocker, property_name
):
    """No peers must be safe before the local address is available."""
    manager = cluster_health_manager
    manager.state.peer_unit_hosts = set()
    mocker.patch.object(
        type(manager.state),
        "node_host",
        new_callable=PropertyMock,
        side_effect=RuntimeError("Local address is unavailable"),
        create=True,
    )

    assert getattr(manager, property_name) == []


@pytest.mark.parametrize("failure", ["connection", "timeout", "503"])
def test_health_falls_back_when_primary_request_fails(cluster_health_manager, failure):
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        for host in ("node0", "node1"):
            http.get(f"https://{host}:9200/", json={})
        if failure == "503":
            http.get("https://node0:9200/_cluster/health", status=503)
        else:
            error = requests.ConnectionError if failure == "connection" else requests.Timeout
            http.get("https://node0:9200/_cluster/health", body=error("unavailable"))
        http.get(
            "https://node1:9200/_cluster/health",
            json={"status": "green", "initializing_shards": 0, "relocating_shards": 0},
        )

        assert cluster_health_manager.get() == HealthColors.GREEN
        assert [call.request.url for call in http.calls] == [
            "https://node0:9200/",
            "https://node1:9200/",
            "https://node0:9200/_cluster/health",
            "https://node1:9200/_cluster/health",
        ]


@pytest.mark.parametrize("alternative_reachable", [False, True])
def test_unavailable_health_keeps_three_attempt_limit(
    cluster_health_manager, alternative_reachable
):
    """Handle both no available peers and a peer that fails after its discovery probe."""
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        http.get("https://node0:9200/", status=503)
        http.get("https://node1:9200/", status=200 if alternative_reachable else 503)
        for host in ("node0", "node1"):
            http.get(
                f"https://{host}:9200/_cluster/health",
                body=requests.ConnectionError("unavailable"),
            )

        assert cluster_health_manager.get() == HealthColors.UNKNOWN
        expected = [
            "https://node0:9200/",
            "https://node1:9200/",
        ]
        if alternative_reachable:
            expected += ["https://node1:9200/_cluster/health"] * 3
        assert [call.request.url for call in http.calls] == expected


@pytest.mark.parametrize("host", [None, "node2"])
@pytest.mark.parametrize("wait_for_green", [False, True])
def test_health_skips_frozen_primary(cluster_health_manager, host, wait_for_green):
    """A frozen primary only receives a short probe, never a long health request."""
    client = cluster_health_manager.opensearch_client
    primary = host or "node0"
    alternatives = ["node1"]
    endpoint = "/_cluster/health"
    if wait_for_green:
        endpoint += "?wait_for_status=green&timeout=1m"
    health = {"status": "green", "initializing_shards": 0, "relocating_shards": 0}
    with responses.RequestsMock() as http:
        http.get(f"https://{primary}:9200/", body=requests.ReadTimeout("frozen"))
        http.get("https://node1:9200/", json={})
        http.get(f"https://node1:9200{endpoint}", json=health)

        assert client.get_health(host, wait_for_green, alternatives) == health
        assert [call.request.url for call in http.calls] == [
            f"https://{primary}:9200/",
            "https://node1:9200/",
            f"https://node1:9200{endpoint}",
        ]
        assert http.calls[0].request.req_kwargs["timeout"] == (1, 1)
        assert alternatives == ["node1"]


@pytest.mark.parametrize("status", ["yellow", "red"])
@pytest.mark.parametrize("transient_error", [False, True])
def test_health_wait_expiry_uses_returned_health(health_manager, status, transient_error):
    """A health-wait expiry supplies current health without a retry or fallback GET."""
    with responses.RequestsMock() as http:
        if transient_error:
            http.get(
                "https://localhost:9200/_cluster/health?wait_for_status=green&timeout=1m",
                status=503,
                json={"error": "unavailable"},
            )
        http.get(
            "https://localhost:9200/_cluster/health?wait_for_status=green&timeout=1m",
            status=408,
            json={
                "status": status,
                "timed_out": True,
                "initializing_shards": 0,
                "relocating_shards": 0,
            },
        )

        assert health_manager.get(wait_for_green_first=True) == status
        assert len(http.calls) == (2 if transient_error else 1)


@pytest.mark.parametrize("response_code, attempts", [(408, 1), (503, 3)])
def test_health_request_error_returns_unknown(health_manager, response_code, attempts):
    """An error without a health result returns unknown after the client's attempts."""
    with responses.RequestsMock() as http:
        http.get(
            "https://localhost:9200/_cluster/health?wait_for_status=green&timeout=1m",
            status=response_code,
            json={"error": "unavailable"},
        )
        assert health_manager.get(wait_for_green_first=True) == HealthColors.UNKNOWN
        assert len(http.calls) == attempts


@pytest.mark.parametrize("status", ["green", "yellow", "red"])
@pytest.mark.parametrize("moving_shards", ["initializing_shards", "relocating_shards"])
def test_relocation_wait_checks_movement_independently_of_colour(
    health_manager, status, moving_shards
):
    """Stopping must wait for moving shards, including in a red cluster."""
    settled = {"status": status, "initializing_shards": 0, "relocating_shards": 0}
    with responses.RequestsMock() as http:
        http.get("https://localhost:9200/_cluster/health", json=settled | {moving_shards: 1})
        http.get("https://localhost:9200/_cluster/health", json=settled)

        health_manager.wait_for_shards_relocation.retry_with(stop=stop_after_attempt(2))(
            health_manager
        )

        assert [request.request.url for request in http.calls] == [
            "https://localhost:9200/_cluster/health",
            "https://localhost:9200/_cluster/health",
        ]


@pytest.mark.parametrize("recovers", [False, True])
def test_relocation_wait_preserves_unavailable_health_behaviour(health_manager, recovers):
    """Keep HTTP retries, but unavailable health must not block recovery or teardown."""
    with responses.RequestsMock() as http:
        http.get("https://localhost:9200/_cluster/health", status=503)
        if recovers:
            http.get(
                "https://localhost:9200/_cluster/health",
                json={"status": "red", "initializing_shards": 0, "relocating_shards": 0},
            )

        health_manager.wait_for_shards_relocation.retry_with(stop=stop_after_attempt(2))(
            health_manager
        )

        assert len(http.calls) == (2 if recovers else 3)


@pytest.mark.parametrize("request_duration, expected_attempts", [(0, 181), (60, 14)])
def test_relocation_wait_budget_includes_request_time(
    health_manager, mocker, request_duration, expected_attempts
):
    """The fifteen-minute budget includes slow requests and ends without authorizing a stop."""
    elapsed = 0

    def advance(seconds):
        nonlocal elapsed
        elapsed += seconds

    def health(*args):
        advance(request_duration)
        return {"status": "red", "initializing_shards": 0, "relocating_shards": 1}

    mocker.patch("time.monotonic", side_effect=lambda: elapsed)
    mocker.patch("time.sleep", side_effect=advance)
    get_health = mocker.patch.object(
        health_manager.opensearch_client, "get_health", side_effect=health
    )

    with pytest.raises(OpenSearchHAError):
        health_manager.wait_for_shards_relocation()

    assert get_health.call_count == expected_attempts
    # An in-flight request may finish beyond the budget; no further retry should begin.
    assert 900 <= elapsed <= 905


def test_health_red_app_status_merges_running():
    state = MagicMock()
    running = SimpleNamespace(status="maintenance", message="something")
    state.statuses.get.return_value = SimpleNamespace(root=[running])
    mgr = HealthManager(state, MagicMock())
    mgr.get = MagicMock(return_value=HealthColors.RED)

    statuses = mgr.get_statuses("app", recompute=False)

    assert running in statuses
    assert HealthStatuses.CLUSTER_HEALTH_RED.value in statuses
    mgr.get.assert_called_once_with(wait_for_green_first=False)


def test_health_recompute_waits_for_green():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    mgr = HealthManager(state, MagicMock())
    mgr.get = MagicMock(return_value=HealthColors.GREEN)

    assert mgr.get_statuses("app", recompute=True) == [GeneralStatuses.ACTIVE_IDLE.value]
    mgr.get.assert_called_once_with(wait_for_green_first=True)


@pytest.mark.parametrize("health", [HealthColors.YELLOW_TEMP, HealthColors.YELLOW])
def test_health_unit_reports_busy_shards_only_during_movement(health_manager, mocker, health):
    health_manager.state.statuses.get.return_value = SimpleNamespace(root=[])
    mocker.patch.object(health_manager, "get", return_value=health)
    busy_shards = mocker.patch.object(
        health_manager.opensearch_client,
        "get_busy_shards_by_unit",
        return_value={"opensearch-0": ["test-index"]},
    )

    statuses = health_manager.get_statuses("unit", recompute=True)

    if health == HealthColors.YELLOW_TEMP:
        assert statuses == [
            format_status(
                HealthStatuses.WAITING_FOR_SPECIFIC_BUSY_SHARDS.value,
                {"shards": "opensearch-0/test-index"},
            )
        ]
        busy_shards.assert_called_once_with(alt_hosts=None)
    else:
        assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]
        busy_shards.assert_not_called()
    health_manager.get.assert_called_once_with(wait_for_green_first=False)


@pytest.mark.parametrize("lookup_fails", [False, True])
def test_health_unit_handles_missing_shard_details(health_manager, mocker, lookup_fails):
    health_manager.state.statuses.get.return_value = SimpleNamespace(root=[])
    mocker.patch.object(health_manager, "get", return_value=HealthColors.YELLOW_TEMP)
    mocker.patch.object(
        health_manager.opensearch_client,
        "get_busy_shards_by_unit",
        return_value={},
        side_effect=OpenSearchHttpError("unavailable", 503) if lookup_fails else None,
    )

    statuses = health_manager.get_statuses("unit")

    if lookup_fails:
        assert statuses == [HealthStatuses.WAITING_FOR_ANY_BUSY_SHARDS.value]
    else:
        assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]
