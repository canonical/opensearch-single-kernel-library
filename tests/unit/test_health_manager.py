# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the health manager."""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest
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
    return HealthManager(state, workload)


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
