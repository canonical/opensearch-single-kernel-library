# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for ClusterState status helpers."""

from unittest.mock import MagicMock

from data_platform_helpers.advanced_statuses import StatusObject

from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.status import format_status

COMPONENT = "test_manager"

RELATION_FAILURE = StatusObject(
    status="blocked", message="Setup failed on relation {id}: {reason}"
)


def _state(cached):
    statuses_state = MagicMock()
    statuses_state.get.return_value = cached
    state = ClusterState.__new__(ClusterState)
    state.statuses = statuses_state
    return state, statuses_state


def _add_failure(state, relation_id, reason):
    state.add_status_if_not_present(
        RELATION_FAILURE,
        "unit",
        COMPONENT,
        dynamic_params={"id": relation_id, "reason": reason},
        search_parameters={"id": relation_id},
    )


def _failure(relation_id, reason):
    return format_status(RELATION_FAILURE, {"id": relation_id, "reason": reason})


def test_add_status_keeps_other_relation_statuses():
    state, statuses_state = _state(cached=[_failure(1, "some reason")])

    _add_failure(state, relation_id=2, reason="some reason")

    statuses_state.delete.assert_not_called()
    statuses_state.add.assert_called_once_with(_failure(2, "some reason"), "unit", COMPONENT)


def test_add_status_updates_only_matching():
    state, statuses_state = _state(cached=[_failure(1, "some reason"), _failure(3, "some reason")])

    _add_failure(state, relation_id=3, reason="some other reason")

    statuses_state.delete.assert_called_once_with(_failure(3, "some reason"), "unit", COMPONENT)
    statuses_state.add.assert_called_once_with(_failure(3, "some other reason"), "unit", COMPONENT)


def test_remove_status_deletes_only_matching():
    state, statuses_state = _state(cached=[_failure(1, "some reason"), _failure(3, "some reason")])

    state.remove_status_if_present(
        RELATION_FAILURE,
        "unit",
        COMPONENT,
        interpolated=True,
        search_parameters={"id": 3},
    )

    statuses_state.delete.assert_called_once_with(_failure(3, "some reason"), "unit", COMPONENT)
