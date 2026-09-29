# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for ExternalClientsManager statuses."""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

from opensearch_single_kernel.common.statuses import (
    ExternalClientsStatuses,
    GeneralStatuses,
)
from opensearch_single_kernel.managers.external_clients import ExternalClientsManager
from opensearch_single_kernel.utils.status import format_status

TEST_INDEX = "test-index"
RELATION_ID = 1


def _manager(
    *,
    requested_index=TEST_INDEX,
    provisioned_index=None,
):
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.server.is_app_leader = True

    relation = MagicMock()
    relation.id = RELATION_ID
    relation.data = {relation.app: {"index": requested_index}, state.model.app: {}}
    if provisioned_index:
        relation.data[state.model.app]["index"] = provisioned_index
    state.external_client_relations = [relation]
    return ExternalClientsManager(state, MagicMock()), state


def _opensearch_client(mocker, *, indices=(), user=True):
    client = MagicMock()
    client.is_node_up.return_value = True
    client.indices.return_value = {index: {} for index in indices}
    client.get_user.return_value = {"user": {}} if user else None
    mocker.patch.object(
        ExternalClientsManager,
        "opensearch_client",
        new_callable=PropertyMock,
        return_value=client,
    )
    return client


def test_get_statuses_returns_cached(mocker):
    """Test cached statuses returned when recompute=False."""
    manager, state = _manager()
    client = _opensearch_client(mocker)
    cached = format_status(
        ExternalClientsStatuses.INDEX_CREATION_FAILED.value,
        {"id": RELATION_ID, "index": TEST_INDEX},
    )

    state.statuses.get.side_effect = lambda *a, **k: SimpleNamespace(
        root=[] if k.get("running_status_only") else [cached]
    )
    assert manager.get_statuses("unit") == [cached]
    client.indices.assert_not_called()


def test_get_status_idle_before_index_created(mocker):
    """Tests no failed status displayed if index requested but not yet provisioned."""
    manager, _ = _manager(requested_index=TEST_INDEX, provisioned_index=None)
    client = _opensearch_client(mocker, indices=())

    assert manager.get_statuses("unit", recompute=True) == [GeneralStatuses.ACTIVE_IDLE.value]
    client.indices.assert_not_called()


def test_get_status_index_missing(mocker):
    """Tests failed status displayed when provisioned index is missing."""
    manager, _ = _manager(requested_index=TEST_INDEX, provisioned_index=TEST_INDEX)
    _opensearch_client(mocker, indices=())

    assert manager.get_statuses("unit", recompute=True) == [
        format_status(
            ExternalClientsStatuses.INDEX_MISSING.value,
            {"id": RELATION_ID, "index": TEST_INDEX},
        )
    ]


def test_get_status_invalid_index_name(mocker):
    """Tests failed status displayed when requested index name invalid."""
    invalid_index = "INVALID"
    manager, _ = _manager(requested_index=invalid_index)
    _opensearch_client(mocker)

    assert manager.get_statuses("unit", recompute=True) == [
        format_status(
            ExternalClientsStatuses.INVALID_INDEX_NAME.value,
            {"id": RELATION_ID, "index": invalid_index},
        )
    ]


def test_get_status_user_missing(mocker):
    """Tests failed status displayed when index provisioned and user missing."""
    manager, _ = _manager(provisioned_index=TEST_INDEX)
    _opensearch_client(mocker, indices=(TEST_INDEX,), user=False)

    assert manager.get_statuses("unit", recompute=True) == [
        format_status(
            ExternalClientsStatuses.USER_MISSING.value,
            {"id": RELATION_ID},
        )
    ]
