# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for PluginManager pure status computation."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.managers.plugin import PluginManager
from opensearch_single_kernel.utils.status import format_status


def _manager():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.application.plugin_config_info = {}
    workload = MagicMock()
    return PluginManager(state, workload), state


def test_get_statuses_active_when_no_missing_plugin_relations():
    mgr, state = _manager()
    state.application.plugin_config_info = {}

    statuses = mgr.get_statuses("app")

    assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]


def test_get_statuses_missing_plugin_relation_pure():
    mgr, state = _manager()
    state.application.plugin_config_info = {
        "plugin-smtp-1": SimpleNamespace(relation_name="smtp"),
    }
    state.relation_exists.return_value = False

    statuses = mgr.get_statuses("app", recompute=True)

    assert (
        format_status(
            PeerClusterStatuses.PEER_CLUSTER_MISSING_RELATIONS.value,
            {"relation": "smtp"},
        )
        in statuses
    )
    state.relation_exists.assert_called_with("smtp")


def test_get_statuses_does_not_require_missing_relations_flag():
    """Missing plugin relations are derived from state, not only a boolean flag."""
    mgr, state = _manager()
    state.application.missing_relations = False
    state.application.plugin_config_info = {
        "plugin-s3": SimpleNamespace(relation_name="s3-credentials"),
    }
    state.relation_exists.return_value = False

    statuses = mgr.get_statuses("app")

    assert any(
        "missing relations" in s.message.lower() or "s3-credentials" in s.message for s in statuses
    )


def test_get_statuses_unit_scope_idle():
    mgr, _ = _manager()
    assert mgr.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]
