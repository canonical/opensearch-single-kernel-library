# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for OAuth relation events."""

from opensearch_single_kernel.common.constants import OAUTH_RELATION


def test_oauth_changed_skips_relation_without_remote_app(harness, mocker):
    harness.disable_hooks()
    relation_id = harness.add_relation(OAUTH_RELATION, "oauth")
    relation = harness.model.get_relation(OAUTH_RELATION, relation_id)
    relation.app = None
    event = mocker.Mock(relation=relation)

    harness.charm.oauth_events._on_oauth_relation_changed(event)

    event.defer.assert_not_called()
