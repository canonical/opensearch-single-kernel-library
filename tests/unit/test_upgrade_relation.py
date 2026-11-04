# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Compatibility tests for persisted upgrade authorization."""

import json

import pytest

from opensearch_single_kernel.common.constants import UPGRADE_RELATION


@pytest.mark.parametrize(
    "stored,expected",
    [
        ({}, False),
        ({"upgrade-resumed": "true"}, True),
        ({"upgrade-resumed": "false"}, False),
    ],
)
def test_resume_reads_stable_operator_state(harness, stored, expected):
    """Read the same persisted flag as the old stable operator."""
    relation = harness.model.get_relation(UPGRADE_RELATION)
    with harness.hooks_disabled():
        harness.update_relation_data(relation.id, harness.charm.app.name, stored)

    assert harness.charm.state.application_upgrade.upgrade_resumed is expected


@pytest.mark.parametrize("value", [False, True])
def test_resume_write_preserves_stable_operator_contract(harness, value):
    """Resume and reset overwrite the stable flag using its original JSON format."""
    relation = harness.model.get_relation(UPGRADE_RELATION)
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.update_relation_data(
            relation.id, harness.charm.app.name, {"upgrade-resumed": json.dumps(not value)}
        )
        harness.charm.state.application_upgrade.upgrade_resumed = value

    bag = harness.get_relation_data(relation.id, harness.charm.app.name)
    # This is the reader used by the old stable operator, including on rollback.
    assert json.loads(bag.get("upgrade-resumed", "false")) is value
    assert set(bag) == {"upgrade-resumed", "-unused-timestamp-upgrade-resume-last-updated"}
    assert harness.charm.state.application_upgrade.upgrade_resumed is value


def test_repeated_reset_still_notifies_other_units(harness, mocker):
    """Even an unchanged reset needs to trigger reconciliation on the other units."""
    relation = harness.model.get_relation(UPGRADE_RELATION)
    mocker.patch("opensearch_single_kernel.core.upgrade_relation.time.time", side_effect=[1, 2])
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.charm.state.application_upgrade.upgrade_resumed = False
        before = harness.get_relation_data(relation.id, harness.charm.app.name).copy()
        harness.charm.state.application_upgrade.upgrade_resumed = False
        after = harness.get_relation_data(relation.id, harness.charm.app.name)

    assert before != after
    assert json.loads(after["upgrade-resumed"]) is False
