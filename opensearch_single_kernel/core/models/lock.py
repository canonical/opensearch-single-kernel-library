#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the node-lock peer relation."""

import os

from pydantic import Field

from opensearch_single_kernel.core.models.persistent import PersistentModel
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    PeerModel,
)


class LockAppStateModel(PersistentModel, PeerModel):
    """Peer model mapping to the Lock application state."""

    # Juju event id during which the leader granted the lock to itself; the leader may
    # only use the lock in a *later* event (see grant_lock for the full rationale).
    leader_acquired_lock_after_juju_event_id: str | None = Field(default=None)
    # Name of the unit currently holding the peer lock, None when the lock is free.
    unit_with_lock: str | None = Field(default=None)

    @property
    def leader_acquired_after_juju_event_id(self) -> str | None:
        """Alias of `leader_acquired_lock_after_juju_event_id`."""
        return self.leader_acquired_lock_after_juju_event_id

    def grant_lock(self, unit_name: str, own_unit_name: str) -> None:
        """Grant the peer lock to `unit_name`.

        If the lock is granted to the local (leader) unit, also record the Juju event
        during which it happened: see LockAppStateModel.leader_acquired_lock_after_juju_event_id
        for why. Prevent leader unit from using lock in the same Juju event that it was
        granted. If the charm code raises an uncaught exception later in the Juju event,
        `unit-with-lock` will be reverted to its previous value -- which could allow another
        unit to get the lock. Therefore, we cannot use the lock in this Juju event. We must
        wait until the next Juju event, when `unit-with-lock` has been committed (i.e. won't
        be reverted), to use the lock.
        """
        assert self.unit_with_lock != unit_name
        with self.update() as m:
            if unit_name == own_unit_name:
                m.leader_acquired_lock_after_juju_event_id = os.environ.get(
                    "JUJU_CONTEXT_ID", None
                )
            m.unit_with_lock = unit_name

    def release_lock(self) -> None:
        """Release the lock and clear `leader_acquired_lock_after_juju_event_id`."""
        if not self.unit_with_lock:
            return
        with self.update() as m:
            m.unit_with_lock = None
            m.leader_acquired_lock_after_juju_event_id = None


class LockServerStateModel(PersistentModel, PeerModel):
    """Peer model mapping to the Lock unit state."""

    # Whether this unit is asking the leader for the peer lock.
    lock_requested: bool = Field(default=False)

    def trigger_relation_changed(self) -> None:
        """Trigger relation changed event on other units by writing to dummy field."""
        # `trigger` is not a declared field -- it lands in the databag through the
        # model's extra="allow" config. `JUJU_CONTEXT_ID` is used only as a value that
        # is guaranteed to differ from the previous one (it is never read back):
        # rewriting an unchanged value would not emit a peer relation-changed event.
        self.trigger = os.environ.get("JUJU_CONTEXT_ID", "")
