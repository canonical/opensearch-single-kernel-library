#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the node-lock peer relation."""

import os

from pydantic import Field

from opensearch_single_kernel.core.models.base import PersistentModel
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    PeerModel,
)


class LockAppStateModel(PersistentModel, PeerModel):
    """Peer model mapping to the Lock application state."""

    leader_acquired_lock_after_juju_event_id: str | None = Field(default=None)
    unit_with_lock: str | None = Field(default=None)
    lock_granted_after_juju_event_id: str | None = Field(default=None)

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

    lock_requested: bool = Field(default=False)
    lock_acquired_after_juju_event_id: str | None = Field(default=None)

    def trigger_relation_changed(self) -> None:
        """Trigger relation changed event on other units by writing to dummy field."""
        # Use `JUJU_CONTEXT_ID` only to ensure that the value changes
        # (Value should never be read)
        # (If we set the same value that is currently in the databag, a peer relation
        # changed event will not be triggered)
        self.trigger = os.environ.get("JUJU_CONTEXT_ID", "")
