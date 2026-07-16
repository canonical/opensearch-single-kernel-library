#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for lock relation."""

import logging
import os

from ops import Relation
from ops.model import Application, Unit

from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    Data,
)

logger = logging.getLogger(__name__)


class LockAppState(RelationState):
    """State collection for the application side of lock relation."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Application,
        unit_name: str,
    ):
        super().__init__(relation, data_interface, component)
        self._unit_name = unit_name
        self.app = component

    @property
    def leader_acquired_after_juju_event_id(self) -> str | None:
        """Juju event ID during which lock was granted to unit.

        Prevent leader unit from using lock in the same Juju event that it was granted
        If the charm code raises an uncaught exception later in the Juju event,
        `unit-with-lock` will be reverted to its previous value—which could allow another
        unit to get the lock.
        Therefore, we cannot use the lock in this Juju event. We must wait until the next
        Juju event, when `unit-with-lock` has been committed (i.e. won't be reverted), to use
        the lock.
        """
        return self.relation_data.get("leader-acquired-lock-after-juju-event-id")

    @property
    def unit_with_lock(self) -> str | None:
        """Get format name of the unit that holds the lock."""
        return self.relation.data[self.app].get("unit-with-lock")

    @unit_with_lock.setter
    def unit_with_lock(self, value: str) -> None:
        """Set format name of the unit that holds the lock.

        Update leader_acquired_after_juju_event_id if lock acquired by the current (leader) unit.
        """
        assert self.unit_with_lock != value

        if value == self._unit_name:
            logger.debug("[Node lock] (leader) granted peer lock to own unit")
            # See LockAppState.leader_acquired_after_juju_event_id
            # description for explanation on why is it needed.
            # `JUJU_CONTEXT_ID` is unique for each Juju event
            # (https://matrix.to/#/!xdClnUGkurzjxqiQcN:ubuntu.com/$yEGjGlDaIPBtCi8uB3fH6ZaXUjN7GF-Y2s9YwvtPM-o?via=ubuntu.com&via=matrix.org&via=cutefunny.art)
            self.relation.data[self.app].update(
                {"leader-acquired-lock-after-juju-event-id": os.environ["JUJU_CONTEXT_ID"]}
            )
        self.relation.data[self.app].update({"unit-with-lock": value})

    @unit_with_lock.deleter
    def unit_with_lock(self) -> None:
        """Remove lock assignment from the units and clear leader_acquired_after_juju_event_id."""
        self.relation.data[self.app].pop("unit-with-lock", None)
        self.relation.data[self.app].pop("leader-acquired-lock-after-juju-event-id", None)


class LockServerState(RelationState):
    """State collection for the unit side of lock relation."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Unit,
    ):
        super().__init__(relation, data_interface, component)
        self.unit = component

    @property
    def lock_requested(self) -> bool:
        """Get whether the lock is requested by unit."""
        return self.relation.data[self.unit].get("lock-requested", "").lower() == "true"

    @lock_requested.setter
    def lock_requested(self, value: bool) -> None:
        """Set whether the lock is requested by unit."""
        if not value:
            self.relation.data[self.unit].pop("lock-requested", None)
        else:
            self.relation.data[self.unit].update({"lock-requested": str(value)})

    def trigger_relation_changed(self) -> None:
        """Trigger relation changed event on other units by writing to dummy field."""
        # Use `JUJU_CONTEXT_ID` only to ensure that the value changes
        # (Value should never be read)
        # (If we set the same value that is currently in the databag, a peer relation
        # changed event will not be triggered)
        self.relation.data[self.unit].update({"-trigger": os.environ["JUJU_CONTEXT_ID"]})
