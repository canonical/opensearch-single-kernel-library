#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for lock relation."""

import logging
import os
from functools import cached_property

from ops import Relation
from ops.model import Application, Unit

from opensearch_single_kernel.core.models import LockAppStateModel, LockServerStateModel
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    OpsPeerRepositoryInterface,
    OpsPeerUnitRepositoryInterface,
)

logger = logging.getLogger(__name__)


class LockAppState:
    """State collection for the application side of lock relation."""

    def __init__(
        self,
        relation: Relation | None,
        repository: OpsPeerRepositoryInterface[LockAppStateModel],
        component: Application,
        unit_name: str,
    ):
        self._unit_name = unit_name
        self.repository = repository
        self.component = component
        self.relation = relation

    @property
    def _model(self) -> LockAppStateModel | None:
        if not self.relation:
            return None

        return self.repository.build_model(self.relation.id)

    def _write(self, model: LockAppStateModel):
        """Internal helper to write the modified peer model back to the databag."""
        if self.relation:
            self.repository.write_model(self.relation.id, model)

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
        return m.leader_acquired_lock_after_juju_event_id if (m := self._model) else None

    @property
    def unit_with_lock(self) -> str | None:
        """Get format name of the unit that holds the lock."""
        return m.unit_with_lock if (m := self._model) else None

    @unit_with_lock.setter
    def unit_with_lock(self, value: str) -> None:
        """Set format name of the unit that holds the lock.

        Update leader_acquired_after_juju_event_id if lock acquired by the current (leader) unit.
        """
        assert self.unit_with_lock != value

        if m := self._model:
            if value == self._unit_name:
                logger.debug("[Node lock] (leader) granted peer lock to own unit")
                # See LockAppState.leader_acquired_after_juju_event_id
                # description for explanation on why is it needed.
                # `JUJU_CONTEXT_ID` is unique for each Juju event
                # (https://matrix.to/#/!xdClnUGkurzjxqiQcN:ubuntu.com/$yEGjGlDaIPBtCi8uB3fH6ZaXUjN7GF-Y2s9YwvtPM-o?via=ubuntu.com&via=matrix.org&via=cutefunny.art)
                m.leader_acquired_lock_after_juju_event_id = os.environ.get(
                    "JUJU_CONTEXT_ID", None
                )
            m.unit_with_lock = value
            self._write(m)

    @unit_with_lock.deleter
    def unit_with_lock(self) -> None:
        """Remove lock assignment from the units and clear leader_acquired_after_juju_event_id."""
        if m := self._model:
            if m.unit_with_lock:
                m.unit_with_lock = None
                m.leader_acquired_lock_after_juju_event_id = None
                self._write(m)


class LockServerState:
    """State collection for the unit side of lock relation."""

    def __init__(
        self,
        relation: Relation | None,
        repository: OpsPeerUnitRepositoryInterface[LockServerStateModel],
        component: Unit,
    ):
        self.repository = repository
        self.component = component
        self.relation = relation

    @cached_property
    def _model(self) -> LockServerStateModel | None:
        if not self.relation:
            return None

        return self.repository.build_model(self.relation.id)

    def _write(self, model: LockServerStateModel):
        """Internal helper to write the modified peer model back to the databag."""
        if self.relation:
            self.repository.write_model(self.relation.id, model)

    @property
    def lock_requested(self) -> bool:
        """Get whether the lock is requested by unit."""
        return m.lock_requested if (m := self._model) else False

    @lock_requested.setter
    def lock_requested(self, value: bool) -> None:
        """Set whether the lock is requested by unit."""
        if m := self._model:
            m.lock_requested = value
            self._write(m)

    def trigger_relation_changed(self) -> None:
        """Trigger relation changed event on other units by writing to dummy field."""
        if m := self._model:
            # Use `JUJU_CONTEXT_ID` only to ensure that the value changes
            # (Value should never be read)
            # (If we set the same value that is currently in the databag, a peer relation
            # changed event will not be triggered)
            m.trigger = os.environ.get("JUJU_CONTEXT_ID", "")
            self._write(m)
