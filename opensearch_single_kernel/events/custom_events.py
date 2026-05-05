#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of Custom Events defined for this charm."""

from typing import Any

from ops import EventBase, Handle


class StartOpenSearch(EventBase):
    """Attempt to acquire lock & start OpenSearch.

    This event will be deferred until OpenSearch starts.
    """

    def __init__(
        self,
        handle: Handle,
        *,
        ignore_lock: bool = False,
        after_upgrade: bool = False,
        is_first_data_node: bool = False,
        override_version: bool = False,
    ) -> None:
        super().__init__(handle)
        self.ignore_lock = ignore_lock
        self.after_upgrade = after_upgrade
        self.is_first_data_node = is_first_data_node
        self.override_version = override_version

    def snapshot(self) -> dict[str, Any]:
        """Snapshot of the event data."""
        return {
            "ignore_lock": self.ignore_lock,
            "after_upgrade": self.after_upgrade,
            "is_first_data_node": self.is_first_data_node,
            "override_version": self.override_version,
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Restore data from Dict."""
        self.ignore_lock = snapshot["ignore_lock"]
        self.after_upgrade = snapshot["after_upgrade"]
        self.is_first_data_node = snapshot["is_first_data_node"]
        self.override_version = snapshot["override_version"]


class RestartOpenSearch(EventBase):
    """Attempt to acquire lock & restart OpenSearch.

    This event will be deferred until OpenSearch stops. Then, `_StartOpenSearch` will be emitted.
    """


class UpgradeOpenSearch(StartOpenSearch):
    """Attempt to acquire lock & upgrade OpenSearch.

    This event will be deferred until OpenSearch stops. Then, the snap will be upgraded and
    `StartOpenSearch` will be emitted.
    """

    def __init__(self, handle: Handle, *, ignore_lock: bool = False) -> None:
        super().__init__(handle, ignore_lock=ignore_lock)


class ReloadKeystoreEvent(EventBase):
    """Event to signal that the keystore should be reloaded."""


class VerifySnapshotsCredentialsEvent(EventBase):
    """Event to verify backup credentials on main orchestrator leader unit."""
