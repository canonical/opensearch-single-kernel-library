#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of Custom Events defined for this charm."""

from typing import Any, Dict

from ops import EventBase


class StartOpenSearch(EventBase):
    """Attempt to acquire lock & start OpenSearch.

    This event will be deferred until OpenSearch starts.
    """

    def __init__(
        self, handle, *, ignore_lock=False, after_upgrade=False, is_first_data_node=False
    ):
        super().__init__(handle)
        self.ignore_lock = ignore_lock
        self.after_upgrade = after_upgrade
        self.is_first_data_node = is_first_data_node

    def snapshot(self) -> Dict[str, Any]:
        """Snapshot of the event data."""
        return {
            "ignore_lock": self.ignore_lock,
            "after_upgrade": self.after_upgrade,
            "is_first_data_node": self.is_first_data_node,
        }

    def restore(self, snapshot: Dict[str, Any]):
        """Restore data from Dict."""
        self.ignore_lock = snapshot["ignore_lock"]
        self.after_upgrade = snapshot["after_upgrade"]
        self.is_first_data_node = snapshot["is_first_data_node"]
