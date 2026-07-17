#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for upgrade-version-a relation."""

import time

import poetry.core.constraints.version as poetry_version
from ops.model import Relation, Unit

from opensearch_single_kernel.core.models import UnitUpgradesState, UpgradeVersions
from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    Data,
)


class UpgradeAppState(RelationState):
    """State collection for the application side of upgrade relation."""

    @property
    def versions(self) -> UpgradeVersions | None:
        """Get the versions of installed OpenSearch from the relation bag.

        Should only be None during first charm install. If a user upgrades from a charm
        that does not set versions, this charm will get stuck.
        """
        if not (raw := self.get_object("versions")):
            return None
        return UpgradeVersions.from_dict(raw)

    @versions.setter
    def versions(self, value: UpgradeVersions) -> None:
        """Set the versions of installed OpenSearch in the relation bag.

        Used after next upgrade to check compatibility (i.e. whether that upgrade should be
        allowed).
        """
        self.put_object("versions", value.to_dict())

    @property
    def upgrade_resumed(self) -> bool:
        """Get whether user has resumed upgrade with Juju action.

        Reset to `False` after each `juju refresh`.
        """
        return self.relation_data.get("upgrade_resumed", "").lower() == "true"

    @upgrade_resumed.setter
    def upgrade_resumed(self, value: bool) -> None:
        """Set whether user has resumed upgrade with Juju action."""
        self.relation_data.update(
            {
                # Trigger peer relation_changed event even if value does not change
                # (Needed when leader sets value to False during `ops.UpgradeCharmEvent`)
                "-unused-timestamp-upgrade-resume-last-updated": str(time.time()),
                "upgrade_resumed": str(value),
            }
        )


class UpgradeServerState(RelationState):
    """State collection for the unit side of upgrade relation."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Unit,
    ) -> None:
        super().__init__(relation, data_interface, component)
        self.unit = component

    @property
    def unit_state(self) -> UnitUpgradesState | None:
        """Get the unit upgrade state from relation bag."""
        return (
            UnitUpgradesState(state)
            if (state := self.relation.data[self.unit].get("state"))
            else None
        )

    @unit_state.setter
    def unit_state(self, value: UnitUpgradesState) -> None:
        """Set the unit upgrade state in relation bag."""
        self.relation.data[self.unit].update({"state": value.value})

    @property
    def snap_revision(self) -> str | None:
        """Get the revision of installed OpenSearch snap from the relation bag."""
        return self.relation.data[self.unit].get("snap_revision")

    @snap_revision.setter
    def snap_revision(self, value: str) -> None:
        """Set the revision of installed OpenSearch snap in the relation bag."""
        self.relation.data[self.unit].update({"snap_revision": value})

    @property
    def workload_version(self) -> str | None:
        """Get the workload version of installed OpenSearch from the relation bag."""
        return self.relation.data[self.unit].get("workload_version")

    @workload_version.setter
    def workload_version(self, value: str) -> None:
        """Set the workload version of installed OpenSearch in the relation bag."""
        self.relation.data[self.unit].update({"workload_version": value})

    @property
    def workload_version_parsed(self) -> poetry_version.Version | None:
        """Get the parsed workload version of installed OpenSearch from the relation bag."""
        return (
            poetry_version.Version.parse(self.workload_version) if self.workload_version else None
        )

    @property
    def unit_number(self) -> int:
        """Get the unit number."""
        return int(self.unit.name.split("/")[-1])

    @property
    def precheck_failed_message(self) -> str | None:
        """Last upgrade precheck failure message for this unit, if any."""
        if not self.relation:
            return None
        return self.relation.data[self.unit].get("precheck_failed_message") or None

    @precheck_failed_message.setter
    def precheck_failed_message(self, value: str | None) -> None:
        """Set or clear the last upgrade precheck failure message."""
        if not self.relation:
            return
        if value:
            self.relation.data[self.unit].update({"precheck_failed_message": value})
        else:
            self.relation.data[self.unit].pop("precheck_failed_message", None)
