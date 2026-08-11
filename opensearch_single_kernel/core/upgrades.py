#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the upgrade peer relation."""

import time
from enum import IntEnum
from typing import Optional

import poetry.core.constraints.version as poetry_version
from pydantic import Field, field_validator

from opensearch_single_kernel.core.plain_base import PlainModel
from opensearch_single_kernel.core.relation_base import RelationModel
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    PeerModel,
)
from opensearch_single_kernel.utils.enum import BaseStrEnum


class UpgradeVersions(PlainModel):
    """Model class for the charm and workload versions used for upgrades."""

    charm: str
    workload: str

    @property
    def charm_parsed(self) -> poetry_version.Version:
        """Parsed charm version with build version omitted."""
        return poetry_version.Version.parse(self.charm.split("+")[0])

    @property
    def workload_parsed(self) -> poetry_version.Version:
        """Parsed workload version."""
        return poetry_version.Version.parse(self.workload)


class UpgradeAppModel(RelationModel, PeerModel):
    """Pydantic model for the upgrade application-level databag."""

    # Charm/workload versions the app is upgrading to.
    versions: Optional[UpgradeVersions] = Field(default=None)
    # Whether the user has resumed the upgrade via the Juju action.
    upgrade_resumed: bool = Field(default=False)
    # Write-only timestamp bumped alongside `upgrade_resumed` so a repeated resume with
    # the same value still changes the databag and re-triggers relation-changed on peers.
    upgrade_resume_last_updated: Optional[str] = Field(
        default=None, alias="-unused-timestamp-upgrade-resume-last-updated"
    )

    @field_validator("upgrade_resume_last_updated", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Coerce numeric timestamp stored as float to str."""
        if v is None:
            return None
        return str(v)

    def set_upgrade_resumed(self, value: bool) -> None:
        """Set whether user has resumed upgrade with Juju action."""
        with self.update() as m:
            m.upgrade_resume_last_updated = str(time.time())
            m.upgrade_resumed = value


class UpgradeServerModel(RelationModel, PeerModel):
    """Model for the upgrade unit-level databag."""

    state: Optional[str] = Field(default=None)
    snap_revision: Optional[str] = Field(default=None)
    workload_version: Optional[str] = Field(default=None)

    @field_validator("snap_revision", "workload_version", "state", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Coerce numeric values stored in the databag to str."""
        if v is None:
            return None
        return str(v)

    @property
    def unit_state(self) -> Optional["UnitUpgradesState"]:
        """Get the unit upgrade state, typed."""
        return UnitUpgradesState(self.state) if self.state else None

    @unit_state.setter
    def unit_state(self, value: "UnitUpgradesState") -> None:
        """Set the unit upgrade state."""
        self.state = value.value

    @property
    def workload_version_parsed(self) -> poetry_version.Version | None:
        """Get the parsed workload version of installed OpenSearch."""
        return (
            poetry_version.Version.parse(self.workload_version) if self.workload_version else None
        )

    @property
    def unit_number(self) -> int:
        """Get the unit number this model is bound to."""
        return int(self.component.name.split("/")[-1])


class UnitUpgradesState(BaseStrEnum):
    """Unit state of upgrade."""

    HEALTHY = "healthy"
    RESTARTING = "restarting"  # Kubernetes only
    UPGRADING = "upgrading"  # Machines only
    OUTDATED = "outdated"  # Machines only


class LifecycleUnitTearingDownAndAppActive(IntEnum):
    """Unit is tearing down and 1+ other units are NOT tearing down"""

    FALSE = 0
    TRUE = 1
    UNKNOWN = 2

    def __bool__(self) -> bool:
        """Return bool evaluation."""
        return self is self.TRUE
