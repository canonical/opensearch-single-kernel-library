#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for upgrade-version-a relation."""

import time

import poetry.core.constraints.version as poetry_version
from ops.model import Application, Relation, Unit

from opensearch_single_kernel.core.models import (
    UnitUpgradesState,
    UpgradeAppModel,
    UpgradeServerModel,
    UpgradeVersions,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    OpsPeerRepositoryInterface,
    OpsPeerUnitRepositoryInterface,
)


class UpgradeAppState:
    """State collection for the application side of upgrade relation."""

    def __init__(
        self,
        relation: Relation | None,
        repository: OpsPeerRepositoryInterface[UpgradeAppModel],
        component: Application,
    ) -> None:
        self.repository = repository
        self.component = component
        self.relation = relation

    @property
    def model(self) -> UpgradeAppModel | None:
        """Internal helper to retrieve the upgrade app model state."""
        if not self.relation:
            return None
        return self.repository.build_model(self.relation.id)

    def write(self, model: UpgradeAppModel) -> None:
        """Internal helper to write the modified upgrade app model back to the databag."""
        if self.relation:
            self.repository.write_model(self.relation.id, model)

    @property
    def versions(self) -> UpgradeVersions | None:
        """Get the versions of installed OpenSearch from the relation bag."""
        if not self.model:
            return None
        return self.model.versions

    @versions.setter
    def versions(self, value: UpgradeVersions) -> None:
        """Set the versions of installed OpenSearch in the relation bag."""
        if m := self.model:
            m.versions = value
            self.write(m)

    @property
    def upgrade_resumed(self) -> bool:
        """Get whether user has resumed upgrade with Juju action."""
        if m := self.model:
            return m.upgrade_resumed
        return False

    @upgrade_resumed.setter
    def upgrade_resumed(self, value: bool) -> None:
        """Set whether user has resumed upgrade with Juju action."""
        if m := self.model:
            m.upgrade_resume_last_updated = str(time.time())
            m.upgrade_resumed = value
            self.write(m)


class UpgradeServerState:
    """State collection for the unit side of upgrade relation."""

    def __init__(
        self,
        relation: Relation | None,
        repository: OpsPeerUnitRepositoryInterface[UpgradeServerModel],
        component: Unit,
    ) -> None:
        self.repository = repository
        self.component = component
        self.relation = relation

    @property
    def model(self) -> UpgradeServerModel | None:
        """Internal helper to retrieve the upgrade unit model state."""
        if not self.relation:
            return None
        return self.repository.build_model(self.relation.id, component=self.component)

    def write(self, model: UpgradeServerModel) -> None:
        """Internal helper to write the modified upgrade unit model back to the databag."""
        if self.relation:
            self.repository.write_model(self.relation.id, model)

    @property
    def unit_state(self) -> UnitUpgradesState | None:
        """Get the unit upgrade state from relation bag."""
        if m := self.model:
            if m.state:
                return UnitUpgradesState(m.state)
        return None

    @unit_state.setter
    def unit_state(self, value: UnitUpgradesState) -> None:
        """Set the unit upgrade state in relation bag."""
        if m := self.model:
            m.state = value.value
            self.write(m)

    @property
    def snap_revision(self) -> str | None:
        """Get the revision of installed OpenSearch snap from the relation bag."""
        if m := self.model:
            return m.snap_revision
        return None

    @snap_revision.setter
    def snap_revision(self, value: str) -> None:
        """Set the revision of installed OpenSearch snap in the relation bag."""
        if m := self.model:
            m.snap_revision = value
            self.write(m)

    @property
    def workload_version(self) -> str | None:
        """Get the workload version of installed OpenSearch from the relation bag."""
        if m := self.model:
            return m.workload_version
        return None

    @workload_version.setter
    def workload_version(self, value: str) -> None:
        """Set the workload version of installed OpenSearch in the relation bag."""
        if m := self.model:
            m.workload_version = value
            self.write(m)

    @property
    def workload_version_parsed(self) -> poetry_version.Version | None:
        """Get the parsed workload version of installed OpenSearch from the relation bag."""
        if m := self.model:
            return poetry_version.Version.parse(m.workload_version) if m.workload_version else None
        return None

    @property
    def unit_number(self) -> int:
        """Get the unit number."""
        return int(self.component.name.split("/")[-1])
