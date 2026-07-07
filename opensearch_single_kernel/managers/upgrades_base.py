# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades

Based off specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""

import abc
import json
import logging
from typing import Any

import ops
from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.constants import UPGRADES_COMPATIBILITY_MATRIX
from opensearch_single_kernel.common.exceptions import (
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchUpgradePrecheckError,
)
from opensearch_single_kernel.common.statuses import GeneralStatuses, UpgradesStatuses
from opensearch_single_kernel.core.models import UpgradeVersions
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.status import format_status
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class UpgradesManagerBase(BaseManager):
    """In-place upgrades"""

    def __init__(
        self,
        state: ClusterState,
        workload: BaseWorkload,
    ) -> None:
        super().__init__(state, workload, "upgrades_manager")
        self.reconcile_compatibility_matrix()

    @property
    def current_versions(self) -> UpgradeVersions:
        """Get the intended versions of OpenSearch by current charm."""
        return UpgradeVersions(
            charm=self.workload.paths.charm_version.read_text().strip(),
            workload=self.workload.paths.workload_version.read_text().strip(),
        )

    @property
    def is_compatible(self) -> bool:
        """Whether upgrade is supported from previous versions"""
        assert (previous_versions := self.state.application_upgrade.versions)

        try:
            if (
                previous_versions.charm_parsed > self.current_versions.charm_parsed
                or previous_versions.charm_parsed.major != self.current_versions.charm_parsed.major
            ):
                logger.debug(
                    f"{previous_versions.charm_parsed=} incompatible with {self.current_versions.charm_parsed=}"
                )
                return False
            if (
                previous_versions.workload_parsed > self.current_versions.workload_parsed
                or previous_versions.workload_parsed.major
                != self.current_versions.workload_parsed.major
            ):
                logger.debug(
                    f"{previous_versions.workload_parsed=} incompatible with {self.current_versions.workload_parsed=}"
                )
                return False
            logger.debug(
                f"Versions before upgrade compatible with versions after upgrade {previous_versions=} {self.current_versions=}"
            )
            return True
        except KeyError as exception:
            logger.debug(f"Version missing from {previous_versions=}", exc_info=exception)
            return False

    @property
    @abc.abstractmethod
    def in_progress(self) -> bool:
        """Whether upgrade is in progress"""

    @property
    @abc.abstractmethod
    def unit_status(self) -> tuple[StatusObject | None, dict[str, Any] | None]:
        """Get unit upgrade status."""

    @property
    def app_status(self) -> StatusObject | None:
        """App upgrade status"""
        if not self.in_progress:
            return None
        if not self.is_compatible:
            logger.info(
                "Upgrade incompatible. If you accept potential *data loss* and *downtime*, you can continue by running `force-upgrade` action on each remaining unit"
            )
            return UpgradesStatuses.UPGRADES_INCOMPATIBLE.value
        if not self.state.application_upgrade.upgrade_resumed:
            # User confirmation needed to resume upgrade (i.e. upgrade second unit)
            # Statuses over 120 characters are truncated in `juju status` as of juju 3.1.6 and
            # 2.9.45
            return UpgradesStatuses.UPGRADES_WAITING_FOR_RESUME.value
        return UpgradesStatuses.UPGRADES_UPGRADING.value

    @abc.abstractmethod
    def reconcile_partition(self, *, action_event: ops.ActionEvent | None = None) -> None:
        """If ready, allow next unit to upgrade."""

    @property
    @abc.abstractmethod
    def authorized(self) -> bool:
        """Whether this unit is authorized to upgrade

        Only applies to machine charm
        """

    @abc.abstractmethod
    def upgrade_unit(self, *, snap: BaseWorkload) -> None:
        """Upgrade this unit.

        Only applies to machine charm
        """

    def pre_upgrade_check(self) -> None:
        """Check if this app is ready to upgrade

        Runs before any units are upgraded

        Does *not* run during rollback

        On machines, this runs before any units are upgraded (after `juju refresh`)
        On machines & Kubernetes, this also runs during pre-upgrade-check action

        Can run on leader or non-leader unit

        Raises:
            PrecheckFailed: App is not ready to upgrade

        TODO Kubernetes: Run (some) checks after `juju refresh` (in case user forgets to run
        pre-upgrade-check action). Note: 1 unit will upgrade before we can run checks (checks may
        need to be modified).
        See https://chat.canonical.com/canonical/pl/cmf6uhm1rp8b7k8gkjkdsj4mya
        """
        logger.debug("Running pre-upgrade checks")

        try:
            deployment_desc = self.state.application.deployment_desc
            if not deployment_desc:
                raise OpenSearchUpgradePrecheckError("Deployment description not available")

            online_nodes = self._nodes(
                use_localhost=self.opensearch_client.is_node_up(),
                hosts=self.alt_hosts,
            )

            # Check if all units are marked as started in peer relation data
            peer_relation = self.state.peer_relation
            all_units_started = peer_relation is not None and all(
                peer_relation.data[unit].get("started") for unit in self.state.all_units
            )

            if (
                not all_units_started
                or len([node for node in online_nodes if node.app.id == deployment_desc.app.id])
                < self.state.model.app.planned_units()
            ):
                raise OpenSearchUpgradePrecheckError(
                    "Not all units are online for the current app."
                )

        except OpenSearchHttpError:
            raise OpenSearchUpgradePrecheckError("Cluster is unreachable")

    @override
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute the manager's statuses."""
        unit_status, unit_dynamic_params = self.unit_status
        if scope == "unit" and unit_status:
            return [format_status(unit_status, unit_dynamic_params)]

        if scope == "app" and (status := self.app_status):
            return [status]

        return [GeneralStatuses.ACTIVE_IDLE.value]

    def override_version(self) -> None:
        """Override the version on disk to allow rollback to proceed."""
        self.workload.run_cmd("opensearch.node", "override-version y")

    @property
    def compatibility_matrix(self) -> dict[str, set[str]]:
        """Read compatibility matrix from file."""
        try:
            content = self.workload.read_text(self.workload.paths.compatibility_matrix)
            return {key: set(value) for key, value in json.loads(content).items()}
        except OpenSearchFileOperationError as e:
            logger.debug("Failed to read compatibility matrix file: %s", str(e))
            return {}
        except (json.JSONDecodeError, TypeError) as e:
            logger.error("Failed to decode compatibility matrix file: %s", str(e))
            return {}

    @compatibility_matrix.setter
    def compatibility_matrix(self, value: dict[str, set[str]]) -> None:
        """Write compatibility matrix to file."""
        try:
            content = json.dumps({key: list(value) for key, value in value.items()}, indent=4)
            self.workload.write_text(content, self.workload.paths.compatibility_matrix)
        except OpenSearchFileOperationError as e:
            logger.debug("Failed to write compatibility matrix file: %s", str(e))

    def reconcile_compatibility_matrix(self) -> dict[str, set[str]]:
        """Reconcile compatibility matrix file."""
        disk_matrix = self.compatibility_matrix
        current_matrix = UPGRADES_COMPATIBILITY_MATRIX
        if disk_matrix != current_matrix:
            # deeply fuse dictionaries
            for key, value in current_matrix.items():
                disk_matrix[key] = disk_matrix.setdefault(key, value) | set(value)  # union of sets
            self.compatibility_matrix = disk_matrix
            logger.debug("Reconciled compatibility matrix file")

        return disk_matrix

    @property
    def is_rollback(self) -> bool:
        """Whether this upgrade is a rollback"""
        if not self.state.application_upgrade.versions or not (
            unit_bag_version := self.state.server_upgrade.workload_version_parsed
        ):
            return False
        version_on_disk = self.current_versions.workload_parsed
        logger.debug("Checking if rollback: %s > %s", str(unit_bag_version), str(version_on_disk))
        return unit_bag_version > version_on_disk

    @property
    def can_rollback(self) -> bool:
        """Whether rollback is supported to previous versions"""
        if not self.state.application_upgrade.versions or not (
            unit_bag_version := self.state.server_upgrade.workload_version_parsed
        ):
            return False

        version_on_disk = self.current_versions.workload_parsed
        compatibility_matrix = self.reconcile_compatibility_matrix()

        if (
            str(unit_bag_version) in compatibility_matrix
            and str(version_on_disk) in compatibility_matrix[str(unit_bag_version)]
        ):
            logger.debug(
                "Rollback supported from %s to %s",
                unit_bag_version,
                version_on_disk,
            )
            return True

        logger.warning("Rollback not supported from %s to %s", unit_bag_version, version_on_disk)
        return False

    def update_grafana_dashboards_title(self, charm_revision: str) -> None:
        """Update the title of the Grafana dashboard file to include the charm revision."""
        dashboard = json.loads(self.workload.read_text(self.workload.paths.grafana_dashboard))

        old_title = dashboard.get("title", "Charmed OpenSearch")
        title_prefix = old_title.split(" - Rev")[0]
        new_title = f"{old_title} - Rev {charm_revision}"
        dashboard["title"] = f"{title_prefix} - Rev {charm_revision}"

        logger.info(
            "Changing the title of grafana dashboard from %s to %s",
            old_title,
            new_title,
        )

        self.workload.write_text(
            json.dumps(dashboard, indent=4), self.workload.paths.grafana_dashboard
        )
