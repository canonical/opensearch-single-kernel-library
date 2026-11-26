# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades on kubernetes

Derived from specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""

import logging
from typing import Any

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope

from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchK8sDeployedWithoutTrustError,
    OpenSearchK8sError,
    OpenSearchReconcilePartitionError,
)
from opensearch_single_kernel.common.statuses import UpgradesStatuses
from opensearch_single_kernel.core.models import UnitUpgradesState
from opensearch_single_kernel.core.state import UpgradeServerState
from opensearch_single_kernel.managers.upgrades_base import (
    UpgradesManagerBase,
)
from opensearch_single_kernel.utils.status import format_status, running_statuses

logger = logging.getLogger(__name__)

FORCE_ACTION_NAME = "force-upgrade"


class UpgradesManagerK8s(UpgradesManagerBase):
    """In-place upgrades on kubernetes"""

    @property
    def partition(self) -> int:
        """Specifies which units should upgrade.

        Unit numbers >= partition should upgrade
        Unit numbers < partition should not upgrade

        https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#partitions

        For Kubernetes, unit numbers are guaranteed to be sequential.
        """
        return self.k8s_client.get_partition()

    @partition.setter
    def partition(self, value: int) -> None:
        """Sets the partition number."""
        self.k8s_client.set_partition(value)

    @property
    def upgrade_resumed(self) -> bool:
        """Whether the partition allows units beyond the first to upgrade."""
        if not (units := self.state.sorted_upgrades_units):
            return False
        highest_unit = units[0]
        return self.partition < highest_unit.unit_number

    def save_upgrades_versions(self) -> None:
        """Save revision on first install"""
        # Save versions on initial start
        logger.debug(
            "Setting %r in upgrade peer relation app databag",
            self.current_versions,
        )
        self.state.application_upgrade.versions = self.current_versions
        logger.debug(
            "Set %r in upgrade peer relation app databag",
            self.current_versions,
        )

    @property
    def unit_status(self) -> tuple[StatusObject | None, dict[str, Any] | None]:
        """Get unit upgrade status."""
        if not self.state.upgrade_relation:
            return (None, None)

        if self.is_rollback:
            if not self.can_rollback:
                return UpgradesStatuses.UPGRADES_ROLLBACK_UNSUPPORTED.value, None
            else:
                return UpgradesStatuses.UPGRADES_ROLLBACK_INCOMPATIBLE.value, None

        if not self.in_progress:
            return (None, None)

        if not self.is_compatible:
            return (UpgradesStatuses.UPGRADES_INCOMPATIBLE.value, None)

        version = self.k8s_client.list_revisions().get(self.state.server.unit.name)
        if version == self.k8s_client.get_revision():
            return (
                UpgradesStatuses.K8S_UPGRADES_ACTIVE.value,
                {
                    "workload_version": self.current_versions.workload,
                    "charm_version": self.current_versions.charm,
                },
            )
        else:
            return (
                UpgradesStatuses.K8S_UPGRADES_ACTIVE_OUTDATED.value,
                {
                    "workload_version": self.current_versions.workload,
                    "charm_version": self.current_versions.charm,
                },
            )

    @property
    def unit_state(self) -> UnitUpgradesState | None:
        """Calculate the upgrade state of current unit."""
        return self.state.server_upgrade.unit_state

    def reconcile_partition(self) -> None:
        """If ready, lower partition to upgrade next unit.

        If upgrade is not in progress, preserve the partition established by pre-upgrade-check.
        This keeps the other units protected before the first unit receives its stop event.

        Automatically upgrades next unit if all upgraded units are healthy, except if only one unit
        has upgraded (need manual user confirmation [via Juju action] to upgrade next unit)

        Manual confirmation and forced resume use get_resume_partition instead.
        The upgrade event handlers apply that request after the action completes.
        """
        partition = self._determine_partition(
            self.state.sorted_upgrades_units, resume=False, force=False
        )
        logger.debug(f"{self.partition=}, {partition=}")
        # Only lower the partition. _determine_partition() can return a higher value
        # on a later hook while the next unit is restarting.
        # Example: If partition is lowered to 1, unit 1 begins to upgrade, and partition is set to
        # 2 right away, the unit/Juju agent will hang
        # Details: https://chat.charmhub.io/charmhub/pl/on8rd538ufn4idgod139skkbfr
        # This does not address the situation where another unit > 1 restarts and sets the
        # partition during the `stop` event, but that is unlikely to occur in the small time window
        # that causes the unit to hang.
        if partition < self.partition:
            self.partition = partition
            logger.debug("Lowered partition to %s", partition)

    def get_resume_partition(self, *, force: bool = False) -> int:
        """Return the partition needed to resume the upgrade, without changing it.

        Normal resume requires the previously upgraded units to be HEALTHY.
        With force=True, allow the next unit to upgrade even if an upgraded unit is
        unhealthy. While any upgraded unit remains unhealthy, each further unit
        requires another forced resume.

        The charm controls the partition, but Kubernetes decides when pods are replaced.
        Even after lowering the partition, Kubernetes may wait if a pod with a higher
        unit number has a charm container that is not Ready. This can also affect a
        normal resume, although it is less likely when all upgraded units are HEALTHY.
        """
        units = self.state.sorted_upgrades_units
        if len(units) < 2:
            raise OpenSearchReconcilePartitionError(message="No further unit to upgrade.")
        partition = self._determine_partition(units, resume=True, force=force)
        if partition > units[1].unit_number:
            raise OpenSearchReconcilePartitionError(
                message="Highest number unit is unhealthy. Upgrade will not resume."
            )
        return partition

    def prepare_for_shutdown(self) -> None:
        """Prepare this unit to stop and leave the OpenSearch cluster.

        K8S only. VM has nothing to do at this step.
        During an upgrade, the partition is used to keep the other units running while
        this unit is replaced. This method prepares the shutdown. The node stops afterward.

        On K8S:
         * First: If the upgrade relation exists, set the unit state to RESTARTING before
         querying Kubernetes, so an API error caught by the stop handler does not leave
         the replacement pod with the old pod's HEALTHY state.
         * Second: Raise partition to prevent other units from restarting if an
         upgrade is in progress. Pre-upgrade-check establishes this protection before
         refresh, so a stop-time API failure does not leave the other units unprotected.
         * Third: Disable shard allocation and flush the translog during an upgrade.

        Note that with how Juju currently operates, we have at most 30 seconds before
        SIGTERM, so these operations are not guaranteed to finish before the pod is removed.
        The replacement must rejoin the cluster and pass its health checks before becoming HEALTHY.
        After restart, the start, peer-relation and update-status hooks can run
        `_reconcile_upgrade` to check readiness and resume the upgrade.
        """
        # Record RESTARTING before any API call. If the stop handler catches an API error,
        # the replacement pod must still pass its own health checks before becoming HEALTHY.
        if self.state.upgrade_relation:
            self.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING

        if not self.in_progress:
            return

        # Raise partition to prevent other units from restarting if an upgrade is in progress.
        current_unit_number = self.state.server_upgrade.unit_number
        if self.k8s_client.get_partition() < current_unit_number:
            self.k8s_client.set_partition(value=current_unit_number)
            logger.debug(f"Partition set to {current_unit_number} during stop event")

        if not self.state.upgrade_relation:
            logger.debug("Upgrade Peer relation missing during stop event")
            return

        try:
            self.opensearch_client.disable_shard_allocation(alt_hosts=self.alt_hosts)
        except OpenSearchHttpError:
            logger.exception("Failed to disable shard allocation before upgrade")
        try:
            self.opensearch_client.flush_translog(alt_hosts=self.alt_hosts)
        except OpenSearchHttpError as e:
            logger.debug("Failed to flush before upgrade", exc_info=e)

    def _determine_partition(
        self, units: list[UpgradeServerState], *, resume: bool, force: bool
    ) -> int:
        """Determine the new partition to use.

        Use the current revisions, unit states, resume and force to choose the partition.
        If resume=False and the second unit still needs to upgrade (upgrade_order_index == 1),
        keep the partition at the first unit until the user runs resume-upgrade.
        With force=True, skip the HEALTHY check when choosing the next unit to upgrade.
        """
        if not self.in_progress:
            return self.partition
        logger.debug(f"{self.state.server_upgrade.relation_data=}")
        logger.debug(f"{resume=}, {force=}, {self.in_progress=}")
        workload_container_versions = self.k8s_client.list_revisions()
        app_container_version = self.k8s_client.get_revision()
        for upgrade_order_index, server_upgrade_unit in enumerate(units):
            logger.debug(f"{upgrade_order_index=}, {server_upgrade_unit=}")
            # Note: upgrade_order_index != unit number
            state = server_upgrade_unit.unit_state
            logger.debug(
                f"{server_upgrade_unit.unit.name=}, {state=}, {workload_container_versions=}, {app_container_version=}"
            )
            # The leader may see the new pod before receiving the old pod's RESTARTING update.
            # Unless forced, require HEALTHY for this revision before the next unit can stop.
            if (
                not force
                and (
                    state != UnitUpgradesState.HEALTHY
                    or server_upgrade_unit.unit_state_revision != app_container_version
                )
            ) or workload_container_versions[
                server_upgrade_unit.unit.name
            ] != app_container_version:
                if not resume and upgrade_order_index == 1:
                    # User confirmation needed to resume upgrade (i.e. upgrade second unit)
                    return int(units[0].unit.name.split("/")[-1])
                return int(server_upgrade_unit.unit.name.split("/")[-1])
        return 0

    @property
    def _unit_workload_container_versions(self) -> dict[str, str]:
        """{Unit name: Kubernetes controller revision hash}

        Even if the workload container version is the same, the workload will restart if the
        controller revision hash changes. (Juju bug: https://bugs.launchpad.net/juju/+bug/2036246).

        Therefore, we must use the revision hash instead of the workload container version. (To
        satisfy the requirement that if and only if this version changes, the workload will
        restart.)
        """
        return self.k8s_client.list_revisions()

    @property
    def _app_workload_container_version(self) -> str:
        """App's Kubernetes controller revision hash"""
        return self.k8s_client.get_revision()

    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Return upgrade statuses, or explain why Kubernetes could not be checked.

        Check trust before reading upgrade state. Report missing trust as blocked and other
        API failures as waiting. Each call checks again, so the failure status clears when
        access is restored.
        """
        if self.state.planned_units == 0:
            return super().get_statuses(scope, recompute)

        try:
            self.k8s_client.check_if_deployed_without_trust()
            return super().get_statuses(scope, recompute)
        except OpenSearchK8sDeployedWithoutTrustError as e:
            status = format_status(
                UpgradesStatuses.K8S_DEPLOYED_WITHOUT_TRUST.value,
                {"charm_app": e.app_name},
            )
        except OpenSearchK8sError as e:
            logger.warning("Cannot check Kubernetes upgrade status: %s", e)
            status = UpgradesStatuses.K8S_API_UNAVAILABLE.value
        return [*running_statuses(self.state.statuses, scope, self.name), status]
