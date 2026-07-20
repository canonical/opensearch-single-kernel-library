# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades on kubernetes

Derived from specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""

import logging
from typing import Any

import ops
from data_platform_helpers.advanced_statuses import StatusObject
from lightkube.core.exceptions import ApiError

from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchK8sDeployedWithoutTrustError,
    OpenSearchReconcilePartitionError,
)
from opensearch_single_kernel.common.statuses import UpgradesStatuses
from opensearch_single_kernel.core.models import UnitUpgradesState, UpgradeServerModel
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.upgrades_base import (
    UpgradesManagerBase,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)

FORCE_ACTION_NAME = "force-upgrade"


class UpgradesManagerK8s(UpgradesManagerBase):
    """In-place upgrades on kubernetes"""

    def __init__(
        self,
        state: ClusterState,
        workload: BaseWorkload,
    ) -> None:
        super().__init__(state, workload)
        try:
            self.k8s_client.get_partition()
        except ApiError as err:
            if err.status.code == 403:
                raise OpenSearchK8sDeployedWithoutTrustError(app_name=self.state.application.name)
            raise

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

        if not self.in_progress:
            return (None, None)

        if not self.is_compatible:
            return (UpgradesStatuses.UPGRADES_INCOMPATIBLE.value, None)

        if self.is_rollback:
            if not self.can_rollback:
                return UpgradesStatuses.UPGRADES_ROLLBACK_UNSUPPORTED.value, None
            else:
                return UpgradesStatuses.UPGRADES_ROLLBACK_INCOMPATIBLE.value, None

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

    def reconcile_partition(
        self, *, action_event: ops.ActionEvent | None = None, force: bool = False
    ) -> str | None:  # noqa: C901
        """If ready, lower partition to upgrade next unit.

        If upgrade is not in progress, set partition to 0. (If a unit receives a stop event, it may
        raise the partition even if an upgrade is not in progress.)

        Automatically upgrades next unit if all upgraded units are healthy—except if only one unit
        has upgraded (need manual user confirmation [via Juju action] to upgrade next unit)

        Handle Juju action to:
        - confirm first upgraded unit is healthy and resume upgrade
        - force upgrade of next unit if 1 or more upgraded units are unhealthy
        """
        message: str | None = None

        units = self.state.sorted_upgrades_units

        partition = self._determine_partition(
            units,
            action_event=action_event,
            force=force,
        )
        logger.debug(f"{self.partition=}, {partition=}")
        # Only lower the partition—do not raise it.
        # If this method is called during the action event and then called during another event a
        # few seconds later, `determine_partition()` could return a lower number during the action
        # and then a higher number a few seconds later.
        # This can cause the unit to hang.
        # Example: If partition is lowered to 1, unit 1 begins to upgrade, and partition is set to
        # 2 right away, the unit/Juju agent will hang
        # Details: https://chat.charmhub.io/charmhub/pl/on8rd538ufn4idgod139skkbfr
        # This does not address the situation where another unit > 1 restarts and sets the
        # partition during the `stop` event, but that is unlikely to occur in the small time window
        # that causes the unit to hang.
        if partition < self.partition:
            self.partition = partition
            logger.debug(
                f"Lowered partition to {partition} {action_event} {force=} {self.in_progress=}"
            )
        if action_event:
            assert len(units) >= 2
            if self.partition > int(units[1].component.name.split("/")[-1]):
                message = "Highest number unit is unhealthy. Upgrade will not resume."
                raise OpenSearchReconcilePartitionError(message=message)
            if force:
                # If a unit was unhealthy and the upgrade was forced, only
                # the next unit will upgrade. As long as 1 or more units
                # are unhealthy, the upgrade will need to be forced for
                # each unit.

                # Include "Attempting to" because (on Kubernetes) we only
                # control the partition, not which units upgrade.
                # Kubernetes may not upgrade a unit even if the partition
                # allows it (e.g. if the charm container of a higher unit
                # is not ready). This is also applicable `if not force`,
                # but is unlikely to happen since all units are healthy `if
                # not force`.
                message = f"Attempting to upgrade unit {partition}."
            else:
                message = f"Upgrade resumed. Unit {partition} is upgrading next."
        return message

    def prepare_for_shutdown(self) -> None:  # pragma: nocover
        """Handler for the stop event.

        K8S Only, VM has nothing to do on this step.
        On K8S:
         * First: Raise partition to prevent other units from restarting if an
         upgrade is in progress. If an upgrade is not in progress, the leader
         unit will reset the partition to 0.
         * Second: Sets the unit state to RESTARTING and step down from replicaset.

        Note that with how Juju currently operates, we only have at most 30
        seconds until SIGTERM command, so we are by no means guaranteed to have
        stepped down before the pod is removed.
        Upon restart, the upgrade will still resume because all hooks run the
        `_reconcile_upgrade` handler.
        """
        # Raise partition to prevent other units from restarting if an upgrade is in progress.
        # If an upgrade is not in progress, the leader unit will reset the partition to 0.
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

        # We update the state to set up the unit as restarting
        self.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING

    def _determine_partition(
        self, units: list[UpgradeServerModel], action_event: ops.ActionEvent | None, force: bool
    ) -> int:
        """Determine the new partition to use.

        We get the current state of each unit, and according to `action_event`,
        `force` and the state, we decide the new value of the partition.
        A specific case:
         * If we don't have action event and the upgrade_order_index is 1, we
         return because it means we're waiting for the resume-refresh/force-refresh event to run.
        """
        if not self.in_progress:
            return 0
        logger.debug(f"{self.state.server_upgrade=}")
        logger.debug(f"{action_event=}, {force=}, {self.in_progress=}")
        for upgrade_order_index, server_upgrade_unit in enumerate(units):
            logger.debug(f"{upgrade_order_index=}, {server_upgrade_unit=}")
            # Note: upgrade_order_index != unit number
            state = server_upgrade_unit.unit_state
            workload_container_versions = self.k8s_client.list_revisions()
            app_container_version = self.k8s_client.get_revision()
            logger.debug(
                f"{server_upgrade_unit.component.name=}, {state=}, {workload_container_versions=}, {app_container_version=}"
            )
            if (
                not force and state is not UnitUpgradesState.HEALTHY
            ) or workload_container_versions[
                server_upgrade_unit.component.name
            ] != app_container_version:
                if not action_event and upgrade_order_index == 1:
                    # User confirmation needed to resume upgrade (i.e. upgrade second unit)
                    return int(units[0].component.name.split("/")[-1])
                return int(server_upgrade_unit.component.name.split("/")[-1])
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
