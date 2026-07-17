# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades on machines

Derived from specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""

import logging
from typing import Any

import ops
from data_platform_helpers.advanced_statuses import StatusObject

from opensearch_single_kernel.common.constants import OPENSEARCH_SNAP_REVISION
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.common.statuses import UpgradesStatuses
from opensearch_single_kernel.core.models import UnitUpgradesState
from opensearch_single_kernel.managers.upgrades_base import (
    UpgradesManagerBase,
)

logger = logging.getLogger(__name__)

FORCE_ACTION_NAME = "force-upgrade"


class UpgradesManagerVM(UpgradesManagerBase):
    """In-place upgrades on machines"""

    @property
    def unit_state(self) -> UnitUpgradesState | None:
        """Calculate the upgrade state of current unit."""
        if (
            snap_revision := self.state.server_upgrade.snap_revision
        ) is not None and snap_revision != OPENSEARCH_SNAP_REVISION:
            logger.debug("Unit upgrade state: outdated")
            return UnitUpgradesState.OUTDATED
        return self.state.server_upgrade.unit_state

    @property
    def unit_status(self) -> tuple[StatusObject | None, dict[str, Any] | None]:
        """Get unit upgrade status."""
        if not self.state.upgrade_relation:
            return (None, None)

        # Episodic precheck failure is pure-computed from unit databag flag.
        if (
            msg := self.state.server_upgrade.precheck_failed_message
        ) and self.state.server_upgrade.snap_revision != OPENSEARCH_SNAP_REVISION:
            return (
                UpgradesStatuses.UPGRADES_PRE_UPGRADE_CHECK_FAILED.value,
                {"message": msg},
            )

        if not self.in_progress:
            return (None, None)

        if self.is_rollback:
            if not self.can_rollback:
                return UpgradesStatuses.UPGRADES_ROLLBACK_UNSUPPORTED.value, None
            else:
                return UpgradesStatuses.UPGRADES_ROLLBACK_INCOMPATIBLE.value, None

        if self.state.server_upgrade.snap_revision == OPENSEARCH_SNAP_REVISION:
            return (
                UpgradesStatuses.UPGRADES_ACTIVE.value,
                {
                    "workload_version": self.state.server_upgrade.workload_version,
                    "snap_revision": self.state.server_upgrade.snap_revision,
                    "charm_version": self.current_versions.charm,
                },
            )
        return (
            UpgradesStatuses.UPGRADES_ACTIVE_OUTDATED.value,
            {
                "workload_version": self.state.server_upgrade.workload_version,
                "snap_revision": self.state.server_upgrade.snap_revision,
                "charm_version": self.current_versions.charm,
            },
        )

    def reconcile_partition(
        self, *, action_event: ops.ActionEvent | None = None, force=False
    ) -> None:
        """Handle Juju action to confirm first upgraded unit is healthy and resume upgrade."""
        if not action_event:
            return

        first_upgrade_unit = self.state.sorted_upgrades_units[0]
        outdated = first_upgrade_unit.snap_revision != OPENSEARCH_SNAP_REVISION
        unhealthy = first_upgrade_unit.unit_state is not UnitUpgradesState.HEALTHY
        if outdated or unhealthy:
            if outdated:
                message = "Highest number unit has not upgraded yet. Upgrade will not resume."
            else:
                message = "Highest number unit is unhealthy. Upgrade will not resume."
            logger.debug(f"Resume upgrade event failed: {message}")
            action_event.fail(message)
            return

        self.state.application_upgrade.upgrade_resumed = True
        message = "Upgrade resumed."
        action_event.set_results({"result": message})
        logger.debug(f"Resume upgrade event succeeded: {message}")

    @property
    def authorized(self) -> bool:
        """Whether this unit is authorized to upgrade

        Only applies to machine charm

        Raises:
            PrecheckFailed: App is not ready to upgrade
        """
        assert self.state.server_upgrade.snap_revision != OPENSEARCH_SNAP_REVISION
        assert self.state.application_upgrade.versions
        for index, unit in enumerate(self.state.sorted_upgrades_units):
            if unit.unit == self.state.server.unit:
                # Higher number units have already upgraded
                if index == 0:
                    if (
                        self.state.application_upgrade.versions.charm
                        == self.current_versions.charm
                    ):
                        # Assumes charm version uniquely identifies charm revision
                        try:
                            self.opensearch_client.enable_shard_allocation(
                                alt_hosts=self.alt_hosts,
                            )
                        except OpenSearchHttpError:
                            logger.exception("Failed to re-enable allocation after rollback")
                    else:
                        # Run pre-upgrade check
                        # (in case user forgot to run pre-upgrade-check action)
                        self.pre_upgrade_check()
                        logger.debug("Pre-upgrade check after `juju refresh` successful")
                elif index == 1:
                    # User confirmation needed to resume upgrade (i.e. upgrade second unit)
                    logger.debug(
                        f"Second unit authorized to upgrade if {self.state.application_upgrade.upgrade_resumed=}"
                    )
                    return self.state.application_upgrade.upgrade_resumed
                return True
            if (
                unit.snap_revision != OPENSEARCH_SNAP_REVISION
                or unit.unit_state is not UnitUpgradesState.HEALTHY
            ):
                # Waiting for higher number units to upgrade
                logger.debug(f"Upgrade not authorized. Waiting for {unit.unit.name=} to upgrade")
                return False
        return False

    def save_upgrades_versions(self) -> None:
        """Save revision on first install"""
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
    def requires_general_prechecks(self) -> bool:
        """Whether this unit should run general prechecks before upgrading.

        Returns True only for the first unit in upgrade order (index 0) and only
        when it's not a rollback. Subsequent units skip general prechecks because
        the cluster is expected to be yellow during a rolling upgrade.
        """
        assert self.state.application_upgrade.versions
        for index, server in enumerate(self.state.sorted_upgrades_units):
            if server.unit == self.state.server.unit:
                is_rollback = (
                    self.state.application_upgrade.versions.charm == self.current_versions.charm
                )
                return index == 0 and not is_rollback
        return False

    @property
    def _unit_workload_container_versions(self) -> dict[str, str]:
        """{Unit name: Kubernetes controller revision hash}

        Even if the workload container version is the same, the workload will restart if the
        controller revision hash changes. (Juju bug: https://bugs.launchpad.net/juju/+bug/2036246).

        Therefore, we must use the revision hash instead of the workload container version. (To
        satisfy the requirement that if and only if this version changes, the workload will
        restart.)
        """
        return {
            server.unit.name: server.snap_revision
            for server in self.state.sorted_upgrades_units
            if server.snap_revision
        }

    @property
    def _app_workload_container_version(self) -> str:
        """App's Kubernetes controller revision hash"""
        return OPENSEARCH_SNAP_REVISION
