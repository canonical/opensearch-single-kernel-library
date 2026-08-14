#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for upgrade events."""

import logging
import typing

import ops
from data_platform_helpers.version_check import get_charm_revision
from ops import Object, UpgradeCharmEvent

from opensearch_single_kernel.common.constants import (
    OPENSEARCH_SNAP_REVISION,
    UPGRADE_RELATION,
    HealthColors,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchReconcilePartitionError,
    OpenSearchStopError,
    OpenSearchUpgradePrecheckError,
)
from opensearch_single_kernel.common.statuses import UpgradesStatuses
from opensearch_single_kernel.core.models import (
    LifecycleUnitTearingDownAndAppActive,
    UnitUpgradesState,
)
from opensearch_single_kernel.events.custom_events import UpgradeOpenSearch
from opensearch_single_kernel.managers.upgrades_vm import UpgradesManagerVM

if typing.TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class UpgradesEventsHandler(Object):
    """Class implementing OpenSearch upgrades event handling."""

    lifecycle_state_stored = ops.StoredState()

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, key="upgrade_events")
        self.charm = charm

        # lifecycle
        for relation_endpoint in self.model.relations.keys():
            self.framework.observe(
                self.charm.on[relation_endpoint].relation_departed,
                self._on_lifecycle_relation_departed,
            )

        self.framework.observe(self.charm.on.upgrade_charm, self._on_upgrade_charm)
        self.framework.observe(
            self.charm.on[UPGRADE_RELATION].relation_created,
            self._on_upgrade_peer_relation_created,
        )
        self.framework.observe(
            self.charm.on[UPGRADE_RELATION].relation_changed, self._reconcile_upgrade
        )
        self.framework.observe(
            self.charm.on.pre_upgrade_check_action, self._on_pre_upgrade_check_action
        )
        self.framework.observe(self.charm.on.resume_upgrade_action, self._on_resume_upgrade_action)
        if self.charm.substrate == Substrates.VM:
            self.framework.observe(
                self.charm.on.force_upgrade_action, self._on_force_upgrade_action
            )
        self.framework.observe(self.charm.upgrade_opensearch_event, self._upgrade_opensearch)

        self.framework.observe(
            self.charm.on.force_refresh_start_action,
            self._on_refresh_force_start_action,
        )

    def _on_upgrade_peer_relation_created(self, _) -> None:
        """Handle relation created events."""
        if self.charm.substrate == Substrates.VM:
            self.charm.state.server_upgrade.snap_revision = OPENSEARCH_SNAP_REVISION
        self.charm.state.server_upgrade.workload_version = (
            self.charm.upgrades_manager.current_versions.workload
        )
        if not self.authorized_leader:
            logger.debug("Skipping upgrade relation created because unit is not leader")
            return

        if self.charm.upgrades_manager.in_progress:
            logger.debug("Skipping upgrade relation created because upgrade in progress")
            return

        self.charm.upgrades_manager.save_upgrades_versions()

    def _reconcile_upgrade(  # noqa: C901
        self,
        _: typing.Optional[ops.RelationChangedEvent] = None,
    ) -> None:
        """Handle upgrade events."""
        if not self.charm.state.upgrade_relation:
            logger.debug("Peer relation not available")
            return

        if not self.charm.state.application_upgrade.versions:
            logger.debug("Peer relation not ready")
            return

        if self.authorized_leader and not self.charm.upgrades_manager.in_progress:
            # Run before checking `self._upgrade.is_compatible` in case incompatible upgrade was
            # forced & completed on all units.
            # Side effect: on machines, if charm was upgraded to a charm with the same snap
            # revision, compatibility checks will be skipped.
            # (The only real use case for this would be upgrading the charm code to an incompatible
            # version without upgrading the snap. In that situation, the upgrade may appear
            # successful and the user will not be notified of the charm incompatibility. This case
            # is much less likely than the forced incompatible upgrade & the impact is not as bad
            # as the impact if we did not handle the forced incompatible upgrade case.)
            logger.debug(
                "Setting %r in upgrade peer relation app databag",
                self.charm.upgrades_manager.current_versions,
            )
            self.charm.state.application_upgrade.versions = (
                self.charm.upgrades_manager.current_versions
            )
            logger.debug(
                "Set %r in upgrade peer relation app databag",
                self.charm.upgrades_manager.current_versions,
            )
        if (
            self.charm.state.substrate == Substrates.VM
            and not self.charm.upgrades_manager.is_compatible
        ):
            self._set_upgrade_status()
            return

        if self.charm.upgrades_manager.unit_state is UnitUpgradesState.OUTDATED and isinstance(
            self.charm.upgrades_manager, UpgradesManagerVM
        ):
            # This is only for VM charms
            try:
                if self.charm.upgrades_manager.requires_general_prechecks:
                    self._run_general_prechecks()
                authorized = self.charm.upgrades_manager.authorized
            except OpenSearchUpgradePrecheckError as exception:
                self.charm.state.add_status_if_not_present(
                    UpgradesStatuses.UPGRADES_PRE_UPGRADE_CHECK_FAILED.value,
                    "unit",
                    self.charm.upgrades_manager.name,
                    dynamic_params={"message": str(exception)},
                )
                logger.error(exception)
                return

            if authorized:
                self._set_upgrade_status()
                self.charm.upgrade_opensearch_event.emit()
            else:
                logger.debug("Waiting to upgrade")

        if self.charm.upgrades_manager.unit_state is UnitUpgradesState.RESTARTING:
            if not self.charm.upgrades_manager.is_compatible:
                logger.info(
                    "Upgrade incompatible. If you accept potential *data loss* and *downtime*, you can continue with resume-upgrade"
                )
                self.charm.state.add_status_if_not_present(
                    UpgradesStatuses.UPGRADES_INCOMPATIBLE.value,
                    "unit",
                    self.charm.upgrades_manager.name,
                )
                return

        if self.charm.state.substrate == Substrates.K8S:
            if (
                self.charm.state.application.deployment_desc
                and self.charm.upgrades_manager.opensearch_client.is_node_up()
            ):
                try:
                    self.charm.cluster_manager.opensearch_client.enable_shard_allocation(
                        alt_hosts=self.charm.cluster_manager.alt_hosts
                    )
                except OpenSearchHttpError:
                    logger.exception("Failed to re-enable allocation after upgrade")
                self.charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
            if self.charm.unit.is_leader():
                self.charm.upgrades_manager.reconcile_partition()

        self._set_upgrade_status()

    def _run_general_prechecks(self) -> None:
        """Check health and snapshot state before upgrade.

        Raises:
            PrecheckFailed: If cluster is not ready to upgrade.
        """
        health = self.charm.health_manager.get(local_app_only=False, wait_for_green_first=True)
        if health != HealthColors.GREEN:
            raise OpenSearchUpgradePrecheckError(f"Cluster health is {health} instead of green")
        if self.charm.snapshots_manager.is_operation_in_progress:
            raise OpenSearchUpgradePrecheckError("Backup or restore is in progress")

    def _set_upgrade_status(self):
        """Set upgrade unit status while clearing all other upgrade statuses."""
        unit_status, unit_dynamic_params = self.charm.upgrades_manager.unit_status
        app_status = self.charm.upgrades_manager.app_status

        for status in UpgradesStatuses:
            if status is not unit_status:
                self.charm.state.remove_status_if_present(
                    status.value, "unit", self.charm.upgrades_manager.name, interpolated=True
                )
            if status is not app_status:
                self.charm.state.remove_status_if_present(
                    status.value, "app", self.charm.upgrades_manager.name
                )

        if unit_status:
            self.charm.state.add_status_if_not_present(
                unit_status,
                "unit",
                self.charm.upgrades_manager.name,
                dynamic_params=unit_dynamic_params,
            )
        if app_status:
            self.charm.state.add_status_if_not_present(
                app_status,
                "app",
                self.charm.upgrades_manager.name,
            )

    def _on_upgrade_charm(self, event: UpgradeCharmEvent) -> None:
        """Handle Juju upgrade charm event."""
        self.charm.upgrades_manager.reconcile_compatibility_matrix()
        self.charm.upgrades_manager.update_grafana_dashboards_title(
            get_charm_revision(self.charm.model.unit)
        )
        # TODO check backwards compatibility for profiles
        if self.charm.substrate == Substrates.VM:
            self.machine_upgrade()
        else:
            self.kubernetes_upgrade(event)

    def _on_pre_upgrade_check_action(self, event: ops.ActionEvent) -> None:
        """Handle pre-upgrade-check action."""
        if not self.authorized_leader:
            message = f"Must run action on leader unit. (e.g. `juju run {self.charm.app.name}/leader pre-upgrade-check`)"
            logger.debug(f"Pre-upgrade check event failed: {message}")
            event.fail(message)
            return

        if not self.charm.state.upgrade_relation or self.charm.upgrades_manager.in_progress:
            message = "Upgrade already in progress"
            logger.debug(f"Pre-upgrade check event failed: {message}")
            event.fail(message)
            return

        try:
            self._run_general_prechecks()
            self.charm.upgrades_manager.pre_upgrade_check()
        except OpenSearchUpgradePrecheckError as exception:
            message = f"Charm is *not* ready for upgrade. Pre-upgrade-check failed: {exception}"
            logger.debug(f"Pre-upgrade-check event failed: {message}")
            event.fail(message)
            return

        message = "Charm is ready for upgrade"
        event.set_results({"result": message})
        logger.debug(f"Pre-upgrade check event succeeded: {message}")

    def _on_resume_upgrade_action(self, event: ops.ActionEvent) -> None:
        """Handle resume-upgrade action."""
        if not self.authorized_leader:
            message = f"Must run action on leader unit. (e.g. `juju run {self.charm.app.name}/leader resume-upgrade`)"
            logger.debug(f"Resume upgrade event failed: {message}")
            event.fail(message)
            return
        if not self.charm.state.upgrade_relation or not self.charm.upgrades_manager.in_progress:
            message = "No upgrade in progress"
            logger.debug(f"Resume upgrade event failed: {message}")
            event.fail(message)
            return
        force = False
        if self.charm.substrate == Substrates.K8S:
            # Get force parameter
            force = event.params.get("force", False)
        try:
            message = self.charm.upgrades_manager.reconcile_partition(
                action_event=event, force=force
            )
            event.set_results({"result": message})
        except OpenSearchReconcilePartitionError as e:
            logger.debug(f"Resume upgrade event failed: {e}")
            event.fail(e.message)
            return

    def _on_force_upgrade_action(self, event: ops.ActionEvent) -> None:
        """Handle force-upgrade action."""
        if self.charm.substrate == Substrates.K8S:
            message = "Force upgrade is not supported on Kubernetes. Use `resume-upgrade` action with `force` parameter instead."
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return

        if not self.charm.state.upgrade_relation or not self.charm.upgrades_manager.in_progress:
            message = "No upgrade in progress"
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return

        if not self.charm.state.application_upgrade.upgrade_resumed:
            message = f"Run `juju run {self.charm.app.name}/leader resume-upgrade` before trying to force upgrade"
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return

        if self.charm.upgrades_manager.unit_state is not UnitUpgradesState.OUTDATED:
            message = "Unit already upgraded"
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return

        logger.debug("Forcing upgrade")
        event.log(f"Forcefully upgrading {self.charm.unit.name}")
        # TODO: replace `ignore_lock=False` with `event.params["ignore-lock"]` if specification
        # DA091 approved
        # (https://docs.google.com/document/d/1rwnS-deJU9Mzc8BFkl3UGgjZiBa6e3bxoT-6BQo9e3E/edit)
        self.charm.upgrade_opensearch_event.emit(ignore_lock=False)

        event.set_results({"result": f"Forcefully upgraded {self.charm.unit.name}"})
        logger.debug("Forced upgrade")

    def _upgrade_opensearch(self, event: UpgradeOpenSearch) -> None:  # noqa: C901
        """Handle upgrade OpenSearch event."""
        if not (isinstance(self.charm.upgrades_manager, UpgradesManagerVM)):
            logger.debug(
                "Upgrade OpenSearch event handler should only be called for machine charms"
            )
            return

        logger.debug("Attempting to acquire lock for upgrade")
        if not self.charm.lock_manager.acquire():
            # (Attempt to acquire lock even if `event.ignore_lock`)
            if event.ignore_lock:
                logger.debug("Upgrading without lock")
            else:
                logger.debug("Lock to upgrade opensearch not acquired. Will retry next event")
                event.defer()
                return
        logger.debug("Acquired lock for upgrade")

        # https://www.elastic.co/guide/en/elastic-stack/8.13/upgrading-elasticsearch.html
        try:
            self.charm.cluster_manager.opensearch_client.disable_shard_allocation()
        except OpenSearchHttpError:
            logger.exception("Failed to disable shard allocation before upgrade")
            self.charm.lock_manager.release()
            event.defer()
            return

        try:
            self.charm.cluster_manager.opensearch_client.flush_translog()
        except OpenSearchHttpError as e:
            logger.debug("Failed to flush before upgrade", exc_info=e)

        logger.debug("Stopping OpenSearch before upgrade")
        try:
            self.charm.stop_opensearch(restart=True)
        except OpenSearchStopError as e:
            logger.exception(e)
            self.charm.lock_manager.release()
            event.defer()
            return
        logger.debug("Stopped OpenSearch before upgrade")

        if event.override_version:
            logger.debug("Overriding OpenSearch version")
            try:
                self.charm.upgrades_manager.override_version()
            except OpenSearchCmdError as e:
                logger.error("Failed to override OpenSearch version: %s", str(e))
        else:
            logger.debug("Upgrading unit")
            self.charm.state.server_upgrade.unit_state = UnitUpgradesState.UPGRADING
            self.charm.workload.install()

            # We check if it is a rollback here only if the unit is highest order
            # If we reach this point we are sure its compatible and upgrade is in progress
            # CHECK FOR ROLLBACK
            if self.charm.upgrades_manager.is_rollback:
                if not self.charm.upgrades_manager.can_rollback:
                    logger.error(
                        "Rollback unsupported. Refresh to a newer revision or consult the recovery documentation"
                    )
                    self._set_upgrade_status()
                    # https://canonical-charmed-opensearch.readthedocs-hosted.com/2/how-to/upgrade/#recovering-from-a-rollback
                    self.charm.lock_manager.release()
                    return
                else:
                    logger.warning("Rollback detected")
                    logger.warning(
                        "Rollback incompatible. Run 'juju run <unit> force-refresh-start' with `check-compatibility` set to false to override node version and attempt startup procedure"
                    )
                    self._set_upgrade_status()
                    self.charm.lock_manager.release()
                    return
        self.charm.state.server_upgrade.snap_revision = OPENSEARCH_SNAP_REVISION
        self.charm.state.server_upgrade.workload_version = (
            self.charm.upgrades_manager.current_versions.workload
        )
        logger.debug(
            f"Saved {OPENSEARCH_SNAP_REVISION=} and {self.charm.upgrades_manager.current_versions.workload=} in unit databag after upgrade"
        )

        logger.debug("Starting OpenSearch after upgrade")
        self.charm.start_opensearch_event.emit(ignore_lock=event.ignore_lock, after_upgrade=True)

    def _on_refresh_force_start_action(self, event: ops.ActionEvent) -> None:
        """Handle force-refresh-start action for rollback scenario."""
        if not self.charm.upgrades_manager.is_rollback:
            logger.debug("For refresh start event failed: No rollback in progress")
            event.fail("No rollback in progress")
            return

        if (
            self.charm.substrate == Substrates.VM
            and self.charm.upgrades_manager.unit_state is not UnitUpgradesState.OUTDATED
        ):
            message = "Unit already upgraded"
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return

        if event.params.get("check-compatibility", True):
            message = "Rollbacks are not supported. This action will attempt to start the unit with the current version of OpenSearch. If the current version is incompatible with the cluster, the unit may fail to start. Rerun with `check-compatibility` set to false to override this check and attempt startup procedure."
            logger.debug("Refresh force start event failed: %s", message)
            event.fail(message)
            return

        if self.charm.substrate == Substrates.VM:
            self.charm.upgrade_opensearch_event.emit(override_version=True)
            event.set_results(
                {"result": f"Overrode OpenSearch version on {self.charm.state.unit_name}"}
            )
            logger.debug("Overrode OpenSearch version")
        else:
            logger.debug("Overriding OpenSearch version")
            try:
                self.charm.upgrades_manager.override_version()
                self.charm.start_opensearch_event.emit(after_upgrade=True)
                event.set_results(
                    {
                        "result": f"Reconciled partition and forcefully upgraded {self.charm.unit.name}"
                    }
                )
            except OpenSearchCmdError as e:
                logger.error("Failed to override OpenSearch version: %s", str(e))
                event.fail(f"Failed to override OpenSearch version: {str(e)}")

    # Lifecycle

    def _on_lifecycle_relation_departed(self, event: ops.RelationDepartedEvent) -> None:
        """Handle relation departed event for lifecycle tracking."""
        if event.departing_unit == self.charm.unit:
            self._unit_tearing_down_and_app_active = LifecycleUnitTearingDownAndAppActive.TRUE

    @property
    def _unit_tearing_down_and_app_active(self) -> LifecycleUnitTearingDownAndAppActive:
        """Whether unit is tearing down and 1+ other units are NOT tearing down."""
        try:
            return LifecycleUnitTearingDownAndAppActive(
                self.lifecycle_state_stored.unit_tearing_down_and_app_active
            )
        except AttributeError:
            return LifecycleUnitTearingDownAndAppActive.FALSE

    @_unit_tearing_down_and_app_active.setter
    def _unit_tearing_down_and_app_active(
        self, enum_member: LifecycleUnitTearingDownAndAppActive
    ) -> None:
        """Set whether unit is tearing down and 1+ other units are NOT tearing down."""
        self.lifecycle_state_stored.unit_tearing_down_and_app_active = enum_member.value

    @property
    def tearing_down_and_app_active(self) -> bool:
        """Whether unit is tearing down and 1+ other units are NOT tearing down

        Cannot be called on subordinate charms
        """
        return (
            self._unit_tearing_down_and_app_active
            is not LifecycleUnitTearingDownAndAppActive.FALSE
        )

    @property
    def authorized_leader(self) -> bool:
        """Whether unit is authorized to act as leader

        Returns `False` if unit is tearing down and will be replaced by another leader

        For subordinate charms, this should not be accessed during *-relation-departed.

        Teardown event sequence:
        *-relation-departed -> *-relation-broken
        stop
        remove

        Workaround for https://bugs.launchpad.net/juju/+bug/1979811
        (Unit receives *-relation-broken event when relation still exists [for other units])
        """
        if not self.charm.unit.is_leader():
            return False
        if self._unit_tearing_down_and_app_active is LifecycleUnitTearingDownAndAppActive.UNKNOWN:
            logger.warning(
                f"{type(self)}.authorized_leader should not be accessed during *-relation-departed for subordinate relations"
            )
        return self._unit_tearing_down_and_app_active is LifecycleUnitTearingDownAndAppActive.FALSE

    def machine_upgrade(self) -> None:
        """On Upgrade charm for machine charms."""
        if not self.authorized_leader:
            return

        if not self.charm.upgrades_manager.in_progress:
            logger.info("Charm upgraded. OpenSearch version unchanged")

        self.charm.state.application_upgrade.upgrade_resumed = False
        # Only call `_reconcile_upgrade` on leader unit to avoid race conditions with
        # `upgrade_resumed`
        self._reconcile_upgrade()

    def kubernetes_upgrade(self, event: UpgradeCharmEvent) -> None:
        """On Upgrade charm for Kubernetes charms.

        For Kubernetes, we configure the workload replan the container and process upgrade status.
        """
        try:
            self.charm.config_manager.update_opensearch_config()
        except OpenSearchFileOperationError as e:
            logger.error("An error occurred while updating opensearch config: %s", str(e))
            event.defer()
            return

        if not self.charm.upgrades_manager.in_progress:
            logger.debug("Upgrade not in progress. OpenSearch version unchanged")
            return

        if not self.charm.upgrades_manager.is_compatible:
            logger.error("Refresh is incompatible")
            self._set_upgrade_status()
            return

        if self.charm.upgrades_manager.is_rollback:
            logger.warning("Rollback detected")
            logger.warning(
                "Rollback incompatible. Run 'juju run <unit> force-refresh-start' with `check-compatibility` set to false to override node version and attempt startup procedure"
            )
            self._set_upgrade_status()
            event.defer()
            return

        # Configure and start the workload
        if not self.charm.cluster_manager.no_blocking_directives():
            logger.debug("Cannot start OpenSearch after upgrade, cluster not ready")
            event.defer()
            return

        # Mark the new version of the unit since in Kubernetes this unit is upgraded now.
        self.charm.state.server_upgrade.workload_version = (
            self.charm.upgrades_manager.current_versions.workload
        )
        logger.debug(
            f"Saved {self.charm.upgrades_manager.current_versions.workload=} in unit databag after upgrade"
        )
        self.charm.start_opensearch_event.emit(ignore_lock=True, after_upgrade=True)
