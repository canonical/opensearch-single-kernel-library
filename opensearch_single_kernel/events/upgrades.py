#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for upgrade events."""

import logging
import typing

import ops
from data_platform_helpers.advanced_statuses.utils import as_status
from data_platform_helpers.version_check import get_charm_revision
from ops import Object, UpgradeCharmEvent

from opensearch_single_kernel.common.constants import (
    UPGRADE_RELATION,
    HealthColors,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchK8sError,
    OpenSearchNotFullyReadyError,
    OpenSearchReconcilePartitionError,
    OpenSearchStopError,
    OpenSearchUpgradePrecheckError,
)
from opensearch_single_kernel.common.statuses import GeneralStatuses, UpgradesStatuses
from opensearch_single_kernel.core.models import (
    LifecycleUnitTearingDownAndAppActive,
    UnitUpgradesState,
    UpgradeResumeRequest,
)
from opensearch_single_kernel.events.custom_events import UpgradeOpenSearch
from opensearch_single_kernel.managers.upgrades_vm import UpgradesManagerVM
from opensearch_single_kernel.utils.helpers import pinned_snap_revision

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
        if self.charm.substrate == Substrates.K8S:
            self.framework.observe(self.charm.on.update_status, self._on_update_status)
        self.framework.observe(
            self.charm.on[UPGRADE_RELATION].relation_created,
            self._on_upgrade_peer_relation_created,
        )
        self.framework.observe(
            self.charm.on[UPGRADE_RELATION].relation_changed,
            self._on_upgrade_peer_relation_changed,
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

    def _on_upgrade_peer_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        """Handle relation created events."""
        if self.charm.substrate == Substrates.VM:
            self.charm.state.server_upgrade.snap_revision = pinned_snap_revision()
        self.charm.state.server_upgrade.workload_version = (
            self.charm.upgrades_manager.current_versions.workload
        )
        if not self.authorized_leader:
            logger.debug("Skipping upgrade relation created because unit is not leader")
            return

        try:
            if self.charm.upgrades_manager.in_progress:
                logger.debug("Skipping upgrade relation created because upgrade in progress")
                return
        except OpenSearchK8sError as e:
            logger.warning("Cannot check upgrade state: %s", e)
            event.defer()
            return

        self.charm.upgrades_manager.save_upgrades_versions()

    def _on_upgrade_peer_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        """Reconcile peer progress without replacing local post-upgrade checks."""
        try:
            self._reconcile_upgrade(during_upgrade=True)
        except OpenSearchK8sError as e:
            logger.warning("Cannot reconcile Kubernetes upgrade state: %s", e)
            event.defer()
            return

    def _reconcile_upgrade(self, *, during_upgrade: bool = False) -> None:  # noqa: C901
        """Handle upgrade events."""
        if not self.charm.state.upgrade_relation:
            logger.debug("Peer relation not available")
            return

        if not self.charm.state.application_upgrade.versions:
            logger.debug("Peer relation not ready")
            return

        if not self.charm.state.upgrade_membership_complete:
            logger.debug("Waiting for all units in the upgrade peer relation")
            return

        in_progress = self.charm.upgrades_manager.in_progress
        # Once every revision is installed, validate even a forced incompatible upgrade.
        # Keep the previous versions until those checks pass so rollback remains possible.
        compatible = self.charm.upgrades_manager.is_compatible
        if self.charm.state.substrate == Substrates.VM and in_progress and not compatible:
            return

        if self.charm.upgrades_manager.unit_state is UnitUpgradesState.OUTDATED and isinstance(
            self.charm.upgrades_manager, UpgradesManagerVM
        ):
            # This is only for VM charms
            try:
                if self.charm.upgrades_manager.requires_general_prechecks:
                    self._run_general_prechecks()
                authorized = self.charm.upgrades_manager.authorized
                self.charm.state.remove_status_if_present(
                    UpgradesStatuses.UPGRADES_PRE_UPGRADE_CHECK_FAILED.value,
                    "unit",
                    self.charm.upgrades_manager.name,
                    interpolated=True,
                )
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
                self.charm.upgrade_opensearch_event.emit()
            else:
                logger.debug("Waiting to upgrade")

        if self.charm.upgrades_manager.unit_state is UnitUpgradesState.RESTARTING:
            if in_progress and not compatible:
                logger.info(
                    "Upgrade incompatible. If you accept potential *data loss* and *downtime*, you can continue with resume-upgrade"
                )
                return

        if self.charm.state.substrate == Substrates.K8S:
            unit_revision = (
                self.charm.upgrades_manager.k8s_client.list_revisions()[self.charm.unit.name]
                if not during_upgrade
                else None
            )
            if (
                not during_upgrade
                and (
                    self.charm.upgrades_manager.unit_state != UnitUpgradesState.HEALTHY
                    or self.charm.state.server_upgrade.unit_state_revision != unit_revision
                )
                and self.charm.state.application.deployment_desc
                and self.charm.state.application.is_security_index_initialised
                and (not in_progress or compatible)
                and self.charm.upgrades_manager.opensearch_client.is_node_up()
            ):
                if self.charm.state.server_upgrade.unit_state == UnitUpgradesState.HEALTHY:
                    self.charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
                try:
                    self.charm.cluster_manager.assert_current_node_joined_cluster()
                except (OpenSearchNotFullyReadyError, OpenSearchHttpError):
                    logger.debug("Waiting for the upgraded node to rejoin the cluster")
                    return
                try:
                    self.charm.cluster_manager.opensearch_client.enable_shard_allocation(
                        alt_hosts=self.charm.cluster_manager.alt_hosts
                    )
                except OpenSearchHttpError:
                    logger.exception("Failed to re-enable allocation after upgrade")
                    return
                # Preserve the post-upgrade health gate when recovery is retried by lifecycle hooks.
                health = self.charm.health_manager.get(local_app_only=False)
                if (
                    self.charm.state.server_upgrade.unit_state
                    in (UnitUpgradesState.UPGRADING, UnitUpgradesState.RESTARTING)
                    and self.charm.state.server_upgrade.unit_state_revision != unit_revision
                ) or self.charm.state.server_upgrade.post_upgrade_health is not None:
                    self.charm.upgrades_manager.record_upgrade_health(health)
                if health not in (
                    HealthColors.GREEN,
                    HealthColors.YELLOW,
                ):
                    return
                self.charm.state.server_upgrade.workload_version = (
                    self.charm.upgrades_manager.current_versions.workload
                )
                self.charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
                self.charm.state.server_upgrade.unit_state_revision = unit_revision
                self.charm.state.remove_status_if_present(
                    GeneralStatuses.WAITING_TO_START.value,
                    "unit",
                    self.charm.cluster_manager.name,
                )
            if self.charm.unit.is_leader():
                if request := self.charm.state.application_upgrade.resume_request:
                    self._apply_resume_request(request)
                else:
                    self.charm.upgrades_manager.reconcile_partition()

        if (
            self.authorized_leader
            and not in_progress
            and not self.charm.upgrades_manager.upgrade_checks_pending
        ):
            # Commit versions after validation, including a forced incompatible upgrade.
            # As before, a machine charm refresh with the same snap revision does not
            # require another workload upgrade. Its charm compatibility check is skipped.
            # Handling a completed forced upgrade takes priority over that rare case.
            self.charm.upgrades_manager.save_upgrades_versions()

    def _on_update_status(self, event: ops.UpdateStatusEvent) -> None:
        """Apply a pending resume even if the leader's OpenSearch service is stopped.

        The normal update-status handler returns early when OpenSearch is down.
        This handler allows a forced resume to proceed in that case.
        """
        if not self.charm.unit.is_leader() or not self.charm.state.upgrade_relation:
            return

        if not (request := self.charm.state.application_upgrade.resume_request):
            return

        try:
            self._apply_resume_request(request)
        except OpenSearchK8sError as e:
            logger.error("Cannot apply the requested upgrade step: %s", e)
            event.defer()

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

    def _on_upgrade_charm(self, event: UpgradeCharmEvent) -> None:
        """Handle Juju upgrade charm event."""
        if (
            self.charm.substrate == Substrates.K8S
            and not self.charm.state.server.start_failed
            and not self.charm.workload.is_service_started()
        ):
            self.charm.unit.status = as_status(GeneralStatuses.WAITING_TO_START.value)
        self.charm.upgrades_manager.reconcile_compatibility_matrix()
        self.charm.upgrades_manager.update_grafana_dashboards_title(
            get_charm_revision(self.charm.model.unit)
        )
        # TODO check backwards compatibility for profiles
        if self.charm.substrate == Substrates.VM:
            # The stable (2.19.4) vm charm stored JWT/OIDC configuration only in YAML
            self.charm.upgrades_manager.migrate_legacy_auth_configuration()
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

        try:
            if not self.charm.state.upgrade_relation or self.charm.upgrades_manager.in_progress:
                message = "Upgrade already in progress"
                logger.debug(f"Pre-upgrade check event failed: {message}")
                event.fail(message)
                return
        except OpenSearchK8sError as e:
            logger.error("Cannot check upgrade state: %s", e)
            event.fail("Cannot check upgrade state. See logs.")
            return

        try:
            self._run_general_prechecks()
            self.charm.upgrades_manager.pre_upgrade_check()
        except OpenSearchUpgradePrecheckError as exception:
            message = f"Charm is *not* ready for upgrade. Pre-upgrade-check failed: {exception}"
            logger.debug(f"Pre-upgrade-check event failed: {message}")
            event.fail(message)
            return

        if self.charm.substrate == Substrates.K8S:
            # Protect the other nodes before refresh can stop the highest unit.
            # The stop hook may be unable to reach Kubernetes once replacement begins.
            try:
                self.charm.upgrades_manager.partition = self.charm.state.sorted_upgrades_units[
                    0
                ].unit_number
            except OpenSearchK8sError as e:
                logger.error("Cannot protect the Kubernetes rolling upgrade: %s", e)
                event.fail(
                    "Cannot protect the Kubernetes rolling upgrade. Retry pre-upgrade-check."
                )
                return

        message = "Charm is ready for upgrade"
        event.set_results({"result": message})
        logger.debug(f"Pre-upgrade check event succeeded: {message}")

    def _on_resume_upgrade_action(self, event: ops.ActionEvent) -> None:
        """Handle resume-upgrade action.

        Confirm that the first upgraded unit has been checked and the upgrade can continue.
        On Kubernetes, force=True also allows the next unit to upgrade despite unhealthy
        upgraded units. Save the request for a later hook so replacing the leader does not
        terminate the action before it reports its result.
        """
        if not self.authorized_leader:
            message = f"Must run action on leader unit. (e.g. `juju run {self.charm.app.name}/leader resume-upgrade`)"
            logger.debug(f"Resume upgrade event failed: {message}")
            event.fail(message)
            return

        if not self.charm.state.upgrade_membership_complete:
            event.fail("Waiting for all units in the upgrade peer relation.")
            return

        try:
            if (
                not self.charm.state.upgrade_relation
                or not self.charm.upgrades_manager.in_progress
            ):
                message = "No upgrade in progress"
                logger.debug(f"Resume upgrade event failed: {message}")
                event.fail(message)
                return
        except OpenSearchK8sError as e:
            logger.error("Cannot check upgrade state: %s", e)
            event.fail(str(e))
            return

        try:
            if self.charm.substrate == Substrates.K8S:
                force = event.params.get("force", False)
                revision = self.charm.upgrades_manager.k8s_client.get_revision()
                partition = self.charm.upgrades_manager.get_resume_partition(force=force)
                self.charm.state.application_upgrade.resume_request = UpgradeResumeRequest(
                    revision=revision, partition=partition, force=force
                )
                event.set_results({"result": f"Upgrade resume requested for unit {partition}."})
            else:
                self.charm.upgrades_manager.reconcile_partition(action_event=event)
        except OpenSearchReconcilePartitionError as e:
            logger.debug(f"Resume upgrade event failed: {e}")
            event.fail(e.message)
            return
        except OpenSearchK8sError as e:
            logger.error("Cannot reconcile the Kubernetes partition: %s", e)
            event.fail(str(e))
            return

    def _apply_resume_request(self, request: UpgradeResumeRequest) -> None:
        """Apply a saved resume request after the action has completed.

        Lowering the partition can replace the leader's pod. Do this in a later hook
        so the action can report its result before its Juju agent is stopped.
        """
        if not self.charm.state.upgrade_membership_complete:
            logger.debug("Waiting for all units in the upgrade peer relation")
            return

        manager = self.charm.upgrades_manager
        if (
            request.revision != self.charm.upgrades_manager.k8s_client.get_revision()
            or manager.partition <= request.partition
        ):
            self.charm.state.application_upgrade.resume_request = None
            return

        try:
            partition = manager.get_resume_partition(force=request.force)
        except OpenSearchReconcilePartitionError as e:
            logger.info("Waiting to resume upgrade: %s", e.message)
            return

        if partition > request.partition:
            return

        # Use the partition requested by the action, even if more units are now HEALTHY.
        manager.partition = request.partition
        self.charm.state.application_upgrade.resume_request = None

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

        if not self.charm.state.upgrade_membership_complete:
            logger.debug("Waiting for all units in the upgrade peer relation")
            event.defer()
            return

        self._publish_app_upgrade_status()

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

        # Leave allocation enabled if the running node cannot safely be restarted.
        try:
            if self.charm.cluster_manager.opensearch_client.is_node_up() and not (
                self.charm.cluster_manager.can_restart_node(
                    self.charm.cluster_manager.get_nodes(True)
                )
            ):
                raise OpenSearchStopError(
                    "Waiting for another cluster manager before restarting OpenSearch."
                )
        except (OpenSearchHttpError, OpenSearchStopError) as e:
            logger.warning("Cannot prepare OpenSearch for upgrade: %s", e)
            self.charm.lock_manager.release()
            event.defer()
            return

        # https://www.elastic.co/guide/en/elastic-stack/8.13/upgrading-elasticsearch.html
        try:
            self.charm.cluster_manager.opensearch_client.disable_shard_allocation(
                alt_hosts=self.charm.cluster_manager.alt_hosts
            )
        except OpenSearchHttpError:
            logger.exception("Failed to disable shard allocation before upgrade")
            self.charm.lock_manager.release()
            event.defer()
            return

        try:
            self.charm.cluster_manager.opensearch_client.flush_translog(
                alt_hosts=self.charm.cluster_manager.alt_hosts
            )
        except OpenSearchHttpError as e:
            logger.debug("Failed to flush before upgrade", exc_info=e)

        logger.debug("Stopping OpenSearch before upgrade")
        try:
            self.charm.stop_opensearch(restart=True)
        except OpenSearchStopError as e:
            logger.exception(e)
            try:
                self.charm.cluster_manager.opensearch_client.enable_shard_allocation(
                    alt_hosts=self.charm.cluster_manager.alt_hosts
                )
            except OpenSearchHttpError:
                logger.exception(
                    "Failed to restore shard allocation after the upgrade stop failed"
                )
            self.charm.lock_manager.release()
            event.defer()
            return
        logger.debug("Stopped OpenSearch before upgrade")

        self.charm.state.server_upgrade.unit_state = UnitUpgradesState.UPGRADING
        self.charm.state.server_upgrade.post_upgrade_health = None
        if event.override_version:
            logger.debug("Overriding OpenSearch version")
            try:
                self.charm.upgrades_manager.override_version()
            except OpenSearchCmdError as e:
                logger.error("Failed to override OpenSearch version: %s", str(e))
        else:
            logger.debug("Upgrading unit")
            self.charm.status_handler.set_running_status(
                GeneralStatuses.INSTALL_IN_PROGRESS.value,
                "unit",
                component_name=self.charm.upgrades_manager.name,
            )
            self.charm.workload.install()

            # Check the installed workload for rollback before starting it.
            # Each affected unit may need explicit version recovery.
            if self.charm.upgrades_manager.is_rollback:
                if not self.charm.upgrades_manager.can_rollback:
                    logger.error(
                        "Rollback unsupported. Refresh to a newer revision or consult the recovery documentation"
                    )
                    # https://canonical-charmed-opensearch.readthedocs-hosted.com/2/how-to/upgrade/#recovering-from-a-rollback
                    self.charm.lock_manager.release()
                    return
                else:
                    logger.warning("Rollback detected")
                    logger.warning(
                        "Rollback incompatible. Run 'juju run <unit> force-refresh-start' with `check-compatibility` set to false to override node version and attempt startup procedure"
                    )
                    self.charm.lock_manager.release()
                    return
        self.charm.state.server_upgrade.snap_revision = pinned_snap_revision()
        self.charm.state.server_upgrade.workload_version = (
            self.charm.upgrades_manager.current_versions.workload
        )
        self.charm.state.remove_status_if_present(
            UpgradesStatuses.UPGRADES_PRE_UPGRADE_CHECK_FAILED.value,
            "unit",
            self.charm.upgrades_manager.name,
            interpolated=True,
        )
        logger.debug(
            f"Saved revision={pinned_snap_revision()} and {self.charm.upgrades_manager.current_versions.workload=} in unit databag after upgrade"
        )

        logger.debug("Starting OpenSearch after upgrade")
        self.charm.start_opensearch_event.emit(ignore_lock=event.ignore_lock, after_upgrade=True)

    def _publish_app_upgrade_status(self) -> None:
        """Publish approved upgrade guidance before a long hook can delay status collection."""
        if not self.charm.unit.is_leader():
            return

        for status in self.charm.upgrades_manager.get_statuses("app"):
            if status.approved_critical_component:
                self.charm.app.status = as_status(status)
                return

    def _on_refresh_force_start_action(self, event: ops.ActionEvent) -> None:
        """Handle force-refresh-start action for rollback scenario."""
        try:
            if not self.charm.upgrades_manager.is_rollback:
                logger.debug("For refresh start event failed: No rollback in progress")
                event.fail("No rollback in progress")
                return
        except OpenSearchK8sError as e:
            logger.error("Cannot check rollback state: %s", e)
            event.fail(str(e))
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
                {
                    "result": f"Requested startup of {self.charm.unit.name}. Check unit status for progress."
                }
            )
            logger.debug("Requested startup after rollback")
        else:
            logger.debug("Overriding OpenSearch version")
            try:
                self.charm.upgrades_manager.override_version()
                self.charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
                self.charm.state.server_upgrade.post_upgrade_health = None
                self.charm.start_opensearch_event.emit(after_upgrade=True)
                event.set_results(
                    {
                        "result": f"Requested startup of {self.charm.unit.name}. Check unit status for progress."
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

        try:
            if not self.charm.upgrades_manager.in_progress:
                logger.debug("Upgrade not in progress. OpenSearch version unchanged")
                return

            if not self.charm.upgrades_manager.is_compatible:
                logger.error("Refresh is incompatible")
                return

            if self.charm.upgrades_manager.is_rollback:
                logger.warning("Rollback detected")
                logger.warning(
                    "Rollback incompatible. Run 'juju run <unit> force-refresh-start' with `check-compatibility` set to false to override node version and attempt startup procedure"
                )
                event.defer()
                return
        except OpenSearchK8sError as e:
            logger.warning("Cannot prepare Kubernetes upgrade: %s", e)
            event.defer()
            return

        # Configure and start the workload
        if not self.charm.cluster_manager.no_blocking_directives():
            logger.debug("Cannot start OpenSearch after upgrade, cluster not ready")
            event.defer()
            return

        if not self.charm.tls_manager.all_tls_resources_stored():
            logger.info("TLS resources not yet stored on disk after upgrade. Deferring.")
            event.defer()
            return

        # The refreshed pod lost the keystore entries and S3 CA with its container filesystem
        try:
            self.charm.ldap_manager.restore_ldap_ca()
            self.charm.snapshots_events.restore_stored_credentials()
            self.charm.notifications_events.restore_keystore_credentials()
        except (OpenSearchCmdError, OpenSearchFileOperationError) as e:
            logger.error("Failed to restore keystore credentials after upgrade: %s", e)
            event.defer()
            return

        # The new pod still needs startup and health checks, even if the old stop hook
        # did not record RESTARTING. Keep any failed check until a retry succeeds.
        self.charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING

        # Mark the new version of the unit since in Kubernetes this unit is upgraded now.
        self.charm.state.server_upgrade.workload_version = (
            self.charm.upgrades_manager.current_versions.workload
        )
        logger.debug(
            f"Saved {self.charm.upgrades_manager.current_versions.workload=} in unit databag after upgrade"
        )
        self._publish_app_upgrade_status()
        self.charm.start_opensearch_event.emit(ignore_lock=True, after_upgrade=True)
