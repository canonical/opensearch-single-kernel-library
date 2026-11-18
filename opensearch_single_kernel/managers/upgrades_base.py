# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades

Based off specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""

import abc
import json
import logging
import re
from typing import Any

import ops
import poetry.core.constraints.version as poetry_version
from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.constants import (
    OPENSEARCH_HTTP_PORT,
    UPGRADES_COMPATIBILITY_MATRIX,
    HealthColors,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
    OpenSearchHttpError,
    OpenSearchUpgradePrecheckError,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    HealthStatuses,
    LockStatuses,
    UpgradesStatuses,
)
from opensearch_single_kernel.core.models import (
    JWTAuthConfiguration,
    UnitUpgradesState,
    UpgradeVersions,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.status import (
    cached_non_running_statuses,
    format_status,
    running_statuses,
)
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

    def migrate_legacy_auth_configuration(self) -> None:
        """Restore unit auth state from the stable (2.19.4) operator's security configuration.

        Called by upgrade-charm before configuration can be regenerated from unit state.
        """
        server = self.state.server
        migrate_jwt = self.state.jwt_relation is not None and server.jwt_auth_configuration is None
        migrate_oidc = (
            self.state.oauth_relation is not None and server.oauth_openid_connect_url is None
        )
        if not (migrate_jwt or migrate_oidc):
            return

        config = YamlConfigSetter(self.workload).load("opensearch-security/config.yml")
        authc = config["config"]["dynamic"]["authc"]

        jwt = authc.get("jwt_auth_domain", {})
        if migrate_jwt and jwt.get("http_enabled"):
            server.jwt_auth_configuration = JWTAuthConfiguration.from_dict(
                jwt["http_authenticator"]["config"]
            )

        oidc = authc.get("openid_auth_domain", {})
        if migrate_oidc and oidc.get("http_enabled"):
            server.oauth_openid_connect_url = oidc["http_authenticator"]["config"][
                "openid_connect_url"
            ]

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
    def in_progress(self) -> bool:
        """Whether an upgrade is in progress"""
        logger.debug(
            f"{self._app_workload_container_version=} {self._unit_workload_container_versions=}"
        )
        return any(
            version != self._app_workload_container_version
            for version in self._unit_workload_container_versions.values()
        )

    @property
    @abc.abstractmethod
    def unit_status(self) -> tuple[StatusObject | None, dict[str, Any] | None]:
        """Get unit upgrade status."""

    @property
    def app_status(self) -> StatusObject | None:
        """App upgrade status"""
        in_progress = self.in_progress
        if in_progress and not self.is_compatible:
            logger.info(
                "Upgrade incompatible. If you accept potential *data loss* and *downtime*, you can continue by running `force-upgrade` action on each remaining unit"
            )
            return UpgradesStatuses.UPGRADES_INCOMPATIBLE.value

        if not in_progress:
            if self.upgrade_checks_pending:
                return UpgradesStatuses.UPGRADES_UPGRADING.value
            return None

        if not self.upgrade_resumed:
            units = self.state.sorted_upgrades_units
            if not self.state.upgrade_membership_complete or len(units) < 2:
                return UpgradesStatuses.UPGRADES_UPGRADING.value
            first_unit = units[0]
            target_revision = self._app_workload_container_version
            if (
                first_unit.unit_state != UnitUpgradesState.HEALTHY
                or first_unit.unit_state_revision != target_revision
                or self._unit_workload_container_versions.get(first_unit.unit.name)
                != target_revision
            ):
                return UpgradesStatuses.UPGRADES_UPGRADING.value
            # User confirmation needed to resume upgrade (i.e. upgrade second unit)
            # Statuses over 120 characters are truncated in `juju status` as of juju 3.1.6 and
            # 2.9.45
            return UpgradesStatuses.UPGRADES_WAITING_FOR_RESUME.value

        return UpgradesStatuses.UPGRADES_UPGRADING.value

    @property
    def upgrade_checks_pending(self) -> bool:
        """Whether installed revisions still need their post-upgrade checks.

        Older charms did not record the revision checked on machines. A missing
        record alone does not mean an unchanged unit needs another upgrade.
        An ordinary restart has the same validated revision and workload version.
        A rollback can reuse an older pod revision while its data still needs recovery.
        """
        revisions = self._unit_workload_container_versions
        return any(
            unit.unit_state == UnitUpgradesState.UPGRADING
            or (
                unit.unit_state == UnitUpgradesState.RESTARTING
                and (
                    not revisions.get(unit.unit.name)
                    or unit.unit_state_revision != revisions[unit.unit.name]
                    or unit.workload_version != self.current_versions.workload
                )
            )
            or (
                unit.unit_state_revision
                and revisions.get(unit.unit.name)
                and unit.unit_state_revision != revisions[unit.unit.name]
            )
            for unit in self.state.sorted_upgrades_units
        )

    @property
    @abc.abstractmethod
    def upgrade_resumed(self) -> bool:
        """Whether the user has resumed the upgrade with the Juju action."""

    @abc.abstractmethod
    def reconcile_partition(
        self, *, action_event: ops.ActionEvent | None = None, force=False
    ) -> None:
        """If ready, allow next unit to upgrade."""

    @property
    @abc.abstractmethod
    def unit_state(self) -> UnitUpgradesState | None:
        """Calculate the upgrade state of current unit."""

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

        if not self.state.upgrade_membership_complete:
            raise OpenSearchUpgradePrecheckError(
                "Waiting for all units in the upgrade peer relation."
            )

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
        """Compute upgrade statuses from upgrade state."""
        if self.state.planned_units == 0:
            return [GeneralStatuses.ACTIVE_IDLE.value]

        status_list = running_statuses(self.state.statuses, scope, self.name)
        if not self.state.upgrade_relation or not self.state.application_upgrade.versions:
            return status_list or [GeneralStatuses.ACTIVE_IDLE.value]

        if scope == "unit":
            status_list.extend(
                cached_non_running_statuses(
                    self.state.statuses,
                    scope,
                    self.name,
                    message_contains=["Pre upgrade check failed"],
                )
            )

        unit_status, unit_dynamic_params = self.unit_status
        if scope == "unit" and unit_status:
            if unit_status.status != "active" or (
                not self.state.unit_operation_in_progress
                and self.state.server.started
                and not self.state.server.start_pending
                and not self.state.server.start_failed
                and LockStatuses.REQUEST_LOCK_ON_START.value
                not in self.state.statuses.get("unit", "lock_manager").root
                and self.state.server_upgrade.unit_state
                not in (UnitUpgradesState.UPGRADING, UnitUpgradesState.RESTARTING)
                and not any(
                    status in self.state.statuses.get("unit", "cluster_manager").root
                    for status in (
                        GeneralStatuses.WAITING_TO_START.value,
                        GeneralStatuses.SERVICE_START_ERROR.value,
                    )
                )
                and self.workload.is_service_started()
                and self.workload.is_reachable(self.state.node_host, OPENSEARCH_HTTP_PORT)
            ):
                formatted = format_status(unit_status, unit_dynamic_params)
                if formatted not in status_list:
                    status_list.append(formatted)

        if scope == "unit" and (not unit_status or unit_status.status != "blocked"):
            status_list.extend(self._pending_upgrade_statuses())

        if scope == "app" and (status := self.app_status) and status not in status_list:
            status_list.append(status)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]

    def _pending_upgrade_statuses(self) -> list[StatusObject]:
        """Describe unfinished upgrade checks even after the display cache is cleared."""
        if not self.state.upgrade_relation or self.state.server_upgrade.unit_state not in (
            UnitUpgradesState.UPGRADING,
            UnitUpgradesState.RESTARTING,
        ):
            return []
        # A unit being removed will not restart or complete upgrade checks.
        if self.state.unit_dying:
            return []
        # Application status shows upgrade progress. Report failed health checks on the unit.
        health = self.state.server_upgrade.post_upgrade_health
        if health == HealthColors.RED:
            return [
                UpgradesStatuses.UPGRADES_UNHEALTHY.value,
                HealthStatuses.CLUSTER_HEALTH_RED_UPGRADE.value,
            ]
        if health == HealthColors.YELLOW_TEMP:
            return [HealthStatuses.WAITING_FOR_BUSY_SHARDS.value]
        if health in (HealthColors.UNKNOWN, HealthColors.IGNORE):
            return [UpgradesStatuses.UPGRADES_UNHEALTHY.value]
        if (
            self.state.server.start_failed
            or GeneralStatuses.WAITING_TO_START.value
            in self.state.statuses.get("unit", "cluster_manager").root
            or LockStatuses.REQUEST_LOCK_ON_START.value
            in self.state.statuses.get("unit", "lock_manager").root
        ):
            return []
        # Compute this from the saved upgrade state so it clears when startup finishes.
        return [GeneralStatuses.WAITING_TO_START.value.model_copy(update={"running": None})]

    def record_upgrade_health(self, health: HealthColors) -> None:
        """Keep failed post-upgrade checks visible until a later check succeeds.

        This only records the status. The caller still decides when the unit is HEALTHY
        and whether the next unit may upgrade.
        """
        self.state.server_upgrade.post_upgrade_health = (
            None if health in (HealthColors.GREEN, HealthColors.YELLOW) else HealthColors(health)
        )

    def get_version_before_override(self) -> poetry_version.Version | None:  # noqa: C901
        """Get the version of OpenSearch before override-version is run."""
        if self.workload.is_service_started():
            logger.debug("Service is started. The override version can not be run unless we stop.")
            return None

        # Regex to match the version to be overridden
        regex = r"last written by OpenSearch version \[([0-9]+\.[0-9]+\.[0-9]+)\]"
        # Exact error message when the version is already overridden
        already_overridden_error = "so there is no need to override the version checks"

        def check_output_for_version(output: str) -> poetry_version.Version | None:
            """Check the output for the version to be overridden."""
            version = re.search(regex, str(output))
            if version:
                return poetry_version.Version.parse(version.group(1))
            return None

        output = ""

        try:
            if self.state.substrate == Substrates.K8S:
                output = self.workload.run_script(
                    "bin/opensearch-node", "override-version", stdin="N\n"
                )
            else:
                # Separated the command and passed 'N' via stdin to match the K8s behavior
                output = self.workload.run_cmd("opensearch.node", "override-version", stdin="N\n")

            # Optional: strip() the output if your framework doesn't do it automatically
            if isinstance(output, str):
                output = output.strip()

            return check_output_for_version(str(output))
        except OpenSearchCmdError as e:
            # The failed command may report the version in stdout or stderr.
            output = "\n".join(part for part in (e.out, e.err) if part)

            if version := check_output_for_version(str(output)):
                return version

            # Check if the error message indicates that the version is already overridden
            if already_overridden_error in str(output):
                logger.debug("Version is already overridden. No need to override again.")
                return None

            # If neither condition is met, re-raise the exception
            logger.error(f"Unexpected error running override-version. Output: {output}")
            raise e

    def override_version(self) -> None:
        """Override the version on disk to allow rollback to proceed."""
        if self.state.substrate == Substrates.K8S:
            self.workload.run_script("bin/opensearch-node", "override-version", stdin="y\n")
        else:
            self.workload.run_cmd("opensearch.node", "override-version", stdin="y\n")

    @property
    def compatibility_matrix(self) -> dict[str, set[str]]:
        """Read compatibility matrix from file."""
        try:
            content = self.workload.read_text(self.workload.paths.compatibility_matrix)
            return {key: set(value) for key, value in json.loads(content).items()}
        except OpenSearchFileOperationError as e:
            logger.debug("Failed to read compatibility matrix file: %s", str(e))
            return {}
        except json.JSONDecodeError as e:
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

    def should_check_rollback(self) -> bool:
        """Return whether this unit needs to be checked for rollback.

        Keep the compatibility check so this does not permit an arbitrary downgrade.
        The last unit may already have the target revision while its startup and
        health checks are still pending, so revision differences alone are not enough.
        """
        if not (self.in_progress or self.upgrade_checks_pending):
            return False

        if not (previous_versions := self.state.application_upgrade.versions):
            return False

        return (
            self.is_compatible
            and previous_versions.workload_parsed == self.current_versions.workload_parsed
        )

    @property
    def is_rollback(self) -> bool:
        """Whether this upgrade is a rollback"""
        # First source of truth is the result of override-version command.
        # If it raises an error, we check in the databag.
        # The reason for this is that the databag can be out of sync because
        # of errors in the upgrade process
        if not self.should_check_rollback():
            return False

        logger.debug("Checking if it is a rollback")
        try:
            version_before_override = self.get_version_before_override()
            return version_before_override is not None
        except OpenSearchCmdError as e:
            logger.debug(f"Failed to get version before override: {e}")
            logger.debug("Reverting to check rollback based on databag in unit state")
            if unit_databag := self.state.server_upgrade.workload_version_parsed:
                return unit_databag > self.current_versions.workload_parsed
            return False

    @property
    def can_rollback(self) -> bool:
        """Whether rollback is supported to previous versions"""
        if not self.state.application_upgrade.versions:
            return False

        if not self.should_check_rollback():
            return False
        try:
            version_before_override = self.get_version_before_override()
        except OpenSearchCmdError as e:
            logger.debug(f"Failed to get version before override: {e}")
            logger.debug("Reverting to check rollback based on databag in unit state")
            version_before_override = self.state.server_upgrade.workload_version_parsed

        if not version_before_override:
            logger.debug("Version before override not found")
            return False

        version_on_disk = self.current_versions.workload_parsed
        compatibility_matrix = self.reconcile_compatibility_matrix()

        if (
            str(version_before_override) in compatibility_matrix
            and str(version_on_disk) in compatibility_matrix[str(version_before_override)]
        ):
            logger.debug(
                "Rollback supported from %s to %s",
                version_before_override,
                version_on_disk,
            )
            return True

        logger.warning(
            "Rollback not supported from %s to %s", version_before_override, version_on_disk
        )
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

    @abc.abstractmethod
    def save_upgrades_versions(self) -> None:
        """Save revision on first install"""
        ...

    @property
    @abc.abstractmethod
    def _unit_workload_container_versions(self) -> dict[str, str]:
        """{Unit name: Kubernetes controller revision hash}

        Even if the workload container version is the same, the workload will restart if the
        controller revision hash changes. (Juju bug: https://bugs.launchpad.net/juju/+bug/2036246).

        Therefore, we must use the revision hash instead of the workload container version. (To
        satisfy the requirement that if and only if this version changes, the workload will
        restart.)
        """

    @property
    @abc.abstractmethod
    def _app_workload_container_version(self) -> str:
        """App's Kubernetes controller revision hash"""
