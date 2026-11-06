#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch profiles."""

import logging

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.constants import PerformanceType
from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.common.statuses import GeneralStatuses, ProfileStatuses
from opensearch_single_kernel.core.models import (
    OpenSearchProfile,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.status import format_status, running_statuses
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ProfilesManager(BaseManager):
    """Manage all profile related operations"""

    JVM_OPTIONS = "jvm.options"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "profiles_manager")
        self.yaml_setter = YamlConfigSetter(self.workload)
        if self.state.server.profile and self.state.server.profile.type == PerformanceType.TESTING:
            logger.warning(
                "Testing profile is used. This profile is not suitable for production use and should only be used for testing purposes."
            )

    def get_missing_requirements(self, profile: OpenSearchProfile) -> list[str]:
        """Get the missing requirements of a profile, defaulting to the current profile."""
        missing_requirements: list[str] = []

        missing_requirements.extend(self.workload.check_missing_system_requirements())
        missing_requirements.extend(self.check_memory_requirements(profile))
        missing_requirements.extend(self.check_cluster_topology(profile))
        return missing_requirements

    @property
    def current_profile(self) -> OpenSearchProfile | None:
        """The profile the unit runs with: the applied one, or the configured one until applied.

        Returns None if no profile is applied and the configured one is invalid, as only a new
        config change can fix the value.
        """
        if self.state.server.profile:
            return self.state.server.profile
        try:
            return self.state.config_profile
        except ValueError:
            logger.error(
                "Invalid profile configuration. Value: %s",
                self.state.config.get("profile"),
            )
            return None

    def check_profile_requirements(self, profile: OpenSearchProfile | None = None) -> bool:
        """Check all requirements of the given profile, defaulting to the current one.

        Args:
            profile: The profile to check requirements for. Defaults to the current profile,
                i.e. the one applied on the unit, or the configured one until one is applied.

        Returns:
            True if all requirements of the profile are met.
        """
        if profile is None:
            profile = self.current_profile
            if profile is None:
                return False
        try:
            return not self.get_missing_requirements(profile)
        except OpenSearchCmdError as e:
            logger.error("An error occurred while checking profile requirements: %s", str(e))
            return False

    def check_memory_requirements(self, profile: OpenSearchProfile) -> list[str]:
        """Checks memory requirements for the unit."""
        if not profile.memory_requirements.memory_size:
            return []

        memory_size = self.workload.memtotal()
        logger.debug("Unit memory size: %s", memory_size)

        if memory_size < profile.memory_requirements.memory_size:
            logger.error(
                "Insufficient memory: %s < %s",
                memory_size,
                profile.memory_requirements.memory_size,
            )
            return [
                f"Insufficient memory: {memory_size} < {profile.memory_requirements.memory_size}"
            ]

        return []

    def check_cluster_topology(self, profile: OpenSearchProfile) -> list[str]:
        """Check the cluster topology requirements."""
        cluster_fleet_apps = self.state.application.cluster_fleet_apps
        current_app = self.state.current_peer_cluster_app
        # backwards compatibility for revisions that do not set generated roles
        # in cluster_fleet_apps
        if current_app and (not cluster_fleet_apps or current_app.app.id in cluster_fleet_apps):
            cluster_fleet_apps[current_app.app.id] = current_app

        logger.debug("current_cluster_fleet_apps: %s", cluster_fleet_apps)
        error_message = None

        nbr_cm_nodes = sum(
            app.planned_units
            for app in cluster_fleet_apps.values()
            if "cluster_manager" in app.roles
        )
        nbr_data_nodes = sum(
            app.planned_units for app in cluster_fleet_apps.values() if "data" in app.roles
        )

        match (
            nbr_cm_nodes < profile.cluster_topology_requirements.cluster_managers,
            nbr_data_nodes < profile.cluster_topology_requirements.data,
        ):
            case (True, True):
                error_message = f"At least {profile.cluster_topology_requirements.cluster_managers} cluster manager nodes and {profile.cluster_topology_requirements.data} data nodes are required."
            case (True, False):
                error_message = f"At least {profile.cluster_topology_requirements.cluster_managers} cluster manager nodes are required."
            case (False, True):
                error_message = f"At least {profile.cluster_topology_requirements.data} data nodes are required."
            case _:
                return []

        logger.error("Missing cluster topology requirements: %s", error_message)
        return [error_message]

    def apply_profile(self) -> bool:
        """Apply the configured profile on the unit, once all its requirements are met.

        Returns:
            True if a new profile was applied: OpenSearch must restart for it to take effect.
        """
        try:
            profile = self.state.config_profile
        except ValueError:
            logger.error(
                "Invalid profile configuration. Value: %s",
                self.state.config.get("profile"),
            )
            return False

        if profile == self.state.server.profile:
            return False

        if not self.check_profile_requirements(profile):
            return False

        heap_size = profile.get_jvm_heap_size(self.workload.memtotal())
        logger.debug("Updating JVM heap size to %s KB based on profile requirements", heap_size)
        self._update_jvm_heap_size(heap_size)
        self.state.server.profile = profile
        return True

    def _update_jvm_heap_size(self, heap_size_in_kb: int) -> None:
        """Update Opensearch JVM config file using the provided values."""
        self.yaml_setter.replace(
            self.JVM_OPTIONS,
            "-Xms[0-9]+[kmgKMG]",
            f"-Xms{heap_size_in_kb}k",
            regex=True,
        )
        self.yaml_setter.replace(
            self.JVM_OPTIONS,
            "-Xmx[0-9]+[kmgKMG]",
            f"-Xmx{heap_size_in_kb}k",
            regex=True,
        )

    @override
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute profile statuses from current config and local checks."""
        status_list = running_statuses(self.state.statuses, scope, self.name)

        if not self.state.current_peer_cluster_app:
            return status_list or [GeneralStatuses.ACTIVE_IDLE.value]

        if scope == "unit":
            try:
                config_profile = self.state.config_profile
            except ValueError:
                status_list.append(ProfileStatuses.INVALID_PROFILE_CONFIG_OPTION.value)
                return status_list

            try:
                if missing_requirements := self.get_missing_requirements(config_profile):
                    status_list.append(
                        format_status(
                            ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value,
                            {"requirements": "; ".join(missing_requirements)},
                        )
                    )
            except OpenSearchCmdError as e:
                logger.warning("Error checking profile requirements: %s", e)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
