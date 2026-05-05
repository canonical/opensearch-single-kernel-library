#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch profiles."""

import logging

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.constants import PerformanceType
from opensearch_single_kernel.common.statuses import GeneralStatuses, ProfileStatuses
from opensearch_single_kernel.core.models import (
    OpenSearchProfile,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.status import format_status
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ProfilesManager(BaseManager):
    """Manage all profile related operations"""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "profiles_manager")
        try:
            if self.profile.type == PerformanceType.TESTING:
                logger.warning(
                    "Testing profile is used. This profile is not suitable for production use and should only be used for testing purposes."
                )
        except ValueError:
            logger.error(
                "Invalid profile configuration. Value: %s",
                self.state.config.get("profile"),
            )

    def get_missing_requirements(self) -> list[str]:
        """Get the profile missing requirements."""
        missing_requirements: list[str] = []

        missing_requirements.extend(self.workload.check_missing_system_requirements())
        missing_requirements.extend(self.check_memory_requirements(self.profile))
        missing_requirements.extend(self.check_cluster_topology(self.profile))
        return missing_requirements

    def check_memory_requirements(self, profile: OpenSearchProfile) -> list[str]:
        """Checks memory requirements for the unit."""
        memory_size = self.workload.meminfo()["MemTotal"]

        if (
            profile.memory_requirements.memory_size
            and memory_size < profile.memory_requirements.memory_size
        ):
            logger.error(
                "Insufficient memory: %s < %s",
                memory_size,
                profile.memory_requirements.memory_size,
            )
            return [
                "Insufficient memory: %s < %s"
                % (memory_size, profile.memory_requirements.memory_size)
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

    @property
    def profile(self) -> OpenSearchProfile:
        """Get the current profile."""
        return self.state.server.profile or self.config_profile

    @property
    def config_profile(self) -> OpenSearchProfile:
        """Get the current config profile."""
        return (
            ProductionProfile()
            if PerformanceType(self.state.config.get("profile")) == PerformanceType.PRODUCTION
            else TestingProfile()
        )

    @override
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute the manager's statuses."""
        if not recompute:
            return self.state.statuses.get(scope, self.name).root or [
                GeneralStatuses.ACTIVE_IDLE.value
            ]

        status_list: list[StatusObject] = []
        missing_requirements = self.get_missing_requirements()
        if scope == "unit":
            try:
                self.config_profile
            except ValueError:
                status_list.append(ProfileStatuses.INVALID_PROFILE_CONFIG_OPTION.value)

            if missing_requirements:
                status_list.append(
                    format_status(
                        ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value,
                        {"requirements": " - ".join(missing_requirements)},
                    )
                )

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
