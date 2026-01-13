#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch profiles."""
import logging

from opensearch_single_kernel.common.constants import PerformanceType, StartMode
from opensearch_single_kernel.core.models import (
    OpenSearchProfile,
    PeerClusterApp,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import format_unit_name
from opensearch_single_kernel.utils.topology import ClusterTopology
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ProfilesManager(BaseManager):
    """Manage all profile related operations"""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "profiles_manager"
        try:
            if self.profile.type == PerformanceType.TESTING:
                logger.warning(
                    "Testing profile is used. This profile is not suitable for production use and should only be used for testing purposes."
                )
        except ValueError:
            logger.error(
                "Invalid profile configuration. Value: %s", self.state.config.get("profile")
            )

    def check_missing_system_requirements(self) -> list[str]:
        """Checks the system requirements."""
        return self.workload.check_missing_system_requirements()

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
        current_app = self._current_peer_cluster_app()
        # backwards compatibility for revisions that do not set generated roles
        # in cluster_fleet_apps
        if not cluster_fleet_apps or current_app.app.id in cluster_fleet_apps:
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

        match nbr_cm_nodes < profile.cluster_topology_requirements.cluster_managers, nbr_data_nodes < profile.cluster_topology_requirements.data:
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

    def _current_peer_cluster_app(self) -> PeerClusterApp:
        deployment_desc = self.state.application.deployment_desc
        return PeerClusterApp(
            app=deployment_desc.app,
            planned_units=self.state.planned_units,
            units=[format_unit_name(u, app=deployment_desc.app) for u in self.state.all_units],
            roles=(
                deployment_desc.config.roles
                if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES
                else ClusterTopology.generated_roles()
            ),
        )

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
