#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch profiles."""
from abc import ABC, abstractmethod
from typing import List, Optional

from opensearch_single_kernel.common.constants import PerformanceType, StartMode
from opensearch_single_kernel.core.models import Model, PeerClusterApp
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import format_unit_name
from opensearch_single_kernel.utils.topology import ClusterTopology
from opensearch_single_kernel.workload.base import BaseWorkload

_1GB_IN_KB = 1024 * 1024  # 1GB in KB
MAX_HEAP_SIZE = 31 * _1GB_IN_KB  # 31GB in KB


class ProfileMemoryRequirements(Model):
    """Memory requirements for a profile"""

    memory_size: Optional[int] = None
    jvm_heap_percentage: Optional[float] = None


class ClusterTopologyRequirements(Model):
    """Cluster Topology requirements for a profile"""

    cluster_managers: int = 1
    data: int = 1


class OpenSearchProfile(ABC):
    """Abstract class for an OpenSearch profile"""

    type: PerformanceType

    @property
    @abstractmethod
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile"""
        pass

    @property
    @abstractmethod
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        pass

    def get_jvm_heap_size(self, mem_size: float) -> int:
        """Get the JVM heap size in KB based on the memory requirements."""
        if self.memory_requirements.jvm_heap_percentage:
            return min(int(self.memory_requirements.jvm_heap_percentage * mem_size), MAX_HEAP_SIZE)
        return _1GB_IN_KB

    def __hash__(self):
        """Get the hash of the profile."""
        return hash(self.type)

    def __eq__(self, value: object) -> bool:
        """Check equality with another OpenSearchProfile."""
        return self.type == value.type if isinstance(value, OpenSearchProfile) else False


class ProductionProfile(OpenSearchProfile):
    """Production profile for opensearch.

    Ensures cluster meets production minimal requirements
    """

    type = PerformanceType.PRODUCTION

    @property
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile."""
        return ProfileMemoryRequirements(
            memory_size=8 * _1GB_IN_KB,
            jvm_heap_percentage=0.5,
        )

    @property
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        return ClusterTopologyRequirements(
            cluster_managers=3,
            data=3,
        )


class TestingProfile(OpenSearchProfile):
    """Testing profile for opensearch.

    Ensures basic system requirements and 1 CM+ 1 Data roles.
    """

    type = PerformanceType.TESTING

    @property
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile."""
        return ProfileMemoryRequirements(
            memory_size=None,
            jvm_heap_percentage=None,
        )

    @property
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        return ClusterTopologyRequirements(
            cluster_managers=1,
            data=1,
        )


class ProfilesManager(BaseManager):
    """Manage all profile related operations"""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        self.state = state
        self.workload = workload
        try:
            if self.profile.type == PerformanceType.TESTING:
                self.logger.warning(
                    "Testing profile is used. This profile is not suitable for production use and should only be used for testing purposes."
                )
        except ValueError:
            self.logger.error(
                "Invalid profile configuration. Value: %s", self.state.config.get("profile")
            )

    def check_missing_system_requirements(self) -> List[str]:
        """Checks the system requirements."""
        return self.workload.check_missing_system_requirements()

    def check_memory_requirements(self, profile: OpenSearchProfile) -> List[str]:
        """Checks memory requirements for the unit."""
        memory_size = self.workload.meminfo()["MemTotal"]

        if (
            profile.memory_requirements.memory_size
            and memory_size < profile.memory_requirements.memory_size
        ):
            self.logger.error(
                "Insufficient memory: %s < %s",
                memory_size,
                profile.memory_requirements.memory_size,
            )
            return [
                "Insufficient memory: %s < %s"
                % (memory_size, profile.memory_requirements.memory_size)
            ]

        return []

    def check_cluster_topology(self, profile: OpenSearchProfile) -> List[str]:
        """Check the cluster topology requirements."""
        cluster_fleet_apps = self.state.application.cluster_fleet_apps
        current_app = self._current_peer_cluster_app()
        # backwards compatibility for revisions that do not set generated roles
        # in cluster_fleet_apps
        if not cluster_fleet_apps or current_app.app.id in cluster_fleet_apps:
            cluster_fleet_apps[current_app.app.id] = current_app

        self.logger.debug("current_cluster_fleet_apps: %s", cluster_fleet_apps)
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

        self.logger.error("Missing cluster topology requirements: %s", error_message)
        return [error_message]

    def _current_peer_cluster_app(self) -> PeerClusterApp:
        deployment_desc = self.state.app.deployment_description
        return PeerClusterApp(
            app=deployment_desc.app,
            planned_units=self.state.charm.app.planned_units(),
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
        return self.state.unit.profile or self.config_profile

    @property
    def config_profile(self) -> OpenSearchProfile:
        """Get the current config profile."""
        return (
            ProductionProfile()
            if PerformanceType(self.state.config.get("profile")) == PerformanceType.PRODUCTION
            else TestingProfile()
        )
