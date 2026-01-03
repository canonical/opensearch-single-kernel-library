#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Health management."""
import time

from tenacity import retry, stop_after_attempt, wait_fixed

from opensearch_single_kernel.common.constants import HealthColors, StartMode
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHAError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.topology import ClusterTopology
from opensearch_single_kernel.workload.base import BaseWorkload


class HealthManager(BaseManager):
    """Class for managing OpenSearch statuses."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "health_manager"

    def get(  # noqa: C901
        self,
        wait_for_green_first: bool = False,
        use_localhost: bool = True,
        local_app_only: bool = True,
    ) -> str:
        """Fetch the current cluster status."""
        if not (deployment_desc := self.state.application.deployment_desc):
            return HealthColors.UNKNOWN

        # the health depends on data nodes, for large deployments: an ML cluster
        # may not be concerned about reporting or relying on the health of the
        # data nodes in other clusters. We should therefore get this info from
        # the deployment descriptor which has an overview of all the cluster.
        # compute health only in clusters where data nodes exist
        compute_health = (
            deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            or ClusterTopology.is_data_role_in_cluster_fleet_apps(self.state)
            or not local_app_only
        )
        if not compute_health:
            return HealthColors.IGNORE

        host = self.state.unit_ip if use_localhost else None
        response = self.opensearch_client.get_health(host, wait_for_green_first, self.alt_hosts)
        if wait_for_green_first and not response:
            response = self.opensearch_client.get_health(host, False, self.alt_hosts)

        if not response:
            return HealthColors.UNKNOWN

        self.logger.info(f"Health: {response}")
        try:
            status = response["status"].lower()
        except (AttributeError, TypeError, KeyError) as e:
            self.logger.error(e)  # means the status was reported as an int (i.e: 503)
            return HealthColors.UNKNOWN

        # we differentiate between a temp yellow (moving shards) and a permanent
        # one (such as: missing replicas)
        if status in [HealthColors.GREEN, HealthColors.YELLOW] and (
            response["initializing_shards"] > 0 or response["relocating_shards"] > 0
        ):
            try:
                self.logger.debug(
                    f"\n\nHealth: {status} -- Shards: {self.opensearch_client.get_shards(host, verbose=True)}\n\n"
                )
                self.logger.debug(
                    f"Allocation explanations: {self.opensearch_client.get_allocation_explain(host)}\n\n"
                )
            except OpenSearchHttpError:
                pass
            return HealthColors.YELLOW_TEMP

        return status

    @retry(stop=stop_after_attempt(90), wait=wait_fixed(5), reraise=True)
    def wait_for_shards_relocation(self) -> None:
        """Blocking function until the shards relocation completes in the cluster."""
        time.sleep(5)

        health = self.get(local_app_only=False)

        if health == HealthColors.YELLOW_TEMP:
            self.logger.info("Shards still moving before stopping Opensearch.")
            # we throw an error because various operations should NOT start while data
            # is being relocated. Examples are: simple stop, unit removal, upgrade
            raise OpenSearchHAError("Shards haven't completed relocating.")
