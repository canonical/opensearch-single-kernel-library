#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Health management."""

import logging
import time

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override
from tenacity import retry, stop_after_attempt, wait_fixed

from opensearch_single_kernel.common.constants import (
    HealthColors,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHAError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    HealthStatuses,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.status import format_status
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class HealthManager(BaseManager):
    """Class for managing OpenSearch statuses."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "health_manager")

    def get(  # noqa: C901
        self,
        wait_for_green_first: bool = False,
        use_localhost: bool = True,
        local_app_only: bool = True,
    ) -> str:
        """Fetch the current cluster status."""
        if not (deployment_desc := self.state.application.deployment_description):
            return HealthColors.UNKNOWN

        # the health depends on data nodes, for large deployments: an ML cluster
        # may not be concerned about reporting or relying on the health of the
        # data nodes in other clusters. We should therefore get this info from
        # the deployment descriptor which has an overview of all the cluster.
        # compute health only in clusters where data nodes exist
        compute_health = (
            deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            or self.state.application.is_data_role_in_cluster_fleet_apps
            or not local_app_only
        )
        if not compute_health:
            return HealthColors.IGNORE

        host = self.state.node_host if use_localhost else None
        response = self.opensearch_client.get_health(host, wait_for_green_first, self.alt_hosts)
        if wait_for_green_first and not response:
            response = self.opensearch_client.get_health(host, False, self.alt_hosts)

        if not response:
            return HealthColors.UNKNOWN

        logger.info("Health: %s", response)
        try:
            status = response["status"].lower()
        except (AttributeError, TypeError, KeyError) as e:
            logger.error(e)  # means the status was reported as an int (i.e: 503)
            return HealthColors.UNKNOWN

        # we differentiate between a temp yellow (moving shards) and a permanent
        # one (such as: missing replicas)
        if status in [HealthColors.GREEN, HealthColors.YELLOW] and (
            response["initializing_shards"] > 0 or response["relocating_shards"] > 0
        ):
            try:

                logger.debug(
                    "Health: %s -- Shards: %s",
                    status,
                    self.opensearch_client.get_shards(host, verbose=True),
                )
                logger.debug(
                    "Allocation explanations: %s\n\n",
                    self.opensearch_client.get_allocation_explain(host),
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
            logger.info("Shards still moving before stopping Opensearch.")
            # we throw an error because various operations should NOT start while data
            # is being relocated. Examples are: simple stop, unit removal, upgrade
            raise OpenSearchHAError("Shards haven't completed relocating.")

    @override
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute the manager's statuses."""
        status_list: list[StatusObject] = []

        status = self.get(wait_for_green_first=recompute)

        if scope == "app":
            match status:
                case HealthColors.RED:
                    status_list.append(HealthStatuses.CLUSTER_HEALTH_RED.value)
                case HealthColors.YELLOW_TEMP:
                    status_list.append(HealthStatuses.WAITING_FOR_BUSY_SHARDS.value)
                case HealthColors.YELLOW:
                    status_list.append(HealthStatuses.CLUSTER_HEALTH_YELLOW.value)
        elif status == HealthColors.YELLOW and (
            busy_shards := self.opensearch_client.get_busy_shards_by_unit(alt_hosts=self.alt_hosts)
        ):
            message = sorted([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
            status_list.append(
                format_status(
                    HealthStatuses.WAITING_FOR_SPECIFIC_BUSY_SHARDS.value,
                    {"shards": " - ".join(message)},
                )
            )

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
