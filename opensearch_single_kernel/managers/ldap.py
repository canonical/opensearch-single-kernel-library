#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch LDAP manager."""

import logging

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.constants import Substrates
from opensearch_single_kernel.common.statuses import GeneralStatuses, LdapStatuses
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.status import running_statuses
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class LdapManager(BaseManager):
    """OpenSearch LDAP manager class.

    This class is responsible for monitoring the LDAP relation state.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "ldap_manager")

    def reconcile_k8s_runtime_resources(self) -> None:
        """Restore LDAP chain resources from relation.

        On K8s, LDAP certificates can be present in relations while the workload container
        filesystem is empty after pod restart. This reconciliation restores TLS files onto
        the workload filesystem. On VM, this is a no-op.
        """
        if self.state.substrate != Substrates.K8S:
            return

        if not (ca_certs := self.state.ldap_certificates):
            logger.debug(
                "Ldap certificates not published by provider. Early exiting k8s runtime reconciliation."
            )
            return

        if not self.workload.exists(self.workload.paths.ldap_chain):
            logger.debug("Restoring ldap certificates files")
            self.workload.write_text("\n".join(sorted(ca_certs)), self.workload.paths.ldap_chain)

    @override()
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute statuses from roles and deployment state."""
        status_list = running_statuses(self.state.statuses, scope, self.name)

        if (
            scope != "app"
            or not self.state.application.deployment_desc
            or not self.state.ldap_relation
        ):
            return [GeneralStatuses.ACTIVE_IDLE.value]

        if not self.state.is_main_orchestrator:
            status_list.append(LdapStatuses.RELATION_INVALID.value)
        elif not (ldap_data := self.state.ldap_data):
            status_list.append(LdapStatuses.LDAP_DATA_UNAVAILABLE.value)
        elif not ldap_data.ldaps_urls:
            status_list.append(LdapStatuses.LDAPS_NOT_ENABLED.value)

        if not self.state.ldap_certificates:
            status_list.append(LdapStatuses.CERT_NOT_CONNECTED.value)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
