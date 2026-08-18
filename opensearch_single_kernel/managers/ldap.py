#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch LDAP manager."""

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.statuses import GeneralStatuses, LdapStatuses
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.status import running_statuses
from opensearch_single_kernel.workload.base import BaseWorkload


class LdapManager(BaseManager):
    """OpenSearch LDAP manager class.

    This class is responsible for monitoring the LDAP relation state.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "config_manager")

    @override()
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute statuses from roles and deployment state."""
        status_list = running_statuses(self.state.statuses, scope, self.name)

        if scope != "app" or not self.state.ldap_relation:
            return [GeneralStatuses.ACTIVE_IDLE.value]

        if self.state.is_non_main_orchestrator:
            status_list.append(LdapStatuses.RELATION_INVALID.value)
        elif not (ldap_data := self.state.ldap_data):
            status_list.append(LdapStatuses.LDAP_DATA_UNAVAILABLE.value)
        elif not ldap_data.ldaps_urls:
            status_list.append(LdapStatuses.LDAPS_NOT_ENABLED.value)

        if not self.workload.exists(self.workload.paths.ldap_chain):
            status_list.append(LdapStatuses.CERT_NOT_CONNECTED.value)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
