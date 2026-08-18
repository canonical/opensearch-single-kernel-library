# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for events handler related to OpenSearch LDAP authentication configuration."""

import logging
from typing import TYPE_CHECKING

from ops import (
    ConfigChangedEvent,
    EventBase,
    Object,
)

from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.lib.charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateAvailableEvent,
    CertificateRemovedEvent,
)
from opensearch_single_kernel.lib.charms.glauth_k8s.v0.ldap import (
    LdapReadyEvent,
    LdapUnavailableEvent,
)

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class LdapEventsHandler(Object):
    """Handler for managing LDAP relations."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, "oauth")
        self.charm = charm

        self.framework.observe(self.charm.state.ldap_requirer.on.ldap_ready, self._on_ldap_ready)
        self.framework.observe(
            self.charm.state.ldap_requirer.on.ldap_unavailable, self._on_ldap_unavailable
        )
        self.framework.observe(
            self.charm.state.ldap_certificate_transfer_requires.on.certificate_available,
            self._on_ldap_certificate_available,
        )
        self.framework.observe(
            self.charm.state.ldap_certificate_transfer_requires.on.certificate_removed,
            self._on_ldap_certificate_removed,
        )
        self.framework.observe(self.charm.on.config_changed, self._on_config_changed)

    def _on_ldap_ready(self, event: LdapReadyEvent) -> None:
        """Handle the LDAP integration event."""
        if not self.charm.workload.can_connect:
            event.defer()
            return

        if self.charm.state.is_non_main_orchestrator:
            return

        if not (
            ldap_data := self.charm.state.ldap_requirer.consume_ldap_relation_data(
                relation=event.relation
            )
        ):
            return

        if not ldap_data.ldaps_urls:
            return

        if not self.charm.workload.exists(self.charm.workload.paths.ldap_chain):
            return

        self._update_security_config(event)

    def _on_ldap_unavailable(self, event: LdapUnavailableEvent) -> None:
        """Handle the removal of LDAP integration."""
        if not self.charm.workload.can_connect:
            event.defer()
            return

        if not self.charm.state.is_non_main_orchestrator:
            self._update_security_config(event)

    def _on_ldap_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handle the receiving of LDAP certificates."""
        if not self.charm.workload.can_connect:
            event.defer()
            return

        full_chain = "\n".join(event.chain)
        self.charm.workload.write_text(full_chain, self.charm.workload.paths.ldap_chain)
        if not self.charm.state.is_non_main_orchestrator:
            self._update_security_config(event)

    def _on_ldap_certificate_removed(self, event: CertificateRemovedEvent) -> None:
        """Handle the removal of LDAP certificates."""
        if not self.charm.workload.can_connect:
            event.defer()
            return

        self.charm.workload.unlink(self.charm.workload.paths.ldap_chain)
        if not self.charm.state.is_non_main_orchestrator:
            self._update_security_config(event)

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Handle config-related changes to security config.

        Such scenario can happen if user changes LDAP related charm config fields
        during which the LDAP is connected.
        """
        if not self.charm.workload.can_connect:
            event.defer()
            return

        if not self.charm.state.is_non_main_orchestrator:
            self._update_security_config(event)

    def _update_security_config(self, event: EventBase) -> None:
        """Update & apply the security config."""
        self.charm.config_manager.update_security_config()

        if not self.charm.unit.is_leader():
            return

        if not (admin_secrets := self.charm.state.application.admin_secrets):
            event.defer()
            return

        if self.charm.upgrades_manager.in_progress:
            logger.warning(
                "Changing config during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
            event.defer()
            return

        if not self.charm.cluster_manager.workload.is_service_started():
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            event.defer()
            return

        try:
            self.charm.cluster_manager.apply_security_config(
                admin_secrets, self.charm.config_manager.SECURITY_CONFIG_YML
            )
        except OpenSearchCmdError as e:
            logger.debug(f"Error when updating the security index: {e.out}")
            event.defer()
            return
