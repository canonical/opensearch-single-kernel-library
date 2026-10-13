# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for events handler related to OpenSearch LDAP authentication configuration."""

import logging
from typing import TYPE_CHECKING

from charmlibs.interfaces.certificate_transfer import (
    CertificatesAvailableEvent,
    CertificatesRemovedEvent,
)
from ops import (
    ModelError,
    Object,
    SecretChangedEvent,
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
        super().__init__(charm, "ldap")
        self.charm = charm

        self.framework.observe(self.charm.state.ldap_requirer.on.ldap_ready, self._on_ldap_ready)
        self.framework.observe(
            self.charm.state.ldap_requirer.on.ldap_unavailable, self._on_ldap_unavailable
        )
        self.framework.observe(
            self.charm.state.ldap_certificate_transfer_requires.on.certificate_set_updated,
            self._on_ldap_certificate_available,
        )
        self.framework.observe(
            self.charm.state.ldap_certificate_transfer_requires.on.certificates_removed,
            self._on_ldap_certificate_removed,
        )
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_ldap_ready(self, event: LdapReadyEvent) -> None:
        """Handle the LDAP integration event."""
        self.charm.reconcile_security_config(event)

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        """Handle the rotation of the LDAP bind password.

        The provider rotates the password within the same secret, so the relation data does not
        change and the LDAP ready event is not emitted again.
        """
        if not self.charm.state.is_ldap_bind_password_secret(event.secret):
            return

        try:
            # The LDAP library reads the tracked revision: move to the latest one first.
            event.secret.get_content(refresh=True)
        except ModelError as e:
            logger.error("Cannot refresh LDAP bind password secret: %s", e)
            return

        self.charm.reconcile_security_config(event)

    def _on_ldap_unavailable(self, event: LdapUnavailableEvent) -> None:
        """Handle the removal of LDAP integration."""
        self.charm.reconcile_security_config(event)

    def _on_ldap_certificate_available(self, event: CertificatesAvailableEvent) -> None:
        """Handle the receiving of LDAP certificates."""
        if not self.charm.workload.can_connect:
            logger.debug("Workload connection failure. Deferring event.")
            event.defer()
            return

        if ca_certs := self.charm.state.ldap_certificates:
            logger.debug("Writing ldap certificates files")
            self.charm.workload.write_text(
                "\n".join(sorted(ca_certs)), self.charm.workload.paths.ldap_chain
            )
        else:
            # The provider withdrew its certificates while keeping the relation.
            logger.debug("Ldap certificates not published by provider. Removing stale files")
            self.charm.workload.unlink(self.charm.workload.paths.ldap_chain, missing_ok=True)

        self.charm.reconcile_security_config(event)

    def _on_ldap_certificate_removed(self, event: CertificatesRemovedEvent) -> None:
        """Handle the removal of LDAP certificates."""
        if self.charm.is_unit_going_away(event):
            # The relation only goes away for this unit, which still serves requests.
            logger.debug("Unit is going away. Keeping the LDAP certificates.")
            return

        if not self.charm.workload.can_connect:
            logger.debug("Workload connection failure. Deferring event.")
            event.defer()
            return

        logger.debug("Removing ldap certificates files")
        self.charm.workload.unlink(self.charm.workload.paths.ldap_chain, missing_ok=True)

        self.charm.reconcile_security_config(event)
