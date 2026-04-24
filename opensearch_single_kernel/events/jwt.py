# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for events handler related to OpenSearch JWT authentication configuration."""

import logging
from typing import TYPE_CHECKING

from ops import (
    EventBase,
    Object,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationCreatedEvent,
    SecretChangedEvent,
)
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import (
    JWT_CONFIG_RELATION,
)
from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.common.statuses import JwtStatuses
from opensearch_single_kernel.core.models import DeploymentType

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class JWTEventsHandler(Object):
    """Handler for managing JWT relations."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, "jwt")
        self.charm = charm

        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)
        self.framework.observe(
            self.charm.on[JWT_CONFIG_RELATION].relation_created,
            self._on_jwt_relation_created,
        )
        self.framework.observe(
            self.charm.on[JWT_CONFIG_RELATION].relation_changed,
            self._on_jwt_relation_changed,
        )
        self.framework.observe(
            self.charm.on[JWT_CONFIG_RELATION].relation_broken,
            self._on_jwt_relation_broken,
        )

    def _on_jwt_relation_created(self, _: RelationCreatedEvent) -> None:
        """Handle relation creation."""
        if (
            deployment_desc := self.charm.state.application.deployment_desc
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            # in large deployments, JWT configuration must only be handled by the main orchestrator
            # this is a safeguard to avoid different sources for applying security configuration
            if self.charm.unit.is_leader():
                self.charm.state.add_status_if_not_present(
                    JwtStatuses.JWT_RELATION_INVALID.value,
                    "app",
                    self.charm.cluster_manager.name,
                )

    def _on_jwt_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handle changed relation data."""
        if not self.charm.state.jwt.relation:
            logger.error(f"Cannot access relation data for {JWT_CONFIG_RELATION}")
            return

        self._validate_and_apply_jwt_auth_config(event)

    def _on_jwt_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle the removal of the relation."""
        if (
            deployment_desc := self.charm.state.application.deployment_desc
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.state.remove_status_if_present(
                    JwtStatuses.JWT_RELATION_INVALID.value,
                    "app",
                    self.charm.cluster_manager.name,
                )
                self.charm.state.remove_status_if_present(
                    JwtStatuses.JWT_AUTH_CONFIG_INVALID.value,
                    "app",
                    self.charm.cluster_manager.name,
                )
            return

        del self.charm.state.server.jwt_auth_configuration
        self.charm.config_manager.update_security_config()

        self.apply_security_config_if_needed(event)

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        """Handle changed secret data."""
        if not self.charm.state.jwt.relation:
            return

        if not self.charm.state.jwt.is_related_secret_label(event.secret.label):
            logger.debug("Updated secret not relevant")
            return

        self._validate_and_apply_jwt_auth_config(event)

    def _validate_and_apply_jwt_auth_config(self, event: EventBase) -> None:
        """Check the provided configuration and apply, if valid."""
        if (
            deployment_desc := self.charm.state.application.deployment_desc
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.state.add_status_if_not_present(
                    JwtStatuses.JWT_RELATION_INVALID.value,
                    "app",
                    self.charm.cluster_manager.name,
                )
                self.charm.state.remove_status_if_present(
                    JwtStatuses.JWT_AUTH_CONFIG_INVALID.value,
                    "app",
                    self.charm.cluster_manager.name,
                )
            return

        if not self.charm.state.application.is_security_index_initialised:
            logger.debug("Deferring jwt event as security index not initialised yet")
            event.defer()
            return

        try:
            self.charm.state.server.jwt_auth_configuration = (
                self.charm.state.jwt.auth_configuration
            )
        except ValidationError as e:
            # safety mechanism, this should not happen; config is validated on the jwt-integrator
            logger.error(f"Validation failed for JWT authentication config: {e}")
            if self.charm.unit.is_leader():
                self.charm.state.add_status_if_not_present(
                    JwtStatuses.JWT_AUTH_CONFIG_INVALID.value,
                    "app",
                    self.charm.cluster_manager.name,
                )
            return

        if self.charm.unit.is_leader():
            self.charm.state.remove_status_if_present(
                JwtStatuses.JWT_AUTH_CONFIG_INVALID.value,
                "app",
                self.charm.cluster_manager.name,
            )

        self.charm.config_manager.update_security_config()
        logger.info("Updated JWT authentication configuration")

        self.apply_security_config_if_needed(event)

    def apply_security_config_if_needed(self, event: EventBase) -> None:
        """Update Opensearch's security index after updating the JWT auth configuration."""
        if not self.charm.unit.is_leader():
            return

        if not (admin_secrets := self.charm.state.application.admin_secrets):
            event.defer()
            return

        try:
            self.charm.cluster_manager.apply_security_config(
                admin_secrets, self.charm.config_manager.SECURITY_CONFIG_YML
            )
            logger.info("Updated Opensearch security index")
        except OpenSearchCmdError as e:
            logger.debug(f"Error when updating the security index: {e.out}")
            # we need to come back in this case because there will not be a follow-up event
            event.defer()
            return
