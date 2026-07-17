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
        """Handle relation creation.

        JWT statuses (invalid on non-main, invalid auth config) are pure-computed by
        ``ClusterManager.get_statuses``; no imperative status writes here.
        """
        if (
            deployment_desc := self.charm.state.application.deployment_desc
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            # Large deployments: only main should apply JWT security configuration.
            logger.warning(
                "JWT relation created on non-main orchestrator; status is derived purely."
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
            return

        del self.charm.state.server.jwt_auth_configuration
        self.charm.config_manager.update_security_config()

        self.apply_security_config_if_needed(event)

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        """Handle changed secret data."""
        if not self.charm.state.jwt.relation:
            return

        if not self.charm.state.jwt.is_jwt_secret(event.secret.label):
            logger.debug("Updated secret not relevant")
            return

        self._validate_and_apply_jwt_auth_config(event)

    def _validate_and_apply_jwt_auth_config(self, event: EventBase) -> None:
        """Check the provided configuration and apply, if valid."""
        if (
            deployment_desc := self.charm.state.application.deployment_desc
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            # Status computed by ClusterManager.get_statuses
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
            return

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

        if not self.charm.cluster_manager.apply_security_config(
            admin_secrets, self.charm.config_manager.SECURITY_CONFIG_YML
        ):
            # we need to come back in this case because there will not be a follow-up event
            event.defer()
            return
        logger.info("Updated Opensearch security index")
