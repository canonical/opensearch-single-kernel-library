# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for events handler related to OpenSearch JWT authentication configuration."""

import logging
from typing import TYPE_CHECKING

from dpcharmlibs.interfaces import (
    RequirerCommonModel,
    ResourceRequirerEventHandler,
)
from ops import (
    EventBase,
    Object,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationCreatedEvent,
)

from opensearch_single_kernel.common.constants import (
    JWT_CONFIG_RELATION,
    DeploymentType,
)
from opensearch_single_kernel.core.jwt import JWTAuthConfiguration

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class JWTEventsHandler(Object):
    """Handler for managing JWT relations."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, "jwt")
        self.charm = charm

        self.jwt_interface = ResourceRequirerEventHandler(
            self.charm,
            relation_name=JWT_CONFIG_RELATION,
            requests=[RequirerCommonModel(resource="jwt-configuration")],
            response_model=JWTAuthConfiguration,
        )
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
            deployment_desc := self.charm.state.application.deployment_description
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            # Only the main orchestrator applies JWT config.
            logger.warning("JWT relation created on non-main orchestrator.")

    def _on_jwt_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle the removal of the relation."""
        if (
            deployment_desc := self.charm.state.application.deployment_description
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            return

        self.charm.config_manager.update_security_config()

        self.apply_security_config_if_needed(event)

    def _on_jwt_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handle relation changes directly."""
        if not event.app:
            return

        parsed_config = self.charm.state.jwt

        if not parsed_config:
            logger.debug("No valid JWT configuration found in the databag yet.")
            return

        self._validate_and_apply_jwt_auth_config(event)

    def _validate_and_apply_jwt_auth_config(self, event: RelationChangedEvent) -> None:
        """Check the provided configuration and apply, if valid."""
        if (
            deployment_desc := self.charm.state.application.deployment_description
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            return

        if not self.charm.state.application.security_index_initialised:
            logger.debug("Deferring jwt event as security index not initialised yet")
            event.defer()
            return

        self.charm.config_manager.update_security_config()
        logger.info("Updated JWT authentication configuration")

        self.apply_security_config_if_needed(event)

    def apply_security_config_if_needed(self, event: EventBase) -> None:
        """Update Opensearch's security index after updating the JWT auth configuration."""
        if not self.charm.unit.is_leader():
            return

        if (
            not self.charm.state.application.admin_truststore_password
            or not self.charm.state.application.admin_keystore_password
        ):
            logger.debug("Admin truststore or keystore password is missing, deferring")
            event.defer()
            return

        if not self.charm.cluster_manager.apply_security_config(
            self.charm.config_manager.SECURITY_CONFIG_YML
        ):
            # we need to come back in this case because there will not be a follow-up event
            event.defer()
            return
        logger.info("Updated Opensearch security index")
