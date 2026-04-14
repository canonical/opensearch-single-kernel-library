# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for events handler related to OpenSearch OAuth authentication configuration."""

import logging
from typing import TYPE_CHECKING

from ops import (
    EventBase,
    Object,
    RelationBrokenEvent,
    RelationCreatedEvent,
    RelationDepartedEvent,
)

from opensearch_single_kernel.common.constants import (
    OAUTH_CLIENT_AUDIENCE,
    OAUTH_CLIENT_GRANT_TYPES,
    OAUTH_CLIENT_REDIRECT_URI,
    OAUTH_CLIENT_SCOPE,
    OAUTH_RELATION,
)
from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.core.models import DeploymentType
from opensearch_single_kernel.lib.charms.hydra.v0.oauth import (
    ClientConfig,
    OAuthRequirer,
)

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class OAuthEventsHandler(Object):
    """Handler for managing oauth relations."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, "oauth")
        self.charm = charm

        # NOTE: Placeholder config options, not really needed by Opensearch
        client_config = ClientConfig(
            audience=OAUTH_CLIENT_AUDIENCE,
            redirect_uri=OAUTH_CLIENT_REDIRECT_URI,
            scope=OAUTH_CLIENT_SCOPE,
            grant_types=OAUTH_CLIENT_GRANT_TYPES,
        )
        self.oauth = OAuthRequirer(self.charm, client_config, relation_name=OAUTH_RELATION)
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_created,
            self._on_oauth_relation_created,
        )
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_changed,
            self._on_oauth_relation_changed,
        )
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_departed,
            self._on_oauth_relation_departed,
        )
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_broken,
            self._on_oauth_relation_broken,
        )

    def _on_oauth_relation_created(self, event: RelationCreatedEvent) -> None:
        """Handler for `relation_created` event."""
        if (
            deployment_desc := self.charm.state.application.deployment_desc
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            # in large deployments, OAuth config must only be handled by the main orchestrator
            # this is a safeguard to avoid different sources for applying security configuration
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.OAUTH_RELATION_INVALID, app=True)

    def _on_oauth_relation_changed(self, event: EventBase) -> None:
        """Handler for `_on_oauth_relation_changed` event.

        Updates the security config.yml with the OIDC info and update the cluster.
        """
        if (
            deployment_desc := self.charm.state.application.deployment_desc
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            # in large deployments, OAuth config must only be handled by the main orchestrator
            # this is a safeguard to avoid different sources for applying security configuration
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.OAUTH_RELATION_INVALID, app=True)
            return

        if not (relation := self.charm.state.oauth_relation):
            return

        if not relation.data[relation.app]:
            logger.debug("Oauth relation not yet set up")
            return

        if not self.charm.state.application.is_security_index_initialised:
            logger.debug("Deferring oauth relation changed event as cluster is not ready yet")
            event.defer()
            return

        self.charm.state.server.oauth_openid_connect_url = (
            f"{relation.data[relation.app].get('issuer_url')}/.well-known/openid-configuration"
        )
        self.charm.config_manager.update_security_config()

        if not self.charm.unit.is_leader():
            return

        if not (admin_secrets := self.charm.state.application.admin_secrets):
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

    def _on_oauth_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Handler for `relation_departed` event."""
        if event.departing_unit == self.charm.unit and self.charm.state.peer_relation is not None:
            self.charm.state.server.oauth_departing = True

    def _on_oauth_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handler for `relation_broken` event."""
        if (
            deployment_desc := self.charm.state.application.deployment_desc
        ) and deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.clear(CharmStatuses.OAUTH_RELATION_INVALID, app=True)
            return

        if (
            self.charm.state.server.oauth_departing
            or not self.charm.state.application.is_security_index_initialised
        ):
            return

        self.charm.state.server.oauth_openid_connect_url = None
        self.charm.config_manager.update_security_config()

        if not self.charm.unit.is_leader():
            return

        if not (admin_secrets := self.charm.state.application.admin_secrets):
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
