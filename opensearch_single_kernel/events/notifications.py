# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP integration for the OpenSearch charm.

NotificationsEvents: handles the smtp-integrator relation (credentials available,
  relation broken, secret changed). Validates SMTP parameters, creates/updates
  OpenSearch notification configs and keystore entries, and cleans up on
  relation break.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from ops.charm import RelationBrokenEvent, SecretChangedEvent
from ops.framework import Object

from opensearch_single_kernel.common.constants import (
    SMTP_SECRET_LABEL,
    DeploymentType,
    Scope,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchSmtpMissingParametersError,
)
from opensearch_single_kernel.common.statuses import (
    NotificationsStatuses,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    SecretError,
)
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import (
    DEFAULT_RELATION_NAME as SMTP_RELATION,
)
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import (
    SmtpDataAvailableEvent,
)
from opensearch_single_kernel.utils.helpers import decode_plugin_secret_content

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class NotificationsEvents(Object):
    """Events handler for smtp events"""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "notifications_events")
        self.charm = charm

        self.framework.observe(
            self.charm.state.smtp_requires.on.smtp_data_available,
            self._on_smtp_credentials_changed,
        )
        self.framework.observe(
            self.charm.on[SMTP_RELATION].relation_broken,
            self._on_smtp_credentials_gone,
        )
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_smtp_credentials_changed(self, event: SmtpDataAvailableEvent) -> None:  # noqa: C901
        """Configure notifications sender/group/channel and keystore creds for this relation.

        Args:
            event: Smtp credentials available event
        """
        is_leader = self.charm.unit.is_leader()
        smtp_data = None
        if not (deployment_desc := self.charm.state.application.deployment_desc):
            logger.debug("Deployment not ready. Deferring event.")
            event.defer()
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if is_leader:
                self.charm.state.add_status_if_not_present(
                    NotificationsStatuses.SMTP_RELATION_INVALID.value,
                    "app",
                    self.charm.notifications_manager.name,
                )
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            logger.debug("OpenSearch is not ready yet. Deferring event.")
            event.defer()
            return

        try:
            smtp_data = self.charm.state.smtp_requires.get_relation_data_from_relation(
                event.relation
            )
        except SecretError as e:
            logger.error(f"Could not read smtp relation data: {e}")
            if is_leader:
                self.charm.state.add_status_if_not_present(
                    NotificationsStatuses.SMTP_COULD_NOT_READ_DATA.value,
                    "app",
                    self.charm.notifications_manager.name,
                    {"id": event.relation.id, "exc": str(e)},
                    {"id": event.relation.id},
                )
                return

        if is_leader:
            self.charm.state.remove_status_if_present(
                NotificationsStatuses.SMTP_COULD_NOT_READ_DATA.value,
                "app",
                self.charm.notifications_manager.name,
                interpolated=True,
                search_parameters={"id": event.relation.id},
            )

        if not smtp_data:
            if is_leader:
                self.charm.state.add_status_if_not_present(
                    NotificationsStatuses.SMTP_NO_RELATION_DATA.value,
                    "app",
                    self.charm.notifications_manager.name,
                    {"id": event.relation.id},
                    {"id": event.relation.id},
                )
            return
        if is_leader:
            self.charm.state.remove_status_if_present(
                NotificationsStatuses.SMTP_NO_RELATION_DATA.value,
                "app",
                self.charm.notifications_manager.name,
                interpolated=True,
                search_parameters={"id": event.relation.id},
            )

        try:
            config = self.charm.notifications_manager.get_smtp_config(smtp_data, event.relation.id)
        except OpenSearchSmtpMissingParametersError as e:
            if self.charm.unit.is_leader():
                self.charm.state.add_status_if_not_present(
                    NotificationsStatuses.SMTP_MISSING_REQUIRED_PARAMETERS.value,
                    "app",
                    self.charm.notifications_manager.name,
                    {"id": event.relation.id, "params": ", ".join(e.missing_parameters)},
                    {"id": event.relation.id},
                )
            return

        if self.charm.unit.is_leader():
            self.charm.state.remove_status_if_present(
                NotificationsStatuses.SMTP_MISSING_REQUIRED_PARAMETERS.value,
                "app",
                self.charm.notifications_manager.name,
                interpolated=True,
                search_parameters={"id": event.relation.id},
            )

        # create/update SMTP sender config (config_id is relation-based)
        if self.charm.unit.is_leader():
            try:
                self.charm.notifications_manager.put_smtp_sender(
                    smtp_account_id=config.smtp_account_id,
                    host=smtp_data.host,
                    port=smtp_data.port,
                    transport_security=config.transport_security,
                    from_address=config.sender_email,
                )
            except OpenSearchHttpError as e:
                logger.error(
                    "Failed to create SMTP sender with smtp_account_id: %s with Error: %s",
                    config.smtp_account_id,
                    str(e),
                )
                self.charm.state.add_status_if_not_present(
                    NotificationsStatuses.SMTP_CONFIGURATION_ERROR.value,
                    "app",
                    self.charm.notifications_manager.name,
                    dynamic_params={"id": event.relation.id},
                )
                event.defer()
                return

            self.charm.state.remove_status_if_present(
                NotificationsStatuses.SMTP_CONFIGURATION_ERROR.value,
                "app",
                self.charm.notifications_manager.name,
                interpolated=True,
                search_parameters={"id": event.relation.id},
            )

        if smtp_data.auth_type != "none":
            # store keystore creds on every unit
            credentials = self.charm.keystore_manager.put_notifications_plugin_smtp_credentials(
                config.smtp_account_id, smtp_data.user, smtp_data.password
            )

            # reload secure settings
            self.charm.reload_keystore_event.emit()
            # store cleanup info per relation
            self.charm.plugin_manager.put_notifications_plugin_smtp_config(
                config, credentials, self.charm.unit.is_leader(), SMTP_RELATION
            )
        else:
            # No keystore entries for auth_type "none", still store smtp_account_id for cleanup
            self.charm.plugin_manager.put_plugin_config(
                scope=Scope.UNIT,
                label=config.label,
                cleanup={"smtp_account_id": [config.smtp_account_id]},
            )

        if not self.charm.unit.is_leader():
            return
        # create recipient group and email channel if recipients are provided
        if smtp_data.recipients:
            self.charm.state.remove_status_if_present(
                NotificationsStatuses.SMTP_WAITING_RECIPIENTS.value,
                "app",
                self.charm.notifications_manager.name,
                interpolated=True,
                search_parameters={"id": event.relation.id},
            )

            try:
                self.charm.notifications_manager.put_email_group(
                    group_id=config.group_id,
                    recipients=[str(r) for r in smtp_data.recipients],
                )
                self.charm.notifications_manager.put_email_channel(
                    channel_id=config.channel_id,
                    smtp_account_id=config.smtp_account_id,
                    email_group_ids=[config.group_id],
                    fallback_recipients=[],
                )
            except OpenSearchHttpError as e:
                logger.error(
                    "Failed to create SMTP email channel with group: %s with Error: %s",
                    config.group_id,
                    str(e),
                )
                self.charm.state.add_status_if_not_present(
                    NotificationsStatuses.SMTP_CONFIGURATION_ERROR.value,
                    "app",
                    self.charm.notifications_manager.name,
                    dynamic_params={"id": event.relation.id},
                )
                event.defer()
                return
            self.charm.state.remove_status_if_present(
                NotificationsStatuses.SMTP_CONFIGURATION_ERROR.value,
                "app",
                self.charm.notifications_manager.name,
                interpolated=True,
                search_parameters={"id": event.relation.id},
            )
        else:
            self.charm.state.add_status_if_not_present(
                NotificationsStatuses.SMTP_WAITING_RECIPIENTS.value,
                "app",
                self.charm.notifications_manager.name,
                {"id": event.relation.id},
                {"id": event.relation.id},
            )

        # propagate to subclusters if this is the main provider
        if self.charm.state.is_peer_cluster_provider():
            if self.charm.peer_cluster_orchestrator_manager.refresh_relation_data():
                event.defer()

    def _on_smtp_credentials_gone(self, event: RelationBrokenEvent) -> None:  # noqa: C901
        """Cleanup for a broken smtp relation (relation-scoped).

        Args:
            event: RelationBrokenEvent
        """
        if self.charm.unit.is_leader():
            for status in NotificationsStatuses:
                if status is NotificationsStatuses.SMTP_RELATION_INVALID:
                    continue
                self.charm.state.remove_status_if_present(
                    status.value,
                    "app",
                    self.charm.notifications_manager.name,
                    interpolated=True,
                    search_parameters={"id": event.relation.id},
                )
            if not self.charm.state.smtp_relations:
                self.charm.state.remove_status_if_present(
                    NotificationsStatuses.SMTP_RELATION_INVALID.value,
                    "app",
                    self.charm.notifications_manager.name,
                )

        label = self.charm.notifications_manager.label(event.relation.id)
        plugin_config = self.charm.state.server.plugin_config_info.get(label)
        if not plugin_config:
            return
        cleanup = plugin_config.cleanup or {}
        # smtp_account_id is always stored per relation, keys only when auth is used
        # if no keys, smtp_account_id may still exist
        keys = list(cleanup.get("keys", []))
        smtp_account_ids = cleanup.get("smtp_account_id")
        smtp_account_id = smtp_account_ids[0] if smtp_account_ids else None

        # No smtp_account_id; nothing to clean in keystore or notifications
        if not smtp_account_id:
            self.charm.plugin_manager.remove_plugin_config(scope=Scope.UNIT, label=label)
            if self.charm.unit.is_leader():
                self.charm.plugin_manager.remove_plugin_secret(label)
                if self.charm.state.is_peer_cluster_provider():
                    if self.charm.peer_cluster_orchestrator_manager.refresh_relation_data():
                        event.defer()
            return

        # Delete notification configs first so we never have configs that reference
        # missing keystore credentials (channel -> group -> smtp account dependency order)
        if self.charm.unit.is_leader():
            channel_id = self.charm.notifications_manager.email_channel_id(smtp_account_id)
            group_id = self.charm.notifications_manager.recipient_group_id(smtp_account_id)
            for config_id in (channel_id, group_id, smtp_account_id):
                try:
                    self.charm.notifications_manager.opensearch_client.delete_notification_config(
                        config_id
                    )
                except OpenSearchHttpError:
                    logger.exception("Failed deleting notifications config %s", config_id)

        # Keystore cleanup after configs: keys may be absent when smtp_account_id exists
        if keys:
            self.charm.keystore_manager.remove_entries(keys)
            self.charm.reload_keystore_event.emit()

        self.charm.plugin_manager.remove_plugin_config(scope=Scope.UNIT, label=label)

        if not self.charm.unit.is_leader():
            return

        self.charm.plugin_manager.remove_plugin_secret(label)

        if self.charm.state.is_peer_cluster_provider():
            if self.charm.peer_cluster_orchestrator_manager.refresh_relation_data():
                event.defer()

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        """Handles smtp secrets changes (support multiple smtp relations).

        Args:
            event: SecretChangedEvent
        """
        label = event.secret.label

        if not label or SMTP_SECRET_LABEL not in label:
            return

        content = event.secret.get_content(refresh=True)

        if not (match := re.search(r"(plugin-notifications-\d+)", event.secret.label)):
            return
        label = match.group(1)

        if not (plugin_config := decode_plugin_secret_content(content, label)):
            return

        if not (keys := plugin_config.get("keys")):
            return

        smtp_account_id_list = plugin_config.get("smtp_account_id") or []
        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.UNIT,
            label=label,
            cleanup={
                "keys": list(keys.keys()),
                "smtp_account_id": smtp_account_id_list,
            },
        )

        self.charm.keystore_manager.put_entries(keys)
        self.charm.reload_keystore_event.emit()
