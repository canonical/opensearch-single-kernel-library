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
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.common.statuses import CharmStatuses
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    SecretError,
)
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import (
    DEFAULT_RELATION_NAME as SMTP_RELATION,
)
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import (
    SmtpDataAvailableEvent,
    SmtpRequires,
)
from opensearch_single_kernel.managers.notification import NotificationsClientError
from opensearch_single_kernel.utils.helpers import decode_plugin_secret_content
from opensearch_single_kernel.utils.status import Status

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class NotificationsEvents(Object):
    """Events handler for smtp events"""

    relation_name = SMTP_RELATION

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "plugin:notifications")
        self.charm = charm
        self.smtp = SmtpRequires(self.charm, self.relation_name)

        self.framework.observe(self.smtp.on.smtp_data_available, self._on_smtp_credentials_changed)
        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken,
            self._on_smtp_credentials_gone,
        )
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_smtp_credentials_changed(self, event: SmtpDataAvailableEvent) -> None:  # noqa: C901
        """Configure notifications sender/group/channel and keystore creds for this relation.

        Args:
            event: Smtp credentials available event
        """
        parameters = None
        if not (deployment_desc := self.charm.state.application.deployment_desc):
            logger.debug("Deployment not ready. Deferring event.")
            event.defer()
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.SMTP_RELATION_INVALID, app=True)
            return

        if not self.charm.cluster_manager.opensearch_client.is_node_up():
            logger.debug("OpenSearch is not ready yet. Deferring event.")
            event.defer()
            return

        try:
            parameters = self.smtp.get_relation_data_from_relation(event.relation)
        except SecretError as exc:
            logger.error(f"Could not read smtp relation data: {exc}")
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    CharmStatuses.SMTP_COULD_NOT_READ_DATA,
                    app=True,
                    dynamic_params={"exc": str(exc)},
                )
                return

        if self.charm.unit.is_leader():
            self.charm.status.clear(
                CharmStatuses.SMTP_COULD_NOT_READ_DATA,
                app=True,
                pattern=Status.CheckPattern.Interpolated,
            )

        if not parameters:
            if self.charm.unit.is_leader():
                self.charm.status.set(CharmStatuses.SMTP_NO_RELATION_DATA, app=True)
            return
        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.SMTP_NO_RELATION_DATA, app=True)

        missing = []
        if not parameters.smtp_sender:
            missing.append("smtp_sender")
        if not parameters.host:
            missing.append("host")
        if not parameters.port:
            missing.append("port")
        if not parameters.transport_security:
            missing.append("transport_security")
        if parameters.auth_type != "none":
            if not parameters.user:
                missing.append("user")
            if not parameters.password:
                missing.append("password")

        if missing:
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    CharmStatuses.SMTP_MISSING_REQUIRED_PARAMETERS,
                    app=True,
                    dynamic_params={"params": ", ".join(missing)},
                )
                return

        if self.charm.unit.is_leader():
            self.charm.status.clear(
                CharmStatuses.SMTP_MISSING_REQUIRED_PARAMETERS,
                pattern=Status.CheckPattern.Interpolated,
                app=True,
            )

        config = self.charm.notifications_manager.get_smtp_config(parameters, event.relation.id)

        # create/update SMTP sender config (config_id is relation-based)
        if self.charm.unit.is_leader():
            try:
                self.charm.notifications_manager.put_smtp_sender(
                    smtp_account_id=config.smtp_account_id,
                    host=parameters.host,
                    port=parameters.port,
                    transport_security=config.transport_security,
                    from_address=config.sender_email,
                )
            except NotificationsClientError as e:
                logger.error(
                    "Failed to create SMTP sender with smtp_account_id: %s with Error: %s",
                    config.smtp_account_id,
                    str(e),
                )
                self.charm.status.set(
                    CharmStatuses.SMTP_CONFIGURATION_ERROR,
                    app=True,
                )
                event.defer()
                return

            self.charm.status.clear(CharmStatuses.SMTP_CONFIGURATION_ERROR, app=True)

        if parameters.auth_type != "none":
            # store keystore creds on every unit
            entries = {
                f"opensearch.notifications.core.email.{config.smtp_account_id}.username": parameters.user,
                f"opensearch.notifications.core.email.{config.smtp_account_id}.password": parameters.password,
            }
            self.charm.keystore_manager.put_entries(entries)

            # reload secure settings
            self.charm.reload_keystore_event.emit()
            # store cleanup info per relation
            cleanup = {
                "keys": list(entries.keys()),
                "smtp_account_id": [config.smtp_account_id],
            }
            self.charm.plugin_manager.put_plugin_config(
                scope=Scope.UNIT, label=config.label, cleanup=cleanup
            )

            if self.charm.unit.is_leader():
                # leader stores secret for subclusters for per relation
                self.charm.plugin_manager.store_plugin_secret(
                    content={
                        "keys": entries,
                        "smtp_account_id": cleanup["smtp_account_id"],
                    },
                    label=config.label,
                    relation_name=self.relation_name,
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
        if parameters.recipients:
            try:
                self.charm.notifications_manager.put_email_group(
                    group_id=config.group_id,
                    recipients=[str(r) for r in parameters.recipients],
                )
                self.charm.notifications_manager.put_email_channel(
                    channel_id=config.channel_id,
                    smtp_account_id=config.smtp_account_id,
                    email_group_ids=[config.group_id],
                    fallback_recipients=[],
                )
            except NotificationsClientError as e:
                logger.error(
                    "Failed to create SMTP email channel with group: %s with Error: %s",
                    config.group_id,
                    str(e),
                )
                self.charm.status.set(
                    CharmStatuses.SMTP_CONFIGURATION_ERROR,
                    app=True,
                )
                event.defer()
                return
            self.charm.status.clear(CharmStatuses.SMTP_WAITING_RECIPIENTS, app=True)
            self.charm.status.clear(CharmStatuses.SMTP_CONFIGURATION_ERROR, app=True)
        else:
            self.charm.status.set(CharmStatuses.SMTP_WAITING_RECIPIENTS, app=True)

        # propagate to subclusters if this is the main provider
        # if self.charm.opensearch_peer_cm.is_provider(typ="main"):
        #     self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_smtp_credentials_gone(self, event: RelationBrokenEvent) -> None:  # noqa: C901
        """Cleanup for a broken smtp relation (relation-scoped).

        Args:
            event: RelationBrokenEvent
        """
        if self.charm.unit.is_leader():
            self.charm.status.clear(CharmStatuses.SMTP_RELATION_INVALID, app=True)
            self.charm.status.clear(CharmStatuses.SMTP_CONFIGURATION_ERROR, app=True)
            self.charm.status.clear(CharmStatuses.SMTP_NO_RELATION_DATA, app=True)
            self.charm.status.clear(
                CharmStatuses.SMTP_MISSING_REQUIRED_PARAMETERS,
                pattern=Status.CheckPattern.Interpolated,
                app=True,
            )
            self.charm.status.clear(
                CharmStatuses.SMTP_COULD_NOT_READ_DATA,
                pattern=Status.CheckPattern.Interpolated,
                app=True,
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
                # if self.charm.opensearch_peer_cm.is_provider(typ="main"):
                #     self.charm.peer_cluster_provider.refresh_relation_data(event)
            return

        # Delete notification configs first so we never have configs that reference
        # missing keystore credentials (channel -> group -> smtp account dependency order)
        if self.charm.unit.is_leader():
            channel_id = self.charm.notifications_manager.email_channel_id(smtp_account_id)
            group_id = self.charm.notifications_manager.recipient_group_id(smtp_account_id)
            for config_id in (channel_id, group_id, smtp_account_id):
                try:
                    self.charm.notifications_manager.delete_config(config_id)
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

        # if self.charm.opensearch_peer_cm.is_provider(typ="main"):
        #     self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        """Handles secret changes (support multiple smtp relations).

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
