# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Notifications plugin API client (configs CRUD).

This client wraps OpenSearchDistribution.request() to manage notifications configs:
- smtp sender (config_type: smtp_account)
- email group (config_type: email_group)
- email channel (config_type: email)
"""

from __future__ import annotations

from collections.abc import Iterable

from opensearch_single_kernel.common.constants import (
    SMTP_SECRET_LABEL,
    SmtpTransportSecurity,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchSmtpMissingParametersError,
)
from opensearch_single_kernel.core.models import SmtpConfig
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.lib.charms.smtp_integrator.v0.smtp import SmtpRelationData
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.workload.base import BaseWorkload


class NotificationsManager(BaseManager):
    """Notifications plugin API client using OpenSearchDistribution request."""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        """Creates the notifications manager class."""
        super().__init__(state, workload)
        self.name = "notifications_manager"

    @staticmethod
    def label(relation_id: int) -> str:
        """Return label for this relation.

        Args:
            relation_id: relation id

        Returns:
            relation label
        """
        return f"{SMTP_SECRET_LABEL}-{relation_id}"

    @staticmethod
    def recipient_group_id(smtp_account_id: str) -> str:
        """Return recipient group id for this relation.

        The group ids use the relation base (e.g. smtp-88).
        Removes _smtp-account suffix, if present.

        Args:
            smtp_account_id: smtp account config id (e.g. smtp-88_smtp-account)

        Returns:
            recipient group id (e.g. smtp-88_recipients)
        """
        base = smtp_account_id.removesuffix("_smtp-account") or smtp_account_id
        return f"{base}_recipients"

    @staticmethod
    def email_channel_id(smtp_account_id: str) -> str:
        """Return email channel id for this relation.

        The channel ids use the relation base (e.g. smtp-88).
        Strips _smtp-account suffix, if present.

        Args:
            smtp_account_id: smtp account config id (e.g. smtp-88_smtp-account)

        Returns:
            email channel id (e.g. smtp-88_email-channel)
        """
        base = smtp_account_id.removesuffix("_smtp-account") or smtp_account_id
        return f"{base}_email-channel"

    @staticmethod
    def smtp_account_id_from_relation(relation_id: int) -> str:
        """Return smtp account config id for this relation.

        Config identity is relation-based with smtp-account suffix, e.g. smtp-88_smtp-account.

        Args:
            relation_id: Juju relation id

        Returns:
            smtp account config id
        """
        return f"smtp-{relation_id}_smtp-account"

    def get_smtp_config(self, smtp_data: SmtpRelationData, relation_id: int) -> SmtpConfig:
        """Derive SMTP-related config IDs and normalized values from relation data.

        Args:
            parameters: SMTP relation data from the smtp-integrator.
            relation_id: ID of the relation.

        Returns:
            SmtpConfig with sender_email, smtp_account_id, label, group_id,
            channel_id, and transport_security.
        """
        missing = []
        if not smtp_data.smtp_sender:
            missing.append("smtp_sender")
        if not smtp_data.host:
            missing.append("host")
        if not smtp_data.port:
            missing.append("port")
        if not smtp_data.transport_security:
            missing.append("transport_security")
        if smtp_data.auth_type != "none":
            if not smtp_data.user:
                missing.append("user")
            if not smtp_data.password:
                missing.append("password")
        if missing:
            raise OpenSearchSmtpMissingParametersError(missing)

        sender_email = str(smtp_data.smtp_sender)
        smtp_account_id = self.smtp_account_id_from_relation(relation_id)
        label = self.label(relation_id)
        group_id = self.recipient_group_id(smtp_account_id)
        channel_id = self.email_channel_id(smtp_account_id)
        ts = smtp_data.transport_security
        raw_ts = ts.value if hasattr(ts, "value") else ts
        transport_security = SmtpTransportSecurity(str(raw_ts).strip().lower())
        return SmtpConfig(
            sender_email=sender_email,
            smtp_account_id=smtp_account_id,
            label=label,
            group_id=group_id,
            channel_id=channel_id,
            transport_security=transport_security,
        )

    def put_smtp_sender(
        self,
        *,
        smtp_account_id: str,
        host: str,
        port: int,
        transport_security: SmtpTransportSecurity,
        from_address: str,
        description: str = "",
    ) -> None:
        """Put smtp account configuration.

        Args:
            smtp_account_id: the id of the smtp account config
            host: the smtp host
            port: the smtp port
            transport_security: security protocol to use for the outgoing SMTP relay
            from_address: the smtp address
            description: the smtp description
        """
        method = transport_security.api_method()
        config = {
            "name": smtp_account_id,
            "description": description or f"SMTP sender: ({smtp_account_id})",
            "config_type": "smtp_account",
            "smtp_account": {
                "host": host,
                "port": int(port),
                "method": method,
                "from_address": from_address,
            },
        }
        self.opensearch_client.create_or_update_notification_config(
            config_id=smtp_account_id, name=smtp_account_id, config=config
        )

    def put_email_group(
        self,
        *,
        group_id: str,
        recipients: Iterable[str],
        description: str = "",
    ) -> None:
        """Put email group configuration.

        Args:
            group_id: the id of the email group
            recipients: the email recipients
            description: the email description
        """
        config = {
            "name": group_id,
            "description": description or f"Email group managed by ({group_id})",
            "config_type": "email_group",
            "email_group": {
                "recipient_list": [{"recipient": r} for r in recipients],
            },
        }
        self.opensearch_client.create_or_update_notification_config(
            config_id=group_id, name=group_id, config=config
        )

    def put_email_channel(
        self,
        *,
        channel_id: str,
        smtp_account_id: str,
        email_group_ids: list[str],
        fallback_recipients: Iterable[str] | None = None,
        description: str = "",
    ) -> None:
        """Put email channel configuration.

        Args:
            channel_id: the id of the email channel
            smtp_account_id: the id of the smtp account config (email_account_id in API)
            email_group_ids: the email group ids
            fallback_recipients: the email recipients
            description: the email description
        """
        config = {
            "name": channel_id,
            "description": description or f"Email channel: ({channel_id})",
            "config_type": "email",
            "email": {
                "email_account_id": smtp_account_id,
                "recipient_list": [{"recipient": r} for r in (fallback_recipients or [])],
                "email_group_id_list": list(email_group_ids),
            },
        }
        self.opensearch_client.create_or_update_notification_config(
            config_id=channel_id, name=channel_id, config=config
        )
