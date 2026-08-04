#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP related models."""

from dataclasses import dataclass

from opensearch_single_kernel.common.constants import SmtpTransportSecurity


@dataclass(frozen=True)
class SmtpConfig:
    """SMTP-related config derived from relation data.

    Attributes:
        sender_email: From-address for the SMTP sender (relation smtp_sender).
        smtp_account_id: OpenSearch config id for the SMTP account (e.g. smtp-88_smtp-account).
        label: Plugin/config label for this relation (e.g. plugin-notifications-88).
        group_id: OpenSearch config id for the recipient group (e.g. smtp-88_recipients).
        channel_id: OpenSearch config id for the email channel (e.g. smtp-88_email-channel).
        transport_security: SMTP transport security (none, start_tls, tls).
    """

    sender_email: str
    smtp_account_id: str
    label: str
    group_id: str
    channel_id: str
    transport_security: SmtpTransportSecurity
