#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Secret-group sibling models for the opensearch-peers relation.

Each of these models splits a Juju secret group out of a plain peer model
(OpenSearchAppPeerModel / OpenSearchServerPeerModel) so that reading or writing a
plain field doesn't also resolve the secret group. The plain models wire these up
via `_secret_group_fields` (see RelationModel), so callers transparently read/write
e.g. `application.admin_ca_cert` without building the secret model themselves.
"""

from pydantic import Field

from opensearch_single_kernel.core.models.relation_base import (
    AdminSecretStr,
    HttpSecretStr,
    PluginsSecretStr,
    RelationModel,
    TransportSecretStr,
    UserSecretStr,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    PeerModel,
)


class OpenSearchAppPeerUserSecretsModel(RelationModel, PeerModel):
    """Peer model mapping to the OpenSearch application's internal-user credentials.

    Split out of OpenSearchAppPeerModel so that reading/writing a plain
    application field doesn't also resolve the Juju secret group.
    """

    admin_password: UserSecretStr = Field(default="")
    admin_hashed_password: UserSecretStr = Field(default="")
    kibana_server_password: UserSecretStr = Field(default="")
    kibana_server_hashed_password: UserSecretStr = Field(default="")
    cos_password: UserSecretStr = Field(default="")
    cos_hashed_password: UserSecretStr = Field(default="")


class OpenSearchAppPeerAdminTlsSecretsModel(RelationModel, PeerModel):
    """Peer model mapping to the OpenSearch application's admin-TLS secrets.

    Split out of OpenSearchAppPeerModel so that reading/writing a plain
    application field doesn't also resolve the Juju secret group.
    """

    admin_truststore_password: AdminSecretStr = Field(default="")
    admin_subject: AdminSecretStr = Field(default="")
    admin_keystore_password: AdminSecretStr = Field(default="")
    admin_key: AdminSecretStr = Field(default="")
    admin_key_password: AdminSecretStr = Field(default="")
    admin_csr: AdminSecretStr = Field(default="")
    admin_chain: AdminSecretStr = Field(default="")
    admin_cert: AdminSecretStr = Field(default="")
    admin_ca_cert: AdminSecretStr = Field(default="")


class OpenSearchAppPeerPluginSecretsModel(RelationModel, PeerModel):
    """Peer model mapping to the OpenSearch application's plugin secrets.

    Split out of OpenSearchAppPeerModel so that reading/writing a plain
    application field doesn't also resolve the Juju secret group.
    """

    plugin_secrets: PluginsSecretStr = Field(default="")


class OpenSearchServerPeerTransportSecretsModel(RelationModel, PeerModel):
    """Peer model mapping to the OpenSearch unit's transport-layer TLS secrets.

    Split out of OpenSearchServerPeerModel so that reading/writing a plain (non-secret)
    server field doesn't also resolve the "unit-transport" Juju secret group.
    """

    transport_key: TransportSecretStr = Field(default="")
    transport_key_password: TransportSecretStr = Field(default="")
    transport_csr: TransportSecretStr = Field(default="")
    transport_chain: TransportSecretStr = Field(default="")
    transport_cert: TransportSecretStr = Field(default="")
    transport_ca_cert: TransportSecretStr = Field(default="")
    transport_truststore_password: TransportSecretStr = Field(default="")
    transport_subject: TransportSecretStr = Field(default="")
    transport_keystore_password: TransportSecretStr = Field(default="")


class OpenSearchServerPeerHttpSecretsModel(RelationModel, PeerModel):
    """Peer model mapping to the OpenSearch unit's HTTP-layer TLS secrets.

    Split out of OpenSearchServerPeerModel so that reading/writing a plain (non-secret)
    server field doesn't also resolve the "unit-http" Juju secret group.
    """

    http_keystore_password: HttpSecretStr = Field(default="")
    http_key: HttpSecretStr = Field(default="")
    http_key_password: HttpSecretStr = Field(default="")
    http_csr: HttpSecretStr = Field(default="")
    http_chain: HttpSecretStr = Field(default="")
    http_cert: HttpSecretStr = Field(default="")
    http_ca_cert: HttpSecretStr = Field(default="")
    http_truststore_password: HttpSecretStr = Field(default="")
    http_subject: HttpSecretStr = Field(default="")
