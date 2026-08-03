#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Models for the opensearch-peers relation (unit databags)."""

import logging
from typing import ClassVar, Optional

from pydantic import Field, field_serializer, field_validator

from opensearch_single_kernel.common.constants import PerformanceType
from opensearch_single_kernel.core.models.peer_secrets import (
    OpenSearchServerPeerHttpSecretsModel,
    OpenSearchServerPeerTransportSecretsModel,
)
from opensearch_single_kernel.core.models.plain_base import (
    PluginConfigInfo,
    _sort_nested_dicts,
)
from opensearch_single_kernel.core.models.profiles import (
    OpenSearchProfile,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.core.models.relation_base import RelationModel
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    PeerModel,
)

logger = logging.getLogger(__name__)


class OpenSearchServerPeerModel(RelationModel, PeerModel):
    """Peer model mapping to the OpenSearch unit state."""

    # Transparent proxying of secret-group fields (see RelationModel._secret_group_fields):
    # reading/writing e.g. `server.transport_key` delegates to the dedicated sibling secret model,
    # so callers never need to build the secret models themselves.
    _secret_group_fields: ClassVar[dict[str, type]] = {
        **dict.fromkeys(
            OpenSearchServerPeerTransportSecretsModel.__pydantic_fields__,
            OpenSearchServerPeerTransportSecretsModel,
        ),
        **dict.fromkeys(
            OpenSearchServerPeerHttpSecretsModel.__pydantic_fields__,
            OpenSearchServerPeerHttpSecretsModel,
        ),
    }

    # Performance profile ("testing"/"production") applied to this unit's JVM/OpenSearch config.
    # None means "not yet set" callers fall back to the profile configured via charm config.
    # Stored under the databag key "profile"; the `opensearch_profile` property below exposes the
    # value as a resolved OpenSearchProfile instance.
    profile: Optional[PerformanceType] = Field(default=None, alias="profile")
    # Whether this unit was one of the initial seed nodes used to bootstrap the cluster.
    # Alias pinned to the underscored key deployed databags use (the PeerModel alias
    # generator would otherwise hyphenate it).
    bootstrap_contributor: bool = Field(default=False, alias="bootstrap_contributor")
    # Whether this unit has been removed from the cluster_manager-eligible role (e.g. scale-down).
    cluster_manager_removed: bool = Field(default=False, alias="cluster_manager_removed")
    # Timestamp (str(time.time())) set once the unit's OpenSearch service has started; unset
    # means "not started". Used elsewhere as a truthy started/not-started flag.
    started: Optional[str] = Field(default=None)
    # Whether this unit is currently mid CA-rotation (new CA generated but not yet fully rolled).
    tls_ca_renewing: bool = Field(default=False, alias="tls_ca_renewing")
    # Whether this unit has finished renewing to the new CA.
    tls_ca_renewed: bool = Field(default=False, alias="tls_ca_renewed")
    # Whether this unit's TLS certificates (transport/HTTP) are fully configured.
    tls_configured: bool = Field(default=False, alias="tls_configured")
    # Last time this unit's databag was updated; used to force relation-changed observers to
    # notice a change even when no other field differs.
    update_ts: str = Field(default="")
    # Timestamp of the last time this unit checked its certificates for upcoming expiry.
    certs_exp_checked_at: str = Field(default="1970-01-01 00:00:00", alias="certs_exp_checked_at")
    # Allocation-exclusion entries (node names/IDs) this unit still needs to remove from the
    # cluster's shard allocation exclusion settings.
    allocation_exclusions_to_delete: set[str] = Field(default_factory=set)
    # Voting-exclusion entries this unit still needs to remove from the cluster's voting config.
    delete_voting_exclusions: set[str] = Field(default_factory=set)
    # Last known IP address of this unit; used to detect IP changes across reconciliation.
    last_host_ip: str = Field(default="", alias="last_host_ip")
    # Plugin configuration/cleanup metadata this unit is responsible for, keyed by plugin label.
    plugin_config_info: dict[str, PluginConfigInfo] = Field(
        default_factory=dict, alias="plugin_config_info"
    )
    # OAuth OpenID Connect URL configured on this unit (if an oauth relation is active).
    oauth_openid_connect_url: str = Field(default="", alias="oauth_openid_connect_url")
    # Set when this specific unit is departing/scaling down (as opposed to a related app or an
    # external relation being removed). Used to skip relation-broken side effects triggered by
    # the unit's own removal.
    unit_dying: bool = Field(default=False)
    # PID of this unit's running pebble-observer subprocess, or None if not started/stopped.
    pebble_observer_pid: Optional[int] = Field(default=None)

    @field_serializer("plugin_config_info")
    def _sort_plugin_config_info(self, value: dict) -> dict:
        """Sort nested dicts so serialized databag output is stable and order-independent."""
        return _sort_nested_dicts(value)

    @field_validator("allocation_exclusions_to_delete", "delete_voting_exclusions", mode="before")
    @classmethod
    def parse_comma_separated_strings(cls, v):
        """Parse the comma-separated databag string into a list, dropping empty entries."""
        if isinstance(v, str):
            return list(filter(None, v.split(",")))
        return v

    @field_serializer("allocation_exclusions_to_delete", "delete_voting_exclusions")
    def serialize_comma_separated_strings(self, v: set[str]) -> str:
        """Serialize the set to a sorted, comma-separated string for stable databag output."""
        return ",".join(sorted(v))

    @field_validator("started", mode="before")
    @classmethod
    def coerce_to_str(cls, v):
        """Ensure non-None values are always strings, even if the databag returns a float/int."""
        if v is None:
            return None
        return str(v)

    @field_validator("update_ts", mode="before")
    @classmethod
    def coerce_update_ts_to_str(cls, v):
        """Ensure update_ts is always a string, even if the databag returns a float/int."""
        if v is None:
            return ""
        return str(v)

    @property
    def opensearch_profile(self) -> Optional[OpenSearchProfile]:
        """Current profile of the unit, as an OpenSearchProfile instance."""
        if not self.profile:
            return None
        return (
            ProductionProfile() if self.profile == PerformanceType.PRODUCTION else TestingProfile()
        )

    @opensearch_profile.setter
    def opensearch_profile(self, value: OpenSearchProfile) -> None:
        """Set current profile of the unit from an OpenSearchProfile instance."""
        self.profile = value.type

    @property
    def is_app_leader(self) -> bool:
        """Check if the unit this model is bound to is the leader of the application."""
        return self.component.is_leader() if self.component is not None else False

    @property
    def unit_id(self) -> int:
        """The id of the unit this model is bound to, from its unit name."""
        return int(self.component.name.split("/")[1])

    @property
    def unit(self):
        """The ops.Unit this model is bound to (alias of `component`)."""
        return self.component

    def initialize_empty_secrets(self) -> None:
        """Initialize empty unit-level secrets to prevent log spam."""
        # Use truthy placeholders only for fields whose secrets don't exist yet
        if transport_m := self.sibling_model(OpenSearchServerPeerTransportSecretsModel):
            if not transport_m.transport_key_password:
                transport_m.transport_key_password = " "
        if http_m := self.sibling_model(OpenSearchServerPeerHttpSecretsModel):
            if not http_m.http_key_password:
                http_m.http_key_password = " "
