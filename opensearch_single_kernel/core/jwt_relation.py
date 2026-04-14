#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for jwt relation."""

from opensearch_single_kernel.core.models import JWTAuthConfiguration
from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    SecretGroup,
)


class JwtState(RelationState):
    """State for the JWT relation data."""

    def is_related_secret_label(self, label: str | None) -> bool:
        """Check whether provided secret label is related to this relation."""
        return (
            label
            == self.data_interface._generate_secret_label(
                relation.name, relation.id, SecretGroup("extra")
            )
            if label is not None
            and (relation := self.data_interface._relation_from_secret_label(label))
            else False
        )

    @property
    def auth_configuration(self) -> JWTAuthConfiguration:
        """Build a JWT auth configuration from the relation data.

        Might throw a validation exception.
        """
        return JWTAuthConfiguration(
            signing_key=self.relation_data.get("signing-key", ""),
            jwt_header=self.relation_data.get("jwt-header"),
            jwt_url_parameter=self.relation_data.get("jwt-url-parameter"),
            roles_key=self.relation_data.get("roles-key", ""),
            subject_key=self.relation_data.get("subject-key"),
            required_audience=self.relation_data.get("required-audience"),
            required_issuer=self.relation_data.get("required-issuer"),
            jwt_clock_skew_tolerance_seconds=self.relation_data.get(
                "jwt-clock-skew-tolerance-seconds"
            ),
        )
