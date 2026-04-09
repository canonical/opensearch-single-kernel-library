#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for jwt relation."""

import logging

from ops import Model, Relation
from pydantic import ValidationError

from opensearch_single_kernel.core.models import JWTAuthConfiguration
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    DataContractV1,
    OpsRelationRepository,
    build_model,
)

logger = logging.getLogger(__name__)


class JwtState:
    """State for the JWT relation data."""

    def __init__(self, relation: Relation | None, model: Model):
        self.relation = relation
        self.model = model

    @property
    def auth_configuration(self) -> JWTAuthConfiguration | None:
        """Build a JWT auth configuration from the relation data."""
        relation = self.relation
        if not relation or not relation.app:
            return None
        repository = OpsRelationRepository(self.model, relation, component=relation.app)
        version = repository.get_field("version") or "v0"
        try:
            if version == "v0":
                parsed_config = build_model(repository, JWTAuthConfiguration)
            else:
                contract = build_model(repository, DataContractV1[JWTAuthConfiguration])
                if not contract.requests:
                    return None
                parsed_config = contract.requests[0]
            return parsed_config

        except ValidationError as e:
            logger.error(f"failed to validate jwt: {e}")
            return None
