#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for external client relation."""

import logging

from ops.model import Application, Relation
from pydantic import ValidationError

from opensearch_single_kernel.core.models import (
    ExternalClientEntityPermissions,
    ExternalClientRequestedEntity,
)
from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    Data,
)

logger = logging.getLogger(__name__)


class ExternalOpenSearchClient(RelationState):
    """State collection for a single related external opensearch client."""

    relation: Relation

    def __init__(
        self,
        relation: Relation,
        data_interface: Data,
        component: Application,
        relation_name: str,
    ):
        super().__init__(relation, data_interface, component)
        self.app = component
        self.relation_name = relation_name

    @property
    def relation_username(self) -> str:
        """Get the relation username key for this relation."""
        return f"{self.relation_name}_{self.relation.id}"

    @property
    def version(self) -> str:
        """Get the OpenSearch version of the related client from relation databag."""
        return self.relation_data.get("version", "")

    @version.setter
    def version(self, version: str) -> None:
        """Set the OpenSearch version of the related client in relation databag."""
        self.update({"version": version})

    @property
    def username(self) -> str:
        """Get the username for this relation."""
        return self.relation_data.get("username", "")

    @username.setter
    def username(self, username: str) -> None:
        """Set the username for this relation."""
        self.update({"username": username})

    @property
    def password(self) -> str:
        """Get the password for this relation."""
        return self.relation_data.get("password", "")

    @password.setter
    def password(self, password: str) -> None:
        """Set the password for this relation."""
        self.update({"password": password})

    @property
    def index(self) -> str:
        """Get the index this relation is using from relation databag."""
        return self.relation_data.get("index", "")

    @index.setter
    def index(self, index: str) -> None:
        """Set the index this relation is using in relation databag."""
        self.update({"index": index})

    @property
    def tls_ca(self) -> str:
        """Get the TLS CA for this relation."""
        return self.relation_data.get("tls-ca", "")

    @tls_ca.setter
    def tls_ca(self, tls_ca: str) -> None:
        """Set the TLS CA for this relation."""
        self.update({"tls-ca": tls_ca})

    @property
    def endpoints(self) -> set[str]:
        """Get the endpoints for this relation."""
        endpoints_str = self.relation_data.get("endpoints", "")
        return set(filter(None, endpoints_str.split(",")))

    @endpoints.setter
    def endpoints(self, endpoints: set[str]) -> None:
        """Set the endpoints for this relation."""
        # sort
        endpoints = sorted(endpoints)
        self.update({"endpoints": ",".join(endpoints)})

    @property
    def extra_user_roles(self) -> str:
        """Get the extra user roles for this relation."""
        return self.relation_data.get("extra-user-roles", "")

    @extra_user_roles.setter
    def extra_user_roles(self, roles: str) -> None:
        """Set the extra user roles for this relation."""
        self.update({"extra-user-roles": roles})

    @property
    def extra_group_roles(self) -> list[str]:
        """Get the extra group roles for this relation."""
        return [
            role.strip() for role in self.relation_data.get("extra-group-roles", "").split(",")
        ]

    @property
    def entity_type(self) -> str:
        """Get entity type of this relation."""
        return self.relation_data.get("entity-type", "")

    @property
    def entity_permissions(self) -> dict[str, list[dict[str, list[str]]]] | None:
        """Receive, validate and reformat entity permissions into OpenSearch role permissions.

        If request is invalid or absent the None is returned and error is logged.
        """
        if not (raw := self.relation_data.get("entity-permissions")):
            return None
        try:
            return ExternalClientEntityPermissions.model_validate_json(raw).to_role_permissions()
        except ValidationError as e:
            logger.error(
                "Invalid entity-permissions field in client relation %d: %s",
                self.relation.id,
                e,
            )
            return None

    @property
    def requested_entity_secret(self) -> str | None:
        """Get entity secret id for this relation."""
        return self.relation_data.get("requested-entity-secret")

    def get_requested_entity(self) -> ExternalClientRequestedEntity | None:
        """Retrieve and validate entity from requested entity secret using model.

        If content is invalid or absent the None is returned and error is logged.
        """
        if not (requested_entity := self.requested_entity_secret):
            logger.info(
                "No requested entities secret provided for GROUP requirer relation %d",
                self.relation.id,
            )
            return None
        requested_entity = requested_entity.split(":")
        if len(requested_entity) != 2:
            logger.error(
                "Invalid requested entities secret content for GROUP requirer relation %d",
                self.relation.id,
            )
            return None
        return ExternalClientRequestedEntity(
            username=requested_entity[0], password=requested_entity[1]
        )
