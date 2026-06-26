#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for external client relation."""

from ops.model import Application, Relation

from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    Data,
)


class ExternalOpenSearchClient(RelationState):
    """State collection for a single related external opensearch client."""

    def __init__(
        self,
        relation: Relation | None,
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
