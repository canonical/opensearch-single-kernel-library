#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for peer cluster relation."""

import json
import logging
from typing import Any

from opensearch_single_kernel.core.models import (
    PeerClusterApp,
    PeerClusterRelData,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.core.secrets import OpenSearchSecrets

logger = logging.getLogger(__name__)


class PeerCluster(RelationState):
    """State collection metadata for a peer-cluster application."""

    def __init__(self, relation, data_interface, component, secrets: OpenSearchSecrets):
        super().__init__(relation, data_interface, component)
        self.app = component
        self.secrets = secrets

    @property
    def first_data_node(self) -> str:
        """Get the value of 'first_data_node' in application databag."""
        return self.relation.data[self.app].get("first_data_node", "")

    @first_data_node.setter
    def first_data_node(self, value: str):
        """Set the value of 'first_data_node' in application databag."""
        self.update({"first_data_node": value})

    @first_data_node.deleter
    def first_data_node(self):
        """Delete the 'first_data_node' field to notify related clusters."""
        self.update({"first_data_node": ""})

    @property
    def security_index_initialised(self) -> bool:
        """Return whether the security index has been initialised."""
        return self.relation.data[self.app].get("security_index_initialised", "") == "True"

    @security_index_initialised.setter
    def security_index_initialised(self, value: bool):
        """Set the security index initialised value."""
        self.update({"security_index_initialised": str(value)})

    @property
    def cluster_fleet_apps(self) -> dict[str, PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = json.loads(self.relation_data.get("cluster_fleet_apps", "{}")) or {}
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps.items()}

    @cluster_fleet_apps.setter
    def cluster_fleet_apps(self, cluster_fleet_apps: dict[str, PeerClusterApp]):
        """Set the cluster fleet applications."""
        self.put_object(
            "cluster_fleet_apps", {id: app.to_dict() for id, app in cluster_fleet_apps.items()}
        )

    def set_error_data(self, error_data: PeerClusterRelErrorData):
        """Set the error data."""
        self.update({"error_data": error_data.to_str()})

    def get_data(self, peek_secrets: bool = False) -> PeerClusterRelData:
        """Get the relation data as a PeerClusterRelData object."""
        content = self.relation.data[self.app].get("data", "{}")
        return PeerClusterRelData.peer_cluster_rel_data_from_str(
            self.secrets, content, peek_secrets=peek_secrets
        )

    @property
    def trigger(self) -> str:
        """Get the value of 'trigger' in application databag."""
        return self.relation.data[self.app].get("trigger", "")

    @trigger.setter
    def trigger(self, value: str):
        """Set the value of 'trigger' in application databag."""
        self.update({"trigger": value})

    @trigger.deleter
    def trigger(self):
        """Delete the trigger field to notify related clusters."""
        self.update({"trigger": ""})

    @property
    def orchestrators(self) -> dict[str, Any]:
        """Return the value of 'orchestrators' in application databag."""
        orchestrators_data = self.relation.data[self.app].get("orchestrators", "{}")
        return json.loads(orchestrators_data)

    @orchestrators.setter
    def orchestrators(self, orchestrators: dict[str, Any]):
        """Set the value of 'orchestrators' in application databag."""
        self.put_object("orchestrators", orchestrators)

    @property
    def main_orchestrator_registered(self) -> str:
        """Return the value of 'main_orchestrator_registered' in the databag."""
        return self.relation.data[self.app].get("main_orchestrator_registered", "")

    @main_orchestrator_registered.setter
    def main_orchestrator_registered(self, value: bool):
        """Set the value of 'main_orchestrator_registered' in the databag."""
        self.update({"main_orchestrator_registered": str(value).lower()})

    @main_orchestrator_registered.deleter
    def main_orchestrator_registered(self):
        """Delete the 'main_orchestrator_registered' field to notify related clusters."""
        if "main_orchestrator_registered" not in self.relation.data[self.app]:
            logger.debug("No main_orchestrator_registered field found to delete.")
            return
        self.update({"main_orchestrator_registered": ""})


class PeerClusterServer(RelationState):
    """State collection metadata for a peer-cluster unit."""

    def __init__(self, relation, data_interface, component):
        super().__init__(relation, data_interface, component)
        self.unit = component

    @property
    def tls_ca_renewing(self) -> bool:
        """Return value of 'tls_ca_renewing' from unit state"""
        return self.relation.data[self.unit].get("tls_ca_renewing", "") == "True"

    @tls_ca_renewing.setter
    def tls_ca_renewing(self, value: bool):
        """Update value of tls_ca_renewing from unit state."""
        self.update({"tls_ca_renewing": str(value)})

    @property
    def tls_ca_renewed(self) -> bool:
        """Get the value of 'tls_ca_renewed' from unit data bag"""
        return self.relation.data[self.unit].get("tls_ca_renewed", "") == "True"

    @tls_ca_renewed.setter
    def tls_ca_renewed(self, value: bool):
        """Update value of 'tls_ca_renewed'"""
        self.update({"tls_ca_renewed": str(value)})

    @property
    def tls_configured(self) -> bool:
        """Get the value of 'tls_configured' from unit data bag."""
        return self.relation.data[self.unit].get("tls_configured", "") == "True"

    @tls_configured.setter
    def tls_configured(self, value: bool):
        """Update the value of 'tls_configured'"""
        self.update({"tls_configured": str(value)})

    @property
    def credentials_saved(self) -> str:
        """Get the value of 'credentials_saved' from unit data bag."""
        return self.relation.data[self.unit].get("credentials_saved", "")

    @credentials_saved.setter
    def credentials_saved(self, value: bool):
        """Update the value of 'credentials_saved'"""
        self.update({"credentials_saved": str(value)})

    @credentials_saved.deleter
    def credentials_saved(self):
        """Delete the 'credentials_saved' field to notify related clusters."""
        if "credentials_saved" not in self.relation.data[self.unit]:
            logger.debug("No credentials_saved field found to delete.")
            return
        self.update({"credentials_saved": ""})
