#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for peer cluster relation."""

import json
import logging
from hashlib import sha1
from typing import Any

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_USER,
    KIBANA_SERVER_USER,
    CertType,
    Scope,
)
from opensearch_single_kernel.core.models import (
    PeerClusterApp,
    PeerClusterRelData,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.core.secrets import OpenSearchSecrets
from opensearch_single_kernel.utils.secrets import hash_key, password_key

logger = logging.getLogger(__name__)


class PeerCluster(RelationState):
    """State collection metadata for a peer-cluster application."""

    def __init__(self, relation, data_interface, component, secrets: OpenSearchSecrets):
        super().__init__(relation, data_interface, component)
        self.app = component
        self.secrets = secrets

    @property
    def is_candidate_failover_orchestrator(self) -> bool:
        """Return whether this cluster is a candidate failover orchestrator."""
        return (
            self.relation.data[self.app].get("is_candidate_failover_orchestrator", "").lower()
            == "true"
        )

    @is_candidate_failover_orchestrator.setter
    def is_candidate_failover_orchestrator(self, value: bool):
        """Set whether this cluster is a candidate failover orchestrator."""
        self.relation.data[self.app].update({"is_candidate_failover_orchestrator": str(value)})

    @is_candidate_failover_orchestrator.deleter
    def is_candidate_failover_orchestrator(self):
        """Delete the 'is_candidate_failover_orchestrator' field to notify related clusters."""
        self.relation.data[self.app].pop("is_candidate_failover_orchestrator", None)

    @property
    def first_data_node(self) -> str:
        """Get the value of 'first_data_node' in application databag."""
        return self.relation.data[self.app].get("first_data_node", "")

    @first_data_node.setter
    def first_data_node(self, value: str):
        """Set the value of 'first_data_node' in application databag."""
        self.relation.data[self.app].update({"first_data_node": value})

    @first_data_node.deleter
    def first_data_node(self):
        """Delete the 'first_data_node' field to notify related clusters."""
        self.relation.data[self.app].pop("first_data_node", None)

    @property
    def security_index_initialised(self) -> bool:
        """Return whether the security index has been initialised."""
        return self.relation.data[self.app].get("security_index_initialised", "").lower() == "true"

    @security_index_initialised.setter
    def security_index_initialised(self, value: bool):
        """Set the security index initialised value."""
        self.relation.data[self.app].update({"security_index_initialised": str(value)})

    @property
    def cluster_fleet_apps(self) -> dict[str, PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = json.loads(
            self.relation.data[self.app].get("cluster_fleet_apps", "{}")
        )
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps.items()}

    @cluster_fleet_apps.setter
    def cluster_fleet_apps(self, cluster_fleet_apps: dict[str, PeerClusterApp]):
        """Set the cluster fleet applications."""
        self.put_object(
            "cluster_fleet_apps", {id: app.to_dict() for id, app in cluster_fleet_apps.items()}
        )

    @cluster_fleet_apps.deleter
    def cluster_fleet_apps(self):
        """Delete the 'cluster_fleet_apps' field to notify related clusters."""
        self.relation.data[self.app].pop("cluster_fleet_apps", None)

    @property
    def error_data(self) -> PeerClusterRelErrorData | None:
        """Get the error data."""
        error_data_str = self.relation.data[self.app].get("error_data", "")
        return PeerClusterRelErrorData.from_str(error_data_str) if error_data_str else None

    @error_data.setter
    def error_data(self, error_data: PeerClusterRelErrorData):
        """Set the error data."""
        self.relation.data[self.app].update({"error_data": error_data.to_str()})

    @error_data.deleter
    def error_data(self):
        """Delete the 'error_data' field to notify related clusters."""
        self.relation.data[self.app].pop("error_data", None)

    def data(self, peek_secrets: bool = False) -> PeerClusterRelData | None:
        """Get the relation data as a PeerClusterRelData object."""
        if not (content := self.relation.data[self.app].get("data", None)):
            return None
        return PeerClusterRelData.peer_cluster_rel_data_from_str(
            self.secrets, content, peek_secrets=peek_secrets
        )

    def set_data(self, rel_data: PeerClusterRelData, is_provider: bool = True):
        """Set the relation data from a dict."""
        # replace the plaintext credentials in
        # rel_data with their corresponding secret IDs
        rel_data_redacted_dict = self._protect_secrets_relation_data(rel_data)
        logger.debug(
            "Setting peer cluster relation data with redacted secrets: %s", rel_data_redacted_dict
        )

        # grant the secrets inside the rel_data to all the related clusters
        self.secrets.grant_secrets_to_peer_clusters(
            rel_data_redacted_dict, is_provider=is_provider
        )
        # we add the hash of the rel_data to only emit a change event
        # if the data has actually changed
        self.relation.data[self.app].update(
            {
                "data": json.dumps(rel_data_redacted_dict),
            }
        )
        self.rel_data_hash = sha1(
            json.dumps(rel_data.to_dict(), sort_keys=True).encode()
        ).hexdigest()

    def delete_data(self):
        """Delete the field 'data' in the peer-cluster relation"""
        if "data" not in self.relation.data[self.app]:
            logger.debug("No 'data' field found to delete.")
            return

        self.relation.data[self.app].pop("data", None)

    @property
    def rel_data_hash(self) -> str:
        """Get the hash of the relation data."""
        return self.relation.data[self.app].get("rel_data_hash", "")

    @rel_data_hash.setter
    def rel_data_hash(self, value: str):
        """Set the hash of the relation data."""
        self.relation.data[self.app].update({"rel_data_hash": value})

    @rel_data_hash.deleter
    def rel_data_hash(self):
        """Delete the 'rel_data_hash' field to notify related clusters."""
        self.relation.data[self.app].pop("rel_data_hash", None)

    def _protect_secrets_relation_data(
        self, rel_data: PeerClusterRelData | None
    ) -> dict[str, Any] | None:
        """Replace the secrets' plain text content in the rel data by their IDs."""
        # hide the secrets and instead pass their ids so that
        # they can be fetched when needed in the requirer side
        # returns None if rel_data has not been successfully created
        if not rel_data:
            return None

        redacted_dict = rel_data.to_dict()

        redacted_dict["credentials"] = {
            "admin_username": ADMIN_USER,
            "admin_password": self.secrets.get_secret_id(Scope.APP, password_key(ADMIN_USER)),
            "admin_password_hash": self.secrets.get_secret_id(Scope.APP, hash_key(ADMIN_USER)),
            "kibana_password": self.secrets.get_secret_id(
                Scope.APP, password_key(KIBANA_SERVER_USER)
            ),
            "kibana_password_hash": self.secrets.get_secret_id(
                Scope.APP, hash_key(KIBANA_SERVER_USER)
            ),
        }

        if monitor_password := self.secrets.get_secret_id(Scope.APP, password_key(COS_USER)):
            redacted_dict["credentials"]["monitor_password"] = monitor_password
        if admin_tls := self.secrets.get_secret_id(Scope.APP, CertType.APP_ADMIN.val):
            redacted_dict["credentials"]["admin_tls"] = admin_tls

        if (
            rel_data.credentials.s3
            and rel_data.credentials.s3.access_key
            and rel_data.credentials.s3.secret_key
        ):
            # TODO Move this to s3 relation and include both in one secret
            redacted_dict["credentials"]["s3"] = {
                "access-key": self.secrets.get_secret_id(Scope.APP, "s3-access-key"),
                "secret-key": self.secrets.get_secret_id(Scope.APP, "s3-secret-key"),
            }

        if rel_data.credentials and getattr(rel_data.credentials.s3, "s3_tls_ca_chain", None):
            if sid := self.secrets.get_secret_id(Scope.APP, "s3-tls-ca-chain"):
                redacted_dict["credentials"]["s3"]["s3-tls-ca-chain"] = sid

        if (
            rel_data.credentials.azure
            and rel_data.credentials.azure.storage_account
            and rel_data.credentials.azure.secret_key
        ):
            # TODO Move this to azure relation and include both in one secret
            redacted_dict["credentials"]["azure"] = {
                "storage-account": self.secrets.get_secret_id(Scope.APP, "azure-storage-account"),
                "secret-key": self.secrets.get_secret_id(Scope.APP, "azure-secret-key"),
            }

        if rel_data.credentials.gcs and rel_data.credentials.gcs.secret_key:
            redacted_dict["credentials"]["gcs"] = {
                "secret-key": self.secrets.get_secret_id(Scope.APP, "gcs-secret-key"),
            }

        return redacted_dict

    @property
    def trigger(self) -> str:
        """Get the value of 'trigger' in application databag."""
        return self.relation.data[self.app].get("trigger", "")

    @trigger.setter
    def trigger(self, value: str):
        """Set the value of 'trigger' in application databag."""
        self.relation.data[self.app].update({"trigger": value})

    @trigger.deleter
    def trigger(self):
        """Delete the trigger field to notify related clusters."""
        self.relation.data[self.app].pop("trigger", None)

    @property
    def orchestrators(self) -> dict[str, Any]:
        """Return the value of 'orchestrators' in application databag."""
        orchestrators_data = self.relation.data[self.app].get("orchestrators", "{}")
        return json.loads(orchestrators_data)

    @orchestrators.setter
    def orchestrators(self, orchestrators: dict[str, Any]):
        """Set the value of 'orchestrators' in application databag."""
        self.put_object("orchestrators", orchestrators)

    @orchestrators.deleter
    def orchestrators(self):
        """Delete the 'orchestrators' field to notify related clusters."""
        if "orchestrators" not in self.relation.data[self.app]:
            logger.debug("No orchestrators field found to delete.")
            return
        self.relation.data[self.app].pop("orchestrators", None)

    @property
    def main_orchestrator_registered(self) -> str:
        """Return the value of 'main_orchestrator_registered' in the databag."""
        return self.relation.data[self.app].get("main_orchestrator_registered", "")

    @main_orchestrator_registered.setter
    def main_orchestrator_registered(self, value: bool) -> None:
        """Set the value of 'main_orchestrator_registered' in the databag."""
        self.relation.data[self.app].update({"main_orchestrator_registered": str(value)})

    @main_orchestrator_registered.deleter
    def main_orchestrator_registered(self) -> None:
        """Delete the 'main_orchestrator_registered' field to notify related clusters."""
        self.relation.data[self.app].pop("main_orchestrator_registered", None)


class PeerClusterServer(RelationState):
    """State collection metadata for a peer-cluster unit."""

    def __init__(self, relation, data_interface, component):
        super().__init__(relation, data_interface, component)
        self.unit = component

    @property
    def tls_ca_renewing(self) -> bool:
        """Return value of 'tls_ca_renewing' from unit state"""
        return self.relation.data[self.unit].get("tls_ca_renewing", "").lower() == "true"

    @tls_ca_renewing.setter
    def tls_ca_renewing(self, value: bool):
        """Update value of tls_ca_renewing from unit state."""
        self.relation.data[self.unit].update({"tls_ca_renewing": str(value)})

    @tls_ca_renewing.deleter
    def tls_ca_renewing(self):
        """Remove value of 'tls_ca_renewing' from unit state."""
        self.relation.data[self.unit].pop("tls_ca_renewing", None)

    @property
    def tls_ca_renewed(self) -> bool:
        """Get the value of 'tls_ca_renewed' from unit data bag"""
        return self.relation.data[self.unit].get("tls_ca_renewed", "").lower() == "true"

    @tls_ca_renewed.setter
    def tls_ca_renewed(self, value: bool):
        """Update value of 'tls_ca_renewed'"""
        self.relation.data[self.unit].update({"tls_ca_renewed": str(value)})

    @tls_ca_renewed.deleter
    def tls_ca_renewed(self):
        """Remove value of 'tls_ca_renewed' from unit state."""
        self.relation.data[self.unit].pop("tls_ca_renewed", None)

    @property
    def tls_configured(self) -> bool:
        """Get the value of 'tls_configured' from unit data bag."""
        return self.relation.data[self.unit].get("tls_configured", "").lower() == "true"

    @tls_configured.setter
    def tls_configured(self, value: bool):
        """Update the value of 'tls_configured'"""
        self.relation.data[self.unit].update({"tls_configured": str(value)})

    @tls_configured.deleter
    def tls_configured(self):
        """Delete the 'tls_configured' field to notify related clusters."""
        self.relation.data[self.unit].pop("tls_configured", None)

    @property
    def snapshots_credentials_saved(self) -> str:
        """Get the value of 'credentials_saved' from unit data bag."""
        return self.relation.data[self.unit].get("credentials_saved", "")

    @snapshots_credentials_saved.setter
    def snapshots_credentials_saved(self, value: bool):
        """Update the value of 'credentials_saved'"""
        self.relation.data[self.unit].update({"credentials_saved": str(value)})

    @snapshots_credentials_saved.deleter
    def snapshots_credentials_saved(self):
        """Delete the 'credentials_saved' field to notify related clusters."""
        self.relation.data[self.unit].pop("credentials_saved", None)
