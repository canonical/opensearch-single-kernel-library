#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""State collection for opensearch-peers relation."""

import json
import logging
from typing import Any

from ops.model import Application, Relation, Unit

from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_USER,
    KIBANA_SERVER_USER,
    PERFORMANCE_PROFILE,
    CertType,
    Scope,
)
from opensearch_single_kernel.core.models import (
    DeploymentDescription,
    JWTAuthConfiguration,
    Node,
    OpenSearchProfile,
    PeerClusterApp,
    PeerClusterOrchestrators,
    PerformanceType,
    PluginConfigInfo,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.core.relations import RelationState
from opensearch_single_kernel.core.secrets import OpenSearchSecrets
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerUnitData,
)
from opensearch_single_kernel.utils.helpers import normalized_tls_subject
from opensearch_single_kernel.utils.secrets import hash_key, password_key

logger = logging.getLogger(__name__)


class OpenSearchServer(RelationState):
    """State/Relation data collection for an opensearch unit"""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerUnitData,
        component: Unit,
        secrets: OpenSearchSecrets,
    ):
        super().__init__(relation, data_interface, component)
        self.unit = component
        self.secrets = secrets

    @property
    def unit_id(self) -> int:
        """The id of the unit from the unit name."""
        return int(self.unit.name.split("/")[1])

    @property
    def profile(self) -> OpenSearchProfile | None:
        """Current profile of the unit"""
        if profile_str := self.relation_data.get(PERFORMANCE_PROFILE, None):
            return (
                ProductionProfile()
                if PerformanceType(profile_str) == PerformanceType.PRODUCTION
                else TestingProfile()
            )
        return None

    @profile.setter
    def profile(self, profile_value: OpenSearchProfile):
        """Set current profile of the unit."""
        self.relation_data.update({PERFORMANCE_PROFILE: profile_value.type.value})

    @property
    def is_app_leader(self) -> bool:
        """Check if the current unit is the leader of the application."""
        return self.unit.is_leader()

    @property
    def is_bootstrap_contributor(self) -> bool:
        """Get value of 'bootstrap_contributor'"""
        return self.relation_data.get("bootstrap_contributor", "").lower() == "true"

    @is_bootstrap_contributor.setter
    def is_bootstrap_contributor(self, value: bool):
        """Set the value of 'bootstrap_contributor' in application state."""
        self.update({"bootstrap_contributor": str(value)})

    @property
    def is_cluster_manager_removed(self) -> bool:
        """Get value of 'cluster_manager_removed'"""
        return self.relation_data.get("cluster_manager_removed", "").lower() == "true"

    @is_cluster_manager_removed.setter
    def is_cluster_manager_removed(self, value: bool):
        """Set value of 'cluster_manager_removed'"""
        self.update({"cluster_manager_removed": str(value)})

    @is_cluster_manager_removed.deleter
    def is_cluster_manager_removed(self):
        """Remove value of 'cluster_manager_removed'"""
        self.update({"cluster_manager_removed": ""})

    @property
    def started(self) -> str:
        """Get the value of 'started' key from unit data bag"""
        return self.relation_data.get("started", "")

    @property
    def tls_ca_renewing(self) -> bool:
        """Return value of 'tls_ca_renewing' from unit state"""
        return self.relation.data[self.unit].get("tls_ca_renewing", "").lower() == "true"

    @tls_ca_renewing.setter
    def tls_ca_renewing(self, value: bool):
        """Update value of tls_ca_renewing from unit state."""
        self.update({"tls_ca_renewing": str(value)})

    @tls_ca_renewing.deleter
    def tls_ca_renewing(self):
        """Remove value of 'tls_ca_renewing' from unit state."""
        self.update({"tls_ca_renewing": ""})

    @property
    def tls_ca_renewed(self) -> bool:
        """Get the value of 'tls_ca_renewed' from unit data bag"""
        return self.relation.data[self.unit].get("tls_ca_renewed", "").lower() == "true"

    @tls_ca_renewed.setter
    def tls_ca_renewed(self, value: bool):
        """Update value of 'tls_ca_renewed'"""
        self.update({"tls_ca_renewed": str(value)})

    @tls_ca_renewed.deleter
    def tls_ca_renewed(self):
        """Remove value of 'tls_ca_renewed' from unit state."""
        self.update({"tls_ca_renewed": ""})

    @property
    def tls_configured(self) -> bool:
        """Get the value of 'tls_configured' from unit data bag."""
        return self.relation.data[self.unit].get("tls_configured", "").lower() == "true"

    @tls_configured.setter
    def tls_configured(self, value: bool):
        """Update the value of 'tls_configured'"""
        self.update({"tls_configured": str(value)})

    @tls_configured.deleter
    def tls_configured(self):
        """Delete the 'tls_configured' field to notify related clusters."""
        self.relation.data[self.unit].pop("tls_configured", None)

    @property
    def update_ts(self) -> str:
        """Get the value of 'update-ts' from the unit databag."""
        return self.relation_data.get("update-ts", "")

    @update_ts.setter
    def update_ts(self, timestamp: int):
        """Update the value of 'update-ts' in the unit databag."""
        self.update({"update-ts": str(timestamp)})

    @property
    def certs_exp_checked_at(self) -> str:
        """Get the value of 'certs_exp_checked_at' from unit data bag."""
        return self.relation_data.get("certs_exp_checked_at", "1970-01-01 00:00:00")

    @certs_exp_checked_at.setter
    def certs_exp_checked_at(self, value: str):
        """Update the value of 'certs_exp_checked_at'"""
        self.update({"certs_exp_checked_at": value})

    @property
    def allocation_exclusions_to_delete(self) -> set[str]:
        """Return the value of 'allocation_exclusion_to_delete' from application databag."""
        return set(
            filter(
                None,
                self.relation_data.get("allocation-exclusions-to-delete", "").split(","),
            )
        )

    @allocation_exclusions_to_delete.setter
    def allocation_exclusions_to_delete(self, value: set[str]) -> None:
        """Set the value of 'allocation_exclusion_to_delete' in application databag."""
        self.update({"allocation-exclusions-to-delete": ",".join(value)})

    @property
    def voting_exclusions_to_delete(self) -> set[str]:
        """Return the value of 'delete_voting_exclusions' from application databag."""
        return set(
            filter(
                None,
                self.relation_data.get("delete-voting-exclusions", "").split(","),
            )
        )

    @voting_exclusions_to_delete.setter
    def voting_exclusions_to_delete(self, value: set[str]) -> None:
        """Set the value of 'delete_voting_exclusions' in application databag."""
        self.update({"delete-voting-exclusions": ",".join(value)})

    @property
    def last_host_ip(self) -> str | None:
        """Get the last configured IP for the unit. Used for tracking the IP change."""
        return self.relation_data.get("last_host_ip")

    @last_host_ip.setter
    def last_host_ip(self, value: str) -> None:
        """Set the value of last configured IP for the unit. Used for tracking the IP change."""
        self.update({"last_host_ip": value})

    @property
    def plugin_config_info(self) -> dict[str, PluginConfigInfo]:
        """Returns configuration information for plugins this unit is managing"""
        plugin_config_info = self.get_object("plugin_config_info") or {}
        return {
            label: PluginConfigInfo.from_dict(plugin)
            for label, plugin in plugin_config_info.items()
        }

    @plugin_config_info.setter
    def plugin_config_info(self, value: dict[str, PluginConfigInfo]) -> None:
        """Returns configuration information for plugins this unit is managing"""
        if not value:
            self.update({"plugin_config_info": ""})
            return
        self.put_object("plugin_config_info", value)

    @property
    def jwt_auth_configuration(self) -> JWTAuthConfiguration | None:
        """Return JWT auth configuration if any."""
        if not (config := self.get_object("jwt-auth-configuration")):
            return None
        return JWTAuthConfiguration.from_dict(config)

    @jwt_auth_configuration.setter
    def jwt_auth_configuration(self, value: JWTAuthConfiguration) -> None:
        """Update JWT auth configuration."""
        self.put_object("jwt-auth-configuration", value.to_dict())

    @jwt_auth_configuration.deleter
    def jwt_auth_configuration(self) -> None:
        """Remove JWT auth configuration."""
        self.relation.data[self.unit].pop("jwt-auth-configuration", None)

    @property
    def oauth_openid_connect_url(self) -> str | None:
        """Return OAuth openid_connect_url if configured."""
        return self.relation_data.get("oauth_openid_connect_url")

    @oauth_openid_connect_url.setter
    def oauth_openid_connect_url(self, value: str | None) -> None:
        """Set or remove OAuth openid_connect_url."""
        self.update({"oauth_openid_connect_url": value or ""})

    @property
    def oauth_departing(self) -> bool:
        """Return whether oauth relation broken event should be skipped.

        When current leader is unit oauth relation isn't breaking
        even if unit receives oauth relation broken event.
        """
        return self.relation_data.get("oauth_departing", "").lower() == "true"

    @oauth_departing.setter
    def oauth_departing(self, value: bool) -> None:
        """Set whether oauth relation broken event should be skipped.

        When current leader is unit oauth relation isn't breaking
        even if unit receives oauth relation broken event.
        """
        self.update({"oauth_departing": str(value)})

    @property
    def transport_secrets(self) -> dict[str, str]:
        """Get the Transport layer TLS secrets."""
        return self.secrets.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT, peek=True) or {}

    @property
    def http_secrets(self) -> dict[str, str]:
        """Get the HTTP layer TLS secrets."""
        return self.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP, peek=True) or {}

    @property
    def transport_keystore_password(self) -> str | None:
        """Get the keystore-password of transport TLS cert from the TLS cert_secret."""
        return self.transport_secrets.get("keystore-password")

    @property
    def http_keystore_password(self) -> str | None:
        """Get the keystore-password of HTTP TLS cert from the TLS cert_secret."""
        return self.http_secrets.get("keystore-password")


class OpenSearchApplication(RelationState):
    """An OpenSearch Application is a charm application with a given role.

    In OpenSearch a cluster can be formed using one or more applications.
    This class defines state/relation data for a single opensearch application.
    """

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerData,
        component: Application,
        # TODO to be removed when integrating data interfaces v1
        secrets: OpenSearchSecrets,
    ):
        super().__init__(relation, data_interface, component)
        self.app = component
        self.secrets = secrets

    @property
    def name(self) -> str:
        """Return the name of the Application."""
        return self.app.name

    @property
    def is_admin_user_initialized(self) -> bool:
        """Return the value of 'admin_user_initialized' in application state."""
        return self.relation_data.get("admin_user_initialized", "").lower() == "true"

    @property
    def bootstrap_contributors_count(self) -> int:
        """Get the value of 'bootstrap_contributors_count'"""
        return int(self.relation_data.get("bootstrap_contributors_count", 0))

    @bootstrap_contributors_count.setter
    def bootstrap_contributors_count(self, value: int) -> None:
        """Set value of bootstrap contributors count in application state."""
        self.update({"bootstrap_contributors_count": str(value)})

    @is_admin_user_initialized.setter
    def is_admin_user_initialized(self, value: bool) -> None:
        """Update the value of 'admin_user_initialized' in application state."""
        self.update({"admin_user_initialized": str(value)})

    @property
    def is_security_index_initialised(self) -> bool:
        """Return the value of 'security_index_initialised' in application state."""
        return self.relation_data.get("security_index_initialised", "").lower() == "true"

    @is_security_index_initialised.setter
    def is_security_index_initialised(self, value: bool) -> None:
        """Update the value of 'security_index_initialised' in application state."""
        self.update({"security_index_initialised": str(value)})

    @property
    def nodes_config(self) -> dict[str, Node]:
        """Return the value of 'nodes_config' in application state"""
        nodes_config = self.get_object("nodes_config")
        if not nodes_config:
            return {}
        return {name: Node.from_dict(node) for name, node in nodes_config.items()}

    @nodes_config.setter
    def nodes_config(self, value: dict[str, Node]) -> None:
        """Set the value of 'nodes_config' in application state."""
        self.put_object("nodes_config", {name: node.to_dict() for name, node in value.items()})

    @property
    def bootstrapped(self) -> bool:
        """Return the value of 'bootstrapped' in application state"""
        return self.relation_data.get("bootstrapped", "").lower() == "true"

    @bootstrapped.setter
    def bootstrapped(self, value: bool) -> None:
        """Set the value of 'bootstrapped' in application state."""
        self.update({"bootstrapped": str(value)})

    @property
    def deployment_desc(self) -> DeploymentDescription | None:
        """Return the deployment description object if any."""
        if not (current_deployment_desc := self.get_object("deployment-description")):
            return None
        return DeploymentDescription.from_dict(current_deployment_desc)

    @deployment_desc.setter
    def deployment_desc(self, deployment_desc: DeploymentDescription) -> None:
        """Set the deployment description."""
        self.put_object("deployment-description", deployment_desc.to_dict())

    @property
    def cluster_fleet_apps(self) -> dict[str, PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = json.loads(self.relation_data.get("cluster_fleet_apps", "{}"))
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps.items()}

    @cluster_fleet_apps.setter
    def cluster_fleet_apps(self, cluster_fleet_apps: dict[str, PeerClusterApp]) -> None:
        """Set the cluster fleet applications."""
        self.put_object(
            "cluster_fleet_apps", {id: app.to_dict() for id, app in cluster_fleet_apps.items()}
        )

    @property
    def cluster_fleet_apps_rels(self) -> dict[str, PeerClusterApp]:
        """Get the cluster fleet applications from relations."""
        if not (cluster_fleet_apps_rels := self.get_object("cluster_fleet_apps_rels")):
            return {}
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps_rels.items()}

    @cluster_fleet_apps_rels.setter
    def cluster_fleet_apps_rels(self, cluster_fleet_apps_rels: dict[str, PeerClusterApp]) -> None:
        """Set the cluster fleet applications to relations."""
        self.put_object(
            "cluster_fleet_apps_rels",
            {id: app.to_dict() for id, app in cluster_fleet_apps_rels.items()},
        )

    @property
    def apps_in_fleet(self) -> list[PeerClusterApp]:
        """Returns list of apps in cluster fleet"""
        return self.cluster_fleet_apps.values()

    @property
    def update_ts(self) -> str:
        """Get the value of 'update-ts' from the application databag."""
        return self.relation_data.get("update-ts", "")

    @update_ts.setter
    def update_ts(self, timestamp: int) -> None:
        """Update the value of 'update-ts' in the application databag."""
        self.update({"update-ts": str(timestamp)})

    @property
    def voting_exclusions_to_delete(self) -> set[str]:
        """Return the value of 'delete_voting_exclusions' from application databag."""
        return set(
            filter(
                None,
                self.relation_data.get("delete-voting-exclusions", "").split(","),
            )
        )

    @voting_exclusions_to_delete.setter
    def voting_exclusions_to_delete(self, value: set[str]) -> None:
        """Set the value of 'delete_voting_exclusions' in application databag."""
        self.update({"delete-voting-exclusions": ",".join(value)})

    @property
    def allocation_exclusions_to_delete(self) -> set[str]:
        """Return the value of 'allocation_exclusion_to_delete' from application databag."""
        return set(
            filter(
                None,
                self.relation_data.get("allocation-exclusions-to-delete", "").split(","),
            )
        )

    @allocation_exclusions_to_delete.setter
    def allocation_exclusions_to_delete(self, value: set[str]) -> None:
        """Set the value of 'allocation_exclusion_to_delete' in application databag."""
        self.update({"allocation-exclusions-to-delete": ",".join(value)})

    @property
    def is_data_role_in_cluster_fleet_apps(self) -> bool:
        """Look for data-role through all the roles of all the nodes in all applications"""
        data_apps_in_fleet = [app for app in self.apps_in_fleet if "data" in app.roles]
        return bool(data_apps_in_fleet) and any(
            app.planned_units > 0 for app in data_apps_in_fleet
        )

    @property
    def client_users_dict(self) -> dict[str, str]:
        """Get the client relation users dict from application databag."""
        return self.get_object("client_relation_users") or {}

    @client_users_dict.setter
    def client_users_dict(self, users_dict: dict[str, str]) -> None:
        """Set the client relation users dict in application databag."""
        self.put_object("client_relation_users", users_dict)

    @property
    def plugin_config_info(self) -> dict[str, PluginConfigInfo]:
        """Returns configuration information for plugins this app is managing"""
        plugin_config_info = self.get_object("plugin_config_info") or {}
        return {
            label: PluginConfigInfo.from_dict(plugin)
            for label, plugin in plugin_config_info.items()
        }

    @plugin_config_info.setter
    def plugin_config_info(self, value: dict[str, PluginConfigInfo]) -> None:
        """Returns configuration information for plugins this app is managing"""
        if not value:
            self.update({"plugin_config_info": ""})
            return
        self.put_object("plugin_config_info", value)

    @property
    def admin_secrets(self) -> dict[str, str]:
        """Get the admin secrets dict."""
        return self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}

    @property
    def tls_truststore_password(self) -> str | None:
        """Get the truststore-password from the TLS admin_secrets."""
        return (
            truststore_pwd
            if (admin_secrets := self.admin_secrets)
            and (truststore_pwd := admin_secrets.get("truststore-password"))
            else None
        )

    @property
    def tls_subject(self) -> str | None:
        """Get the normalized_tls_subject from the TLS admin_secrets."""
        return (
            normalized_tls_subject(subject)
            if (admin_secrets := self.admin_secrets) and (subject := admin_secrets.get("subject"))
            else None
        )

    @property
    def admin_password(self) -> str | None:
        """Get the admin password from the admin secrets."""
        return self.secrets.get(Scope.APP, password_key(ADMIN_USER))

    @property
    def kibana_server_password(self) -> str | None:
        """Get the kibana server password from the admin secrets."""
        return self.secrets.get(Scope.APP, password_key(KIBANA_SERVER_USER))

    @property
    def cos_password(self) -> str | None:
        """Get the cos user password from the admin secrets."""
        return self.secrets.get(Scope.APP, password_key(COS_USER))

    @property
    def admin_hashed_password(self) -> str | None:
        """Get the admin hashed password from the admin secrets."""
        return self.secrets.get(Scope.APP, hash_key(ADMIN_USER))

    @property
    def kibana_server_hashed_password(self) -> str | None:
        """Get the kibana server hashed password from the admin secrets."""
        return self.secrets.get(Scope.APP, hash_key(KIBANA_SERVER_USER))

    @property
    def cos_hashed_password(self) -> str | None:
        """Get the cos user hashed password from the admin secrets."""
        return self.secrets.get(Scope.APP, hash_key(COS_USER))

    def get_user_password(self, user: str) -> str | None:
        """Get the password for a given user from the client relation users dict."""
        if user == ADMIN_USER:
            return self.admin_password
        elif user == KIBANA_SERVER_USER:
            return self.kibana_server_password
        elif user == COS_USER:
            return self.cos_password

        raise ValueError(f"User {user} is not an internal user.")

    def get_user_hashed_password(self, user: str) -> str | None:
        """Get the hashed password for a given user from the client relation users dict."""
        if user == ADMIN_USER:
            return self.admin_hashed_password
        elif user == KIBANA_SERVER_USER:
            return self.kibana_server_hashed_password
        elif user == COS_USER:
            return self.cos_hashed_password

        raise ValueError(f"User {user} is not an internal user.")

    @property
    def orchestrators(self) -> PeerClusterOrchestrators:
        """Return the value of 'orchestrators' in application databag."""
        orchestrators_dict = self.get_object("orchestrators")
        return PeerClusterOrchestrators.from_dict(orchestrators_dict)

    @property
    def orchestrators_dict(self) -> dict[str, Any]:
        """Return the value of 'orchestrators' in application databag as dict."""
        orchestrators_dict = self.get_object("orchestrators")
        return orchestrators_dict if orchestrators_dict else {}

    @orchestrators.setter
    def orchestrators(self, orchestrators: PeerClusterOrchestrators) -> None:
        """Set the value of 'orchestrators' in application databag."""
        self.put_object("orchestrators", orchestrators.to_dict())

    @orchestrators.deleter
    def orchestrators(self) -> None:
        """Remove the value of 'orchestrators' from application databag."""
        self.relation.data[self.app].pop("orchestrators", None)

    @property
    def missing_relations(self) -> bool:
        """Return the value of 'missing_relations' in application databag."""
        return self.relation_data.get("missing_relations", "") == "True"

    @missing_relations.setter
    def missing_relations(self, value: bool) -> None:
        """Set the value of 'missing_relations' in application databag."""
        self.update({"missing_relations": str(value)})

    @property
    def first_data_node(self) -> str:
        """Return the value of 'first_data_node' in application databag."""
        return self.relation_data.get("first_data_node", "")

    @first_data_node.setter
    def first_data_node(self, value: str) -> None:
        """Set the value of 'first_data_node' in the application databag."""
        self.update({"first_data_node": value})

    @first_data_node.deleter
    def first_data_node(self) -> None:
        """Remove the value of 'first_data_node' from the application databag."""
        self.update({"first_data_node": ""})
