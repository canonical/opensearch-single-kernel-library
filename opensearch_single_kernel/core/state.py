#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object representing the global state of OpenSearch Charm."""

import json
import logging
import socket
from json import JSONDecodeError
from typing import TYPE_CHECKING

from ops import Application, JujuVersion, Object, Relation, Unit

from opensearch_single_kernel.common.constants import (
    CLIENT_RELATION,
    GENERATED_ROLES,
    JWT_CONFIG_RELATION,
    KIBANA_SERVER_ROLE,
    NODE_LOCK_RELATION,
    OAUTH_RELATION,
    OPENSEARCH_HTTP_PORT,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    PERFORMANCE_PROFILE,
    TLS_RELATION,
    CertType,
    Scope,
    StartMode,
    Substrates,
)
from opensearch_single_kernel.core.models import (
    DeploymentDescription,
    DeploymentType,
    JWTAuthConfiguration,
    Node,
    OpenSearchProfile,
    PeerClusterApp,
    PerformanceType,
    PluginConfigInfo,
    ProductionProfile,
    TestingProfile,
)
from opensearch_single_kernel.core.relations import (
    JwtData,
    PeerCluster,
    PeerClusterData,
    PeerClusterOrchestratorData,
    RelationState,
)
from opensearch_single_kernel.core.secrets import OpenSearchSecrets
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    Data,
    DataPeerData,
    DataPeerUnitData,
    OpenSearchProvidesData,
    SecretGroup,
)
from opensearch_single_kernel.utils.certificates import normalized_tls_subject
from opensearch_single_kernel.utils.helpers import (
    format_unit_name,
    get_k8s_seed_host,
)

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


logger = logging.getLogger(__name__)


class OpenSearchServer(RelationState):
    """State/Relation data collection for an opensearch unit"""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerUnitData,
        component: Unit,
    ):
        super().__init__(relation, data_interface, component)
        self.unit = component

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
        return self.relation_data.get("bootstrap_contributor", "") == "True"

    @is_bootstrap_contributor.setter
    def is_bootstrap_contributor(self, value: bool):
        """Set the value of 'bootstrap_contributor' in application state."""
        self.update({"bootstrap_contributor": str(value)})

    @property
    def is_cluster_manager_removed(self) -> bool:
        """Get value of 'cluster_manager_removed'"""
        return self.relation_data.get("cluster_manager_removed", "") == "True"

    @is_cluster_manager_removed.setter
    def is_cluster_manager_removed(self, value: bool):
        """Set value of 'cluster_manager_removed'"""
        self.update({"cluster_manager_removed": str(value)})

    @property
    def started(self) -> str:
        """Get the value of 'started' key from unit data bag"""
        return self.relation_data.get("started", "")

    @property
    def tls_ca_renewing(self) -> bool:
        """Return value of 'tls_ca_renewing' from unit state"""
        return self.relation_data.get("tls_ca_renewing", "") == "True"

    @tls_ca_renewing.setter
    def tls_ca_renewing(self, value: bool):
        """Update value of tls_ca_renewing from unit state."""
        self.update({"tls_ca_renewing": str(value)})

    @property
    def tls_ca_renewed(self) -> bool:
        """Get the value of 'tls_ca_renewed' from unit data bag"""
        return self.relation_data.get("tls_ca_renewed", "") == "True"

    @tls_ca_renewed.setter
    def tls_ca_renewed(self, value: bool):
        """Update value of 'tls_ca_renewed'"""
        self.update({"tls_ca_renewed": str(value)})

    @property
    def tls_configured(self) -> bool:
        """Get the value of 'tls_configured' from unit data bag."""
        return self.relation_data.get("tls_configured", "") == "True"

    @tls_configured.setter
    def tls_configured(self, value: bool):
        """Update the value of 'tls_configured'"""
        self.update({"tls_configured": str(value)})

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
    def allocation_exclusions_to_delete(self, value: set[str]):
        """Set the value of 'allocation_exclusion_to_delete' in application databag."""
        self.update({"allocation-exclusions-to-delete": ",".join(value)})

    @property
    def delete_voting_exclusions(self) -> set[str]:
        """Return the value of 'delete_voting_exclusions' from application databag."""
        return set(
            filter(
                None,
                self.relation_data.get("delete-voting-exclusions", "").split(","),
            )
        )

    @delete_voting_exclusions.setter
    def delete_voting_exclusions(self, value: set[str]):
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
        self.update({"jwt-auth-configuration": ""})

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
        return self.relation_data.get("oauth_departing", "") == "True"

    @oauth_departing.setter
    def oauth_departing(self, value: bool):
        """Set whether oauth relation broken event should be skipped.

        When current leader is unit oauth relation isn't breaking
        even if unit receives oauth relation broken event.
        """
        self.update({"oauth_departing": str(value)})


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
    ):
        super().__init__(relation, data_interface, component)
        self.app = component

    @property
    def name(self) -> str:
        """Return the name of the Application."""
        return self.app.name

    @property
    def is_admin_user_initialized(self) -> bool:
        """Return the value of 'admin_user_initialized' in application state."""
        return self.relation_data.get("admin_user_initialized", "") == "True"

    @property
    def bootstrap_contributors_count(self) -> int:
        """Get the value of 'bootstrap_contributors_count'"""
        return int(self.relation_data.get("bootstrap_contributors_count", 0))

    @bootstrap_contributors_count.setter
    def bootstrap_contributors_count(self, value: int):
        """Set value of bootstrap contributors count in application state."""
        self.update({"bootstrap_contributors_count": str(value)})

    @is_admin_user_initialized.setter
    def is_admin_user_initialized(self, value: bool):
        """Update the value of 'admin_user_initialized' in application state."""
        self.update({"admin_user_initialized": str(value)})

    @property
    def is_security_index_initialised(self) -> bool:
        """Return the value of 'security_index_initialised' in application state."""
        return self.relation_data.get("security_index_initialised", "") == "True"

    @is_security_index_initialised.setter
    def is_security_index_initialised(self, value: bool):
        """Update the value of 'security_index_initialised' in application state."""
        self.update({"security_index_initialised": str(value)})

    @property
    def nodes_config(self) -> dict[str, Node]:
        """Return the value of 'nodes_config' in application state"""
        nodes_config = self.get_object("nodes_config")
        if not nodes_config:
            return {}
        return {name: Node.from_dict(node) for name, node in nodes_config.items()}

    @property
    def bootstrapped(self) -> bool:
        """Return the value of 'bootstrapped' in application state"""
        return self.relation_data.get("bootstrapped", "") == "True"

    @property
    def deployment_desc(self) -> DeploymentDescription | None:
        """Return the deployment description object if any."""
        current_deployment_desc = self.get_object("deployment-description")
        if not current_deployment_desc:
            return None
        return DeploymentDescription.from_dict(current_deployment_desc)

    @deployment_desc.setter
    def deployment_desc(self, deployment_desc: DeploymentDescription):
        """Set the deployment description."""
        self.put_object("deployment-description", deployment_desc.to_dict())

    @property
    def cluster_fleet_apps(self) -> dict[str, PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = json.loads(self.relation_data.get("cluster_fleet_apps", "{}")) or {}
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps.items()}

    def apps_in_fleet(self) -> list[PeerClusterApp]:
        """Returns list of apps in cluster fleet"""
        cluster_fleet_apps = self.get_object("cluster_fleet_apps")
        if not cluster_fleet_apps:
            cluster_fleet_apps = {}
        elif not json.loads(cluster_fleet_apps):
            cluster_fleet_apps = json.loads(cluster_fleet_apps)
        return [PeerClusterApp.from_dict(app) for app in cluster_fleet_apps.values()]

    @property
    def update_ts(self) -> str:
        """Get the value of 'update-ts' from the application databag."""
        return self.relation_data.get("update-ts", "")

    @update_ts.setter
    def update_ts(self, timestamp: int):
        """Update the value of 'update-ts' in the application databag."""
        self.update({"update-ts": str(timestamp)})

    @property
    def delete_voting_exclusions(self) -> set[str]:
        """Return the value of 'delete_voting_exclusions' from application databag."""
        return set(
            filter(
                None,
                self.relation_data.get("delete-voting-exclusions", "").split(","),
            )
        )

    @delete_voting_exclusions.setter
    def delete_voting_exclusions(self, value: set[str]):
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
    def allocation_exclusions_to_delete(self, value: set[str]):
        """Set the value of 'allocation_exclusion_to_delete' in application databag."""
        self.update({"allocation-exclusions-to-delete": ",".join(value)})

    @property
    def is_data_role_in_cluster_fleet_apps(self) -> bool:
        """Look for data-role through all the roles of all the nodes in all applications"""
        data_apps_in_fleet = [app for app in self.apps_in_fleet() if "data" in app.roles]
        return bool(data_apps_in_fleet) and any(
            app.planned_units > 0 for app in data_apps_in_fleet
        )

    @property
    def client_users_dict(self) -> dict[str, str]:
        """Get the client relation users dict from application databag."""
        return self.get_object("client_relation_users") or {}

    @client_users_dict.setter
    def client_users_dict(self, users_dict: dict[str, str]):
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


class ClusterState(Object):
    """The global OpenSearch Cluster State ."""

    def __init__(self, charm: "OpenSearchBaseCharm", substrate: Substrates):
        super().__init__(charm, "cluster_state")
        self.config = charm.config
        self.substrate = substrate

        # Secrets  FIXME: Handle this separately.
        self.secrets = OpenSearchSecrets(charm, peer_relation=PEER_RELATION)

        # TODO: Add secrets
        self.peer_app_interface = DataPeerData(model=charm.model, relation_name=PEER_RELATION)
        self.peer_unit_interface = DataPeerUnitData(model=charm.model, relation_name=PEER_RELATION)
        self.client_data_interface = OpenSearchProvidesData(
            model=charm.model, relation_name=CLIENT_RELATION
        )

    # -- Relations

    @property
    def peer_relation(self) -> Relation | None:
        """Get charm peer relation."""
        return self.model.get_relation(PEER_RELATION)

    @property
    def node_lock_relation(self) -> Relation | None:
        """Get Node Lock Peer Relation."""
        return self.model.get_relation(NODE_LOCK_RELATION)

    @property
    def tls_relation(self) -> Relation | None:
        """Get TLS relation."""
        return self.model.get_relation(TLS_RELATION)

    @property
    def peer_cluster_relation(self) -> Relation | None:
        """The 'peer-cluster' relation that the charm is requiring."""
        return self.model.get_relation(PEER_CLUSTER_RELATION)

    @property
    def peer_cluster_orchestrator_relation(self) -> Relation | None:
        """The 'peer-cluster-orchestrator' relation that the charm is requiring."""
        return self.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION)

    @property
    def external_client_relations(self) -> set[Relation]:
        """Get OpenSearch client relation."""
        return self.model.relations[CLIENT_RELATION]

    @property
    def peer_cluster_orchestrator(self) -> PeerCluster:
        """The State for the requirer side of the 'peer-cluster-orchestrator' relation.."""
        return PeerCluster(
            relation=self.peer_cluster_orchestrator_relation,
            data_interface=PeerClusterData(self.model, PEER_CLUSTER_RELATION),
            component=self.model.app,
        )

    @property
    def peer_cluster(self) -> PeerCluster:
        """State for the provider side of the 'peer-cluster-orchestrator' relation."""
        return PeerCluster(
            relation=self.peer_cluster_relation,
            data_interface=PeerClusterOrchestratorData(
                self.model, PEER_CLUSTER_ORCHESTRATOR_RELATION
            ),
            component=self.model.app,
        )

    # -- Core Components

    @property
    def server(self) -> OpenSearchServer:
        """Get the opensearch unit state."""
        return OpenSearchServer(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
        )

    @property
    def servers(self) -> list[OpenSearchServer]:
        """Return all opensearch servers using peer relation."""
        return [
            OpenSearchServer(
                relation=self.peer_relation,
                data_interface=self.peer_unit_interface,
                component=unit,
            )
            for unit in self.all_units
        ]

    @property
    def application(self) -> OpenSearchApplication:
        """Get the opensearch application state."""
        return OpenSearchApplication(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
        )

    @property
    def external_clients(self) -> set[ExternalOpenSearchClient]:
        """Get all related external opensearch clients."""
        clients = set()
        for relation in self.external_client_relations:
            if not relation.app:
                continue

            clients.add(
                ExternalOpenSearchClient(
                    relation=relation,
                    data_interface=self.client_data_interface,
                    component=relation.app,
                    relation_name=CLIENT_RELATION,
                )
            )

        return clients

    def external_client_by_relation(self, relation: Relation) -> ExternalOpenSearchClient | None:
        """Get external opensearch client by relation."""
        if relation not in self.external_client_relations:
            return None
        if not relation.app:
            return None

        return ExternalOpenSearchClient(
            relation=relation,
            data_interface=self.client_data_interface,
            component=relation.app,
            relation_name=CLIENT_RELATION,
        )

    @property
    def dashboards_clients(self) -> list[ExternalOpenSearchClient]:
        """Return the dashboard relations out of all."""
        result = []
        for external_client in self.external_clients:
            if (roles := external_client.extra_user_roles) and KIBANA_SERVER_ROLE in roles:
                # if any(key.name == "opensearch-dashboards" for key in relation.data.keys()):
                result.append(external_client)
        return result

    # -- Cluster State Properties

    @property
    def unit_name(self):
        """Juju unit identity (such as opensearch-0.2fe, opensearch-1.2fe).

        Use this for relation data, lock documents and OpenSearch node identity. It
        requires the deployment description to be available so the unit name can be
        formatted consistently across all units.
        """
        return format_unit_name(self.model.unit, app=self.application.deployment_desc.app)

    @property
    def node_config(self) -> Node | None:
        """Return the current node from 'nodes_config' in application state."""
        return (
            new_node_conf
            if (nodes_config := self.application.nodes_config)
            and (new_node_conf := nodes_config.get(self.unit_name))
            else None
        )

    @property
    def node_host(self) -> str | None:
        """Return a connectable host for the current unit.

        On K8s this is the unit DNS name. On VM this is the unit IP address.
        """
        if self.substrate == Substrates.K8S:
            return socket.getfqdn()
        return self.host_ip

    @property
    def planned_units(self) -> int:
        """Return the planned units for the charm."""
        return self.model.app.planned_units()

    @property
    def host_ip(self) -> str:
        """Fetches the IP address of the current unit."""
        address = self.model.get_binding(PEER_RELATION).network.bind_address
        return str(address)

    @property
    def fqdn(self) -> str:
        """Return a stable FQDN for the current unit.

        - VM: local host FQDN from the runtime environment.
        - K8s: canonical endpoint FQDN for this unit service name (must match TLS SANs;
          never rely on socket.getfqdn() alone, which can return the pod IP and break HTTPS).
        """
        if self.substrate == Substrates.K8S:
            deployment_desc = self.application.deployment_desc
            app_name = (
                deployment_desc.app.name
                if deployment_desc and deployment_desc.app.name
                else self.model.app.name
            )
            if app_name:
                unit_key = (
                    str(self.unit_name)
                    if deployment_desc
                    else self.model.unit.name.replace("/", "-")
                )
                return get_k8s_seed_host(unit_key, app_name)
        return socket.getfqdn()

    @property
    def network_hosts(self) -> list[str]:
        """All HTTP/Transport hosts for the current node."""
        if self.substrate == Substrates.K8S:
            # K8s should bind on stable DNS identity.
            return [self.fqdn]
        return [socket.getfqdn(), self.host_ip]

    @property
    def port(self) -> int:
        """Return Port of OpenSearch unit."""
        return OPENSEARCH_HTTP_PORT

    def unit_ip(self, unit: Unit) -> str | None:
        """Returns the ip address of a given unit."""
        # check if host is current host
        if unit == self.model.unit:
            return self.host_ip

        if self.peer_relation:
            private_address = self.peer_relation.data[unit].get("private-address")
            if private_address:
                return str(private_address)

    def get_unit(self, name: str):
        """Get unit by name"""
        return self.model.get_unit(name)

    @property
    def is_tls_full_configured_in_cluster(self) -> bool:
        """Check if TLS is configured in all the units of the current cluster."""
        if not self.peer_relation:
            return False
        for unit in self.all_units:
            if (
                self.peer_relation.data[unit].get("tls_configured") != "True"
                or "tls_ca_renewing" in self.peer_relation.data[unit]
                or "tls_ca_renewed" in self.peer_relation.data[unit]
            ):
                return False
        return True

    @property
    def ca_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        rotation_in_progress = False
        rotation_complete = True

        # check peer units and current unit
        rotation_in_progress = any([server.tls_ca_renewing for server in self.servers])
        rotation_complete = all([server.tls_ca_renewed for server in self.servers])

        # TODO: Support peer cluster and peer cluster orchestrator
        logger.debug(
            "CA rotation happening in cluster: %s | \
                rotation complete in cluster: %s | return value: %s \
                ",
            rotation_in_progress,
            rotation_complete,
            not rotation_in_progress or rotation_complete,
        )
        # if no unit is renewing the CA, or all of them renewed it, the rotation is complete
        return not rotation_in_progress or rotation_complete

    def ca_and_certs_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        rotation_complete = True

        # the current unit is not in the relation.units list
        # if tls is not configured or in the middle of rotation, return False
        if not all([server.tls_configured for server in self.servers]) or all(
            [server.tls_ca_renewing and not server.tls_ca_renewed for server in self.servers]
        ):
            return False

        # TODO: Support peer cluster and peer cluster orchestrator
        return rotation_complete

    def reset_ca_rotation_state(self) -> None:
        """Handle internal flags during CA rotation routine."""
        if not self.server.tls_ca_renewing:
            # if the CA is not being renewed we don't have to do anything here
            return

        # if this flag is set, the CA rotation routine is complete for this unit
        if self.server.tls_ca_renewed and self.ca_and_certs_rotation_complete_in_cluster():
            # both CA rotation and certs rotation completed in the cluster
            self.server.update({"tls_ca_renewing": ""})
            self.server.update({"tls_ca_renewed": ""})
            # TODO: Handle large deployment
            # self.update_tls_flag_to_peer_cluster_relation(
            # flag="tls_ca_renewing", operation="remove"
            # )
            # self.update_tls_flag_to_peer_cluster_relation(
            #    flag="tls_ca_renewed", operation="remove"
            # )
            return

        # this means only the CA rotation completed, still need to create certificates
        self.server.tls_ca_renewed = True
        # TODO: Handle large deployment
        # self.update_tls_flag_to_peer_cluster_relation(flag="tls_ca_renewed", operation="add")

    @property
    def network_ingress_address(self) -> str:
        """Get the public ip address of the unit."""
        return str(self.model.get_binding(PEER_RELATION).network.ingress_address)

    @property
    def units_ips(self) -> dict[str, str]:
        """Returns the mapping "unit id / ip address" of all units."""
        unit_ip_map = {}
        if not self.peer_relation:
            return unit_ip_map

        for unit in self.peer_relation.units:
            unit_id = unit.name.split("/")[1]
            unit_ip_map[unit_id] = self.unit_ip(unit)

        # Sometimes the above command doesn't get the current node,
        # so ensure we get this unit's ip.
        unit_ip_map[self.model.unit.name.split("/")[1]] = self.host_ip

        return unit_ip_map

    @property
    def all_units(self) -> list[Unit]:
        """Fetch the list of units for the current app."""
        if not self.peer_relation:
            return []
        return list(self.peer_relation.units.union({self.server.unit}))

    @property
    def implements_secrets(self):
        """Property to cache results from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    @property
    def model_uuid(self):
        """UUID of the Charm Model."""
        return self.model.uuid

    # TODO: Once we handle large deployment we will add a separate
    # state object for peer cluster and peer cluster orchestrator
    @property
    def current_peer_cluster_app(self) -> PeerClusterApp | None:
        """Return the current peer cluster App."""
        # During early lifecycle (first pebble-ready), the deployment description may not
        # be computed yet, callers should handle None.
        if not (deployment_desc := self.application.deployment_desc):
            return None
        logger.info("Current deployment desc %s", deployment_desc)
        return PeerClusterApp(
            app=deployment_desc.app,
            planned_units=self.planned_units,
            units=[format_unit_name(u, app=deployment_desc.app) for u in self.all_units],
            roles=(
                deployment_desc.config.roles
                if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES
                else GENERATED_ROLES
            ),
        )

    def get_relation_mapped_users(self, role: str) -> list[str]:
        """Get the list of users mapped to a specific role from config roles_mapping."""
        config_roles_mapping = self.config.get("roles_mapping")
        if not config_roles_mapping:
            return []
        try:
            roles_mapping = json.loads(config_roles_mapping)
            if not isinstance(roles_mapping, dict):
                logger.error("Bad roles_mapping config value")
                return []
        except JSONDecodeError:
            logger.error("Bad roles_mapping config value")
            return []

        return [
            mapped_user
            for mapped_user, mapped_role in roles_mapping.items()
            if mapped_role == role
        ]

    @property
    def tls_truststore_password(self) -> str | None:
        """Get the truststore-password from the TLS admin_secrets."""
        return (
            truststore_pwd
            if (
                admin_secrets := self.secrets.get_object(
                    Scope.APP, CertType.APP_ADMIN.val, peek=True
                )
            )
            and (truststore_pwd := admin_secrets.get("truststore-password"))
            else None
        )

    def get_tls_keystore_password(self, cert_type: CertType) -> str | None:
        """Get the keystore-password of provided cert_type from the TLS cert_secret."""
        return (
            keystore_pwd
            if (cert_secret := self.secrets.get_object(Scope.UNIT, cert_type.val, peek=True))
            and (keystore_pwd := cert_secret.get("keystore-password"))
            else None
        )

    @property
    def tls_subject(self) -> str | None:
        """Get the normalized_tls_subject from the TLS admin_secrets."""
        return (
            normalized_tls_subject(subject)
            if (
                admin_secrets := self.secrets.get_object(
                    Scope.APP, CertType.APP_ADMIN.val, peek=True
                )
            )
            and (subject := admin_secrets.get("subject"))
            else None
        )

    def computed_roles(self) -> list[str]:
        """Return computed_roles"""
        if (
            deployment_desc := self.application.deployment_desc
        ).start == StartMode.WITH_PROVIDED_ROLES:
            computed_roles = deployment_desc.config.roles
        else:
            computed_roles = GENERATED_ROLES

        # If the failover orchestrator is the only data node in the cluster, remove the
        # cluster-manager role from it to avoid it bootstrapping the cluster
        # which is the responsibility of the main orchestrator
        # who then broadcasts `security_index_initialized` to the peer clusters.
        if (
            self.model.unit.is_leader()
            and self._is_failover_and_sole_data_app()
            and not self.application.is_security_index_initialised
        ):
            self.server.is_cluster_manager_removed = True
            computed_roles.remove("cluster_manager")

        if computed_roles == ["coordinating"]:
            computed_roles = []  # to mark a node as dedicated coordinating only, we clear the list
        return computed_roles

    def _is_failover_and_sole_data_app(self) -> bool:
        """Check if the current node is a failover and the only data node in the cluster."""
        deployment_desc = self.application.deployment_desc
        cluster_fleet_apps = self.application.cluster_fleet_apps or {}
        return (
            # data node in a failover orchestrator deployment
            deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR
            and (
                "data" in deployment_desc.config.roles
                or deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            )
            # No pure data nodes in the cluster
            and not any(
                self.application.name != cluster_fleet_apps[app].get("app", {}).get("name")
                and "data" in cluster_fleet_apps[app].get("roles", [])
                and "cluster_manager" not in cluster_fleet_apps[app].get("roles", [])
                for app in cluster_fleet_apps
            )
        )

    @property
    def jwt_relation(self) -> Relation | None:
        """Get JWT relation."""
        return self.model.get_relation(JWT_CONFIG_RELATION)

    @property
    def jwt(self) -> JwtState:
        """Get JWT state."""
        return JwtState(
            relation=self.jwt_relation,
            data_interface=JwtData(self.model, JWT_CONFIG_RELATION),
            component=self.model.app,
        )

    @property
    def oauth_relation(self) -> Relation | None:
        """Get OAuth relation."""
        return self.model.get_relation(OAUTH_RELATION)
