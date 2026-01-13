#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
from collections import namedtuple

from opensearch_single_kernel.core.models import (
    App,
    Node,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class ConfigManager(BaseManager):
    """OpenSearch Config Manager."""

    CONFIG_YML = "opensearch.yml"
    SECURITY_CONFIG_YML = "opensearch-security/config.yml"
    JVM_OPTIONS = "jvm.options"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "config_manager"
        self.yaml_setter = YamlConfigSetter(self.workload.paths.conf)

    def set_node(
        self,
        app: App,
        cluster_name: str,
        unit_name: str,
        roles: list[str],
        cm_names: list[str],
        cm_ips: list[str],
        contribute_to_bootstrap: bool,
        node_temperature: str | None = None,
    ) -> None:
        """Set base config for each node in the cluster."""
        self.yaml_setter.put(self.CONFIG_YML, "cluster.name", cluster_name)
        self.yaml_setter.put(self.CONFIG_YML, "node.name", unit_name)
        self.yaml_setter.put(
            self.CONFIG_YML, "network.host", ["_site_"] + self.state.network_hosts
        )
        if self.state.host_ip:
            self.yaml_setter.put(self.CONFIG_YML, "network.publish_host", self.state.host_ip)
        public_address = self.workload.get_host_public_ip() or self.state.network_ingress_address
        self.yaml_setter.put(self.CONFIG_YML, "http.publish_host", public_address)

        self.yaml_setter.put(self.CONFIG_YML, "node.roles", roles, inline_array=len(roles) == 0)
        if node_temperature:
            self.yaml_setter.put(self.CONFIG_YML, "node.attr.temp", node_temperature)
        else:
            self.yaml_setter.delete(self.CONFIG_YML, "node.attr.temp")

        # Set the current app full id
        self.yaml_setter.put(self.CONFIG_YML, "node.attr.app_id", app.id)

        # This allows the new CMs to be discovered automatically (hot reload of unicast_hosts.txt)
        self.yaml_setter.put(self.CONFIG_YML, "discovery.seed_providers", "file")
        self.add_seed_hosts(cm_ips)

        if "cluster_manager" in roles and contribute_to_bootstrap:  # cluster NOT bootstrapped yet
            self.yaml_setter.put(
                self.CONFIG_YML, "cluster.initial_cluster_manager_nodes", cm_names
            )

        self.yaml_setter.put(self.CONFIG_YML, "path.data", self.workload.paths.data)
        self.yaml_setter.put(self.CONFIG_YML, "path.logs", self.workload.paths.logs)

        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={self.workload.paths.logs}/")

        self.yaml_setter.put(self.CONFIG_YML, "plugins.security.disabled", False)
        self.yaml_setter.put(self.CONFIG_YML, "plugins.security.ssl.http.enabled", True)
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.ssl.transport.enforce_hostname_verification",
            True,
        )

        # security plugin rest API access
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.restapi.roles_enabled",
            ["all_access", "security_rest_api_access"],
        )
        # to use the PUT and PATCH methods of the security rest API
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.unsupported.restapi.allow_securityconfig_modification",
            True,
        )

        # enable hot reload of TLS certs (without restarting the node)
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.ssl_cert_reload_enabled",
            True,
        )

    def cleanup_initial_cluster_managers(self):
        """Update the opensearch.yaml by deleting initiali_cluster_manager_nodes."""
        self.yaml_setter.delete(self.CONFIG_YML, "cluster.initial_cluster_manager_nodes")

    def set_client_auth(self):
        """Configure TLS and basic http for clients."""
        # The security plugin will accept TLS client certs if certs but doesn't require them
        # TODO this may be set to REQUIRED if we want to ensure certs provided by the client app
        self.yaml_setter.put(
            self.CONFIG_YML, "plugins.security.ssl.http.clientauth_mode", "OPTIONAL"
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/basic_internal_auth_domain/http_enabled",
            True,
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/clientcert_auth_domain/http_enabled",
            True,
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/clientcert_auth_domain/transport_enabled",
            True,
        )

        self.yaml_setter.append(
            self.JVM_OPTIONS,
            "-Djdk.tls.client.protocols=TLSv1.2",
        )

    def update_host_if_needed(self) -> bool:
        """Update the opensearch config with the current network hosts, after having started.

        Returns: True if host updated, False otherwise.
        """
        NetworkHost = namedtuple("NetworkHost", ["entry", "old", "new"])

        node = self.yaml_setter.load(self.CONFIG_YML)
        result = False
        for host in [
            NetworkHost(
                "network.host",
                set(node.get("network.host", [])),
                set(["_site_"] + self.state.network_hosts),
            ),
            NetworkHost(
                "network.publish_host",
                node.get("network.publish_host"),
                self.state.host_ip,
            ),
            NetworkHost(
                "http.publish_host",
                node.get("http.publish_host"),
                self.workload.get_host_public_ip() or self.state.network_ingress_address,
            ),
        ]:
            if not host.old:
                # Unit not configured yet
                continue

            if host.old != host.new:
                logger.info(f"Updating {host.entry} from: {host.old} - to: {host.new}")
                self.yaml_setter.put(self.CONFIG_YML, host.entry, host.new)
                result = True

        return result

    def reconfigure_unit(self) -> bool:
        """Reconfigure unit based on the nodes_config.

        Returns if a restart is needed or not.
        """
        if not (nodes_config := self.state.application.get_object("nodes_config")):
            return False

        nodes_config = {name: Node.from_dict(node) for name, node in nodes_config.items()}

        # update (append) CM IPs
        self.add_seed_hosts(
            [node.ip for node in list(nodes_config.values()) if node.is_cm_eligible()]
        )

        if not (new_node_conf := nodes_config.get(self.state.unit_name)):
            # the conf could not be computed / broadcast, because this node is
            # "starting" and is not online "yet" - either barely being configured (i.e. TLS)
            # or waiting to start.
            return False

        current_conf = self.yaml_setter.load(self.CONFIG_YML)
        stored_roles = current_conf["node.roles"] or ["coordinating"]
        new_conf_roles = new_node_conf.roles or ["coordinating"]
        if (
            sorted(stored_roles) == sorted(new_conf_roles)
            and current_conf.get("node.attr.temp") == new_node_conf.temperature
        ):
            # no conf change (roles for now)
            return False
        return True

    def add_seed_hosts(self, cm_ips: list[str]):
        """Add CM nodes ips / host names to the seed host list of this unit."""
        cm_ips_set = set(cm_ips)

        # only update the file if there is data to update
        # TODO: This should be handled at the workload level since on K8s it will be different
        if cm_ips_set:
            with open(self.workload.paths.seed_hosts, "w+") as f:
                lines = "\n".join([entry for entry in cm_ips_set if entry.strip()])
                f.write(f"{lines}\n")
