#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""
from collections import namedtuple
from typing import List

from opensearch_single_kernel.core.models import (
    Node,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.workload.base import BaseWorkload


class ConfigManager(BaseManager):
    """OpenSearch Config Manager."""

    CONFIG_YML = "opensearch.yml"
    SECURITY_CONFIG_YML = "opensearch-security/config.yml"
    JVM_OPTIONS = "jvm.options"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "config_manager"
        self.yaml_setter = YamlConfigSetter(self.workload.paths.conf)

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
                self.logger.info(f"Updating {host.entry} from: {host.old} - to: {host.new}")
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

    def add_seed_hosts(self, cm_ips: List[str]):
        """Add CM nodes ips / host names to the seed host list of this unit."""
        cm_ips_set = set(cm_ips)

        # only update the file if there is data to update
        # TODO: This should be handled at the workload level since on K8s it will be different
        if cm_ips_set:
            with open(self.workload.paths.seed_hosts, "w+") as f:
                lines = "\n".join([entry for entry in cm_ips_set if entry.strip()])
                f.write(f"{lines}\n")
