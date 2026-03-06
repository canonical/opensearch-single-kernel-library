#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
from typing import Any

from opensearch_single_kernel.common.constants import (
    CertType,
)
from opensearch_single_kernel.core.models import OpenSearchProfile
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

    @property
    def yaml_setter(self) -> YamlConfigSetter:
        """Return the yaml_setter."""
        return YamlConfigSetter(self.workload)

    def update_opensearch_config(
        self,
        roles: list[str] | None = None,
        cm_names: list[str] | None = None,
        cm_ips: list[str] | None = None,
    ) -> bool:
        """Reconcile whole Opensearch config using values from application state.

        Updates opensearch.yml & unicast_hosts.txt config files and assures
        jvm.options & opensearch-security/config.yml are populated with right static options.

        Args:
            roles: override node roles got from nodes_config.
            cm_names: cluster manager nodes for bootstrapping.
            cm_ips: override seed_hosts got from nodes_config.

        Returns:
            whether the opensearch.yml config was changed.
        """
        if roles is None:
            roles = self._opensearch_roles

        config = (
            self._opensearch_static_config()
            | self._opensearch_general_config(roles)
            | self._opensearch_host_config()
            | self._opensearch_temperature_config()
            | self._opensearch_cluster_manager_config(roles=roles, cm_names=cm_names)
            | self._opensearch_admin_tls_config()
            | self._opensearch_tls_config(CertType.UNIT_HTTP)
            | self._opensearch_tls_config(CertType.UNIT_TRANSPORT)
        )

        self._update_static_jvm_options()
        self._update_static_security_options()

        if cm_ips:
            self._update_seeds_file(cm_ips)
        else:
            self.update_seeds_config()

        self.state.server.last_host_ip = self.state.host_ip

        res = self.yaml_setter.rewrite(self.CONFIG_YML, config)
        return res

    @staticmethod
    def _opensearch_static_config() -> dict[str, Any]:
        """Get set of static config options for the Opensearch.

        Intended for opensearch.yml config file.
        """
        return {
            # This allows the new CMs to be discovered automatically
            # (hot reload of unicast_hosts.txt)
            "discovery.seed_providers": "file",
            "plugins.security.disabled": False,
            "plugins.security.ssl.http.enabled": True,
            "plugins.security.ssl.transport.enforce_hostname_verification": True,
            # enable hot reload of TLS certs (without restarting the node)
            "plugins.security.ssl_cert_reload_enabled": True,
            # to use the PUT and PATCH methods of the security rest API
            "plugins.security.unsupported.restapi.allow_securityconfig_modification": True,
            # security plugin rest API access
            "plugins.security.restapi.roles_enabled": [
                "all_access",
                "security_rest_api_access",
            ],
            # The security plugin will accept TLS client certs if certs but doesn't require them
            # TODO this may be REQUIRED if we want to ensure certs provided by the client app
            "plugins.security.ssl.http.clientauth_mode": "OPTIONAL",
            "prometheus.metric_name.prefix": "opensearch_",
            "prometheus.indices": "false",
            "prometheus.cluster.settings": "false",
            "prometheus.nodes.filter": "_local",
        }

    def _opensearch_general_config(self, roles: list[str]) -> dict[str, Any]:
        """Get set of general config options for the Opensearch from the deployment_desc.

        Intended for opensearch.yml config file.
        """
        return (
            {
                "cluster.name": deployment_desc.config.cluster_name,
                "node.name": self.state.unit_name,
                "network.host": ["_site_", *sorted(self.state.network_hosts)],
                "http.publish_host": self.workload.get_host_public_ip()
                or self.state.network_ingress_address,
                "node.roles": sorted(roles),
                "node.attr.app_id": deployment_desc.app.id,  # Set the current app full id
                "path.data": self.workload.paths.data.as_posix(),
                "path.logs": self.workload.paths.logs.as_posix(),
                "path.home": self.workload.paths.home.as_posix(),
            }
            if (deployment_desc := self.state.application.deployment_desc)
            else {}
        )

    def _opensearch_host_config(self) -> dict[str, Any]:
        """Get set of network host config options for the Opensearch.

        Intended for opensearch.yml config file.
        """
        return {"network.publish_host": self.state.host_ip} if self.state.host_ip else {}

    def _opensearch_temperature_config(self) -> dict[str, Any]:
        """Get the set of network host config options for the Opensearch.

        Intended for opensearch.yml config file.
        """
        return (
            {"node.attr.temp": self._opensearch_data_temperature}
            if self._opensearch_data_temperature
            else {}
        )

    def _opensearch_cluster_manager_config(
        self,
        roles: list[str],
        cm_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Get set of initial cluster manager config options for the Opensearch.

        Returns non-empty result only during bootstrapping process.
        Intended for opensearch.yml config file.
        """
        return (
            {
                "cluster.initial_cluster_manager_nodes": sorted(cm_names),
            }
            if cm_names
            and "cluster_manager" in roles
            and self.state.server.is_bootstrap_contributor
            else {}
        )

    def _opensearch_admin_tls_config(self) -> dict[str, Any]:
        """Get set of admin TLS config options for the Opensearch.

        Intended for opensearch.yml config file.
        """
        return (
            {"plugins.security.authcz.admin_dn": [tls_subject]}
            if (tls_subject := self.state.tls_subject)
            else {}
        )

    def _opensearch_tls_config(self, cert_type: CertType) -> dict[str, Any]:
        """Get set of TLS config options of provided cert_type for the Opensearch.

        Intended for opensearch.yml config file.
        """
        layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"

        return (
            {
                f"plugins.security.ssl.{layer}.keystore_type": "PKCS12",
                f"plugins.security.ssl.{layer}.keystore_filepath": f"{self.workload.paths.certs_relative}/{cert_type.val}.p12",
                f"plugins.security.ssl.{layer}.truststore_type": "PKCS12",
                f"plugins.security.ssl.{layer}.truststore_filepath": f"{self.workload.paths.certs_relative}/ca.p12",
                f"plugins.security.ssl.{layer}.keystore_alias": cert_type.val,
                f"plugins.security.ssl.{layer}.keystore_keypassword": keystore_pwd,
                f"plugins.security.ssl.{layer}.keystore_password": keystore_pwd,
                f"plugins.security.ssl.{layer}.truststore_password": truststore_pwd,
                f"plugins.security.ssl.{layer}.enabled_protocols": "TLSv1.2",
            }
            if (truststore_pwd := self.state.tls_truststore_password)
            and (keystore_pwd := self.state.get_tls_keystore_password(cert_type))
            else {}
        )

    @property
    def _opensearch_data_temperature(self) -> str | None:
        """Get current node data temperature configuration from nodes_config or deployment_desc."""
        if node := self.state.node_config:
            return node.temperature

        return (
            deployment_desc.config.data_temperature
            if (deployment_desc := self.state.application.deployment_desc)
            else None
        )

    @property
    def _opensearch_roles(self) -> list[str]:
        """Get current node configured roles from nodes_config or deployment_desc."""
        if node := self.state.node_config:
            return node.roles

        if self.state.application.deployment_desc:
            return self.state.computed_roles()

        return []

    def load_node(self) -> dict[str, Any]:
        """Load the opensearch.yml config of the node."""
        return self.yaml_setter.load(self.CONFIG_YML)

    def _update_static_jvm_options(self) -> None:
        """Update Opensearch JVM config file with the right static options."""
        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={self.workload.paths.logs}/")
        self.yaml_setter.append(
            self.JVM_OPTIONS,
            "-Djdk.tls.client.protocols=TLSv1.2",
        )

    def _update_static_security_options(self) -> None:
        """Update Opensearch security config file with the right static options.

        Configures TLS and basic http for clients.
        Intended for opensearch-security/config.yml file.
        """
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

    def update_seeds_config(self) -> None:
        """Reconcile Opensearch unicast_hosts.txt config file using values from nodes_config."""
        if nodes_config := self.state.application.nodes_config:
            self._update_seeds_file(
                [node.ip for node in list(nodes_config.values()) if node.is_cm_eligible()]
            )

    def _update_seeds_file(self, cm_ips: list[str] | None) -> None:
        """Reconcile Opensearch unicast_hosts.txt config file using provided values."""
        # only update the file if there is data to update
        if not cm_ips:
            return
        cm_ips_set = set(cm_ips)
        lines = "\n".join(sorted([entry for entry in cm_ips_set if entry.strip()]))
        self.workload.write_text(f"{lines}\n", self.workload.paths.seed_hosts)

    def update_profile_configuration(self, profile: OpenSearchProfile) -> bool:
        """Update Opensearch JVM config file with the values from provided performance profile.

        Returns:
            whether the configuration changed and restart required.
        """
        current_profile = self.state.server.profile
        logger.debug("current profile: %s, config profile: %s", current_profile, profile)
        if current_profile is None or current_profile != profile:
            self._update_jvm_heap_size(
                profile.get_jvm_heap_size(self.workload.meminfo()["MemTotal"])
            )
            self.state.server.profile = profile
            return True
        return False

    def _update_jvm_heap_size(self, heap_size_in_kb: int) -> None:
        """Update Opensearch JVM config file using the provided values."""
        self.yaml_setter.replace(
            self.JVM_OPTIONS,
            "-Xms[0-9]+[kmgKMG]",
            f"-Xms{str(heap_size_in_kb)}k",
            regex=True,
        )

        self.yaml_setter.replace(
            self.JVM_OPTIONS,
            "-Xmx[0-9]+[kmgKMG]",
            f"-Xmx{str(heap_size_in_kb)}k",
            regex=True,
        )
