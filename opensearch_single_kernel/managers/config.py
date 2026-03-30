#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
from typing import Any

from opensearch_single_kernel.common.constants import CertType, Scope, Substrates
from opensearch_single_kernel.core.models import OpenSearchProfile
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter, get_nested_value
from opensearch_single_kernel.utils.helpers import (
    get_k8s_seed_host,
    path_as_posix,
)
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
        seed_hosts: list[str] | None = None,
    ) -> bool:
        """Reconcile whole Opensearch config using values from application state.

        Updates opensearch.yml & unicast_hosts.txt config files and assures
        jvm.options & opensearch-security/config.yml are populated with right static options.

        Args:
            roles: override node roles got from nodes_config.
            cm_names: cluster manager nodes for bootstrapping.
            seed_hosts: override seed hosts got from nodes_config.

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

        if seed_hosts:
            self._update_seeds_file(seed_hosts)
        else:
            self.update_seeds_config()

        self.state.server.last_host_ip = self.state.host_ip
        # rewrite() returns whether the on-disk YAML text changed after the update.
        return self.yaml_setter.rewrite(self.CONFIG_YML, config)

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

    def _network_hosts(self) -> list[str]:
        """Compute network.host entries for opensearch.yml."""
        # Include _local_ (localhost) so localhost checks can succeed (readiness, internal checks).
        return ["_site_", "_local_", *sorted(self.state.network_hosts)]

    def _opensearch_general_config(self, roles: list[str]) -> dict[str, Any]:
        """General OpenSearch settings written to opensearch.yml."""
        if not (deployment_desc := self.state.application.deployment_desc):
            return {}

        publish_host = (
            self.state.fqdn
            if self.state.substrate == Substrates.K8S
            else self.workload.get_publish_host()
        )

        return {
            "cluster.name": deployment_desc.config.cluster_name,
            "node.name": self.state.unit_name,
            "network.host": self._network_hosts(),
            "http.publish_host": publish_host or self.state.network_ingress_address,
            "node.roles": sorted(roles),
            "node.attr.app_id": deployment_desc.app.id,  # Set the current app full id
            "path.data": path_as_posix(self.workload.paths.data),
            "path.logs": path_as_posix(self.workload.paths.logs),
            "path.home": path_as_posix(self.workload.paths.home),
        }

    def _opensearch_host_config(self) -> dict[str, Any]:
        """Network publish host settings written to opensearch.yml."""
        return {"network.publish_host": self.state.host_ip} if self.state.host_ip else {}

    def _opensearch_temperature_config(self) -> dict[str, Any]:
        """Optional data temperature settings written to opensearch.yml."""
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
        """Get Admin DN settings to be written to opensearch.yml."""
        return (
            {"plugins.security.authcz.admin_dn": [tls_subject]}
            if (tls_subject := self.state.tls_subject)
            else {}
        )

    def _opensearch_tls_config(self, cert_type: CertType) -> dict[str, Any]:
        """TLS store settings written to opensearch.yml (paths + passwords)."""
        layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"
        truststore_pwd = self.state.tls_truststore_password
        keystore_pwd = self.state.get_tls_keystore_password(cert_type)
        if not truststore_pwd or not keystore_pwd:
            return {}

        return {
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

    @property
    def _opensearch_data_temperature(self) -> str | None:
        """Current node temperature from nodes_config or deployment_desc."""
        if node := self.state.node_config:
            return node.temperature
        return (
            deployment_desc.config.data_temperature
            if (deployment_desc := self.state.application.deployment_desc)
            else None
        )

    @property
    def _opensearch_roles(self) -> list[str]:
        """Current node roles from nodes_config or deployment_desc."""
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
        logs_path = path_as_posix(self.workload.paths.logs)
        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={logs_path}/")
        self.yaml_setter.append(self.JVM_OPTIONS, "-Djdk.tls.client.protocols=TLSv1.2")

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
        """Reconcile OpenSearch unicast_hosts.txt using values from nodes_config."""
        if nodes_config := self.state.application.nodes_config:
            if self.state.substrate == Substrates.K8S:
                self._update_seeds_file(
                    [
                        get_k8s_seed_host(node.name, node.app.name)
                        for node in nodes_config.values()
                        if node.is_cm_eligible()
                    ]
                )
            else:
                self._update_seeds_file(
                    [node.ip for node in nodes_config.values() if node.is_cm_eligible()]
                )

    def _update_seeds_file(self, seed_hosts: list[str] | None) -> None:
        """Reconcile OpenSearch unicast_hosts.txt using provided values."""
        if not seed_hosts:
            return
        lines = "\n".join(sorted(set(seed_hosts)))
        self.workload.write_text(f"{lines}\n", self.workload.paths.seed_hosts)

    def update_profile_configuration(self, profile: OpenSearchProfile) -> bool:
        """Update JVM heap based on the performance profile.

        Returns:
            whether the configuration changed and restart required.
        """
        current_profile = self.state.server.profile
        logger.debug("current profile: %s, config profile: %s", current_profile, profile)
        if current_profile is None or current_profile != profile:
            meminfo = self.workload.meminfo()
            self._update_jvm_heap_size(profile.get_jvm_heap_size(meminfo["MemTotal"]))
            self.state.server.profile = profile
            return True
        return False

    def _update_jvm_heap_size(self, heap_size_in_kb: int) -> None:
        """Update jvm.options heap values."""
        self.yaml_setter.replace(
            self.JVM_OPTIONS,
            "-Xms[0-9]+[kmgKMG]",
            f"-Xms{heap_size_in_kb}k",
            regex=True,
        )
        self.yaml_setter.replace(
            self.JVM_OPTIONS,
            "-Xmx[0-9]+[kmgKMG]",
            f"-Xmx{heap_size_in_kb}k",
            regex=True,
        )

    def _is_tls_layer_configured(self, layer: str, keystore_filename: str) -> bool:
        """Check if TLS config for a layer is present and files exist."""
        try:
            config = self.yaml_setter.load(self.CONFIG_YML)
            required_keys = [
                f"plugins.security.ssl.{layer}.keystore_filepath",
                f"plugins.security.ssl.{layer}.truststore_filepath",
                f"plugins.security.ssl.{layer}.keystore_password",
                f"plugins.security.ssl.{layer}.truststore_password",
            ]
            for key_path in required_keys:
                value = get_nested_value(config, key_path)
                if not (isinstance(value, str) and value.strip()):
                    return False

            keystore_path = self.workload.paths.certs / keystore_filename
            truststore_path = self.workload.paths.certs / "ca.p12"
            return keystore_path.exists() and truststore_path.exists()
        except Exception:
            return False

    def is_transport_tls_configured(self) -> bool:
        """Check if transport TLS is configured."""
        return self._is_tls_layer_configured("transport", "unit-transport.p12")

    def is_http_tls_configured(self) -> bool:
        """Check if HTTP TLS is configured."""
        return self._is_tls_layer_configured("http", "unit-http.p12")

    def ensure_k8s_tls_config_present(self) -> bool:
        """Ensure TLS config is present in opensearch.yml on K8s when TLS secrets are ready.

        Returns:
            bool: True when TLS config is already present or successfully written.
                False when TLS secrets are not ready yet.
        """
        if self.state.substrate != Substrates.K8S:
            return True

        admin_secrets = (
            self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )
        transport_secrets = (
            self.state.secrets.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val, peek=True) or {}
        )
        http_secrets = (
            self.state.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val, peek=True) or {}
        )

        truststore_pwd = admin_secrets.get("truststore-password")
        transport_keystore_pwd = transport_secrets.get("keystore-password")
        http_keystore_pwd = http_secrets.get("keystore-password")
        if not (truststore_pwd and transport_keystore_pwd and http_keystore_pwd):
            return False

        if self.is_transport_tls_configured() and self.is_http_tls_configured():
            return True

        # /etc/opensearch may come from image defaults.
        # Reconcile full config so TLS/admin DN are restored from state.
        self.update_opensearch_config()
        return True
