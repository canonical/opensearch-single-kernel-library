#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
from typing import Any

from opensearch_single_kernel.common.constants import CertType, Substrates
from opensearch_single_kernel.common.exceptions import (
    ContainerNotReadyError,
    OpenSearchError,
)
from opensearch_single_kernel.core.models import OpenSearchProfile
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import (
    get_nested_value,
    normalized_tls_subject,
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

        return {
            "cluster.name": deployment_desc.config.cluster_name,
            "node.name": self.state.node_name,
            "network.host": self._network_hosts(),
            "http.publish_host": self.workload.get_host_public_ip()
            or self.state.network_ingress_address,
            "node.roles": sorted(roles),
            "node.attr.app_id": deployment_desc.app.id,  # Set the current app full id
            "path.data": path_as_posix(self.workload.paths.data_dir),
            "path.logs": path_as_posix(self.workload.paths.logs_dir),
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
        """Initial cluster-manager settings written to opensearch.yml."""
        if (
            not cm_names
            or "cluster_manager" not in roles
            or not self.state.server.is_bootstrap_contributor
        ):
            return {}

        if self.state.substrate == Substrates.K8S:
            # K8s bootstrap names must match OpenSearch runtime node.name (hostname).
            # Each unit writes its own hostname here.
            names = [self.state.node_name]
        else:
            names = sorted(cm_names)

        return {"cluster.initial_cluster_manager_nodes": names} if names else {}

    def _opensearch_admin_tls_config(self) -> dict[str, Any]:
        """Admin DN settings written to opensearch.yml."""
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
        """Node temperature from nodes_config or deployment_desc."""
        if node := self.state.node_config:
            return node.temperature
        return (
            deployment_desc.config.data_temperature
            if (deployment_desc := self.state.application.deployment_desc)
            else None
        )

    @property
    def _opensearch_roles(self) -> list[str]:
        """Node roles from nodes_config or deployment_desc."""
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
        logs_path = path_as_posix(self.workload.paths.logs_dir)
        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={logs_path}/")
        self.yaml_setter.append(self.JVM_OPTIONS, "-Djdk.tls.client.protocols=TLSv1.2")

    def _update_static_security_options(self) -> None:
        """Update OpenSearch security config file with static options."""
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
            self._update_seeds_file(
                [node.ip for node in nodes_config.values() if node.is_cm_eligible()]
            )

    def _update_seeds_file(self, cm_ips: list[str] | None) -> None:
        """Reconcile OpenSearch unicast_hosts.txt using provided values."""
        if not cm_ips:
            return
        cm_ips_set = {ip.strip() for ip in cm_ips if ip and ip.strip()}
        if not cm_ips_set:
            return
        lines = "\n".join(sorted(cm_ips_set))
        self.workload.write_text(f"{lines}\n", self.workload.paths.seed_hosts)

    def reconfigure_unit(self) -> bool:
        """Reconfigure this unit based on nodes_config (roles/temperature)."""
        if self.state.substrate == Substrates.K8S and not self.workload.workload_present:
            raise ContainerNotReadyError("Container is not ready for filesystem operations")

        if not (nodes_config := self.state.application.nodes_config):
            return False

        # Always refresh seed hosts when topology changes.
        self._update_seeds_file([n.ip for n in nodes_config.values() if n.is_cm_eligible()])

        node_conf = nodes_config.get(self.state.unit_name)
        if node_conf is None:
            return False

        config = self.yaml_setter.load(self.CONFIG_YML)
        stored_roles = sorted(config.get("node.roles") or [])
        new_roles = sorted(node_conf.roles or [])
        stored_temp = config.get("node.attr.temp")
        new_temp = node_conf.temperature

        if stored_roles == new_roles and stored_temp == new_temp:
            return False

        if stored_roles != new_roles:
            self.yaml_setter.put(self.CONFIG_YML, "node.roles", new_roles)
        if stored_temp != new_temp:
            if new_temp:
                self.yaml_setter.put(self.CONFIG_YML, "node.attr.temp", new_temp)
            else:
                self.yaml_setter.delete(self.CONFIG_YML, "node.attr.temp")

        return True

    def update_profile_configuration(self, profile: OpenSearchProfile) -> bool:
        """Update JVM heap based on the performance profile."""
        current_profile = self.state.server.profile
        logger.debug("current profile: %s, config profile: %s", current_profile, profile)
        if current_profile is None or current_profile != profile:
            meminfo = self.workload.meminfo()
            if "MemTotal" not in meminfo:
                logger.warning(
                    "Could not read MemTotal from meminfo. Skipping profile configuration."
                )
                return False
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

    def set_admin_tls_conf(self, secrets: dict[str, Any]) -> None:
        """Configure admin DN in opensearch.yml."""
        if "subject" not in secrets:
            raise OpenSearchError("Admin TLS secret missing subject")
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.authcz.admin_dn/{}",
            normalized_tls_subject(secrets["subject"]),
        )

    def set_node_tls_conf(self, cert_type: CertType, truststore_pwd: str, keystore_pwd: str):
        """Configure node TLS (HTTP or transport) in opensearch.yml."""
        layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"
        certs_dir = path_as_posix(self.workload.paths.certs)

        # Store paths
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.keystore_type",
            "PKCS12",
        )
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.keystore_filepath",
            f"{certs_dir}/{cert_type.val}.p12",
        )
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.truststore_type",
            "PKCS12",
        )
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.truststore_filepath",
            f"{certs_dir}/ca.p12",
        )

        # Passwords
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.keystore_password",
            keystore_pwd,
        )
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.truststore_password",
            truststore_pwd,
        )
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.enabled_protocols",
            "TLSv1.2",
        )

        # Enable TLS
        self.yaml_setter.put(self.CONFIG_YML, f"plugins.security.ssl.{layer}.enabled", True)

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
