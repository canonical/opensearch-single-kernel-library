#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
import socket
from collections import namedtuple
from typing import Any

from opensearch_single_kernel.common.constants import CertType, Substrates
from opensearch_single_kernel.common.exceptions import ContainerNotReadyError
from opensearch_single_kernel.core.models import App, Node, OpenSearchProfile
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.helpers import (
    get_nested_value,
    normalized_tls_subject,
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
    def yaml_setter(self):
        """Return the yaml_setter."""
        return YamlConfigSetter(self.workload)

    def _get_keytool_path(self) -> str:
        """Get the full path to keytool executable.

        keytool is part of the JDK and should be available at {JAVA_HOME}/bin/keytool.
        For K8s, JDK is at /usr/lib/jvm/java-21-openjdk-amd64.
        For VM, JDK path comes from workload.paths.jdk.

        Returns:
            Full path to keytool executable
        """
        java_home = str(self.workload.paths.jdk)
        return f"{java_home}/bin/keytool"

    def set_node(  # noqa: C901
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

        # For K8s, use container hostname for node.name to match OpenSearch runtime
        # OpenSearch uses hostname by default, so node.name must match or bootstrap fails
        # For VM, continue using unit_name (Juju unit name)
        if self.state.substrate == Substrates.K8S:
            try:
                # Get container hostname ("pod_name-0" in K8s pods)
                node_name = socket.gethostname()
                logger.info(
                    f"K8s detected: Using container hostname '{node_name}' for node.name (unit_name was '{unit_name}')"
                )
            except Exception as e:
                logger.warning(f"Could not get hostname, falling back to unit_name: {e}")
                node_name = unit_name
        else:
            # VM: use unit_name (Juju unit name)
            node_name = unit_name

        self.yaml_setter.put(self.CONFIG_YML, "node.name", node_name)
        #  Include _local_ (localhost) in network.host for K8s readiness checks
        # _site_ binds to pod IP (for external access via Kubernetes Service)
        # _local_ binds to localhost (for Pebble health checks and internal monitoring)
        # Both are needed: pod IP for external access, localhost for health checks
        network_hosts = ["_site_", "_local_"] + self.state.network_hosts
        self.yaml_setter.put(self.CONFIG_YML, "network.host", network_hosts)
        if self.state.host_ip:
            self.yaml_setter.put(self.CONFIG_YML, "network.publish_host", self.state.host_ip)
        # For K8s, get_host_public_ip() returns DNS name which never changes
        # For VM, returns IP address
        # DNS names are preferred for K8s as pod IPs are ephemeral.
        public_address = self.workload.get_host_public_ip() or self.state.network_ingress_address
        self.yaml_setter.put(self.CONFIG_YML, "http.publish_host", public_address)

        self.yaml_setter.put(self.CONFIG_YML, "node.roles", roles, inline_array=len(roles) == 0)
        if node_temperature:
            self.yaml_setter.put(self.CONFIG_YML, "node.attr.temp", node_temperature)
        else:
            self.yaml_setter.delete(self.CONFIG_YML, "node.attr.temp")

        # Set the current app full id
        self.yaml_setter.put(self.CONFIG_YML, "node.attr.app_id", app.id)

        # Use file-based discovery for hot reload of unicast_hosts.txt
        # This allows new CMs to be discovered automatically without restart
        self.yaml_setter.put(self.CONFIG_YML, "discovery.seed_providers", "file")
        self.add_seed_hosts(cm_ips)

        # Set initial cluster manager nodes for bootstrap
        # This is critical for brand-new clusters to elect a cluster-manager
        # Only set if this node is CM-eligible and will contribute to bootstrap
        if "cluster_manager" in roles:
            if contribute_to_bootstrap:
                # Set initial cluster manager nodes for bootstrap
                # For K8s, bootstrap names must match node.name (hostname), not unit_name
                # OpenSearch will fail with ClusterManagerNotDiscoveredException
                # if names don't match
                # For VM, use cm_names as-is (unit_name matches hostname)
                if self.state.substrate == Substrates.K8S:
                    # For K8s, we need to use hostnames instead of unit_names for bootstrap
                    # Single-node case: use current node's hostname
                    # Multi-node case: each node should use its own hostname
                    # Since we're setting this on the current node, use current node's hostname
                    # Other nodes will set their own hostnames when they bootstrap
                    bootstrap_cm_names = [node_name]
                    logger.info(
                        f"K8s bootstrap: Using hostname '{node_name}' for cluster.initial_cluster_manager_nodes "
                        f"(unit_name was '{unit_name}', cm_names was {cm_names})"
                    )
                else:
                    bootstrap_cm_names = cm_names

                self.yaml_setter.put(
                    self.CONFIG_YML, "cluster.initial_cluster_manager_nodes", bootstrap_cm_names
                )
                logger.info(
                    f"Setting bootstrap config: cluster.initial_cluster_manager_nodes={bootstrap_cm_names}"
                )
            elif not cm_names:
                # if no CM names provided but we are CM-eligible, log warning
                logger.warning(
                    "CM-eligible node but no CM names provided for bootstrap. "
                    "Cluster may fail to bootstrap."
                )

        # For K8s rock image, data and logs need subdirectories
        # path.data should be /var/lib/opensearch/data (not just /var/lib/opensearch)
        # path.logs should be /var/log/opensearch/logs (not just /var/log/opensearch)
        data_path = str(self.workload.paths.data)
        logs_path = str(self.workload.paths.logs)

        # Check if we're on K8s (rock image), paths won't have snap structure
        # For K8s, append /data and /logs subdirectories
        if "/var/lib/opensearch" in data_path and not data_path.endswith("/data"):
            data_path = f"{data_path}/data"
        if "/var/log/opensearch" in logs_path and not logs_path.endswith("/logs"):
            logs_path = f"{logs_path}/logs"

        self.yaml_setter.put(self.CONFIG_YML, "path.data", data_path)
        self.yaml_setter.put(self.CONFIG_YML, "path.logs", logs_path)

        # Use the computed logs_path (with /logs subdirectory) for JVM options
        # This ensures consistency between OpenSearch logs and GC logs
        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={logs_path}/")

        self.yaml_setter.put(self.CONFIG_YML, "plugins.security.disabled", False, sep=".")

        # security plugin rest API access
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.restapi.roles_enabled",
            ["all_access", "security_rest_api_access"],
            sep=".",  # we need to use sep as `.` as the default one is `/`.
        )
        # to use the PUT and PATCH methods of the security rest API
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.unsupported.restapi.allow_securityconfig_modification",
            True,
            sep=".",
        )

        # enable hot reload of TLS certs (without restarting the node)
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.ssl_cert_reload_enabled",
            True,
            sep=".",
        )

    def cleanup_initial_cluster_managers(self) -> None:
        """Update the opensearch.yaml by deleting initiali_cluster_manager_nodes."""
        self.yaml_setter.delete(self.CONFIG_YML, "cluster.initial_cluster_manager_nodes")

    def set_client_auth(self) -> None:
        """Configure TLS and basic http for clients."""
        # Set HTTP client auth mode to OPTIONAL to enable mTLS (mutual TLS) for HTTP layer
        # OPTIONAL allows clients to present certificates (required for securityadmin.sh)
        # but doesn't require all clients to use certs (more flexible than REQUIRE)
        # TODO this may be set to REQUIRED if we want to ensure certs provided by the client app
        self.yaml_setter.put(
            self.CONFIG_YML, "plugins.security.ssl.http.clientauth_mode", "OPTIONAL", sep="."
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
        """Update network host configuration if needed.

        Returns:
            bool: True if config was updated, False otherwise

        Raises:
            ContainerNotReadyError: If container is not ready (for K8s)
        """
        # For K8s, check container readiness before filesystem operations
        if self.state.substrate == Substrates.K8S and not self.workload.workload_present:
            raise ContainerNotReadyError("Container is not ready for filesystem operations")

        NetworkHost = namedtuple("NetworkHost", ["entry", "old", "new"])

        # Check if config file exists before trying to load it
        config_path = self.yaml_setter.base_path / self.CONFIG_YML
        if not config_path.exists():
            logger.debug(f"Config file {config_path} does not exist yet. Skipping host update.")
            return False

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
                # For K8s, get_host_public_ip() returns DNS name and for VM, it returns IP address
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

        Actually applies configuration changes (roles, temperature) and updates seed hosts.
        Returns True if opensearch.yml was reconfigured, in which case a restart will be required.
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
        stored_roles = current_conf.get("node.roles") or []
        new_conf_roles = new_node_conf.roles or []

        stored_temp = current_conf.get("node.attr.temp")
        new_temp = new_node_conf.temperature

        # Check if configuration actually changed
        if sorted(stored_roles) == sorted(new_conf_roles) and stored_temp == new_temp:
            # no conf change
            return False

        # Apply the configuration changes
        if sorted(stored_roles) != sorted(new_conf_roles):
            if new_conf_roles:
                self.yaml_setter.put(self.CONFIG_YML, "node.roles", new_conf_roles)
            else:
                self.yaml_setter.put(self.CONFIG_YML, "node.roles", [])

        if stored_temp != new_temp:
            if new_temp:
                self.yaml_setter.put(self.CONFIG_YML, "node.attr.temp", new_temp)
            else:
                self.yaml_setter.delete(self.CONFIG_YML, "node.attr.temp")

        return True

    def add_seed_hosts(self, cm_ips: list[str]) -> None:
        """Add CM nodes ips / host names to the seed host list of this unit."""
        cm_ips_set = set(cm_ips)

        # only update the file if there is data to update
        if cm_ips_set:
            lines = "\n".join([entry for entry in cm_ips_set if entry.strip()])
            self.workload.write_text(f"{lines}\n", self.workload.paths.seed_hosts)

    def _validate_tls_config_inputs(
        self, layer: str, certs_dir: str, truststore_pwd: str, keystore_pwd: str
    ) -> None:
        """Validate inputs for TLS configuration.

        Args:
            layer: TLS layer name ("transport" or "http").
            certs_dir: Directory path for certificates.
            truststore_pwd: Truststore password.
            keystore_pwd: Keystore password.

        Raises:
            RuntimeError: If any input is invalid.
        """
        if not certs_dir or not certs_dir.strip():
            raise RuntimeError(f"Cannot write {layer} TLS config: certs_dir is empty or None")
        if not certs_dir.startswith("/"):
            raise RuntimeError(
                f"Cannot write {layer} TLS config: certs_dir must be absolute path, got: {certs_dir}"
            )
        if not truststore_pwd or not truststore_pwd.strip():
            raise RuntimeError(f"Cannot write {layer} TLS config: truststore_pwd is empty or None")
        if not keystore_pwd or not keystore_pwd.strip():
            raise RuntimeError(f"Cannot write {layer} TLS config: keystore_pwd is empty or None")

    def _get_cert_filename(self, cert_type: CertType, store_type: str) -> str:
        """Get certificate filename for a given cert type and store type.

        Args:
            cert_type: Certificate type (UNIT_HTTP or UNIT_TRANSPORT).
            store_type: Store type ("keystore" or "truststore").

        Returns:
            Certificate filename (e.g., "unit-http.p12", "ca.p12").
        """
        if store_type == "truststore":
            return "ca.p12"
        if cert_type == CertType.UNIT_HTTP:
            return "unit-http.p12"
        if cert_type == CertType.UNIT_TRANSPORT:
            return "unit-transport.p12"
        return f"{cert_type.val}.p12"

    def _write_tls_store_configs(self, layer: str, cert_type: CertType, certs_dir: str) -> None:
        """Write keystore and truststore type and filepath configurations.

        Args:
            layer: TLS layer name ("transport" or "http").
            cert_type: Certificate type (UNIT_HTTP or UNIT_TRANSPORT).
            certs_dir: Directory path for certificates.
        """
        for store_type, cert in [("keystore", layer), ("truststore", "ca")]:
            # Set store type (PKCS12)
            self.yaml_setter.put(
                self.CONFIG_YML,
                f"plugins.security.ssl.{layer}.{store_type}_type",
                "PKCS12",
                sep=".",
            )

            # Set store filepath
            cert_filename = self._get_cert_filename(cert_type, store_type)
            self.yaml_setter.put(
                self.CONFIG_YML,
                f"plugins.security.ssl.{layer}.{store_type}_filepath",
                f"{certs_dir}/{cert_filename}",
                sep=".",
            )

    def _write_tls_passwords(self, layer: str, keystore_pwd: str, truststore_pwd: str) -> None:
        """Write keystore and truststore passwords.

        Args:
            layer: TLS layer name ("transport" or "http").
            keystore_pwd: Keystore password.
            truststore_pwd: Truststore password.
        """
        for store_type, pwd in [("keystore", keystore_pwd), ("truststore", truststore_pwd)]:
            self.yaml_setter.put(
                self.CONFIG_YML,
                f"plugins.security.ssl.{layer}.{store_type}_password",
                pwd,
                sep=".",
            )

    def _write_tls_layer_specific_configs(self, layer: str) -> None:
        """Write layer-specific TLS configurations (enabled flags, protocols, client auth).

        Args:
            layer: TLS layer name ("transport" or "http").
        """
        # Set enabled TLS protocols
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.enabled_protocols",
            "TLSv1.2",
            sep=".",
        )

        # Enable layer-specific TLS
        self.yaml_setter.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{layer}.enabled",
            True,
            sep=".",
        )
        logger.info(
            f"Enabled {layer} SSL after {layer} TLS configuration was written to opensearch.yml"
        )

        # Set HTTP client auth mode (only for HTTP layer)
        if layer == "http":
            self.yaml_setter.put(
                self.CONFIG_YML,
                "plugins.security.ssl.http.clientauth_mode",
                "OPTIONAL",
                sep=".",
            )
            logger.debug("Set HTTP clientauth_mode to OPTIONAL (mTLS enabled for HTTP layer)")

    def _validate_tls_config_after_write(self, layer: str) -> None:
        """Validate TLS configuration after writing to ensure all required keys are present.

        Args:
            layer: TLS layer name ("transport" or "http").

        Raises:
            RuntimeError: If required keys are missing or empty.
        """
        try:
            written_config = self.yaml_setter.load(self.CONFIG_YML)
            required_keys = [
                f"plugins.security.ssl.{layer}.keystore_filepath",
                f"plugins.security.ssl.{layer}.truststore_filepath",
                f"plugins.security.ssl.{layer}.keystore_password",
                f"plugins.security.ssl.{layer}.truststore_password",
            ]

            missing_keys = []
            empty_keys = []
            present_keys = []

            for key_path in required_keys:
                value = get_nested_value(written_config, key_path)
                if value is None:
                    missing_keys.append(key_path)
                elif not isinstance(value, str) or not value.strip():
                    empty_keys.append(key_path)
                else:
                    present_keys.append(key_path)

            if missing_keys or empty_keys:
                error_msg = (
                    f"CRITICAL: {layer} TLS config write failed! "
                    f"Missing keys: {missing_keys}. Empty keys: {empty_keys}. "
                    f"Present keys: {present_keys}"
                )
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            logger.info(
                f"Successfully wrote {layer} TLS configuration. "
                f"All required keys present and non-empty: {present_keys}"
            )
        except RuntimeError:
            raise
        except Exception as e:
            logger.warning(f"Could not verify {layer} TLS config after write: {e}")

    def set_node_tls_conf(self, cert_type: CertType, truststore_pwd: str, keystore_pwd: str):
        """Configures TLS for nodes.

        This method writes the complete TLS configuration (keystore/truststore paths and passwords)
        for either HTTP or transport layer. Both HTTP and transport TLS configs must be complete
        before OpenSearch can start with TLS enabled.

        Args:
            cert_type: Either CertType.UNIT_HTTP or CertType.UNIT_TRANSPORT
            truststore_pwd: Password for the CA truststore (ca.p12)
            keystore_pwd: Password for the unit keystore (unit-http.p12 or unit-transport.p12)
        """
        layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"
        certs_dir = str(self.workload.paths.certs)

        self._validate_tls_config_inputs(layer, certs_dir, truststore_pwd, keystore_pwd)

        config_path = self.yaml_setter.base_path / self.CONFIG_YML
        logger.info(
            f"Writing {layer} TLS configuration to {config_path} "
            f"(cert_type={cert_type.val}, certs_dir={certs_dir})"
        )

        # Write all TLS configurations
        self._write_tls_store_configs(layer, cert_type, certs_dir)
        self._write_tls_passwords(layer, keystore_pwd, truststore_pwd)
        self._write_tls_layer_specific_configs(layer)

        # Validate after write
        self._validate_tls_config_after_write(layer)

    def _is_tls_layer_configured(self, layer: str, keystore_filename: str) -> bool:
        """Check if TLS configuration for a specific layer is present and files exist.

        Args:
            layer: TLS layer name ("transport" or "http").
            keystore_filename: Expected keystore filename (e.g., "unit-transport.p12").

        Returns:
            True if all required config keys are present and certificate files exist.
        """
        try:
            config = self.yaml_setter.load(self.CONFIG_YML)
            required_keys = [
                f"plugins.security.ssl.{layer}.keystore_filepath",
                f"plugins.security.ssl.{layer}.truststore_filepath",
                f"plugins.security.ssl.{layer}.keystore_password",
                f"plugins.security.ssl.{layer}.truststore_password",
            ]

            # Check if all config keys are present and non-empty
            for key_path in required_keys:
                value = get_nested_value(config, key_path)
                if value is None:
                    logger.debug(f"{layer.capitalize()} TLS config missing key: {key_path}")
                    return False
                if not isinstance(value, str) or not value.strip():
                    logger.debug(
                        f"{layer.capitalize()} TLS config has empty value for key: {key_path}"
                    )
                    return False

            # Verify certificate files exist
            keystore_path = self.workload.paths.certs / keystore_filename
            truststore_path = self.workload.paths.certs / "ca.p12"

            if not keystore_path.exists():
                logger.debug(f"{layer.capitalize()} keystore file not found: {keystore_path}")
                return False

            if not truststore_path.exists():
                logger.debug(f"{layer.capitalize()} truststore file not found: {truststore_path}")
                return False

            return True
        except Exception as e:
            logger.debug(f"Could not check {layer} TLS config: {e}")
            return False

    def is_transport_tls_configured(self) -> bool:
        """Check if transport TLS configuration is present in opensearch.yml and files exist."""
        return self._is_tls_layer_configured("transport", "unit-transport.p12")

    def is_http_tls_configured(self) -> bool:
        """Check if HTTP TLS configuration is present in opensearch.yml and files exist."""
        return self._is_tls_layer_configured("http", "unit-http.p12")

    def _repair_tls_config_if_needed(
        self, cert_type: CertType, keystore_filename: str, layer: str
    ) -> bool:
        """Repair TLS configuration if certificate files exist but config is missing.

        Args:
            cert_type: Certificate type (UNIT_HTTP or UNIT_TRANSPORT).
            keystore_filename: Expected keystore filename (e.g., "unit-http.p12").
            layer: TLS layer name ("transport" or "http").

        Returns:
            True if config was written, False otherwise.
        """
        from opensearch_single_kernel.common.constants import Scope

        keystore_path = self.workload.paths.certs / keystore_filename
        truststore_path = self.workload.paths.certs / "ca.p12"

        if not (keystore_path.exists() and truststore_path.exists()):
            return False

        # Check if config is already present
        is_configured = (
            self.is_transport_tls_configured()
            if layer == "transport"
            else self.is_http_tls_configured()
        )
        if is_configured:
            return False

        logger.info(
            f"{layer.capitalize()} TLS certificate files exist but config is missing. "
            f"Writing {layer} TLS configuration to opensearch.yml."
        )

        try:
            admin_secrets = (
                self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
            )
            truststore_pwd = admin_secrets.get("truststore-password")

            unit_secrets = (
                self.state.secrets.get_object(Scope.UNIT, cert_type.val, peek=True) or {}
            )
            keystore_pwd = unit_secrets.get("keystore-password")

            if not (truststore_pwd and keystore_pwd):
                logger.warning(
                    f"{layer.capitalize()} TLS certificates exist but passwords are missing. "
                    f"Cannot write {layer} TLS config."
                )
                return False

            self.set_node_tls_conf(
                cert_type, truststore_pwd=truststore_pwd, keystore_pwd=keystore_pwd
            )
            logger.info(f"Successfully wrote {layer} TLS configuration.")
            return True
        except Exception as e:
            logger.warning(f"Failed to write {layer} TLS config: {e}")
            return False

    def ensure_tls_config_if_certificates_exist(self) -> bool:
        """Ensure TLS configuration is written if certificate files exist but config is missing.

        This is a repair function that handles cases where certificate files were stored
        but the TLS configuration wasn't written to opensearch.yml (e.g., due to race
        conditions or event ordering issues).

        Returns:
            bool: True if config was written or already exists, False if certificates don't exist
        """
        from opensearch_single_kernel.common.constants import CertType

        written_transport = self._repair_tls_config_if_needed(
            CertType.UNIT_TRANSPORT, "unit-transport.p12", "transport"
        )
        written_http = self._repair_tls_config_if_needed(
            CertType.UNIT_HTTP, "unit-http.p12", "http"
        )

        return written_transport or written_http

    def set_admin_tls_conf(self, secrets: dict[str, Any]) -> None:
        """Configures the admin certificate."""
        self.yaml_setter.put(
            self.CONFIG_YML,
            "plugins.security.authcz.admin_dn/{}",
            normalized_tls_subject(secrets["subject"]),
        )

    def set_profile_configuration_if_needed(
        self, current_profile: OpenSearchProfile, config_profile: OpenSearchProfile
    ) -> bool:
        """Configure the profile and return whether restart is needed or not"""
        logger.debug("current profile: %s, config profile: %s", current_profile, config_profile)
        if current_profile is None or current_profile != config_profile:
            meminfo_data = self.workload.meminfo()
            if "MemTotal" not in meminfo_data:
                logger.warning(
                    "Could not read MemTotal from meminfo. Skipping profile configuration."
                )
                return False

            self.set_jvm_heap_size(config_profile.get_jvm_heap_size(meminfo_data["MemTotal"]))

            # store profile in unit state
            self.state.server.profile = config_profile
            return True
        return False

    def set_jvm_heap_size(self, heap_size_in_kb: int) -> None:
        """Apply the performance profile's jvm heap size to the opensearch config."""
        # Check if jvm.options file exists before trying to modify it
        jvm_options_path = self.yaml_setter.base_path / self.JVM_OPTIONS
        if not jvm_options_path.exists():
            logger.debug(
                f"JVM options file {jvm_options_path} does not exist yet. Skipping heap size configuration."
            )
            return

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
