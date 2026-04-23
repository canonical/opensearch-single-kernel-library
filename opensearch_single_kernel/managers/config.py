#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Config manager."""

import logging
from typing import Any

from opensearch_single_kernel.common.constants import (
    CA_ALIAS,
    CA_TRUSTSTORE_P12,
    CertType,
    Scope,
    Substrates,
)
from opensearch_single_kernel.core.models import OpenSearchProfile
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter, get_nested_value
from opensearch_single_kernel.utils.helpers import (
    get_k8s_seed_host,
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

        Updates opensearch.yml & unicast_hosts.txt & opensearch-security/config.yml config files
        and assures jvm.options is populated with right static options.

        Args:
            roles: override node roles got from nodes_config.
            cm_names: cluster manager nodes for bootstrapping.
            seed_hosts: override seed hosts got from nodes_config.
                        (Cluster Manager hosts to be written to unicast_hosts.txt)

        Returns:
            whether the config was changed.

        Raises:
            OpenSearchFileOperationError: if there is an error writing to any of the config files
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

        self.update_security_config()

        if seed_hosts:
            self._update_seeds_file(seed_hosts)
        else:
            self.update_seeds_config()

        self.state.server.last_host_ip = self.state.host_ip
        # rewrite() returns whether the on-disk YAML text changed after the update.
        return self.yaml_setter.rewrite(self.CONFIG_YML, config)

    def update_security_config(self) -> bool:
        """Reconcile whole Opensearch security config using values from application state.

        Updates opensearch-security/config.yml config file.

        Returns:
            whether the config was changed.
        """
        config = {
            "_meta": {
                "type": "config",
                "config_version": 2,
            },
            "config": {
                "dynamic": {
                    "authc": self._security_authc_static_config()
                    | self._security_authc_jwt_config()
                    | self._security_authc_oauth_config(),
                    "authz": self._security_authz_static_config(),
                },
            },
        }

        return self.yaml_setter.rewrite(self.SECURITY_CONFIG_YML, config)

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
            "node.name": self.state.unit_name,
            "network.host": self._network_hosts(),
            "http.publish_host": self.state.publish_host,
            "node.roles": sorted(roles),
            "node.attr.app_id": deployment_desc.app.id,  # Set the current app full id
            "path.data": self.workload.paths.data.as_posix(),
            "path.logs": self.workload.paths.logs.as_posix(),
            "path.home": self.workload.paths.home.as_posix(),
        }

    def _opensearch_host_config(self) -> dict[str, Any]:
        """Network publish host settings written to opensearch.yml."""
        return {"network.publish_host": self.state.publish_host}

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
            if (tls_subject := self.state.application.tls_subject)
            else {}
        )

    def _opensearch_tls_config(self, cert_type: CertType) -> dict[str, Any]:
        """Get set of TLS config options of provided cert_type for the Opensearch.

        Intended for opensearch.yml config file.
        """
        if cert_type == CertType.UNIT_HTTP:
            layer = "http"
            keystore_pwd = self.state.server.http_keystore_password
        else:
            layer = "transport"
            keystore_pwd = self.state.server.transport_keystore_password

        truststore_pwd = self.state.application.tls_truststore_password

        if not (truststore_pwd and keystore_pwd):
            return {}

        return {
            f"plugins.security.ssl.{layer}.keystore_type": "PKCS12",
            f"plugins.security.ssl.{layer}.keystore_filepath": f"{self.workload.paths.certs_relative}/{cert_type.val}.p12",
            f"plugins.security.ssl.{layer}.truststore_type": "PKCS12",
            f"plugins.security.ssl.{layer}.truststore_filepath": f"{self.workload.paths.certs_relative}/{CA_ALIAS}.p12",
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
        self.yaml_setter.replace(self.JVM_OPTIONS, "=logs/", f"={self.workload.paths.logs}/")
        self.yaml_setter.append(self.JVM_OPTIONS, "-Djdk.tls.client.protocols=TLSv1.2")

    @staticmethod
    def _security_authc_static_config() -> dict[str, Any]:
        """Get set of static config options for the Opensearch security.

        Intended for authc category in opensearch-security/config.yml config file.
        """
        return {
            "basic_internal_auth_domain": {
                "description": "Authenticate via HTTP Basic against internal users database",
                "http_enabled": True,
                "transport_enabled": True,
                "order": 4,
                "http_authenticator": {
                    "type": "basic",
                    "challenge": True,
                },
                "authentication_backend": {
                    "type": "intern",
                },
            },
            "clientcert_auth_domain": {
                "description": "Authenticate via SSL client certificates",
                "http_enabled": True,
                "transport_enabled": True,
                "order": 2,
                "http_authenticator": {
                    "type": "clientcert",
                    "challenge": False,
                    "config": {"username_attribute": "cn"},
                },
                "authentication_backend": {"type": "noop"},
            },
            "kerberos_auth_domain": {
                "http_enabled": False,
                "transport_enabled": False,
                "order": 6,
                "http_authenticator": {
                    "type": "kerberos",
                    "challenge": True,
                    "config": {"krb_debug": False, "strip_realm_from_principal": True},
                },
                "authentication_backend": {"type": "noop"},
            },
            "proxy_auth_domain": {
                "description": "Authenticate via proxy",
                "http_enabled": False,
                "transport_enabled": False,
                "order": 3,
                "http_authenticator": {
                    "type": "proxy",
                    "challenge": False,
                    "config": {
                        "user_header": "x-proxy-user",
                        "roles_header": "x-proxy-roles",
                    },
                },
                "authentication_backend": {"type": "noop"},
            },
            "ldap": {
                "description": "Authenticate via LDAP or Active Directory",
                "http_enabled": False,
                "transport_enabled": False,
                "order": 5,
                "http_authenticator": {
                    "type": "basic",
                    "challenge": False,
                },
                "authentication_backend": {
                    "type": "ldap",
                    "config": {
                        "enable_ssl": False,
                        "enable_start_tls": False,
                        "enable_ssl_client_auth": False,
                        "verify_hostnames": True,
                        "hosts": ["localhost:8389"],
                        "bind_dn": None,
                        "password": None,
                        "userbase": "ou=people,dc=example,dc=com",
                        "usersearch": "(sAMAccountName={0})",
                        "username_attribute": None,
                    },
                },
            },
        }

    def _security_authc_jwt_config(self) -> dict[str, Any]:
        """Get set of JWT auth config options for the Opensearch security.

        Intended for authc category in opensearch-security/config.yml config file.
        """
        jwt_config = self.state.server.jwt_auth_configuration
        return {
            "jwt_auth_domain": {
                "description": "Authenticate via Json Web Token",
                "http_enabled": bool(jwt_config),
                "transport_enabled": bool(jwt_config),
                "order": 0,
                "http_authenticator": {
                    "type": "jwt",
                    "challenge": False,
                    "config": (
                        {
                            "signing_key": jwt_config.signing_key,
                            "jwt_header": jwt_config.jwt_header,
                            "jwt_url_parameter": jwt_config.jwt_url_parameter,
                            "roles_key": jwt_config.roles_key,
                            "subject_key": jwt_config.subject_key,
                            "required_audience": jwt_config.required_audience,
                            "required_issuer": jwt_config.required_issuer,
                            "jwt_clock_skew_tolerance_seconds": jwt_config.jwt_clock_skew_tolerance_seconds,
                        }
                        if jwt_config
                        else {
                            "signing_key": "base64 encoded HMAC key or public RSA/ECDSA pem key",
                            "jwt_header": "Authorization",
                            "jwt_url_parameter": None,
                            "roles_key": None,
                            "subject_key": None,
                            "jwt_clock_skew_tolerance_seconds": 30,
                        }
                    ),
                },
                "authentication_backend": {"type": "noop"},
            }
        }

    def _security_authc_oauth_config(self) -> dict[str, Any]:
        """Get set of OAuth config options for the Opensearch security.

        Intended for authc category in opensearch-security/config.yml config file.
        """
        return (
            {
                "openid_auth_domain": {
                    "http_enabled": True,
                    "transport_enabled": True,
                    # NOTE: Order value needs to be lower than basic_internal_auth_domain section,
                    # which is set to 4 by default. Only available number is 1, if we want a
                    # different number, all other numbers need to be reshuffled.
                    "order": 1,
                    "http_authenticator": {
                        "type": "openid",
                        "challenge": False,
                        "config": {
                            "subject_key": "sub",
                            "openid_connect_url": self.state.server.oauth_openid_connect_url,
                            "openid_connect_idp": {
                                "enable_ssl": True,
                                "verify_hostnames": False,
                                # NOTE: this assumes Hydra and Opensearch
                                # are using the same certificates relation.
                                "pemtrustedcas_filepath": self.workload.paths.certs_chain.as_posix(),
                            },
                        },
                    },
                    "authentication_backend": {"type": "noop"},
                }
            }
            if self.state.server.oauth_openid_connect_url
            else {}
        )

    @staticmethod
    def _security_authz_static_config() -> dict[str, Any]:
        """Get set of static config options for the Opensearch security.

        Intended for authz category in opensearch-security/config.yml config file.
        """
        return {
            "roles_from_myldap": {
                "description": "Authorize via LDAP or Active Directory",
                "http_enabled": False,
                "transport_enabled": False,
                "authorization_backend": {
                    "type": "ldap",
                    "config": {
                        "enable_ssl": False,
                        "enable_start_tls": False,
                        "enable_ssl_client_auth": False,
                        "verify_hostnames": True,
                        "hosts": ["localhost:8389"],
                        "bind_dn": None,
                        "password": None,
                        "rolebase": "ou=groups,dc=example,dc=com",
                        "rolesearch": "(member={0})",
                        "userroleattribute": None,
                        "userrolename": "disabled",
                        "rolename": "cn",
                        "resolve_nested_roles": True,
                        "userbase": "ou=people,dc=example,dc=com",
                        "usersearch": "(uid={0})",
                    },
                },
            },
            "roles_from_another_ldap": {
                "description": "Authorize via another Active Directory",
                "http_enabled": False,
                "transport_enabled": False,
                "authorization_backend": {"type": "ldap"},
            },
        }

    def update_seeds_config(self) -> None:
        """Reconcile OpenSearch unicast_hosts.txt using values from nodes_config.

        Raises:
            OpenSearchFileOperationError: if there is an error writing to the seeds file.
        """
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
        """Reconcile OpenSearch unicast_hosts.txt using provided values.

        Args:
            seed_hosts: list of host IPs or DNS names to be written to unicast_hosts

        Returns:
            None

        Raises:
            OpenSearchFileOperationError: if there is an error writing to the seeds file.
        """
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
            truststore_path = self.workload.paths.certs / f"{CA_ALIAS}.p12"
            cacert_path = self.workload.paths.certs / CA_TRUSTSTORE_P12
            return keystore_path.exists() and truststore_path.exists() and cacert_path.exists()
        except Exception:
            return False

    def is_transport_tls_configured(self) -> bool:
        """Check if transport TLS is configured."""
        return self._is_tls_layer_configured("transport", "unit-transport.p12")

    def is_http_tls_configured(self) -> bool:
        """Check if HTTP TLS is configured."""
        return self._is_tls_layer_configured("http", "unit-http.p12")
