#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch TLS manager."""

import logging
import socket
from datetime import datetime
from typing import Any

from charmlibs.pathops import PathProtocol
from ops.pebble import ConnectionError as PebbleConnectionError

from opensearch_single_kernel.common.constants import (
    OPENSEARCH_RUN_AS_GROUP,
    OPENSEARCH_RUN_AS_USER,
    CertType,
    Scope,
    StoreType,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.certificates import (
    CA_ALIAS,
    CERTS_EXPIRATION_DATE_FORMAT,
    OLD_CA_ALIAS,
    read_ca,
    remove_ca,
    store_ca,
)
from opensearch_single_kernel.utils.helpers import (
    cert_expiration_remaining_hours,
    generate_password,
    parse_tls_file,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class TlsManager(BaseManager):
    """OpenSearch TLS Manager.

    This manager provides functionalities to deal with certificates creation,
    signing request, managing the keystore, and updating secrets related to tls. It
    can be used by different events handlers not only tls events handler.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "tls_manager"

    def _get_workload_uid_gid(self) -> tuple[int, int]:
        """Return numeric uid/gid used by the workload process.

        For Kubernetes substrates, the OpenSearch container runs as a fixed numeric UID/GID to
        match the rock image user definition. These IDs are used for best-effort `chown` calls
        when writing TLS artifacts. On VM, this value is currently unused.
        """
        return OPENSEARCH_RUN_AS_USER, OPENSEARCH_RUN_AS_GROUP

    @property
    def keytool(self) -> str:
        """Return the correct keytool command based on substrate.

        For VM (snap): uses 'opensearch.keytool' (snap command wrapper)
        For K8s: tries 'keytool' from PATH first, falls back to explicit JDK path

        Rationale:
        - VM uses snap installation where 'opensearch.keytool' is a snap command
          wrapper that ensures the correct Java version and environment
        - K8s containers: prefer keytool from PATH (more flexible), fallback to
          explicit JDK path if not found
        """
        if self.state.substrate == Substrates.VM:
            return "opensearch.keytool"
        else:  # K8S
            # Try keytool from PATH first using 'command -v' (more reliable than 'which')
            # Otherwise: command -v keytool || /path/to/keytool
            try:
                result = self.workload.run_cmd(
                    "bash",
                    args="-c 'command -v keytool >/dev/null 2>&1 && command -v keytool || echo FALLBACK'",
                    use_errors_replace=True,
                )
                keytool_from_path = result.out.strip()
                if keytool_from_path and keytool_from_path != "FALLBACK":
                    return keytool_from_path
            except OpenSearchCmdError:
                # keytool not in PATH, fallback to explicit path
                pass

            # Fallback to explicit JDK path
            # JDK path is typically: /usr/lib/jvm/java-21-openjdk-amd64
            jdk_path = self.workload.paths.jdk
            keytool_path = jdk_path / "bin" / "keytool"
            return str(keytool_path)

    def all_tls_resources_stored(self, only_unit_resources: bool = False) -> bool:  # noqa: C901
        """Check if all TLS resources are stored on disk."""
        cert_types = [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]
        if not only_unit_resources:
            cert_types.append(CertType.APP_ADMIN)

        # compare issuer of the cert with the issuer of the CA
        # if they don't match, certs are not up-to-date and need to be renewed after CA rotation
        if not (current_ca := self.read_stored_ca()):
            return False

        ca_issuer = self.get_cert_issuer(cert=current_ca)

        for cert_type in cert_types:
            # Use cert_type.val for explicit filename mapping
            # This ensures consistency: unit-transport.p12, unit-http.p12, app-admin.p12
            cert_type_path = self.workload.paths.certs / f"{cert_type.val}.p12"
            try:
                if not cert_type_path.exists():
                    return False
            except (PebbleConnectionError, AttributeError) as e:
                # If we can't check existence (e.g., container not ready, directory doesn't exist),
                # consider resources as not stored
                logger.debug(f"Could not check if certificate file exists {cert_type_path}: {e}")
                return False

            scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
            secret = self.state.secrets.get_object(scope, cert_type.val, peek=True)

            cert_issuer = self.get_cert_issuer_from_path(
                store_pwd=secret.get("keystore-password"),
                store_path=self.workload.paths.certs / f"{cert_type.val}.p12",
            )
            if not cert_issuer:
                return False

            if cert_issuer != ca_issuer:
                return False

        return True

    def read_stored_ca(self, alias: str = CA_ALIAS) -> str | None:
        """Load stored CA cert."""
        secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        ca_trust_store = self.workload.paths.certs / f"{CA_ALIAS}.p12"
        logger.debug(f"Reading stored ca from {ca_trust_store}")
        if not (ca_trust_store.exists() and secrets):
            return None

        return read_ca(
            workload=self.workload,
            alias=alias,
            store_pwd=secrets.get("truststore-password"),
            store_path=ca_trust_store,
        )

    def all_certificates_available(self) -> bool:
        """Method that checks if all certs available and issued from same CA."""
        secrets = self.state.secrets

        admin_secrets = secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        if not admin_secrets or not admin_secrets.get("cert"):
            return False

        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = secrets.get_object(Scope.UNIT, cert_type.val, peek=True)
            if not unit_secrets or not unit_secrets.get("cert"):
                return False

        return True

    def is_fully_configured(self) -> bool:
        """Check if all TLS secrets and resources exist and are stored."""
        return self.all_certificates_available() and self.all_tls_resources_stored()

    def create_store_pwd_if_not_exists(
        self, scope: Scope, cert_type: CertType, store_type: StoreType
    ):
        """Create passwords for the key stores if not already created.

        Args:
            scope (Scope): The secret scope which can be UNIT / APP.
            cert_type (CertType): The secret certificate type (unit-http, unit-transport).
            store_type (StoreType): The type of store which can be "truststore" or "keystore".
        """
        store_pwd = None

        secrets = self.state.secrets.get_object(scope, cert_type.val, peek=True)
        if secrets:
            store_pwd = secrets.get(f"{store_type.val}-password")

        if not store_pwd:
            # and not (
            # TODO: handle this once large deployment is implemented
            # self.charm.opensearch_peer_cm.is_consumer(of="main")
            # and cert_type == CertType.APP_ADMIN
            # ):

            self.state.secrets.put_object(
                scope,
                cert_type.val,
                {f"{store_type.val}-password": generate_password()},
                merge=True,
            )

    def _get_subject(self, cert_type: CertType) -> str:
        """Get subject of the certificate.

        For K8s, uses stable DNS name (unit name or public address) instead of
        ephemeral pod IP to prevent cert CN changes that cause reload failures.
        """
        if cert_type == CertType.APP_ADMIN:
            return "admin"

        if self.state.substrate == Substrates.K8S:
            # Use stable identity for K8s (DNS name or unit name)
            # This prevents cert CN changes when pod IPs change
            return self.workload.get_host_public_ip() or self.state.unit_name

        # VM: use host IP or fallback to unit name
        return self.state.host_ip or self.state.unit_name

    def _get_sans(self, cert_type: CertType) -> dict[str, list[str]]:
        """Create a list of OID/IP/DNS names for an OpenSearch unit.

        Returns:
            A list representing the hostnames of the OpenSearch unit.
            or None if admin cert_type, because that cert is not tied to a specific host.
        """
        sans = {"sans_oid": ["1.2.3.4.5.5"]}  # required for node discovery
        if cert_type == CertType.APP_ADMIN:
            return sans

        dns = {self.state.unit_name, socket.gethostname(), socket.getfqdn()}
        logger.info(f"This is the current DNS {dns}")
        ips = {self.state.host_ip} if self.state.host_ip else set()

        host_public_ip = self.workload.get_host_public_ip()
        if cert_type == CertType.UNIT_HTTP and host_public_ip:
            # For VM, get_host_public_ip() always returns an IP address
            # For K8s, get_host_public_ip() returns DNS name instead of IP
            if self.state.substrate == Substrates.VM:
                # VM always returns IP addresses
                ips.add(host_public_ip)
            else:
                # K8s: get_host_public_ip() returns DNS name
                dns.add(host_public_ip)

        # Skip reverse DNS lookups for K8s - they're expensive and can timeout
        # For VM, reverse DNS is acceptable
        if self.state.substrate == Substrates.VM:
            for ip in ips.copy():
                try:
                    name, aliases, addresses = socket.gethostbyaddr(ip)
                    logger.info(
                        f"This is the actual return of gethostbyaddr {name, aliases, addresses}"
                    )
                    ips.update(addresses)

                    dns.add(name)
                    dns.update(aliases)
                except (socket.herror, socket.gaierror):
                    continue

        sans["sans_ip"] = [ip for ip in ips if ip.strip()]
        sans["sans_dns"] = [entry for entry in dns if entry.strip()]

        return sans

    def create_certificate_signing_request(
        self,
        scope: Scope,
        cert_type: CertType,
        secrets: dict[str, str] | None = None,
        tls_file: bool = True,
    ) -> bytes:
        """Create CSR and save certificate key and password in secrets."""
        key = None
        password = None
        if secrets:
            key = secrets.get("key") if secrets.get("key") else None
            password = secrets.get("key-password", None)

        if key is None:
            key = generate_private_key()
        else:
            if tls_file:
                key = parse_tls_file(key)

        if type(key) is str:
            key = key.encode("utf-8")

        if password is not None:
            password = password.encode("utf-8")

        subject = self._get_subject(cert_type)
        organization = self.state.application.deployment_desc.config.cluster_name
        csr = generate_csr(
            add_unique_id_to_subject_name=False,
            private_key=key,
            private_key_password=password,
            subject=subject,
            organization=organization,
            **self._get_sans(cert_type),
        )

        self.state.secrets.put_object(
            scope=scope,
            key=cert_type.val,
            value={
                "key": key.decode("utf-8"),
                "key-password": password,
                "csr": csr.decode("utf-8"),
                "subject": f"/O={organization}/CN={subject}",
            },
            merge=True,
        )
        return csr

    def update_certificate_secret_if_needed(
        self, scope: Scope, cert_type: CertType, ca_chain: str, certificate: str, ca: str
    ):
        """Update the certificate secrets if needed"""
        current_secret_obj = self.state.secrets.get_object(scope, cert_type.val, peek=True) or {}
        secret = {
            "chain": current_secret_obj.get("chain"),
            "cert": current_secret_obj.get("cert"),
            "ca-cert": current_secret_obj.get("ca-cert"),
        }

        if secret != {"chain": ca_chain, "cert": certificate, "ca-cert": ca}:
            # Juju is not able to check if secrets' content changed between revisions
            # this IF is intended to reduce a storm of secret-removed/-changed events
            # for the same content
            self.state.secrets.put_object(
                scope,
                cert_type.val,
                {
                    "chain": ca_chain,
                    "cert": certificate,
                    "ca-cert": ca,
                },
                merge=True,
            )

    def find_secret(
        self, event_data: str, secret_name: str
    ) -> tuple[Scope, CertType, dict[str, str]] | None:
        """Find secret across all scopes (app, unit) and across all cert types.

        Returns:
            scope: scope type of the secret.
            cert type: certificate type of the secret (APP_ADMIN, UNIT_HTTP etc.)
            secret: dictionary of the data stored in this secret
        """

        def is_secret_found(secrets: dict[str, str] | None) -> bool:
            return (
                secrets is not None
                and secrets.get(secret_name, "").rstrip() == event_data.rstrip()
            )

        app_secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        if is_secret_found(app_secrets):
            return Scope.APP, CertType.APP_ADMIN, app_secrets

        u_transport_secrets = self.state.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, peek=True
        )
        if is_secret_found(u_transport_secrets):
            return Scope.UNIT, CertType.UNIT_TRANSPORT, u_transport_secrets

        u_http_secrets = self.state.secrets.get_object(
            Scope.UNIT, CertType.UNIT_HTTP.val, peek=True
        )
        if is_secret_found(u_http_secrets):
            return Scope.UNIT, CertType.UNIT_HTTP, u_http_secrets

        return None

    def update_request_ca_bundle(self, ca_chain: str | None = None) -> None:
        """Create a new chain.pem file for requests module"""
        logger.debug("Updating requests TLS CA bundle")
        if ca_chain is None:
            admin_secret = self.state.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val, peek=True
            )
            ca_chain = admin_secret.get("chain")

        # we store the pem format to make it easier for the python requests lib
        chain_path = self.workload.paths.certs / "chain.pem"
        if parent_dir_path := chain_path.parent:
            self.workload.mkdir(parent_dir_path, parents=True, exist_ok=True)

        # if the chain.pem already contains the current CA chain, we can skip rewriting it
        bundle_content = self.workload.read_text(chain_path) if chain_path.exists() else ""
        if ca_chain not in bundle_content:
            self.workload.write_text(f"{bundle_content}\n{ca_chain}", chain_path)

    def _remove_ca_from_request_bundle(self, ca_cert: str) -> None:
        """Remove the CA cert from the request bundle for the requests module."""
        bundle_path = self.workload.paths.certs / "chain.pem"
        if not bundle_path.exists():
            return

        bundle_content = self.workload.read_text(bundle_path)
        self.workload.write_text(bundle_content.replace(ca_cert, ""), bundle_path)

    def store_new_tls_resources(self, cert_type: CertType, secrets: dict[str, Any]) -> None:
        """Add key and cert to keystore."""
        if not self.state.ca_rotation_complete_in_cluster:
            return

        # if the TLS certificate is available before the keystore-password, create it anyway
        if cert_type == CertType.APP_ADMIN:
            self.create_store_pwd_if_not_exists(Scope.APP, cert_type, StoreType.KEYSTORE)
        else:
            self.create_store_pwd_if_not_exists(Scope.UNIT, cert_type, StoreType.KEYSTORE)

        if not secrets.get("key"):
            logger.error("TLS key not found, quitting.")
            return
        logger.debug(f"Storing {cert_type.val} TLS resources on disk.")
        self.store_key_pair(
            name=cert_type.val,
            store_pwd=secrets.get("keystore-password"),
            store_path=self.workload.paths.certs / f"{cert_type}.p12",
            cert=secrets.get("cert"),
            key=secrets.get("key"),
            key_pwd=secrets.get("key-password"),
        )

    def store_key_pair(  # noqa: C901
        self,
        name: str,
        store_pwd: str,
        store_path: PathProtocol,
        cert: str,
        key: str,
        key_pwd: str | None,
    ) -> None:
        """Store cert in keystore."""
        # Verify directory actually exists (critical check)
        cert_dir = str(self.workload.paths.certs)
        if self.state.substrate == Substrates.K8S:
            if hasattr(self.workload, "container") and self.workload.container:
                try:
                    if self.workload.container.can_connect():
                        if not self.workload.container.exists(cert_dir):
                            logger.error(
                                f"Certificates directory {cert_dir} does not exist after _ensure_cert_dir()!"
                            )
                            # Try one more time with direct mkdir
                            try:
                                self.workload.run_cmd(f"mkdir -p {cert_dir}")
                                self.workload.run_cmd(f"chmod 750 {cert_dir}")
                                logger.info(
                                    f"Created certificates directory via emergency fallback: {cert_dir}"
                                )
                            except Exception as emergency_error:
                                logger.error(
                                    f"Emergency directory creation also failed: {emergency_error}"
                                )
                                raise OpenSearchFileOperationError(
                                    f"Cannot create certificates directory {cert_dir}"
                                )
                except Exception as verify_error:
                    logger.warning(
                        f"Could not verify certificates directory existence: {verify_error}"
                    )

        # Wrap unlink in try/except for K8s pebble compatibility
        try:
            store_path.unlink(missing_ok=True)
        except (PebbleConnectionError, OSError) as e:
            logger.debug("Could not unlink %s (may not exist): %s", store_path, e)

        # Convert store_path to absolute string for openssl command
        # PathProtocol objects may not work correctly in shell commands
        store_path_str = str(store_path)
        if not store_path_str.startswith("/"):
            # If relative, make it absolute based on workload paths
            store_path_str = str(self.workload.paths.certs / store_path_str.lstrip("/"))

        # Get the directory for temp files (same directory as target file, like old VM code)
        # This matches the old VM code: dir=os.path.dirname(store_path)
        cert_dir = str(self.workload.paths.certs)

        # Ensure directory exists before creating temp files (critical!)
        # Old VM code assumed directory existed, but for K8s we must create it
        if self.state.substrate == Substrates.K8S:
            if hasattr(self.workload, "container") and self.workload.container:
                try:
                    if self.workload.container.can_connect():
                        if not self.workload.container.exists(cert_dir):
                            # Directory doesn't exist - create it now
                            self.workload.run_cmd(f"mkdir -p {cert_dir}")
                            self.workload.run_cmd(f"chmod 750 {cert_dir}")
                            logger.info(
                                f"Created certificates directory before storing key pair: {cert_dir}"
                            )
                except Exception as dir_error:
                    logger.warning(f"Could not ensure certificates directory exists: {dir_error}")

        with (
            self.workload.temp_file(
                mode="w+t", suffix=".pem", data=key, dir=self.workload.paths.certs
            ) as tmp_key,
            self.workload.temp_file(
                mode="w+t", suffix=".cert", data=cert, dir=self.workload.paths.certs
            ) as tmp_cert,
        ):
            # Use absolute path string for openssl output
            cmd = f"openssl pkcs12 -export -in {tmp_cert} -inkey {tmp_key} -out {store_path_str} -name {name}"
            args = f"-passout pass:{store_pwd}"
            if key_pwd:
                args = f"{args} -passin pass:{key_pwd}"

            try:
                self.workload.run_cmd(cmd, args)

                # Set file permissions (readable by owner/group, not world)
                chmod_cmd = (
                    f"chmod 640 {store_path_str}"
                    if self.state.substrate == Substrates.K8S
                    else f"sudo chmod 640 {store_path_str}"
                )
                try:
                    self.workload.run_cmd(chmod_cmd)
                except OpenSearchCmdError as e:
                    # If chmod fails, file may already have correct permissions
                    logger.debug(f"Could not set permissions on {store_path_str}: {e}")

                # For K8s, optionally set ownership using numeric UID/GID
                # This is best-effort only (may fail if running as non-root)
                if self.state.substrate == Substrates.K8S:
                    try:
                        uid, gid = self._get_workload_uid_gid()
                        chown_cmd = f"chown {uid}:{gid} {store_path_str}"
                        self.workload.run_cmd(chown_cmd)
                        logger.debug(f"Set ownership of {store_path_str} to {uid}:{gid}")
                    except OpenSearchCmdError as e:
                        # Expected to fail if running as non-root - fsGroup handles permissions
                        logger.debug(
                            f"Could not change ownership (non-critical, fsGroup handles this): {e}"
                        )
            except OpenSearchCmdError as e:
                logger.error("Error storing the TLS certificates for %s: %s", name, e)
                raise
        logger.info("TLS certificate for %s stored.", name)

    def store_admin_tls_secrets_if_applies(self) -> None:
        """Store admin TLS resources if available and mark unit as configured if correct."""
        # In the case of the first units before TLS is initialized,
        # or non-main orchestrator units having not received the secrets from the main yet
        if not (
            current_secrets := self.state.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val, peek=True
            )
        ):
            return

        # in the case the cluster was bootstrapped with multiple units at the same time
        # and the certificates have not been generated yet
        if not current_secrets.get("cert") or not current_secrets.get("chain"):
            return

        # Store the "Admin" certificate, key and CA on the disk of the new unit
        self.store_new_tls_resources(CertType.APP_ADMIN, current_secrets)

        # Mark this unit as tls configured
        if self.is_fully_configured():
            self.state.server.tls_configured = True
            # TODO: Update peer cluster relation
            # self.update_tls_flag_to_peer_cluster_relation("tls_configured", "add")

    def get_cert_issuer(self, cert: str) -> str | None:
        """Retrieve the certificate issuer from a string certificate."""
        # to make sure the content is processed correctly by openssl, temporary store it in a file
        try:
            with self.workload.temp_file(
                mode="w+t", data=cert, dir=self.workload.root / "/tmp"
            ) as tmp_ca_file:
                return self.workload.run_cmd(f"openssl x509 -in {tmp_ca_file} -noout -issuer").out
        except (OpenSearchCmdError, OpenSearchFileOperationError) as e:
            logger.error("Error reading the current truststore: %s", e)
            return None

    def get_cert_issuer_from_path(self, store_pwd: str, store_path: PathProtocol) -> str | None:
        """Retrieve the certificate issuer from the cert in the given PKCS12 store."""
        try:
            return self.workload.run_cmd(
                f"openssl pkcs12 -in {store_path}",
                f"""-nodes \
                -passin pass:{store_pwd} \
                | openssl x509 -noout -issuer
                """,
                use_errors_replace=True,
            ).out
        except OpenSearchCmdError as e:
            logger.error("Error reading the current certificate: %s", e)
            return None

    def reload_tls_certificates(self):
        """Reload transport and HTTP layer communication certificates via REST APIs."""
        # using the SSL API requires authentication with app-admin cert and key
        admin_secret = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        with (
            self.workload.temp_file(
                mode="w+t", data=admin_secret["cert"], dir=self.workload.paths.conf
            ) as tmp_cert,
            self.workload.temp_file(
                mode="w+t", data=admin_secret["key"], dir=self.workload.paths.conf
            ) as tmp_key,
        ):

            self.opensearch_client.reload_tls_certificates(
                cert_files=(str(tmp_cert), str(tmp_key))
            )

    def finalize_ca_certs_rotation(self) -> None:
        """Handle the completion of CA rotation."""
        logger.info("CA rotation completed. Deleting old CA and updating request bundle.")
        self.remove_old_ca()
        self.update_request_ca_bundle()

    def get_unit_certificates(self) -> dict[CertType, str]:
        """Retrieve the list of certificates for this unit."""
        certs = {}

        transport_secrets = self.state.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, peek=True
        )
        if transport_secrets and transport_secrets.get("cert"):
            certs[CertType.UNIT_TRANSPORT] = transport_secrets["cert"]

        http_secrets = self.state.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val, peek=True)
        if http_secrets and http_secrets.get("cert"):
            certs[CertType.UNIT_HTTP] = http_secrets["cert"]

        if self.state.server.is_app_leader:
            admin_secrets = self.state.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val, peek=True
            )
            if admin_secrets and admin_secrets.get("cert"):
                certs[CertType.APP_ADMIN] = admin_secrets["cert"]

        return certs

    def check_certs_expiration(self) -> dict[CertType, str] | None:
        """Checks the certificates' expiration. and return those expiring soon."""
        last_cert_check = datetime.strptime(
            self.state.server.certs_exp_checked_at, CERTS_EXPIRATION_DATE_FORMAT
        )

        # See if the last check was made less than 6h ago, if yes - leave
        if (datetime.now() - last_cert_check).seconds < 6 * 3600:
            return None

        certs = self.get_unit_certificates()

        # keep certificates that are expiring in less than 24h
        for cert_type in list(certs.keys()):
            hours = cert_expiration_remaining_hours(certs[cert_type])
            if hours > 24 * 7:
                del certs[cert_type]

        return certs

    def remove_old_ca(self) -> None:
        """Remove old CA cert from trust store."""
        secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        if secrets is None:
            logger.error("Cannot remove old CA: admin secrets not found.")
            return
        trust_store_pwd = secrets.get("truststore-password")
        trust_store_path = self.workload.paths.certs / f"{CA_ALIAS}.p12"

        old_ca = self.read_stored_ca(alias=OLD_CA_ALIAS)
        remove_ca(
            workload=self.workload,
            alias=OLD_CA_ALIAS,
            store_pwd=trust_store_pwd,
            store_path=trust_store_path,
            keytool_cmd=self.keytool,
        )
        # remove it from the request bundle
        self._remove_ca_from_request_bundle(old_ca)

    def store_new_ca(self, secrets: dict[str, Any], create_store_pwd: bool) -> bool:
        """Add new CA cert to trust store."""
        if create_store_pwd:
            self.create_store_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, StoreType.KEYSTORE)

        admin_secrets = (
            self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )

        if not ((secrets or {}).get("ca-cert") and admin_secrets.get("truststore-password")):
            logger.error("CA cert  or truststore-password not found, quitting.")
            return False

        if not store_ca(
            workload=self.workload,
            alias=CA_ALIAS,
            store_pwd=admin_secrets.get("truststore-password"),
            store_path=self.workload.paths.certs / f"{CA_ALIAS}.p12",
            ca=secrets.get("ca-cert"),
            keep_previous=True,
            keytool_cmd=self.keytool,
            use_sudo=self.state.substrate == Substrates.VM,
        ):
            return False

        self.update_request_ca_bundle(secrets.get("chain"))

        return True
