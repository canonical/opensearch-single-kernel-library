#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch TLS manager."""

import base64
import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from opensearch_single_kernel.common.constants import CertType, Scope
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import (
    generate_password,
    is_alias_missing_error,
    split_ca_chain,
)
from opensearch_single_kernel.workload.base import BaseWorkload


class TlsManager(BaseManager):
    """OpenSearch TLS Manager.

    This manager provides functionalities to deal with certificates creation,
    signing request, managing the keystore, and updating secrets related to tls. It
    can be used by different events handlers not only tls events handler.
    """

    CA_ALIAS = "ca"
    OLD_CA_ALIAS = f"old-{CA_ALIAS}"
    KEYTOOL = "opensearch.keytool"
    OLD_CA_PREFIX = "old-"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "tls_manager"

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
            if not self.workload.exists(f"{self.workload.paths.certs}/{cert_type}.p12"):
                return False

            scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
            secret = self.state.secrets.get_object(scope, cert_type.val, peek=True)

            cert_issuer = self.get_cert_issuer_from_path(
                store_pwd=secret.get("keystore-password"),
                store_path=f"{self.workload.paths.certs}/{cert_type}.p12",
            )
            if not cert_issuer:
                return False

            if cert_issuer != ca_issuer:
                return False

        return True

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

    def get_tls_status(self) -> bool:
        """Get TLS Status."""
        pass

    def create_keystore_pwd_if_not_exists(self, scope: Scope, cert_type: CertType, alias: str):
        """Create passwords for the key stores if not already created."""
        store_pwd = None
        store_type = "truststore" if alias == "ca" else "keystore"

        secrets = self.state.secrets.get_object(scope, cert_type.val, peek=True)
        if secrets:
            store_pwd = secrets.get(f"{store_type}-password")

        if not store_pwd:
            # and not (
            # TODO: handle this once large deployment is implemented
            # self.charm.opensearch_peer_cm.is_consumer(of="main")
            # and cert_type == CertType.APP_ADMIN
            # ):

            self.state.secrets.put_object(
                scope,
                cert_type.val,
                {f"{store_type}-password": generate_password()},
                merge=True,
            )

    @staticmethod
    def _parse_tls_file(raw_content: str) -> bytes:
        """Parse TLS files from both plain text or base64 format."""
        if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", raw_content):
            return re.sub(
                r"(-+(BEGIN|END) [A-Z ]+-+)",
                "\\1",
                raw_content,
            ).encode("utf-8")
        return base64.b64decode(raw_content)

    def _get_subject(self, cert_type: CertType) -> str:
        """Get subject of the certificate."""
        if cert_type == CertType.APP_ADMIN:
            cn = "admin"
        else:
            cn = self.state.host_ip

        return cn

    def _get_sans(self, cert_type: CertType) -> Dict[str, List[str]]:
        """Create a list of OID/IP/DNS names for an OpenSearch unit.

        Returns:
            A list representing the hostnames of the OpenSearch unit.
            or None if admin cert_type, because that cert is not tied to a specific host.
        """
        sans = {"sans_oid": ["1.2.3.4.5.5"]}  # required for node discovery
        if cert_type == CertType.APP_ADMIN:
            return sans

        dns = {self.state.unit_name, socket.gethostname(), socket.getfqdn()}
        ips = {self.state.host_ip}

        host_public_ip = self.workload.get_host_public_ip()
        if cert_type == CertType.UNIT_HTTP and host_public_ip:
            ips.add(host_public_ip)

        for ip in ips.copy():
            try:
                name, aliases, addresses = socket.gethostbyaddr(ip)
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
        key: Optional[str] = None,
        password: Optional[str] = None,
    ) -> bytes:
        """Create CSR and save certificate key and password in secrets."""
        if key is None:
            key = generate_private_key()
        else:
            key = self._parse_tls_file(key)

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
                "subject": f"/O={self.state.application.deployment_desc.config.cluster_name}/CN={subject}",
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
    ) -> Optional[Tuple[Scope, CertType, Dict[str, str]]]:
        """Find secret across all scopes (app, unit) and across all cert types.

        Returns:
            scope: scope type of the secret.
            cert type: certificate type of the secret (APP_ADMIN, UNIT_HTTP etc.)
            secret: dictionary of the data stored in this secret
        """

        def is_secret_found(secrets: Optional[Dict[str, str]]) -> bool:
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

    def read_ca(self, alias: str, store_pwd: str, store_path: str) -> Optional[str]:
        """Load stored CA cert."""
        return (self.list_cas(store_pwd, store_path) or {}).get(alias)

    def list_cas(self, store_pwd: str, store_path: str) -> Optional[dict[str, str]]:  # noqa: C901
        """List the CAs currently stored in a trust store.

        Args:
            store_pwd: Password for the trust store.
            store_path: Path to the trust store.

        Returns:
            A mapping from base alias to full concatenated PEM chain.
            If an alias is partitioned as <alias>-0, <alias>-1, ... in the store,
            they are reassembled and returned under the base <alias> key.
        """
        if not self.workload.exists(store_path):
            return None

        cmd = f"openssl pkcs12 -in {store_path}"
        args = f"-passin pass:{store_pwd}"
        try:
            stored_certs = self.workload.run_cmd(cmd, args, use_errors_replace=True).out
        except OpenSearchCmdError as e:
            self.logger.error("Error reading the current truststore: %s", e)
            return None

        # split by -----END CERTIFICATE-----
        cert_blocks = split_ca_chain(stored_certs)

        start_cert_marker = "-----BEGIN CERTIFICATE-----"
        chains: dict[str, list[tuple[int, str]]] = {}

        for block in cert_blocks:
            # find the friendlyName: line produced by openssl pkcs12
            alias_line = next(
                (line for line in block.split("\n") if line.strip().startswith("friendlyName:")),
                None,
            )
            alias = alias_line.split("friendlyName:", 1)[-1].strip()
            pem = f"{start_cert_marker}{block.split(start_cert_marker, 1)[1]}".strip()

            # parse optional trailing -<int> index
            base = alias
            idx = 0
            parts = alias.rsplit("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                # Only treat as index if suffix is purely digits
                idx = int(parts[1])
                base = parts[0]

            chains.setdefault(base, []).append((idx, pem))

        # reassemble chains in index order
        out: dict[str, str] = {}
        for base, items in chains.items():
            items.sort(key=lambda t: t[0])
            out[base] = "\n".join(p for _, p in items if p)

        return out

    def read_stored_ca(self, alias: str = CA_ALIAS) -> Optional[str]:
        """Load stored CA cert."""
        secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        ca_trust_store = f"{self.workload.paths.certs}/ca.p12"
        self.logger.debug(f"Reading stored ca from {ca_trust_store}")
        self.logger.debug(secrets)
        if not (self.workload.exists(ca_trust_store) and secrets):
            return None

        return self.read_ca(
            alias=alias,
            store_pwd=secrets.get("truststore-password"),
            store_path=f"{self.workload.paths.certs}/{self.CA_ALIAS}.p12",
        )

    def store_ca(
        self, alias: str, store_pwd: str, store_path: str, ca: str, keep_previous: bool = True
    ) -> bool:
        """Add new CA cert(s) to a PKCS12 trust store (generic).

        Args:
            alias: Alias to use for the CA certs.
            store_pwd: Password for the trust store.
            store_path: Path to the trust store.
            ca: CA cert(s) to store.
            keep_previous: Whether to keep the previous CA certs in the trust store.

        Returns:
            bool: True if the operation succeeded, False otherwise.
        """
        self.logger.info("Storing CA cert(s) with alias: %s into truststore.", alias)
        return self._store_ca_chain(
            alias=alias,
            store_pwd=store_pwd,
            store_path=store_path,
            ca=ca,
            keep_previous=keep_previous,
            add_read_perm=True,
        )

    def _store_ca_chain(  # noqa: C901
        self,
        *,
        alias: str,
        store_pwd: str,
        store_path: str,
        ca: str,
        keep_previous: bool,
        snap_user_with_write_permission: bool = False,
        add_read_perm: bool = False,
    ) -> bool:
        """Common implementation to store a CA chain into a PKCS12 keystore."""
        tmpdir = self.workload.dirname(store_path)
        starter_mode = "0664"
        snap_user = "snap_daemon:root"
        final_mode = "0640"
        # import root first, then intermediates
        certs = list(reversed(split_ca_chain(ca)))
        if snap_user_with_write_permission and self.workload.exists(store_path):
            try:
                self.workload.run_cmd(f"sudo chmod {starter_mode} {store_path}")
            except OpenSearchCmdError:
                pass

        for i, pem in enumerate(certs):
            internal_alias = f"{alias}-{i}"
            old_internal_alias = f"old-{alias}-{i}"

            # rename existing alias to old-<alias>-<i> if requested
            if keep_previous:
                try:
                    self.workload.run_cmd(
                        f"{self.KEYTOOL} -changealias "
                        f"-alias {internal_alias} -destalias {old_internal_alias} "
                        f"-keystore {store_path} -storetype PKCS12",
                        f"-storepass {store_pwd}",
                    )
                except OpenSearchCmdError as e:
                    msg = (e.out or "") + (e.err or "")
                    if ("does not exist" not in msg) and (
                        "Keystore file does not exist" not in msg
                    ):
                        return False

            # import the cert
            try:
                with self.workload.tempfile(
                    dir=tmpdir,
                    mode="w",
                    encoding="utf-8",
                    errors="replace",
                    delete=True,
                ) as tmp:
                    tmp.write(pem)
                    tmp.flush()
                    tmp_path = tmp.name

                    try:
                        self.workload.run_cmd(
                            f"{self.KEYTOOL} -importcert -noprompt "
                            f"-alias {internal_alias} -keystore {store_path} -file {tmp_path} -storetype PKCS12",
                            f"-storepass {store_pwd}",
                        )
                    except OpenSearchCmdError as e:
                        self.logger.error(
                            "Failed to import cert for alias %s into %s: %s",
                            internal_alias,
                            store_path,
                            (e.out or "") + (e.err or ""),
                        )
                        return False
            except OSError as e:
                # tmp file creation issues
                self.logger.error("Failed to create temporary file for CA import: %s", e)
                return False

        # post-actions
        try:
            command = ""
            if snap_user_with_write_permission:
                command = (
                    f"sudo chown {snap_user} {store_path}; sudo chmod {final_mode} {store_path};"
                )
            if add_read_perm:
                command += f"sudo chmod +r {store_path}"
            self.workload.run_cmd(command)
        except OpenSearchCmdError:
            pass

        return True

    def add_ca_to_request_bundle(self, ca_cert: str) -> None:
        """Add the CA cert to the request bundle for the requests module."""
        bundle_path = Path(self.workload.paths.certs) / "chain.pem"
        if not self.workload.exists(bundle_path):
            return

        bundle_content = self.workload.read_text(bundle_path)
        if ca_cert not in bundle_content:
            self.workload.write_text(bundle_path, f"{bundle_content}\n{ca_cert}")

    def store_new_tls_resources(self, cert_type: CertType, secrets: Dict[str, Any]):
        """Add key and cert to keystore."""
        if not self.state.ca_rotation_complete_in_cluster:
            return

        # if the TLS certificate is available before the keystore-password, create it anyway
        if cert_type == CertType.APP_ADMIN:
            self.create_keystore_pwd_if_not_exists(Scope.APP, cert_type, cert_type.val)
        else:
            self.create_keystore_pwd_if_not_exists(Scope.UNIT, cert_type, cert_type.val)

        if not secrets.get("key"):
            self.logger.error("TLS key not found, quitting.")
            return
        self.logger.debug(f"Storing {cert_type.val} TLS resources on disk.")
        self.store_key_pair(
            name=cert_type.val,
            store_pwd=secrets.get("keystore-password"),
            store_path=f"{self.workload.paths.certs}/{cert_type}.p12",
            cert=secrets.get("cert"),
            key=secrets.get("key"),
            key_pwd=secrets.get("key-password"),
        )

    def store_key_pair(
        self, name: str, store_pwd: str, store_path: str, cert: str, key: str, key_pwd: str | None
    ) -> None:
        """Store cert in keystore."""
        try:
            self.workload.remove_file(store_path)
        except OSError:
            pass

        with (
            self.workload.tempfile(
                mode="w+t", suffix=".pem", dir=self.workload.dirname(store_path)
            ) as tmp_key,
            self.workload.tempfile(
                mode="w+t", suffix=".cert", dir=self.workload.dirname(store_path)
            ) as tmp_cert,
        ):
            # Write key
            tmp_key.write(key)
            tmp_key.flush()
            tmp_key.seek(0)
            # Write Cert
            tmp_cert.write(cert)
            tmp_cert.flush()
            tmp_cert.seek(0)

            cmd = f"openssl pkcs12 -export -in {tmp_cert.name} -inkey {tmp_key.name} -out {store_path} -name {name}"
            args = f"-passout pass:{store_pwd}"
            if key_pwd:
                args = f"{args} -passin pass:{key_pwd}"

            try:
                self.workload.run_cmd(cmd, args)
                self.workload.run_cmd(f"sudo chmod +r {store_path}")
            except OpenSearchCmdError as e:
                self.logger.error("Error storing the TLS certificates for %s: %s", name, e)
        self.logger.info("TLS certificate for %s stored.", name)

    def update_request_ca_bundle(self) -> None:
        """Create a new chain.pem file for requests module"""
        self.logger.debug("Updating requests TLS CA bundle")
        admin_secret = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)

        # we store the pem format to make it easier for the python requests lib
        self.workload.write_file(
            f"{self.workload.paths.certs}/chain.pem",
            admin_secret["chain"],
        )

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

    def get_cert_issuer(self, cert: str) -> Optional[str]:
        """Retrieve the certificate issuer from a string certificate."""
        # to make sure the content is processed correctly by openssl, temporary store it in a file
        with self.workload.tempfile(mode="w+t", dir="/tmp") as tmp_ca_file:
            tmp_ca_file.write(cert)
            tmp_ca_file.flush()
            tmp_ca_file.seek(0)

            try:
                return self.workload.run_cmd(
                    f"openssl x509 -in {tmp_ca_file.name} -noout -issuer"
                ).out
            except OpenSearchCmdError as e:
                self.logger.error("Error reading the current truststore: %s", e)
                return None

    def get_cert_issuer_from_path(self, store_pwd: str, store_path: str) -> Optional[str]:
        """Retrieve the certificate issuer from a string certificate."""
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
            self.logger.error("Error reading the current certificate: %s", e)
            return None

    def reload_tls_certificates(self):
        """Reload transport and HTTP layer communication certificates via REST APIs."""
        url_http = "_plugins/_security/api/ssl/http/reloadcerts"
        url_transport = "_plugins/_security/api/ssl/transport/reloadcerts"

        # using the SSL API requires authentication with app-admin cert and key
        admin_secret = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        with (
            self.workload.tempfile(mode="w+t", dir=self.workload.paths.conf) as tmp_cert,
            self.workload.tempfile(mode="w+t", dir=self.workload.paths.conf) as tmp_key,
        ):
            tmp_cert.write(admin_secret["cert"])
            tmp_cert.flush()
            tmp_cert.seek(0)

            tmp_key.write(admin_secret["key"])
            tmp_key.flush()
            tmp_key.seek(0)

        try:
            self.opensearch_client.request(
                "PUT",
                url_http,
                cert_files=(tmp_cert.name, tmp_key.name),
                retries=3,
            )
            self.opensearch_client.request(
                "PUT",
                url_transport,
                cert_files=(tmp_cert.name, tmp_key.name),
                retries=3,
            )
        except OpenSearchHttpError as e:
            self.logger.error(f"Error reloading TLS certificates via API: {e}")
            raise

    def on_ca_certs_rotation_complete(self) -> None:
        """Handle the completion of CA rotation."""
        self.logger.info("CA rotation completed. Deleting old CA and updating request bundle.")
        self.remove_old_ca()
        self.update_request_ca_bundle()

    def remove_old_ca(self) -> None:
        """Remove old CA cert from trust store."""
        secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        trust_store_pwd = secrets.get("truststore-password")
        trust_store_path = f"{self.workload.paths.certs}/{self.CA_ALIAS}.p12"

        old_ca = self.read_stored_ca(alias=self.OLD_CA_ALIAS)
        self.remove_ca(
            alias=self.OLD_CA_ALIAS,
            store_pwd=trust_store_pwd,
            store_path=trust_store_path,
        )
        # remove it from the request bundle
        self._remove_ca_from_request_bundle(old_ca)

    def remove_ca(self, alias: str, store_pwd: str, store_path: str) -> None:
        """Remove old CA cert from the truststore.

        Args:
            alias: Alias to use for the CA certs.
            store_pwd: Password for the trust store.
            store_path: Path to the trust store.
        """
        if not self.workload.exists(store_path):
            self.logger.debug("Truststore %s does not exist, nothing to remove.", store_path)
            return

        list_cmd = f"{self.KEYTOOL} -list -keystore {store_path} -alias {alias} -storetype PKCS12"
        list_args = f"-storepass {store_pwd}"
        try:
            self.workload.run_cmd(list_cmd, list_args)
        except OpenSearchCmdError as e:
            if is_alias_missing_error(e, alias):
                self.logger.debug(
                    "Alias %s not found in %s when listing before delete, ignoring.",
                    alias,
                    store_path,
                )
                return
            # Anything else is a real error
            raise

        del_cmd = f"{self.KEYTOOL} -delete -keystore {store_path} -alias {alias} -storetype PKCS12"
        del_args = f"-storepass {store_pwd}"
        try:
            self.workload.run_cmd(del_cmd, del_args)
        except OpenSearchCmdError as e:
            if is_alias_missing_error(e, alias):
                self.logger.debug(
                    "Alias %s already gone from %s when deleting, ignoring.",
                    alias,
                    store_path,
                )
                return
            raise

        self.logger.info("Removed %s from truststore.", alias)

    def _remove_ca_from_request_bundle(self, ca_cert: str) -> None:
        """Remove the CA cert from the request bundle for the requests module."""
        bundle_path = Path(self.workload.paths.certs) / "chain.pem"
        if not self.workload.exists(str(bundle_path)):
            return

        bundle_content = self.workload.read_text(bundle_path)
        self.workload.write_text(bundle_path, bundle_content)
        bundle_path.write_text(bundle_content.replace(ca_cert, ""))
