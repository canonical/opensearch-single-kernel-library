#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch TLS manager."""

import logging
import socket
from datetime import datetime
from typing import Any

from charmlibs import pathops
from charmlibs.pathops import PathProtocol
from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.constants import (
    CA_ALIAS,
    CERTS_EXPIRATION_DATE_FORMAT,
    OLD_CA_ALIAS,
    CertType,
    DeploymentType,
    Scope,
    StoreType,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
    OpenSearchHttpError,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    PeerClusterErrorDataStatuses,
    TlsStatuses,
)
from opensearch_single_kernel.core.models import (
    PeerClusterRelData,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.certificates import (
    cert_expiration_remaining_hours,
    parse_tls_file,
    read_ca,
    remove_ca,
    split_ca_chain,
    store_ca_chain,
)
from opensearch_single_kernel.utils.helpers import (
    generate_password,
)
from opensearch_single_kernel.utils.status import format_status
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class TlsManager(BaseManager):
    """OpenSearch TLS Manager.

    This manager provides functionalities to deal with certificates creation,
    signing request, managing the keystore, and updating secrets related to tls. It
    can be used by different events handlers not only tls events handler.
    """

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload, "tls_manager")

    def all_tls_resources_stored(  # noqa: C901
        self, only_unit_resources: bool = False, reconcile: bool = True
    ) -> bool:  # noqa: C901
        """Check if all TLS resources are stored and ready to use.

        For K8s, we need first to save TLS resources from secrets.

        Args:
            only_unit_resources (bool):
                If True, only check for unit TLS resources (transport and HTTP certs).
                If False, also check for app-level admin TLS resources.
            reconcile (bool):
                If True, perform reconciliation of K8s runtime TLS resources before checking.

        Returns:
            bool: True if all required TLS resources are stored and valid, False otherwise.
        """
        if self.state.substrate == Substrates.K8S and reconcile:
            try:
                self.reconcile_k8s_runtime_resources()
            except OpenSearchFileOperationError as e:
                logger.warning(
                    f"Error during TLS runtime resources reconciliation: {e}"
                )
                # If we cannot access the filesystem to check TLS resources
                # we assume they are not ready.
                return False

        cert_types = [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]
        if not only_unit_resources:
            cert_types.append(CertType.APP_ADMIN)

        # compare issuer of the cert with the issuer of the CA
        # if they don't match, certs are not up-to-date and need to be renewed after CA rotation
        if not (current_ca := self.read_stored_ca()):
            return False

        ca_issuer = self.get_cert_issuer(cert=current_ca)

        for cert_type in cert_types:
            cert_type_path = self.workload.paths.certs / f"{cert_type.val}.p12"
            try:
                if not self.workload.exists(cert_type_path):
                    return False
            except OpenSearchFileOperationError as e:
                logger.warning(
                    f"Error checking existence of TLS resource {cert_type_path}: {e}"
                )
                return False

            secret = self.get_secrets_for_cert_type(cert_type)

            cert_issuer = self.get_cert_issuer_from_path(
                store_pwd=secret.get("keystore-password"),
                store_path=self.workload.paths.certs / f"{cert_type.val}.p12",
            )
            if not cert_issuer:
                return False

            if cert_issuer != ca_issuer:
                return False
        logger.info("All TLS resources are stored on disk and valid.")
        return True

    def read_stored_ca(self, alias: str = CA_ALIAS) -> str | None:
        """Load stored CA cert."""
        admin_secrets = self.state.application.admin_secrets
        ca_trust_store = self.workload.paths.certs / f"{CA_ALIAS}.p12"
        logger.debug("Reading stored ca from %s", ca_trust_store)
        return read_ca(
            workload=self.workload,
            alias=alias,
            store_pwd=admin_secrets.get("truststore-password"),
            store_path=ca_trust_store,
        )

    def all_certificates_available(self) -> bool:
        """Method that checks if all certs available and issued from same CA."""
        admin_secrets = self.state.application.admin_secrets
        if not admin_secrets or not admin_secrets.get("cert"):
            return False

        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = self.get_secrets_for_cert_type(cert_type)
            if not unit_secrets or not unit_secrets.get("cert"):
                return False

        return True

    def is_fully_configured(self) -> bool:
        """Check if all TLS secrets and resources exist and are stored."""
        return self.all_certificates_available() and self.all_tls_resources_stored()

    def create_store_pwd_if_not_exists(
        self, scope: Scope, cert_type: CertType, store_type: StoreType
    ) -> None:
        """Create passwords for the key stores if not already created.

        Args:
            scope (Scope): The secret scope which can be UNIT / APP.
            cert_type (CertType): The secret certificate type (unit-http, unit-transport).
            store_type (StoreType): The type of store which can be "truststore" or "keystore".
        """
        store_pwd = None

        secrets = self.get_secrets_for_cert_type(cert_type)
        if secrets:
            store_pwd = secrets.get(f"{store_type.val}-password")

        if not store_pwd and not (
            self.state.is_peer_cluster_consumer(of="main")
            and cert_type == CertType.APP_ADMIN
        ):
            self.state.secrets.put_object(
                scope,
                cert_type.val,
                {f"{store_type.val}-password": generate_password()},
                merge=True,
            )

    def _get_certificate_subject(self, cert_type: CertType) -> str:
        """Get subject of the certificate.

        For K8s, prefer canonical service DNS over pod IP to keep CN stable.
        """
        if cert_type == CertType.APP_ADMIN:
            return "admin"

        if self.state.substrate == Substrates.K8S:
            # X.509 common names are limited to 64 characters. Use the unit_name
            # as CN and keep the full service FQDN in SANs for TLS hostname checks.
            return self.state.unit_name

        # VM: use unit IP from peer binding.
        return str(self.state.host_ip)

    def _get_sans(self, cert_type: CertType) -> dict[str, list[str]]:
        """Create a list of OID/IP/DNS names for an OpenSearch unit.

        Returns:
            A list representing the hostnames of the OpenSearch unit.
            or None if admin cert_type, because that cert is not tied to a specific host.
        """
        sans = {"sans_oid": ["1.2.3.4.5.5"]}  # required for node discovery
        if cert_type == CertType.APP_ADMIN:
            return sans

        # Base DNS names: how this unit can be addressed by clients and other nodes.
        # unit_name is the Juju unit, gethostname/getfqdn cover short and fully-qualified
        # hostnames used in configs or DNS.
        dns = {self.state.unit_name, socket.gethostname(), self.state.fqdn}
        logger.info(f"This is the current DNS {dns}")
        # VM certificates must be reachable by the unit IP. On K8s, pod IPs are ephemeral
        # across pod recreation, so only stable DNS names should be included.
        ips = (
            {self.state.host_ip}
            if self.state.substrate == Substrates.VM and self.state.host_ip
            else set()
        )

        if cert_type == CertType.UNIT_HTTP:
            # HTTP cert must also be valid for the address clients use to reach this
            # unit (load balancer, ingress, or public IP).
            # we always add the fqdn as SAN even for VM
            dns.add(self.state.fqdn)

            if self.state.substrate == Substrates.VM:
                ips.add(self.state.node_host)
                if public_ip := self.workload.get_host_public_ip():
                    ips.add(public_ip)

        # Enrich SANs via reverse DNS: add any hostnames that resolve to our IPs
        # so the certificate is accepted when clients connect by those names.
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

        sans["sans_ip"] = (
            [ip for ip in ips if ip.strip()]
            if self.state.substrate == Substrates.VM
            else []
        )
        sans["sans_dns"] = [entry for entry in dns if entry.strip()]

        return sans

    def create_certificate_signing_request(
        self,
        scope: Scope,
        cert_type: CertType,
        secret: dict[str, str] | None = None,
        tls_file: bool = True,
    ) -> bytes:
        """Create CSR and save certificate key and password in secrets."""
        key = None
        password = None
        if secret:
            key = secret.get("key") if secret.get("key") else None
            password = secret.get("key-password", None)

        if key is None:
            key = generate_private_key()
        else:
            if tls_file:
                key = parse_tls_file(key)

        if type(key) is str:
            key = key.encode("utf-8")

        if password is not None:
            password = password.encode("utf-8")

        subject = self._get_certificate_subject(cert_type)
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
        self,
        scope: Scope,
        cert_type: CertType,
        ca_chain: str,
        certificate: str,
        ca: str,
    ) -> None:
        """Update the certificate secrets if needed"""
        current_secret_obj = self.get_secrets_for_cert_type(cert_type)
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

        app_secrets = self.state.application.admin_secrets
        if is_secret_found(app_secrets):
            return Scope.APP, CertType.APP_ADMIN, app_secrets

        u_transport_secrets = self.state.server.transport_secrets
        if is_secret_found(u_transport_secrets):
            return Scope.UNIT, CertType.UNIT_TRANSPORT, u_transport_secrets

        u_http_secrets = self.state.server.http_secrets
        if is_secret_found(u_http_secrets):
            return Scope.UNIT, CertType.UNIT_HTTP, u_http_secrets

        return None

    def update_request_ca_bundle(self, ca_chain: str | None = None) -> bool:
        """Create a new chain.pem file for requests module.

        Returns:
            True on success, False if a filesystem error occurred.
        """
        logger.debug("Updating requests TLS CA bundle")
        if ca_chain is None:
            admin_secret = self.state.application.admin_secrets
            ca_chain = admin_secret.get("chain")

        # we store the pem format to make it easier for the python requests lib
        chain_path = self.workload.paths.certs_chain
        try:
            if parent_dir_path := chain_path.parent:
                self.workload.mkdir(parent_dir_path, parents=True, exist_ok=True)

            # if the chain.pem already contains the current CA chain, we can skip rewriting it
            bundle_content = (
                self.workload.read_text(chain_path)
                if self.workload.exists(chain_path)
                else ""
            )
            if ca_chain not in bundle_content:
                self.workload.write_text(f"{bundle_content}\n{ca_chain}", chain_path)
        except OpenSearchFileOperationError as e:
            logger.error("Error updating request CA bundle: %s", e)
            return False
        return True

    def _remove_ca_from_request_bundle(self, ca_cert: str) -> None:
        """Remove the CA cert from the request bundle for the requests module."""
        bundle_path = self.workload.paths.certs_chain
        if not self.workload.exists(bundle_path):
            return

        bundle_content = self.workload.read_text(bundle_path)
        self.workload.write_text(bundle_content.replace(ca_cert, ""), bundle_path)

    def store_new_tls_resources(
        self, cert_type: CertType, secrets: dict[str, Any]
    ) -> bool:
        """Add key and cert to keystore.

        Returns:
            True on success, False if a filesystem or command error occurred.
        """
        if not self.state.ca_rotation_complete_in_cluster:
            return True

        # if the TLS certificate is available before the keystore-password, create it anyway
        if cert_type == CertType.APP_ADMIN:
            self.create_store_pwd_if_not_exists(
                Scope.APP, cert_type, StoreType.KEYSTORE
            )
        else:
            self.create_store_pwd_if_not_exists(
                Scope.UNIT, cert_type, StoreType.KEYSTORE
            )

        if not secrets.get("key"):
            logger.error("TLS key not found, quitting.")
            return True
        logger.debug("Storing %s TLS resources on disk.", cert_type.val)
        try:
            self.store_key_pair(
                name=cert_type.val,
                store_pwd=secrets.get("keystore-password"),
                store_path=self.workload.paths.certs / f"{cert_type.val}.p12",
                cert=secrets.get("cert"),
                key=secrets.get("key"),
                key_pwd=secrets.get("key-password"),
            )
        except (OpenSearchFileOperationError, OpenSearchCmdError) as e:
            logger.error("Unable to store TLS resources for %s: %s", cert_type.val, e)
            return False
        return True

    def delete_stored_tls_resources(self) -> None:
        """Delete the TLS resources of the unit that are stored on disk."""
        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            certificate_path = self.workload.paths.certs / f"{cert_type}.p12"
            certificate_path.unlink(missing_ok=True)

    def store_key_pair(
        self,
        name: str,
        store_pwd: str,
        store_path: PathProtocol,
        cert: str,
        key: str,
        key_pwd: str | None,
    ) -> None:
        """Store cert in keystore."""
        logger.debug("Storing TLS key pair for %s at %s", name, store_path)
        certs_dir_path = self.workload.paths.certs
        self.workload.unlink(store_path, missing_ok=True)

        try:
            with (
                self.workload.temp_file(
                    mode="w+t", suffix=".pem", data=key, dir=certs_dir_path
                ) as tmp_key,
                self.workload.temp_file(
                    mode="w+t", suffix=".cert", data=cert, dir=certs_dir_path
                ) as tmp_cert,
            ):
                cmd = f"openssl pkcs12 -export -in {tmp_cert} -inkey {tmp_key} -out {store_path} -name {name}"
                args = f"-passout pass:{store_pwd}"
                if key_pwd:
                    args = f"{args} -passin pass:{key_pwd}"

                self.workload.run_cmd(cmd, args)
                self.workload.run_cmd(f"chmod +r {store_path}")
        except OpenSearchFileOperationError as e:
            logger.error("Error storing the TLS certificates for %s: %s", name, e)
            raise
        except OpenSearchCmdError as e:
            logger.error("Error storing the TLS certificates for %s: %s", name, e)
            raise

        logger.info("TLS certificate for %s stored.", name)
        return True

    def store_admin_tls_secrets_if_applies(self) -> bool:
        """Store admin TLS resources if available and mark unit as configured if correct.

        Returns:
            whether operation was successful.
        """
        # In the case of the first units before TLS is initialized,
        # or non-main orchestrator units having not received the secrets from the main yet
        if not (current_secrets := self.state.application.admin_secrets):
            return False

        # in the case the cluster was bootstrapped with multiple units at the same time
        # and the certificates have not been generated yet
        if not current_secrets.get("cert") or not current_secrets.get("chain"):
            return False

        # Store the "Admin" certificate, key and CA on the disk of the new unit
        if not self.store_new_tls_resources(CertType.APP_ADMIN, current_secrets):
            return False

        # Mark this unit as tls configured
        if self.is_fully_configured():
            self.state.server.tls_configured = True
            peer_cluster_servers = self.state.all_peer_clusters_servers(remote=False)
            for peer_cluster_server in peer_cluster_servers:
                peer_cluster_server.tls_configured = True
        return True

    def reconcile_k8s_runtime_resources(self) -> None:
        """Prepare the K8s runtime and restore TLS artifacts from secrets.

        On K8s, TLS material can be present in Juju secrets while the workload container
        filesystem is empty after pod restart or not yet prepared during early hook ordering.
        This reconciliation prepares the container runtime and then restores TLS files onto the
        workload filesystem.

        On VM, this is a no-op.
        """
        if self.state.substrate != Substrates.K8S:
            return

        # Fast path: if required TLS runtime artifacts already exist, skip heavy reconciliation.
        if self._k8s_runtime_tls_artifacts_ready():
            return

        # TODO: Address scenario of CA rotation
        self.restore_tls_files_from_secrets()

    def _k8s_runtime_tls_artifacts_ready(self) -> bool:
        """Return whether K8s TLS runtime files required by current secrets already exist."""
        certs_dir = self.workload.paths.certs
        if not self.workload.exists(certs_dir):
            return False

        admin_secrets = (
            self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
            or {}
        )
        if admin_secrets.get("ca-cert") and admin_secrets.get("truststore-password"):
            if not self.workload.exists(certs_dir / f"{CA_ALIAS}.p12"):
                return False
            if not self.workload.exists(certs_dir / "chain.pem"):
                return False

        for scope, cert_type in [
            (Scope.APP, CertType.APP_ADMIN),
            (Scope.UNIT, CertType.UNIT_TRANSPORT),
            (Scope.UNIT, CertType.UNIT_HTTP),
        ]:
            secrets = (
                self.state.secrets.get_object(scope, cert_type.val, peek=True) or {}
            )
            if not (
                secrets.get("cert")
                and secrets.get("key")
                and secrets.get("keystore-password")
            ):
                continue
            if not self.workload.exists(certs_dir / f"{cert_type.val}.p12"):
                return False

        return True

    def restore_tls_files_from_secrets(self) -> None:
        """Recreate TLS artifacts on disk from Juju secrets (K8s only).

        This is intended for pod restarts when the container filesystem is ephemeral and we do
        not want to depend on a persistent volume for /etc/opensearch/certificates.

        if secrets are not present yet, it does nothing.
        If Pebble/container isn't ready, it raises PebbleConnectionError so callers can defer.
        """
        if self.state.substrate != Substrates.K8S:
            return

        # ensure CA truststore + chain.pem (if secrets available).
        admin_secrets = (
            self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
            or {}
        )
        if admin_secrets.get("ca-cert") and admin_secrets.get("truststore-password"):
            # create_store_pwd=False, passwords should already be in secrets
            # don't mutate secrets here.
            # keep_previous=False: this is keystore recovery from secrets, not a rotation.
            self.store_new_ca(
                CertType.APP_ADMIN, create_store_pwd=False, keep_previous=False
            )

        # recreate PKCS12 stores for all cert types we might need on startup.
        for scope, cert_type in [
            (Scope.APP, CertType.APP_ADMIN),
            (Scope.UNIT, CertType.UNIT_TRANSPORT),
            (Scope.UNIT, CertType.UNIT_HTTP),
        ]:
            secrets = (
                self.state.secrets.get_object(scope, cert_type.val, peek=True) or {}
            )
            if not (
                secrets.get("cert")
                and secrets.get("key")
                and secrets.get("keystore-password")
            ):
                continue

            self.store_key_pair(
                name=cert_type.val,
                store_pwd=secrets.get("keystore-password"),
                store_path=self.workload.paths.certs / f"{cert_type.val}.p12",
                cert=secrets.get("cert"),
                key=secrets.get("key"),
                key_pwd=secrets.get("key-password"),
            )

    def get_cert_issuer(self, cert: str) -> str | None:
        """Retrieve the certificate issuer from a string certificate."""
        # to make sure the content is processed correctly by openssl, temporary store it in a file
        try:
            with self.workload.temp_file(
                mode="w+t", data=cert, dir=self.workload.root / "/tmp"
            ) as tmp_ca_file:
                return self.workload.run_cmd(
                    f"openssl x509 -in {tmp_ca_file} -noout -issuer"
                ).out
        except (OpenSearchCmdError, OpenSearchFileOperationError) as e:
            logger.error("Error reading the current truststore: %s", e)
            return None

    def get_cert_issuer_from_path(
        self, store_pwd: str, store_path: PathProtocol
    ) -> str | None:
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

    def reload_tls_certificates(self) -> bool:
        """Reload transport and HTTP layer communication certificates via REST APIs.

        Returns:
            True on success, False if the API call failed.
        """
        # using the SSL API requires authentication with app-admin cert and key
        admin_secret = self.state.application.admin_secrets
        # the certs need to be created on the charm container filesystem
        # because the OpenSearch client library expects file paths for the cert and key
        charm_container_tmp_dir = pathops.LocalPath("/tmp") / "opensearch-certs"
        self.workload.mkdir(charm_container_tmp_dir, parents=True, exist_ok=True)
        try:
            with (
                self.workload.temp_file(
                    mode="w+t",
                    data=admin_secret["cert"],
                    dir=charm_container_tmp_dir,
                ) as tmp_cert,
                self.workload.temp_file(
                    mode="w+t",
                    data=admin_secret["key"],
                    dir=charm_container_tmp_dir,
                ) as tmp_key,
            ):
                self.opensearch_client.reload_tls_certificates(
                    cert_files=(tmp_cert.as_posix(), tmp_key.as_posix())
                )
        except OpenSearchHttpError as e:
            logger.error("Could not reload TLS certificates via API: %s", e)
            return False
        return True

    def finalize_ca_certs_rotation(self) -> bool:
        """Handle the completion of CA rotation.

        Returns:
            True on success, False if a filesystem error occurred.
        """
        logger.info(
            "CA rotation completed. Deleting old CA and updating request bundle."
        )
        try:
            self.remove_old_ca()
            return self.update_request_ca_bundle()
        except OpenSearchFileOperationError as e:
            logger.error("Error removing old CA during rotation finalization: %s", e)
            return False

    def get_unit_certificates(self) -> dict[CertType, str]:
        """Retrieve the list of certificates for this unit."""
        certs = {}

        transport_secrets = self.state.server.transport_secrets
        if transport_secrets and transport_secrets.get("cert"):
            certs[CertType.UNIT_TRANSPORT] = transport_secrets["cert"]

        http_secrets = self.state.server.http_secrets
        if http_secrets and http_secrets.get("cert"):
            certs[CertType.UNIT_HTTP] = http_secrets["cert"]

        if self.state.server.is_app_leader:
            admin_secrets = self.state.application.admin_secrets
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
        secrets = self.state.application.admin_secrets
        if secrets is None:
            logger.error("Cannot remove old CA: admin secrets not found.")
            return
        trust_store_pwd = secrets.get("truststore-password")
        trust_store_path = self.workload.paths.certs / f"{CA_ALIAS}.p12"

        old_ca = self.read_stored_ca(alias=OLD_CA_ALIAS)
        # store_ca() persists each certificate in a chain under indexed aliases
        # like old-ca-0, old-ca-1 rather than a single old-ca entry, so
        # CA rotation cleanup must remove the same indexed aliases one by one.
        old_ca_aliases = (
            [f"{OLD_CA_ALIAS}-{i}" for i, _ in enumerate(split_ca_chain(old_ca))]
            if old_ca
            else [OLD_CA_ALIAS]
        )
        for alias in old_ca_aliases:
            remove_ca(
                workload=self.workload,
                alias=alias,
                store_pwd=trust_store_pwd,
                store_path=trust_store_path,
                use_sudo=self.state.substrate == Substrates.VM,
            )
        # remove it from the request bundle
        self._remove_ca_from_request_bundle(old_ca)

    def store_new_ca(
        self, cert_type: CertType, create_store_pwd: bool, keep_previous: bool = True
    ) -> bool:
        """Add new CA cert to trust store.

        keep_previous renames the current CA to old-ca before importing the new one, which is
        the behaviour required for a CA rotation. Callers that just rebuild the
        keystore from secrets (e.g. K8s pod-restart recovery) must pass keep_previous=False,
        otherwise they create an old-ca entry.

        Returns True on success, False if a filesystem error occurred.
        """
        if create_store_pwd:
            self.create_store_pwd_if_not_exists(
                Scope.APP, CertType.APP_ADMIN, StoreType.KEYSTORE
            )

        admin_secrets = self.state.application.admin_secrets
        cert_secrets = self.get_secrets_for_cert_type(cert_type)

        if not (
            cert_secrets.get("ca-cert") and admin_secrets.get("truststore-password")
        ):
            logger.error("CA cert or truststore-password not found, quitting.")
            return False

        try:
            if not store_ca_chain(
                workload=self.workload,
                alias=CA_ALIAS,
                store_pwd=admin_secrets.get("truststore-password"),
                store_path=self.workload.paths.certs / f"{CA_ALIAS}.p12",
                ca=cert_secrets.get("ca-cert"),
                keep_previous=keep_previous,
                use_sudo=self.state.substrate == Substrates.VM,
            ):
                return False
        except OpenSearchFileOperationError as e:
            logger.error("Error storing new CA certificate: %s", e)
            return False

        return self.update_request_ca_bundle(cert_secrets.get("chain"))

    def peer_cluster_error_from_tls(
        self, peer_cluster_rel_data: PeerClusterRelData
    ) -> PeerClusterRelErrorData | None:
        """Compute TLS related errors."""
        blocked_msg, should_sever_relation = None, False

        if self.all_tls_resources_stored():  # compare CAs
            unit_transport_ca_cert = self.state.secrets.get_object(
                Scope.UNIT, CertType.UNIT_TRANSPORT.val
            )["ca-cert"]
            if (
                unit_transport_ca_cert
                != peer_cluster_rel_data.credentials.admin_tls["ca-cert"]
            ):
                blocked_msg = PeerClusterErrorDataStatuses.CA_CERTIFICATE_MISMATCH_BETWEEN_CLUSTERS.value.message
                should_sever_relation = True

        if (
            peer_cluster_rel_data.credentials.admin_tls
            and not peer_cluster_rel_data.credentials.admin_tls.get(
                "truststore-password"
            )
        ):
            logger.info("Relation data for TLS is missing.")
            blocked_msg = PeerClusterErrorDataStatuses.CA_TRUSTSTORE_PASSWORD_NOT_AVAILABLE.value.message
            should_sever_relation = True

        if not blocked_msg:
            return None

        return PeerClusterRelErrorData(
            cluster_name=peer_cluster_rel_data.cluster_name,
            should_sever_relation=should_sever_relation,
            should_wait=not should_sever_relation,
            blocked_message=blocked_msg,
            deployment_desc=self.state.application.deployment_desc,
        )

    def get_secrets_for_cert_type(self, cert_type: CertType) -> dict[str, str]:
        """Get secrets for a given certificate type."""
        match cert_type:
            case CertType.APP_ADMIN:
                return self.state.application.admin_secrets
            case CertType.UNIT_TRANSPORT:
                return self.state.server.transport_secrets
            case CertType.UNIT_HTTP:
                return self.state.server.http_secrets

    def cleanup_peer_cluster_error_relation_data(self) -> None:
        """Clean up the error data in relation data when the error is resolved."""
        # copy the keys to avoid "dictionary changed size during iteration" error
        relation_items = list(self.state.application.relation_data.items())
        for key, _ in relation_items:
            if key.startswith("error_from_tls"):
                # get the relation id from key
                rel_id = int(key.split("-")[-1])
                relation_ids = [rel.id for rel in self.state.peer_cluster_relations]
                if rel_id not in relation_ids:
                    self.state.application.relation_data.pop(key)

    @override
    def get_statuses(  # noqa: C901
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute the manager's statuses."""
        status_list: list[StatusObject] = []

        if not self.state.tls_relation:
            # Unit will fail if we combine the two iF
            if (
                self.state.application.deployment_desc
                and self.state.application.deployment_desc.typ
                == DeploymentType.MAIN_ORCHESTRATOR
            ):
                status_list.append(TlsStatuses.TLS_RELATION_MISSING.value)
            return status_list

        # Means the unit is  being terminated
        if not self.state.peer_relation:
            return status_list

        if scope == "unit":
            if (
                self.state.server.tls_ca_renewing
                and not self.state.server.tls_ca_renewed
            ):
                status_list.append(TlsStatuses.TLS_CA_ROTATION.value)

            # If it is the main orchestrator then it will create all resources
            # Other types will wait for the Peer cluster Main, we also need to check
            # That the orchestrators field has been populated, otherwise it might
            # be a relation that is prohibited
            # Even the failover
            if (
                (
                    (deployment_desc := self.state.application.deployment_desc)
                    and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
                )
                or (
                    self.state.application.orchestrators_dict
                    and self.state.peer_clusters(remote=True, is_provider=False)
                )
                or self.state.peer_clusters(remote=True, is_provider=True)
            ):
                if not self.all_tls_resources_stored(reconcile=False):
                    status_list.append(TlsStatuses.TLS_NOT_FULLY_CONFIGURED.value)

            if not self.state.tls_relation and (certs := self.check_certs_expiration()):
                missing = [cert.val for cert in certs.keys()]
                status_list.append(
                    format_status(
                        TlsStatuses.TLS_CERTS_EXPIRATION_ERROR.value,
                        {"certificates": ", ".join(missing)},
                    )
                )

        if scope == "app":
            if (
                deployment_desc := self.state.application.deployment_desc
            ) and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
                if not self.all_tls_resources_stored():
                    status_list.append(TlsStatuses.TLS_NOT_FULLY_CONFIGURED.value)

            # Clean up any lingering errors
            self.cleanup_peer_cluster_error_relation_data()
            for peer_cluster in self.state.peer_clusters(
                remote=True, is_provider=False
            ):
                if self.state.application.relation_data.get(
                    f"error_from_tls-{peer_cluster.relation.id}"
                ):
                    status = PeerClusterRelErrorData.get_status_from_message(
                        self.state.application.relation_data[
                            f"error_from_tls-{peer_cluster.relation.id}"
                        ]
                    )
                    if status:
                        status_list.append(status)

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
