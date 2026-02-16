#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for reading / writing certificates."""
import logging

from charmlibs.pathops import PathProtocol

from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
)
from opensearch_single_kernel.utils.helpers import is_alias_missing_error
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


CA_ALIAS = "ca"
OLD_CA_ALIAS = f"old-{CA_ALIAS}"
KEYTOOL = "opensearch.keytool"
OLD_CA_PREFIX = "old-"
CERTS_EXPIRATION_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def read_ca(
    workload: BaseWorkload, alias: str, store_pwd: str, store_path: PathProtocol
) -> str | None:
    """Load stored CA cert."""
    return (list_cas(workload, store_pwd, store_path) or {}).get(alias)


def list_cas(
    workload: BaseWorkload, store_pwd: str, store_path: PathProtocol
) -> dict[str, str] | None:  # noqa: C901
    """List the CAs currently stored in a trust store.

    Args:
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.

    Returns:
        A mapping from base alias to full concatenated PEM chain.
        If an alias is partitioned as <alias>-0, <alias>-1, ... in the store,
        they are reassembled and returned under the base <alias> key.
    """
    if not store_path.exists():
        return None

    cmd = f"openssl pkcs12 -in {store_path}"
    args = f"-passin pass:{store_pwd}"
    try:
        stored_certs = workload.run_cmd(cmd, args, use_errors_replace=True).out
    except OpenSearchCmdError as e:
        logger.error("Error reading the current truststore: %s", e)
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
        if alias_line is None:
            continue
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


def store_ca(
    workload: BaseWorkload,
    alias: str,
    store_pwd: str,
    store_path: PathProtocol,
    ca: str,
    keep_previous: bool = True,
    use_sudo: bool = True,
    keytool_cmd: str = KEYTOOL,
) -> bool:
    """Add new CA cert(s) to a PKCS12 trust store (generic).

    Args:
        alias: Alias to use for the CA certs.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
        ca: CA cert(s) to store.
        keep_previous: Whether to keep the previous CA certs in the trust store.
        use_sudo: use sudo if set to True
        keytool_cmd: Command to perform keytool operation.

    Returns:
        bool: True if the operation succeeded, False otherwise.
    """
    logger.info("Storing CA cert(s) with alias: %s into truststore.", alias)
    return store_ca_chain(
        workload,
        alias=alias,
        store_pwd=store_pwd,
        store_path=store_path,
        ca=ca,
        keep_previous=keep_previous,
        add_read_perm=True,
        use_sudo=use_sudo,
        keytool_cmd=keytool_cmd,
    )


def store_ca_chain(  # noqa: C901
    workload: BaseWorkload,
    *,
    alias: str,
    store_pwd: str,
    store_path: PathProtocol,
    ca: str,
    keep_previous: bool,
    snap_user_with_write_permission: bool = False,
    add_read_perm: bool = False,
    use_sudo: bool = True,
    keytool_cmd: str = KEYTOOL,
) -> bool:
    """Common implementation to store a CA chain into a PKCS12 keystore."""
    sudo_prefix = "sudo " if use_sudo else ""
    tmpdir = store_path.parent
    starter_mode = "0664"
    snap_user = "snap_daemon:root"
    final_mode = "0640"
    # import root first, then intermediates
    certs = list(reversed(split_ca_chain(ca)))
    if snap_user_with_write_permission and store_path.exists():
        try:
            workload.run_cmd(f"{sudo_prefix}chmod {starter_mode} {store_path}")
        except OpenSearchCmdError:
            pass

    for i, pem in enumerate(certs):
        internal_alias = f"{alias}-{i}"
        old_internal_alias = f"old-{alias}-{i}"

        # rename existing alias to old-<alias>-<i> if requested
        if keep_previous:
            try:
                workload.run_cmd(
                    f"{keytool_cmd} -changealias "
                    f"-alias {internal_alias} -destalias {old_internal_alias} "
                    f"-keystore {store_path} -storetype PKCS12",
                    f"-storepass {store_pwd}",
                )
            except OpenSearchCmdError as e:
                msg = (e.out or "") + (e.err or "")
                if ("does not exist" not in msg) and ("Keystore file does not exist" not in msg):
                    return False

        # import the cert
        try:
            with workload.temp_file(
                dir=tmpdir.parent,
                data=pem,
                mode="w",
                encoding="utf-8",
                errors="replace",
                delete=True,
            ) as tmp_path:
                try:
                    workload.run_cmd(
                        f"{keytool_cmd} -importcert -noprompt "
                        f"-alias {internal_alias} -keystore {store_path} -file {tmp_path} -storetype PKCS12",
                        f"-storepass {store_pwd}",
                    )
                except OpenSearchCmdError as e:
                    logger.error(
                        "Failed to import cert for alias %s into %s: %s",
                        internal_alias,
                        store_path,
                        (e.out or "") + (e.err or ""),
                    )
                    return False
        except (OSError, OpenSearchFileOperationError) as e:
            # tmp file creation issues
            logger.error("Failed to create temporary file for CA import: %s", e)
            return False

    # post-actions
    try:
        command = ""
        if snap_user_with_write_permission:
            command = (
                f"{sudo_prefix}chown {snap_user} {store_path}; "
                f"{sudo_prefix}chmod {final_mode} {store_path};"
            )
        if add_read_perm:
            command += f"{sudo_prefix}chmod +r {store_path}"
        if command:
            workload.run_cmd(command)
    except OpenSearchCmdError:
        pass

    return True


def remove_ca(
    workload: BaseWorkload,
    alias: str,
    store_pwd: str,
    store_path: PathProtocol,
    keytool_cmd: str = KEYTOOL,
) -> None:
    """Remove old CA cert from the truststore.

    Args:
        workload: The workload instance to run commands.
        alias: Alias to use for the CA certs.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
        keytool_cmd: command to run the keytool command.
    """
    if not store_path.exists():
        logger.debug("Truststore %s does not exist, nothing to remove.", store_path)
        return

    list_cmd = f"{keytool_cmd} -list -keystore {store_path} -alias {alias} -storetype PKCS12"
    list_args = f"-storepass {store_pwd}"
    try:
        workload.run_cmd(list_cmd, list_args)
    except OpenSearchCmdError as e:
        if is_alias_missing_error(e, alias):
            logger.debug(
                "Alias %s not found in %s when listing before delete, ignoring.",
                alias,
                store_path,
            )
            return
        # Anything else is a real error
        raise

    del_cmd = f"{keytool_cmd} -delete -keystore {store_path} -alias {alias} -storetype PKCS12"
    del_args = f"-storepass {store_pwd}"
    try:
        workload.run_cmd(del_cmd, del_args)
    except OpenSearchCmdError as e:
        if is_alias_missing_error(e, alias):
            logger.debug(
                "Alias %s already gone from %s when deleting, ignoring.",
                alias,
                store_path,
            )
            return
        raise

    logger.info("Removed %s from truststore.", alias)


def split_ca_chain(pem_content: str) -> list[str]:
    """Split PEM chain into individual certificates."""
    end_cert_marker = "-----END CERTIFICATE-----"
    parts = [part.strip() for part in pem_content.split(end_cert_marker) if part.strip()]
    return [f"{part}\n{end_cert_marker}" for part in parts]
