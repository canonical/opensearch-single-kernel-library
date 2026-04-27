#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for reading / writing certificates."""
import base64
import logging
import math
import re
from datetime import datetime, timezone

from charmlibs.pathops import PathProtocol
from cryptography import x509

from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
)
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


def normalized_tls_subject(subject: str) -> str:
    """Removes any / character from a subject."""
    if subject.startswith("/"):
        subject = subject[1:]
    return subject.replace("/", ",")


def cert_expiration_remaining_hours(cert: str) -> int:
    """Returns the remaining hours for the cert to expire."""
    certificate_object = x509.load_pem_x509_certificate(data=cert.encode())
    time_difference = certificate_object.not_valid_after - datetime.now(timezone.utc)
    return math.floor(time_difference.total_seconds() / 3600)


def parse_tls_file(raw_content: str) -> bytes:
    """Parse TLS files from both plain text or base64 format."""
    if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", raw_content):
        return re.sub(
            r"(-+(BEGIN|END) [A-Z ]+-+)",
            "\\1",
            raw_content,
        ).encode("utf-8")
    return base64.b64decode(raw_content)


def is_alias_missing_error(exc: OpenSearchCmdError, alias: str) -> bool:
    """Return True if keytool says that given alias does not exist."""
    msg = (exc.out or "") + (exc.err or "")
    return f"Alias <{alias}> does not exist" in msg


def read_ca(
    workload: BaseWorkload, alias: str, store_pwd: str, store_path: PathProtocol
) -> str | None:
    """Load stored CA cert."""
    return (list_cas(workload, store_pwd, store_path) or {}).get(alias)


def list_aliases(
    workload: BaseWorkload, store_pwd: str, store_path: PathProtocol
) -> list[str] | None:
    """Fetch the aliases stored in a store."""
    if not workload.exists(store_path):
        return None

    # we fetch the list of stored aliases
    cmd = f"{workload.keytool_cmd} -v -list -keystore {store_path} -storetype PKCS12"
    args = f"-storepass {store_pwd}"

    try:
        resp = workload.run_cmd(cmd, args).out.split("\n")
        return [
            line.split("Alias name:")[-1].strip()
            for line in resp
            if line.startswith("Alias name:")
        ]
    except OpenSearchCmdError as e:
        logger.error("Error reading the current truststore: %s", e)
        return None


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
    try:
        if not workload.exists(store_path):
            return None
    except OpenSearchFileOperationError as e:
        logger.error("Error accessing the truststore path: %s", e)
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
) -> bool:
    """Common implementation to store a CA chain into a PKCS12 keystore."""
    sudo_prefix = "sudo " if use_sudo else ""
    tmpdir = store_path.parent
    starter_mode = "0664"
    snap_user = "snap_daemon:root"
    should_restore_snap_owner = snap_user_with_write_permission and use_sudo
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
                    f"{workload.keytool_cmd} -changealias "
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
                        f"{workload.keytool_cmd} -importcert -noprompt "
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
        # Only the VM/snap path needs ownership restored to snap_daemon after keytool rewrites
        # the PKCS12 file. K8s uses direct container ownership and should only normalize mode.
        if should_restore_snap_owner:
            command = (
                f"{sudo_prefix}chown {snap_user} {store_path}; "
                f"{sudo_prefix}chmod {final_mode} {store_path};"
            )
        elif snap_user_with_write_permission:
            command = f"{sudo_prefix}chmod {final_mode} {store_path};"
        if add_read_perm:
            command += f"{sudo_prefix}chmod +r {store_path}"
        if command:
            workload.run_cmd(command)
    except OpenSearchCmdError:
        pass

    return True


def _is_keystore_missing_error(exc: OpenSearchCmdError, keystore_path: str) -> bool:
    """Return True if the exception indicates the keystore file does not exist."""
    msg = (exc.out or "") + (exc.err or "")
    # keytool messages change a bit between JDKs, we keep this intentionally.
    return (
        "Keystore file does not exist" in msg
        or ("FileNotFoundException" in msg and keystore_path in msg)
        or ("No such file or directory" in msg and keystore_path in msg)
    )


def remove_ca(
    workload: BaseWorkload,
    alias: str,
    store_pwd: str,
    store_path: PathProtocol,
    use_sudo: bool = True,
) -> None:
    """Remove old CA cert from the truststore.

    Args:
        workload: The workload instance to run commands.
        alias: Alias to use for the CA certs.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
        use_sudo: Whether to prefix chmod with sudo. False for K8s where sudo is unavailable.
    """
    list_cmd = (
        f"{workload.keytool_cmd} -list -keystore {store_path} -alias {alias} -storetype PKCS12"
    )
    list_args = f"-storepass {store_pwd}"
    try:
        workload.run_cmd(list_cmd, list_args)
    except OpenSearchCmdError as e:
        if _is_keystore_missing_error(e, str(store_path)):
            logger.debug("Truststore %s does not exist, nothing to remove.", store_path)
            return
        if is_alias_missing_error(e, alias):
            logger.debug(
                "Alias %s not found in %s when listing before delete, ignoring.",
                alias,
                store_path,
            )
            return
        # Anything else is a real error
        raise

    sudo_prefix = "sudo " if use_sudo else ""
    try:
        workload.run_cmd(f"{sudo_prefix}chmod 0664 {store_path}")
    except OpenSearchCmdError as e:
        logger.warning(
            "Failed to chmod 0664 on %s before CA removal: %s%s",
            store_path,
            e.out or "",
            e.err or "",
        )
    _remove_ca_aliases(
        workload=workload, alias_base=alias, store_pwd=store_pwd, store_path=store_path
    )
    logger.info("Removed %s from truststore %s.", alias, store_path)


def _remove_ca_aliases(
    workload: BaseWorkload, alias_base: str, store_pwd: str, store_path: PathProtocol
) -> None:
    """Core logic to delete aliases for a given base name.

    Args:
        workload: The workload instance to run commands.
        alias_base: The base alias to match.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
    """
    aliases_to_remove = _collect_aliases_to_remove(
        workload=workload, alias_base=alias_base, store_pwd=store_pwd, store_path=store_path
    )

    if not aliases_to_remove:
        logger.debug("No aliases matching %s/* found in %s.", alias_base, store_path)
        return
    logger.info("Aliases: %s going to be removed", ", ".join(aliases_to_remove))
    for name in aliases_to_remove:
        del_cmd = (
            f"{workload.keytool_cmd} -delete -keystore {store_path} "
            f"-alias {name} -storetype PKCS12"
        )
        del_args = f"-storepass {store_pwd}"
        try:
            workload.run_cmd(del_cmd, del_args)
            logger.info("Removed %s from truststore %s.", name, store_path)
        except OpenSearchCmdError as e:
            # If the alias is not found, just ignore it. It can be removed before delete.
            if is_alias_missing_error(e, name):
                logger.debug(
                    "Alias %s already gone from %s when deleting, ignoring.",
                    name,
                    store_path,
                )
                continue
            # Anything else is a real error
            raise


def _collect_aliases_to_remove(
    workload: BaseWorkload, alias_base: str, store_pwd: str, store_path: PathProtocol
) -> list[str]:
    """List aliases that should be removed (base, base-*, old-base-*).

    Args:
        alias_base: The base alias to match.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.

    Returns:
        List of aliases to remove.
    """
    # Get all aliases from the keystore
    all_aliases = list_aliases(workload=workload, store_pwd=store_pwd, store_path=store_path)
    if all_aliases is None:
        logger.debug("Could not list aliases from %s, no aliases to remove.", store_path)
        return []

    aliases_to_remove: list[str] = []
    for name in all_aliases:
        if name == alias_base:
            aliases_to_remove.append(name)
        elif name.startswith(f"{alias_base}-"):
            # Verify the suffix is a digit
            suffix = name.split("-")[-1]
            if suffix.isdigit():
                aliases_to_remove.append(name)

    return aliases_to_remove


def split_ca_chain(pem_content: str) -> list[str]:
    """Split PEM chain into individual certificates."""
    end_cert_marker = "-----END CERTIFICATE-----"
    parts = [part.strip() for part in pem_content.split(end_cert_marker) if part.strip()]
    return [f"{part}\n{end_cert_marker}" for part in parts]


def _normalize_certificate_chain(text: str | None) -> str:
    """Normalize a PEM chain string before hashing.

    Args:
        text (Optional[str]): PEM chain string to be normalized.

    Returns:
        str: Normalized PEM chain string.
    """
    if not text:
        return ""
    return "\n".join(line.strip() for line in text.strip().splitlines() if line.strip())


def normalize_certificate_chain_unordered(chain: str) -> list[str]:
    """Normalize a PEM chain into a sorted list of cert blocks for comparison.

    Args:
        chain: PEM chain string.

    Returns:
        list[str]: List of certificate blocks, sorted by normalized content.

    This makes comparison robust to:
    - whitespace differences
    - order of certificates within the chain
    """
    blocks = _split_pem_chain(chain)
    # Use existing _normalize_certificate_chain on each block to clean whitespace etc.
    normalized_blocks = [
        _normalize_certificate_chain(block) for block in blocks if block and block.strip()
    ]
    # Sort so order does not matter
    return sorted(normalized_blocks)


def _split_pem_chain(chain: str) -> list[str]:
    """Split a PEM chain into individual certificate blocks.

    Args:
        chain: PEM chain string.

    Returns:
        list[str]: List of certificate blocks.
    """
    if not chain:
        return []

    # Match complete / valid certificate blocks
    pattern = r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    matches = re.findall(pattern, chain, flags=re.DOTALL)

    return [
        "\n".join(line.strip() for line in cert.splitlines() if line.strip()) for cert in matches
    ]
