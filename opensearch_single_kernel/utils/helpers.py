#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of helpers functions."""

import json
import logging
import re
import secrets
import socket
import string
from collections.abc import Iterable
from typing import Any

import bcrypt
from charmlibs.pathops import PathProtocol
from ops import Unit

from opensearch_single_kernel.common.constants import (
    PROTECTED_INDEX_NAMES,
    DeploymentType,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.core.models import App, PeerClusterConfig

logger = logging.getLogger(__name__)


def path_as_posix(path: PathProtocol) -> str:
    """Convert a PathProtocol to a POSIX path string.

    The workload code uses PathProtocol and some callers (config generation, command execution)
    need a plain string path, but PathProtocol implementations aren't guaranteed to be
    pathlib.Path. The reason is pathlib.Path is a default type for paths in Python. Hence, we use
    .as_posix() when available and fall back to str().
    """
    as_posix = getattr(path, "as_posix", None)
    return as_posix() if callable(as_posix) else str(path)


def format_unit_name(unit: Unit | str, app: App) -> str:
    """Format unit_name according the app."""
    if isinstance(unit, Unit):
        unit = unit.name
    return f"{unit.replace('/', '-')}.{app.short_id}"


def mask_sensitive_information(cmd: str) -> str:
    """Replace passwords or secrets by 'xxx' and return the masked str."""
    pattern = re.compile(r"(-tspass\s+|-kspass\s+|-keypass\s+|-storepass\s+|-new\s+|pass:)(\S+)")

    return re.sub(pattern, r"\1" + "xxx", cmd)


def hash_string(string: str) -> str:
    """Hashes the given string."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(string.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def generate_password() -> str:
    """Generate a random password string.

    Returns:
       A random password string.
    """
    choices = string.ascii_letters + string.digits
    return "".join([secrets.choice(choices) for _ in range(32)])


def generate_hashed_password(pwd: str | None = None) -> tuple[str, str]:
    """Generates a password and its bcrypt hash.

    Returns:
        A hash and the original password
    """
    pwd = pwd or generate_password()
    return hash_string(pwd), pwd


def deployment_type(
    config: PeerClusterConfig,
    start_mode: StartMode,
    prev_deployment_type: DeploymentType | None = None,
) -> DeploymentType:
    """Check if the current cluster is an independent cluster."""
    has_cm_roles = (
        start_mode == StartMode.WITH_GENERATED_ROLES or "cluster_manager" in config.roles
    )
    if not has_cm_roles:
        return DeploymentType.OTHER

    return prev_deployment_type or (
        DeploymentType.MAIN_ORCHESTRATOR
        if not config.init_hold
        else DeploymentType.FAILOVER_ORCHESTRATOR
    )


def is_srv_dns_record(value: str) -> bool:
    """Return True when value looks like an SRV-style DNS record."""
    pattern = (
        r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?"
        r"\.([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+srv"
        r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?){2,}\.?$"
    )
    return bool(re.match(pattern, value, re.IGNORECASE))


def get_k8s_fqdn(name: str) -> str:
    """Resolve the canonical FQDN for a Kubernetes service or pod name."""
    try:
        info = socket.getaddrinfo(
            name,
            None,
            family=socket.AF_UNSPEC,
            flags=socket.AI_CANONNAME,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as e:
        raise RuntimeError(f"Failed to resolve canonical name for {name}") from e

    for entry in info:
        if (canonname := entry[3]) and is_srv_dns_record(canonname):
            return canonname

    raise RuntimeError(f"Could not determine canonical name for {name}")


def get_k8s_seed_host(unit_name: str, app_name: str) -> str:
    """Return the canonical K8s seed host for a unit."""
    # Strip Juju short id / DNS suffix: "app-0.c67", FQDNs -> pod hostname prefix.
    pod_prefix = (unit_name or "").split(".", 1)[0]
    service_name = f"{pod_prefix}.{app_name}-endpoints"
    try:
        return get_k8s_fqdn(service_name)
    except RuntimeError:
        # Seed hosts follow the stable pod-headless-service DNS pattern. If the charm
        # container cannot obtain a canonical DNS answer for a peer pod, derive the
        # namespace/domain suffix from the current unit FQDN and keep progressing.
        local_fqdn = socket.getfqdn()
        local_parts = local_fqdn.split(".")
        if len(local_parts) > 2:
            return f"{service_name}.{'.'.join(local_parts[2:])}"
        return service_name


def validate_index_name(index_name: str) -> bool:
    """Validates that the index name provided in the relation is acceptable."""
    if index_name in PROTECTED_INDEX_NAMES:
        logger.error(
            "invalid index name %s - tried to access a protected index in %s",
            index_name,
            PROTECTED_INDEX_NAMES,
        )
        return False

    if not index_name.islower():
        logger.error("invalid index name %s - index names must be lowercase", index_name)
        return False

    forbidden_chars = [" ", ",", ":", '"', "*", "+", "\\", "/", "|", "?", "#", ">", "<"]
    if any([char in index_name for char in forbidden_chars]):

        logger.error(
            "invalid index name %s - index name includes one or more of "
            "the following forbidden characters: %s",
            index_name,
            forbidden_chars,
        )
        return False

    return True


def diff(desired: Iterable[str], current: Iterable[str]) -> tuple[set[str], set[str]]:
    """Returns diff needed to turn current list into desired list"""
    desired_labels = set(desired)
    current_labels = set(current)

    add = desired_labels - current_labels
    remove = current_labels - desired_labels
    return add, remove


def decode_plugin_secret_content(content: dict, label: str) -> dict[str, str] | None:
    """Decodes JSON payload from plugin secret

    Args:
        content: dictionary of the secret content
        label: label of the secfet

    Returns:
        A decoded dictionary if successful, else None
    """
    if not (raw := content.get(label)):
        logger.warning("Key '%s' not found in secret content", label)
        return None

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("Malformed JSON in secret %s: %s", label, e)
        return None


def build_command_list(command_with_args: str) -> list[str]:
    """Build command list for container.exec().

    Detects shell metacharacters and wraps command in shell if needed.
    Otherwise splits command into list of arguments.

    Args:
        command_with_args: Full command string with arguments.

    Returns:
        list[str]: Command list suitable for container.exec().
    """
    shell_metachars = ["|", ">", "<", "&&", "||", ";", "$(", "${", "`", "2>", ">>", "<<", "&"]
    if any(char in command_with_args for char in shell_metachars):
        return ["sh", "-c", command_with_args]
    if " " in command_with_args:
        return command_with_args.split()
    return [command_with_args]


def wait_for_process_output(
    process: Any, masked_command: str, original_command: str
) -> tuple[str, str]:
    """Wait for process to complete and return output.

    Args:
        process: Process object from container.exec() (has wait_output()).
        masked_command: Command string with sensitive info masked for logging.
        original_command: Original command string for error messages.

    Returns:
        tuple[str, str]: (stdout, stderr). stderr is typically empty when
        combine_stderr=True was used for exec().

    Raises:
        OpenSearchCmdError: If process fails or returns non-zero exit code.
    """
    try:
        stdout, stderr = process.wait_output()
        return stdout, stderr
    except Exception as e:
        error_string = str(e).lower()
        missing_keystore = (
            "opensearch.keystore" in error_string and "does not exist" in error_string
        ) or "keystore file does not exist" in error_string
        if missing_keystore:
            logger.debug(
                "wait_output() failed for %s (expected missing opensearch.keystore): %s",
                masked_command,
                e,
            )
        else:
            logger.warning("wait_output() failed for %s: %s", masked_command, e)
        raise OpenSearchCmdError(cmd=original_command, out="", err=str(e)) from e
