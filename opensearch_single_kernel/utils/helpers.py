#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of helpers functions."""
import base64
import math
import re
import secrets
import string
from datetime import datetime
from typing import Any

import bcrypt
from charmlibs.pathops import PathProtocol
from cryptography import x509
from ops import Unit

from opensearch_single_kernel.common.constants import (
    DeploymentType,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.core.models import App, PeerClusterConfig


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


def normalize_k8s_bootstrap_name(value: str | None) -> str:
    """Normalize bootstrap names to match K8s container hostnames.

    Typical inputs:
    - "app-0.c67" (formatted unit name)
    - "app-0" (pod hostname)
    - "app-0.namespace.svc.cluster.local" (DNS)
    """
    return (value or "").split(".", 1)[0]


def split_ca_chain(pem_content: str) -> list[str]:
    """Split PEM chain into individual certificates."""
    end_cert_marker = "-----END CERTIFICATE-----"
    parts = [part.strip() for part in pem_content.split(end_cert_marker) if part.strip()]
    return [f"{part}\n{end_cert_marker}" for part in parts]


def normalized_tls_subject(subject: str) -> str:
    """Removes any / character from a subject."""
    if subject.startswith("/"):
        subject = subject[1:]
    return subject.replace("/", ",")


def cert_expiration_remaining_hours(cert: str) -> int:
    """Returns the remaining hours for the cert to expire."""
    certificate_object = x509.load_pem_x509_certificate(data=cert.encode())
    time_difference = certificate_object.not_valid_after - datetime.utcnow()

    return math.floor(time_difference.total_seconds() / 3600)


def is_alias_missing_error(exc: OpenSearchCmdError, alias: str) -> bool:
    """Return True if keytool says that given alias does not exist.

    Args:
        exc: The OpenSearchCmdError to check.
        alias: The alias that was attempted to be deleted.

    Returns:
        bool: True if the error message indicates that the alias does not exist.
    """
    msg = (exc.out or "") + (exc.err or "")
    return f"Alias <{alias}> does not exist" in msg


def parse_tls_file(raw_content: str) -> bytes:
    """Parse TLS files from both plain text or base64 format."""
    if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", raw_content):
        return re.sub(
            r"(-+(BEGIN|END) [A-Z ]+-+)",
            "\\1",
            raw_content,
        ).encode("utf-8")
    return base64.b64decode(raw_content)


def get_nested_value(config: dict, key_path: str) -> Any:
    """Get a nested value from config dict using dotted key path.

    Handles both flat dicts (with dotted keys) and nested dicts.

    Args:
        config: Dictionary to search in.
        key_path: Dotted key path such as "plugins.security.ssl.transport.keystore_filepath".

    Returns:
        The value at the nested path, or None if not found.

    Example:
        config = {"plugins": {"security": {"ssl": {"transport":
            {"keystore_filepath": "/path/to/keystore"}}}}}
        get_nested_value(config, "plugins.security.ssl.transport.keystore_filepath")
        '/path/to/keystore'
    """
    if not isinstance(config, dict):
        return None

    # Fast-path for "flat" YAMLs where the full dotted key exists as-is.
    if key_path in config:
        return config.get(key_path)

    keys = key_path.split(".")
    value: Any = config

    for idx, key in enumerate(keys):
        if not isinstance(value, dict):
            return None

        # Support mixed representations where a prefix is flattened:
        # such as {"plugins.security.disabled": false}
        remaining = ".".join(keys[idx:])
        if remaining in value:
            return value.get(remaining)

        value = value.get(key)
        if value is None:
            return None

    return value
