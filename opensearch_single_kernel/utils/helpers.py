#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of helpers functions."""

import base64
import hashlib
import json
import logging
import math
import re
import secrets
import string
from datetime import datetime
from typing import Iterable

import bcrypt
from cryptography import x509
from ops import Unit

from opensearch_single_kernel.common.constants import (
    PROTECTED_INDEX_NAMES,
    DeploymentType,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import OpenSearchCmdError
from opensearch_single_kernel.core.models import App, PeerClusterConfig

logger = logging.getLogger(__name__)


def format_unit_name(unit: Unit | str, app: App) -> str:
    """Format unit_name according the app."""
    if isinstance(unit, Unit):
        unit = unit.name
    return f"{unit.replace('/', '-')}.{app.short_id}"


def mask_sensitive_information(cmd: str) -> str:
    """Replace passwords or secrets by 'xxx' and return the masked str."""
    pattern = re.compile(r"(-tspass\s+|-kspass\s+|-storepass\s+|-new\s+|pass:)(\S+)")

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


def hash_credentials(credentials: dict[str, str]) -> str:
    """Return a hash of the given credentials.

    Args:
        credentials: credentials in a dict

    Returns:
        hash of the credentials
    """
    return hashlib.sha1(json.dumps(credentials, sort_keys=True).encode()).hexdigest()
