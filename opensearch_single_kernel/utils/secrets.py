#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of utility functions for secrets management."""
from typing import Any

from opensearch_single_kernel.common.constants import (
    HASH_POSTFIX,
    OPENSEARCH_SYSTEM_USERS,
    PW_POSTFIX,
    SECRETS_LABEL_SEPARATOR,
    Scope,
)


def user_from_hash_key(key):
    """Which user is referred to by key?"""
    for user in OPENSEARCH_SYSTEM_USERS:
        if key == hash_key(user):
            return user


def password_key(username: str) -> str:
    """Unified key to store password secrets specific to a user."""
    return f"{username}-{PW_POSTFIX}"


def hash_key(username: str) -> str:
    """Unified key to store password secrets specific to a user."""
    return f"{username}-{HASH_POSTFIX}"


def breakdown_label(label: str) -> dict[str, Any]:
    """Return meaningful components resolved from a secret label."""
    components = label.split(SECRETS_LABEL_SEPARATOR)
    if len(components) < 3 or len(components) > 4:
        raise ValueError(f"Invalid label {label}")

    scope = Scope[components[1].upper()]

    if scope == Scope.APP:
        key = components[2]
        unit_id = None
    else:
        key = components[3]
        unit_id = int(components[2])

    return {
        "application_name": components[0],
        "scope": scope,
        "unit_id": unit_id,
        "key": key,
    }


def safe_obj_data(indict: dict) -> dict[str, Any]:
    """Return a dict with only non-empty values from the input dict."""
    return {key: str(val) for key, val in indict.items() if val is not None and str(val).strip()}
