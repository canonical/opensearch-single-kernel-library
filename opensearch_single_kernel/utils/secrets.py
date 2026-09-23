#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of utility functions for secrets management."""

from typing import Any

from opensearch_single_kernel.common.constants import (
    SECRETS_LABEL_SEPARATOR,
    Scope,
)


def breakdown_label(label: str | None) -> dict[str, Any]:
    """Return meaningful components resolved from a secret label."""
    if not label:
        raise ValueError("No label to breakdown")

    parts = label.split(SECRETS_LABEL_SEPARATOR)

    if not (3 <= len(parts) <= 4):
        raise ValueError(f"Invalid label format: {label}")

    if len(parts) == 3:
        relation_name, application_name, scope_raw = parts
        group = "extra"
    else:
        relation_name, application_name, scope_raw, group = parts

    try:
        scope = Scope(scope_raw.lower())
    except ValueError:
        raise ValueError(f"Invalid scope '{scope_raw}' in label")

    return {
        "relation_name": relation_name,
        "application_name": application_name,
        "scope": scope,
        "group": group,
    }


def safe_obj_data(indict: dict) -> dict[str, Any]:
    """Return a dict with only non-empty values from the input dict."""
    return {key: str(val) for key, val in indict.items() if val is not None and str(val).strip()}
