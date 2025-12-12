#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of helpers functions."""

from typing import Union

from ops import App, Unit


def format_unit_name(unit: Union[Unit, str], app: App) -> str:
    """Format unit_name according the app."""
    if isinstance(unit, Unit):
        unit = unit.name
    return f"{unit.replace('/', '-')}.{app.short_id}"
