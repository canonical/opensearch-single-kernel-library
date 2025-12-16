#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of helpers functions."""
import re
import secrets
import string
from time import time_ns
from typing import TYPE_CHECKING, Optional, Tuple, Union

import bcrypt
from ops import Unit

from opensearch_single_kernel.common.constants import PEER_RELATION, Scope
from opensearch_single_kernel.core.models import App

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


def format_unit_name(unit: Union[Unit, str], app: App) -> str:
    """Format unit_name according the app."""
    if isinstance(unit, Unit):
        unit = unit.name
    return f"{unit.replace('/', '-')}.{app.short_id}"


def trigger_peer_rel_changed(
    charm: "OpenSearchBaseCharm",
    only_by_leader: bool = False,
    on_other_units: bool = True,
    on_current_unit: bool = False,
) -> None:
    """Force trigger a peer rel changed event."""
    if only_by_leader and not charm.unit.is_leader():
        return

    if on_other_units or not on_current_unit:
        charm.peers_data.put(Scope.APP if only_by_leader else Scope.UNIT, "update-ts", time_ns())

    if on_current_unit:
        charm.on[PEER_RELATION].relation_changed.emit(charm.model.get_relation(PEER_RELATION))


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


def generate_hashed_password(pwd: Optional[str] = None) -> Tuple[str, str]:
    """Generates a password and its bcrypt hash.

    Returns:
        A hash and the original password
    """
    pwd = pwd or generate_password()
    return hash_string(pwd), pwd
