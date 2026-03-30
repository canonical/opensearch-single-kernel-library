# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""TLS integration test defaults (TLS operator, unit topology)."""

from tests.integration.conftest import UNIT_IDS

TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"
TLS_STABLE_CHANNEL = "1/stable"


def get_unit_ids(substrate: str) -> list[int]:
    """Return the TLS / integration test unit ids supported by the substrate."""
    return UNIT_IDS
