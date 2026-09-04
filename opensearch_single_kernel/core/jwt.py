#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""JWT authentication configuration model."""

from dpcharmlibs.interfaces import (
    ExtraSecretStr,
    ResourceProviderModel,
)
from pydantic import Field


class JWTAuthConfiguration(ResourceProviderModel):
    """Model class for the configuration parameters of JWT authentication."""

    signing_key: ExtraSecretStr = Field(default=None)
    jwt_header: str | None = Field(default=None)
    jwt_url_parameter: str | None = Field(default=None)
    roles_key: str
    subject_key: str | None = Field(default=None)
    required_audience: str | None = Field(default=None)
    required_issuer: str | None = Field(default=None)
    jwt_clock_skew_tolerance_seconds: int | None = Field(default=None)
