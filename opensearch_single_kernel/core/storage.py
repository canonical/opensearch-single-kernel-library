#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object storage (S3/Azure/GCS) related models."""

import base64
import binascii
import json
import re

from dpcharmlibs.interfaces import (
    OptionalSecretStr,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Annotated, Self

from opensearch_single_kernel.common.constants import SECRET_BACKUPS
from opensearch_single_kernel.core.base_models import PlainModel

BackupSecretKeyStr = Annotated[
    OptionalSecretStr, Field(exclude=True, default=None), SECRET_BACKUPS
]


class _BaseStorage(BaseModel):
    """Base storage model providing from_relation for storage relation data models."""

    @classmethod
    def from_relation(cls, data: dict[str, str]) -> Self:
        """Build the model from raw relation data, mapping hyphenated keys to field names."""
        normalized = {k.replace("-", "_"): v for k, v in data.items()}
        return cls.model_validate(normalized)


class GcsRelData(_BaseStorage):
    """Model for GCS relation data."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    secret_key: BackupSecretKeyStr = Field(default=None)
    path: str | None = Field(default=None)
    bucket: str | None = Field(default=None)
    endpoint: str | None = Field(default=None)
    storage_class: str | None = Field(alias="storage-class", default=None)

    @model_validator(mode="after")
    def validate_core_fields(self):
        """Validate the core fields of the gcs relation data."""
        if not self.secret_key:
            raise ValueError("Missing fields: secret-key")

        content = self.secret_key.strip()
        if content.startswith("{") and content.endswith("}"):
            try:
                json.loads(content)
            except (ValueError, TypeError):
                raise ValueError("secret-key is not valid JSON (may be an unresolved secret URI)")
        else:
            # gcs-integrator may base64-encode the service account JSON
            try:
                decoded = (
                    base64.b64decode(content, altchars=b"-_", validate=True)
                    .decode("utf-8")
                    .strip()
                )
                json.loads(decoded)
                self.secret_key = decoded
            except (binascii.Error, ValueError, UnicodeDecodeError):
                raise ValueError("secret-key is not valid JSON (may be an unresolved secret URI)")

        if not self.bucket:
            raise ValueError("Missing field: bucket")

        # remove any duplicate, prefix or trailing "/" characters
        if path := self.path:
            path = re.sub(r"/+", "/", path).strip().strip("/")
        self.path = path or None

        return self


class AzureRelData(_BaseStorage):
    """Model for Azure relation data."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    storage_account: BackupSecretKeyStr = Field(default=None)
    secret_key: BackupSecretKeyStr = Field(default=None)

    container: str | None = Field(default=None)
    endpoint: str | None = Field(default=None)
    path: str | None = Field(default=None)
    connection_protocol: str | None = Field(alias="connection-protocol", default=None)

    @model_validator(mode="after")
    def validate_core_fields(self):
        """Validate the core fields of the azure relation data."""
        if not self.storage_account or not self.secret_key:
            raise ValueError("Missing fields: storage_account, secret_key")

        # remove any duplicate, prefix or trailing "/" characters
        if path := self.path:
            path = re.sub(r"/+", "/", path).strip().strip("/")
        self.path = path or None

        return self


class S3RelData(_BaseStorage):
    """Model for S3 relation data."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    access_key: BackupSecretKeyStr = Field(default=None)
    secret_key: BackupSecretKeyStr = Field(default=None)
    tls_ca_chain: BackupSecretKeyStr = Field(default=None)

    bucket: str | None = Field(default=None)
    region: str | None = Field(default=None)
    endpoint: str | None = Field(default=None)
    path: str | None = Field(default=None)
    protocol: str | None = Field(default=None)
    s3_uri_style: bool = Field(alias="s3-uri-style", default=False)
    storage_class: str | None = Field(default=None)

    @model_validator(mode="after")
    def validate_core_fields(self):
        """Validate the core fields of the S3 relation data."""
        if not self.access_key or not self.secret_key:
            raise ValueError("Missing fields: access_key, secret_key")

        # NOTE: Both bucket and endpoint must be set. If none of them are set,
        # but credentials were found, this likely means that we are validating for a
        # non cluster_manager application, which only needs credentials.
        if self.bucket and not self.endpoint:
            raise ValueError("Missing field: endpoint")
        if self.endpoint and not self.bucket:
            raise ValueError("Missing field: bucket")
        if not self.region:
            raise ValueError("Missing field: region")

        # remove any duplicate, prefix or trailing "/" characters
        if path := self.path:
            path = re.sub(r"/+", "/", path).strip().strip("/")
        self.path = path or None

        return self

    @field_validator("tls_ca_chain", mode="before", check_fields=False)
    @classmethod
    def _tls_chain(cls, v):
        """Normalize the CA chain (bytes, list of certs, or dict) into a single PEM string."""
        if v is None:
            return None
        if isinstance(v, (bytes, bytearray)):
            v = v.decode()
        if isinstance(v, list):
            return "\n".join(s.strip() for s in v if s)
        if isinstance(v, dict):
            chain = v.get("chain")
            if isinstance(chain, list):
                return "\n".join(s.strip() for s in chain if s)

            return json.dumps(v)
        return str(v)

    @field_validator("s3_uri_style", mode="before")
    @classmethod
    def change_path_style_type(cls, value) -> bool:
        """Coerce a type change of the s3_uri_style into a bool."""
        if isinstance(value, str):
            return value.lower() == "path"
        return bool(value)


class ObjectStorageConfig(PlainModel):
    """Model class for the object storage config for all clouds."""

    s3: S3RelData | None = None
    azure: AzureRelData | None = None
    gcs: GcsRelData | None = None
