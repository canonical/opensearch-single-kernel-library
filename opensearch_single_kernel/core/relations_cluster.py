#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Peer-cluster relation wrappers used by state to access peer-cluster models."""

import logging
from typing import Any

import ops
from dpcharmlibs.interfaces import build_model, write_model
from ops.model import SecretNotFoundError
from pydantic import BaseModel
from pydantic_core import PydanticSerializationError

from opensearch_single_kernel.core.relation_models import (
    PeerClusterAppModel,
    PeerClusterServerModel,
)

logger = logging.getLogger(__name__)


class PeerClusterRelationState:
    """Wrapper around peer cluster app model"""

    model_cls: type[BaseModel]

    def __init__(
        self,
        repository: Any,
        skip_secrets: bool = False,
    ) -> None:
        self.repository = repository
        self.skip_secrets = skip_secrets
        self.model = build_model(repository, self.model_cls)

    @property
    def relation(self) -> ops.model.Relation | None:
        """The ops.Relation this wrapper's data is bound to."""
        return getattr(self.repository, "relation", None)

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown (non-private) reads to the underlying model."""
        if name.startswith("_"):
            raise AttributeError(name)
        model = self.__dict__.get("model")
        if model is None:
            raise AttributeError(name)
        return getattr(model, name)

    def __delattr__(self, name: str) -> None:
        """Reset a model field to its default and persist (supports `del wrapper.field`)."""
        self.delete(name)

    def _context(self) -> dict | None:
        """Serialization context threaded into every write; None unless secrets are skipped."""
        return {"skip_secrets": True} if self.skip_secrets else None

    def update(self, items: dict[str, Any]) -> None:
        """Apply the given field changes and updates the whole model in a single write."""
        for field, value in items.items():
            setattr(self.model, field.replace("-", "_"), value)
        try:
            write_model(self.repository, self.model, context=self._context())
        except (SecretNotFoundError, PydanticSerializationError) as e:
            logger.warning(
                "Secret unavailable while updating %s, writing non-secret fields only: %s",
                type(self.model).__name__,
                e,
            )
            try:
                write_model(self.repository, self.model, context={"skip_secrets": True})
            except (SecretNotFoundError, PydanticSerializationError) as e2:
                logger.warning(
                    "Skipping write for %s, fallback write failed: %s",
                    type(self.model).__name__,
                    e2,
                )

    def delete(self, *fields: str) -> None:
        """Reset the given fields to their declared defaults and update."""
        for field in fields:
            field_info = type(self.model).__pydantic_fields__.get(field)
            default = field_info.get_default(call_default_factory=True) if field_info else None
            setattr(self.model, field, default)
        try:
            write_model(self.repository, self.model, context=self._context())
        except (SecretNotFoundError, PydanticSerializationError) as e:
            logger.warning(
                "Secret unavailable while updating %s, writing non-secret fields only: %s",
                type(self.model).__name__,
                e,
            )
            try:
                write_model(self.repository, self.model, context={"skip_secrets": True})
            except (SecretNotFoundError, PydanticSerializationError) as e2:
                logger.warning(
                    "Skipping write for %s, fallback write failed: %s",
                    type(self.model).__name__,
                    e2,
                )


class PeerClusterApplication(PeerClusterRelationState):
    """State/relation-data wrapper for a peer-cluster application databag."""

    model_cls = PeerClusterAppModel
    model: PeerClusterAppModel

    def empty_secret_placeholders(self) -> dict[str, Any]:
        """Return the placeholder field changes that pre-create the secret groups."""
        if self.model.pc_secrets_initialized:
            return {}
        return {
            "admin_password": self.model.admin_password or " ",
            "admin_cert": self.model.admin_cert or " ",
            "plugin_secrets": self.model.plugin_secrets or " ",
            "pc_secrets_initialized": True,
        }

    def initialize_empty_secrets(self) -> None:
        """Pre-create the peer-cluster secret groups if they are not populated yet."""
        if changes := self.empty_secret_placeholders():
            self.update(changes)


class PeerClusterServer(PeerClusterRelationState):
    """State/relation-data wrapper for a single unit's peer-cluster databag."""

    model_cls = PeerClusterServerModel
    model: PeerClusterServerModel

    @property
    def unit(self) -> ops.model.Unit:
        """The ops.Unit this wrapper's data is bound to."""
        return self.repository.component
