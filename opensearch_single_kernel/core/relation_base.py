#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machinery for relation models."""

import json
import logging
from contextlib import contextmanager
from typing import Any, Iterator, TypeVar

from dpcharmlibs.interfaces import (
    OptionalSecretStr,
    build_model,
    write_model,
)
from ops.model import SecretNotFoundError
from pydantic import (
    BaseModel,
    Field,
    PrivateAttr,
)
from pydantic_core import PydanticSerializationError
from typing_extensions import Annotated

from opensearch_single_kernel.common.constants import (
    SECRET_APP_ADMIN,
    SECRET_BACKUPS,
    SECRET_PLUGIN,
    SECRET_UNIT_HTTP,
    SECRET_UNIT_TRANSPORT,
)

logger = logging.getLogger(__name__)

TransportSecretStr = Annotated[
    OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_TRANSPORT
]
HttpSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_HTTP]
AdminSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_APP_ADMIN]
PluginsSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_PLUGIN]
BackupSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_BACKUPS]


class RelationModel(BaseModel):
    """Base relation model for models fetched from a relation databag through ClusterState.

    Once a model instance is bound, setting any field immediately writes the whole model
    back to its backing relation databag. Use `.update()` to batch several changes into
    one write.

    --- HOW IT ALL WORKS ---

    1) BINDING or giving the model its databag
       A freshly created model is just a plain object in memory;
       it has no idea where to get or write data so saving or reading values does nothing.
       Binding attaches a repository to the model so it can read and write the relation
       databag that repository backs. You don't bind directly, instead use
       `build_and_bound_model()`, which builds the model and attaches its repository.

    2) WRITING A PLAIN FIELD or how auto-save works
       Assigning a field goes through `__setattr__`. For an ordinary field it stores the
       value, then calls `_write_to_databag()`, which serializes the whole model and writes it to
       the databag. You never call _write_to_databag() yourself.

           server.started = "1232323" -> databag: started = 1232323

       Some writes are skipped and kept in-memory only (see `_is_repository_writable`): an
       unbound model, a read-only one (points at another app's databag we can't write), an
       inactive relation, or the local app databag when we're not the leader.

    3) SECRET FIELDS
       Some fields aren't plain databag values because they belong to a Juju secret group.
       They're declared directly on the model as `OptionalSecretStr` annotated with their
       secret-group marker. The data-interfaces lib reads
       and writes them into their Juju secret automatically on build/serialize, so from a
       caller's point of view a secret field looks and behaves exactly like a normal field.

    4) BATCHING or how update multiple fields without rewriting model each time
       Wrap several changes so the model saves once at the end instead of once per field.
       You also need it when mutating a list/dict in place (e.g. `m.roles.append(...)`),
       because that kind of change doesn't go through `__setattr__` and can't auto-save
       on its own.
            `with model.update() as m:
                m.started = "2222"
                m.bootstrap_contributor = True`
    """

    # This model repository for accessing databag
    _repository: Any = PrivateAttr(default=None)
    # When True, self-writes skip secret-group fields
    # used for models bound to a databag whose secrets we consume but don't own.
    _skip_secrets: bool = PrivateAttr(default=False)
    # Counter for `update()`. Incremented on entering a batch block and decremented
    # on exit; while > 0 field writes stay in-memory and the single update happens when it
    # returns to 0
    _update_depth_counter: int = PrivateAttr(default=0)
    # True for models loaded from a databag the charm cannot write (a remote app's/unit's).
    # Field assignments then only mutate the in-memory instance and never triggers an update.
    _read_only: bool = PrivateAttr(default=False)

    def _serialization_context(self) -> dict | None:
        """Serialization context threaded into every write; None unless secrets are skipped."""
        return {"skip_secrets": True} if self._skip_secrets else None

    @property
    def component(self):
        """The Juju unit/application this model's data is bound to, if any."""
        return self._repository.component if self._repository is not None else None

    @property
    def relation(self):
        """The ops.Relation this model's data is bound to, if any."""
        return self._repository.relation if self._repository is not None else None

    def __setattr__(self, name: str, value: Any) -> None:
        """Updates the model whenever a (non-private) attribute is set."""
        super().__setattr__(name, value)
        if not name.startswith("_"):
            self._write_to_databag()

    def __delattr__(self, name: str) -> None:
        """Reset the field to its default value and persist."""
        field_info = type(self).__pydantic_fields__.get(name)
        default = field_info.get_default(call_default_factory=True) if field_info else None
        setattr(self, name, default)

    @contextmanager
    def update(self) -> Iterator["RelationModel"]:
        """Batch several field mutations into a single write.

        Also required for changes that mutate a field's value in place (e.g.
        appending to a list or updating a dict) since those don't go through
        `__setattr__` and wouldn't otherwise trigger an update.
        """
        self._update_depth_counter += 1
        try:
            yield self
        finally:
            self._update_depth_counter -= 1
            if self._update_depth_counter == 0:
                self._write_to_databag()

    def _is_repository_writable(self) -> bool:
        """Return True if the current model values can be uploaded to its databag.

        Combines every "don't write" guard so `_write_to_databag` stays a straight-line
        write. Returns False when any of these hold:
          - a batch `update()` is in progress (writes are suspended until it exits),
          - the model is read-only or was never bound to a repository,
          - the backing relation is no longer active,
          - the repository points at a remote (unwritable) app/unit databag, or
          - it points at the local app databag but this unit is not the leader.
        """
        if self._update_depth_counter > 0 or self._read_only:
            # Suspended inside a batch `update()`, or bound to a remote
            # databag, either way stay in-memory only.
            return False

        repository = self._repository
        if repository is None:
            return False

        relation = getattr(repository, "relation", None)
        if relation is not None and not getattr(relation, "active", True):
            return False

        component: Any = getattr(repository, "component", None)
        local_unit: Any = getattr(repository, "_local_unit", None)
        local_app: Any = getattr(repository, "_local_app", None)
        if component is not None and component not in (local_unit, local_app):
            logger.debug(
                "Not updating %s: bound to remote component %s.",
                type(self).__name__,
                component,
            )
            return False

        if (
            component is not None
            and component == local_app
            and local_unit is not None
            and not local_unit.is_leader()
        ):
            return False

        return True

    def _write_to_databag(self) -> None:
        """Write the current model state back to its bound relation databag."""
        if not self._is_repository_writable():
            return

        repository = self._repository
        self._update_depth_counter += 1

        try:
            write_model(repository, self, context=self._serialization_context())
        except (SecretNotFoundError, PydanticSerializationError) as e:
            logger.warning(
                "Secret unavailable while updating %s, writing non-secret fields only: %s",
                type(self).__name__,
                e,
            )
            try:
                self._write_non_secret_fields(self._repository)
            except (SecretNotFoundError, PydanticSerializationError) as e2:
                logger.warning(
                    "Skipping write for %s, fallback write failed: %s",
                    type(self).__name__,
                    e2,
                )
        finally:
            self._update_depth_counter -= 1

    def _write_non_secret_fields(self, repository: Any) -> None:
        """Write the model's plain databag fields, leaving Juju secrets untouched."""
        dumped = self.model_dump(
            mode="json", context=self._serialization_context(), exclude_none=False
        )
        for field, value in dumped.items():
            if value is None:
                repository.delete_field(field)
                continue
            dumped_value = value if isinstance(value, str) else json.dumps(value)
            repository.write_field(field, dumped_value)


# Only for fixing linter
RelationModelT = TypeVar("RelationModelT", bound="RelationModel")


def build_and_bound_model(
    repository: Any,
    model_cls: type[RelationModelT],
    skip_secrets: bool = False,
    read_only: bool = False,
) -> RelationModelT:
    """Build a RelationModel from an already-built repository and bind it for self-writes.

    The bound model writes itself straight back to the relation databag whenever any of its
    fields is set (or on `.update()`). `model_cls` must be a RelationModel subclass.

    Pass `skip_secrets=True` to serialize plain databag fields only (leaving secret-group
    fields untouched), and `read_only=True` when the repository points at a remote app/unit
    databag we cannot write. Callers can obtain `repository` from
    `ClusterState.get_repository_from_interface`.
    """
    model = build_model(repository, model_cls)
    model._repository = repository
    model._skip_secrets = skip_secrets
    model._read_only = read_only
    return model
