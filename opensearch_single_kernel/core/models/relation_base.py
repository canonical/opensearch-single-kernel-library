#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Persistence machinery for relation-backed models.

Includes:
    - RelationModel: mixin for models fetched from a relation databag through
      ClusterState, which can write themselves back to that databag.
    - bind_model: build a model through an interface and bind it for self-writes.
    - Secret-group field markers shared by the databag models.

Kept separate from `plain_base.PlainModel` (plain value objects): the two do different jobs
and share no code -- value objects carry value semantics, these carry a databag
persistence lifecycle -- so nothing here is inherited by ordinary nested models.
"""

import json
import logging
from contextlib import contextmanager
from typing import Any, ClassVar, Iterator

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
    SECRET_PLUGIN,
    SECRET_UNIT_HTTP,
    SECRET_UNIT_TRANSPORT,
    SECRET_USERS,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    AbstractRepository,
    OptionalSecretStr,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    build_model as _lib_build_model,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    write_model as _write_model,
)

logger = logging.getLogger(__name__)

# Secret-group field markers shared by the peer-databag and peer-cluster models. Each wraps
# OptionalSecretStr with the SECRET_* constant identifying which Juju secret group the field
# is stored/resolved under.
TransportSecretStr = Annotated[
    OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_TRANSPORT
]
HttpSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_HTTP]
AdminSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_APP_ADMIN]
UserSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_USERS]
PluginsSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_PLUGIN]


class RelationModel(BaseModel):
    """Mixin for models fetched from a relation databag through ClusterState.

    Once a model instance is bound (see ClusterState / bind_model), setting any
    field immediately writes the whole model back to its backing relation databag.
    Use `.update()` as a context manager to batch several changes including
    in-place mutation of nested collections into a single write.
    """

    _repository: Any = PrivateAttr(default=None)
    _write_context: dict | None = PrivateAttr(default=None)
    _suspend_persist_depth: int = PrivateAttr(default=0)
    _read_only: bool = PrivateAttr(default=False)
    # Called after this instance successfully writes itself back to the databag. Lets the owning
    # ClusterState drop its parsed-model cache so a read later in the same hook re-reads the
    # databag/Juju secret instead of returning a now-stale cached parse (read-your-writes). Set at
    # bind time and propagated to sibling models so a sibling's write invalidates the cache too.
    _on_persist: Any = PrivateAttr(default=None)
    # Cache of secret-group sibling models keyed by their class (see `sibling_model`). Lazily
    # created. Because ClusterState caches the parent instance for the whole hook, caching the
    # sibling on the parent makes each secret-group model parse once per hook as well, and keeps
    # a secret field's reads/writes flowing through a single shared instance.
    _sibling_cache: dict | None = PrivateAttr(default=None)

    # Maps field name -> sibling RelationModel class, for fields split out into a dedicated
    # secret-group model (e.g. TLS/user secrets split out of a plain peer model). Overridden by
    # subclasses (see `peer.py`); empty here means "no delegation, this model is self-contained".
    _secret_group_fields: ClassVar[dict[str, type]] = {}

    def bind(
        self,
        repository: AbstractRepository,
        write_context: dict | None = None,
        read_only: bool = False,
        on_persist: Any = None,
    ) -> "RelationModel":
        """Attach the repository this instance should persist itself through.

        `read_only` is for models loaded from a databag the charm cannot write
        (a remote app's or remote unit's): field assignments then only mutate the
        in-memory instance instead of triggering a persist.

        `on_persist` is an optional zero-arg callable invoked after a successful
        write (see `_on_persist`); ClusterState passes its cache-invalidation hook.
        """
        self._repository = repository
        self._write_context = write_context
        self._read_only = read_only
        self._on_persist = on_persist
        return self

    @property
    def component(self):
        """The Juju unit/application this model's data is bound to, if any."""
        return self._repository.component if self._repository is not None else None

    @property
    def relation(self):
        """The ops.Relation this model's data is bound to, if any."""
        return self._repository.relation if self._repository is not None else None

    def sibling_model(self, model_cls: type) -> Any:
        """Build another model bound to this same relation/component.

        Used by fields split into a dedicated secret-group model (e.g. TLS secrets
        split out of a plain peer model) so a method on one can reach its sibling
        without needing a separate ClusterState accessor.
        """
        if self._repository is None:
            return None
        cache = self._sibling_cache
        if cache is None:
            cache = self._sibling_cache = {}
        if model_cls in cache:
            return cache[model_cls]
        model = _lib_build_model(self._repository, model_cls)
        if isinstance(model, RelationModel):
            # Propagate on_persist so a write through the sibling invalidates the cache too.
            model.bind(self._repository, self._write_context, on_persist=self._on_persist)
        cache[model_cls] = model
        return model

    def __getattr__(self, name: str) -> Any:
        """Delegate reads of secret-group fields to their sibling model, if any."""
        target_cls = type(self)._secret_group_fields.get(name)
        if target_cls is not None:
            sibling = self.sibling_model(target_cls)
            value = getattr(sibling, name) if sibling is not None else None
            if value is None:
                # extract_secrets() overwrites a field with None when the group's Juju
                # secret exists but doesn't hold that key; surface the field's declared
                # default instead so callers never see None on a defaulted field.
                field_info = target_cls.__pydantic_fields__.get(name)
                if field_info is not None:
                    return field_info.get_default(call_default_factory=True)
            return value
        return super().__getattr__(name)

    def __setattr__(self, name: str, value: Any) -> None:
        """Persist the model whenever a (non-private) attribute is set.

        Fields split out into a sibling secret-group model (see `_secret_group_fields`)
        are delegated there instead of being stored/persisted on this instance.
        """
        target_cls = type(self)._secret_group_fields.get(name)
        if target_cls is not None:
            if sibling := self.sibling_model(target_cls):
                setattr(sibling, name, value)
            return

        super().__setattr__(name, value)
        if not name.startswith("_"):
            self._persist()

    def __delattr__(self, name: str) -> None:
        """Reset the field to its default value and persist."""
        target_cls = type(self)._secret_group_fields.get(name)
        if target_cls is not None:
            if sibling := self.sibling_model(target_cls):
                delattr(sibling, name)
            return

        field_info = type(self).__pydantic_fields__.get(name)
        default = field_info.get_default(call_default_factory=True) if field_info else None
        setattr(self, name, default)

    @contextmanager
    def update(self) -> Iterator["RelationModel"]:
        """Batch several field mutations into a single write.

        Also required for changes that mutate a field's value in place (e.g.
        appending to a list or updating a dict) since those don't go through
        `__setattr__` and wouldn't otherwise trigger a persist.

        Reentrant: nesting `update()` (directly, or via a method like
        `apply_rel_data()` that opens its own) only persists once, when the
        outermost block exits.
        """
        self._suspend_persist_depth += 1
        try:
            yield self
        finally:
            self._suspend_persist_depth -= 1
            if self._suspend_persist_depth == 0:
                self._persist()

    @contextmanager
    def update_secrets(self, model_cls: type) -> Iterator[Any]:
        """Batch-update a dedicated secret-group model bound to this same relation/component."""
        sibling = self.sibling_model(model_cls)
        if sibling is None:
            raise ValueError("Cannot update secrets: model is not bound to a relation.")
        with sibling.update() as m:
            yield m

    def _persist_target(self) -> Any:
        """Return the repository to persist through, or None if this write should be skipped.

        Centralizes every "don't write" guard so `_persist` stays a straight-line
        write: suspended batch, read-only/never-bound instance, inactive relation,
        a remote (unwritable) databag, or an app databag on a non-leader unit.
        """
        if self._suspend_persist_depth > 0 or self._read_only:
            # Suspended inside a batch `update()`, or bound to a remote (unwritable)
            # databag -- either way mutations stay in-memory only.
            return None

        repository = self._repository
        if repository is None:
            # Normal during __init__/validation (secret extraction sets fields before
            # `.bind()` runs) and for plain, never-bound instances -- nothing to persist to.
            # Not logged: models with several secret fields (e.g. PeerClusterAppModel) hit
            # this once per field on every single bind, drowning out real log messages.
            return None

        relation = getattr(repository, "relation", None)
        if relation is not None and not getattr(relation, "active", True):
            return None

        # Juju never allows writing a remote app's/unit's databag -- if this model is
        # bound to one (e.g. built with remote=True), keep mutations in-memory only.
        component = getattr(repository, "component", None)
        local_unit = getattr(repository, "_local_unit", None)
        local_app = getattr(repository, "_local_app", None)
        if component is not None and component not in (local_unit, local_app):
            logger.debug(
                "Not persisting %s: bound to remote component %s.",
                type(self).__name__,
                component,
            )
            return None

        # Only the leader may write an app-scoped databag. On a non-leader the lib would
        # reject every field write/delete with an ERROR log (and no-op anyway), so skip the
        # whole persist silently -- app data is the leader's to own. This changes no data
        # (non-leader app writes are already no-ops in the lib), only removes the log spam.
        if (
            component is not None
            and component == local_app
            and local_unit is not None
            and not local_unit.is_leader()
        ):
            return None

        return repository

    def _persist(self) -> None:
        """Write the current model state back to its bound relation databag."""
        repository = self._persist_target()
        if repository is None:
            return

        # BaseCommonModel/PeerModel serialization can itself call setattr() on this same
        # instance (e.g. to record a newly created secret's URI) -- suspend while writing
        # so that doesn't recursively re-trigger _persist().
        self._suspend_persist_depth += 1

        try:
            _write_model(repository, self, context=self._write_context)
        except (SecretNotFoundError, PydanticSerializationError) as e:
            # A missing/deleted group secret aborts the whole model_dump. Dropping the
            # entire write here would silently lose plain databag fields too (e.g. the
            # demotion flow's trigger/orchestrators update) -- fall back to writing
            # only the non-secret fields instead.
            logger.warning(
                "Secret unavailable while persisting %s -- writing non-secret fields only: %s",
                type(self).__name__,
                e,
            )
            try:
                self._write_non_secret_fields(repository)
            except (SecretNotFoundError, PydanticSerializationError) as e2:
                logger.warning(
                    "Skipping write for %s -- fallback write failed: %s",
                    type(self).__name__,
                    e2,
                )
        finally:
            self._suspend_persist_depth -= 1

        # The databag/Juju secret changed. Drop cached sibling parses and ask ClusterState to
        # drop its parsed-model cache so any read later in this hook re-reads fresh state instead
        # of a now-stale cached parse. Skipped implicitly while suspended (we return above).
        self._sibling_cache = None
        if self._on_persist is not None:
            self._on_persist()

    def _write_non_secret_fields(self, repository: Any) -> None:
        """Write the model's plain databag fields, leaving Juju secrets untouched.

        Mirrors the lib's `write_model()` but dumps without the repository in the
        serialization context: the secret-handling serializers then no-op, and
        secret-backed fields (declared with `Field(exclude=True)`) are absent from
        the dump entirely, so no secret material can land in the databag.
        """
        context = {k: v for k, v in (self._write_context or {}).items()}
        dumped = self.model_dump(mode="json", context=context or None, exclude_none=False)
        for field, value in dumped.items():
            if value is None:
                repository.delete_field(field)
                continue
            dumped_value = value if isinstance(value, str) else json.dumps(value)
            repository.write_field(field, dumped_value)


def bind_model(
    interface: Any,
    relation_id: int,
    model_cls: type,
    component: Any | None = None,
    write_context: dict | None = None,
    read_only: bool = False,
    on_persist: Any = None,
) -> Any:
    """Build a model through `interface` and bind it to its repository for self-writes.

    `interface` is one of the `*RepositoryInterface` classes (e.g.
    OpsPeerRepositoryInterface, OpsPeerUnitRepositoryInterface, ...). If the built
    model is a RelationModel, it is bound so that setting any of its fields (or
    using `.update()`) writes it straight back to the relation databag.

    Pass `read_only=True` when `component` is a remote app/unit whose databag this
    charm cannot write -- field assignments then stay in-memory.

    `on_persist` is forwarded to the model so a successful write can invalidate the
    caller's parsed-model cache (see RelationModel._on_persist).
    """
    repository = interface.repository(relation_id, component)
    model = _lib_build_model(repository, model_cls)
    if isinstance(model, RelationModel):
        model.bind(repository, write_context, read_only=read_only, on_persist=on_persist)
    return model
