#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machinery for relation models.

Includes:
    - RelationModel: Base model for models fetched from a relation databag through
      ClusterState, which can write themselves back to that databag.
    - bind_model_to_repository: build a model through an interface and bind it for self-writes.
    - Secret-group field markers shared by the databag models.
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
    SECRET_BACKUPS,
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

TransportSecretStr = Annotated[
    OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_TRANSPORT
]
HttpSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_UNIT_HTTP]
AdminSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_APP_ADMIN]
UserSecretStr = Annotated[OptionalSecretStr, Field(exclude=True, default=None), SECRET_USERS]
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
       `bind()` adds a repository to it so model can read and write relation's databag
       this repository provides
       You don't use bind directly, instead use `bind_model_to_repository()`.

    2) WRITING A PLAIN FIELD or how auto-save works
       Assigning a field goes through `__setattr__`. For an ordinary field it stores the
       value, then calls `_write_to_databag()`, which serializes the whole model and writes it to
       the databag. You never call _write_to_databag() yourself.

           server.started = "1232323" -> databag: started = 1232323

       Some writes are skipped and kept in-memory only (see `_writable_repository`): an unbound
       model, a read-only one (points at another app's databag we can't write), or an app
       databag when we're not the leader.

    3) SECRET FIELDS is delegated to a "sibling" models
       Some fields are not plain databag values because they belong to a Juju secret group. To
       keep secrets out of the plain databag(only for optimization purposes),
       those fields are defined on a SIBLING model, not on this one.
       `_secret_group_fields` is the map that says
       "field name -> which sibling model owns it".

       A sibling is just another model over the same databag (built + cached by
       `build_sibling_model`). Reads and writes of a secret field are forwarded to it:

         Write: `server.http_key_password = "3323"`
             `__setattr__` sees a secret field -> forwards to the sibling -> the sibling
             saves the value into its Juju secret

         Read: `server.http_key_password`
             `__getattr__` sees this model doesn't store that field -> asks the sibling,
             which resolves the real value back out of the Juju secret.

       So from a caller's point of view a secret field looks and behaves exactly like a
       normal field.

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
    # Model and sibling models "how to serialize me when saving" configuration
    _write_context: dict | None = PrivateAttr(default=None)
    # Counter for `update()`. Incremented on entering a batch block and decremented
    # on exit; while > 0 field writes stay in-memory and the single update happens when it
    # returns to 0
    _update_depth_counter: int = PrivateAttr(default=0)
    # True for models loaded from a databag the charm cannot write (a remote app's/unit's).
    # Field assignments then only mutate the in-memory instance and never triggers an update.
    _read_only: bool = PrivateAttr(default=False)
    # Called after this instance successfully writes itself back to the databag. Lets the owning
    # ClusterState drop its parsed-model cache so a read later in the same hook re-reads the
    # databag/Juju secret instead of returning a now-stale cached model.
    _after_write: Any = PrivateAttr(default=None)
    # Cache of secret-group sibling models keyed by their class (see `build_sibling_model`).
    _sibling_cache: dict | None = PrivateAttr(default=None)
    # Maps field name -> sibling RelationModel class, for fields split out into a dedicated
    # secret-group models
    _secret_group_fields: ClassVar[dict[str, type["RelationModel"]]] = {}

    def bind(
        self,
        repository: AbstractRepository,
        write_context: dict | None = None,
        read_only: bool = False,
        after_write: Any = None,
    ) -> "RelationModel":
        """Attach the repository this instance should persist itself through.

        `read_only` is for models loaded from a databag the charm cannot write
        (a remote app's or remote unit's): field assignments then only mutate the
        in-memory instance instead of triggering a persist.

        `after_write` is an optional zero-arg callable invoked after a successful
        write (see `_after_write`); ClusterState passes its cache-invalidation hook.
        """
        # "Binding" == handing the model its databag handle. From here on the model can
        # read/write the databag: `_repository` is what every persist writes through, and
        # `component`/`relation` below read straight off it. Before bind() these are None
        # and the model is a plain in-memory object that saves nothing.
        self._repository = repository
        self._write_context = write_context
        self._read_only = read_only
        self._after_write = after_write
        return self

    @property
    def component(self):
        """The Juju unit/application this model's data is bound to, if any."""
        return self._repository.component if self._repository is not None else None

    @property
    def relation(self):
        """The ops.Relation this model's data is bound to, if any."""
        return self._repository.relation if self._repository is not None else None

    def build_sibling_model(self, model_cls: type[BaseModel]) -> Any:
        """Build another model bound to this same relation.

        Used by fields split into a dedicated secret-group model so a method on one can reach
        its sibling without needing a separate ClusterState accessor.
        """
        # A sibling is just another model over the same databag as this one. We
        # build it lazily the first time a secret field needs it, then cache it so repeated
        # reads/writes of secret fields all go through one shared instance (one parse per hook).
        if self._repository is None:
            return None
        cache = self._sibling_cache
        if cache is None:
            cache = self._sibling_cache = {}
        if model_cls in cache:
            return cache[model_cls]
        # Build the sibling from our repository (so it reads/writes the same databag) and
        # bind it too, so setting a field on the sibling updates exactly like on the parent.
        model = _lib_build_model(self._repository, model_cls)
        if isinstance(model, RelationModel):
            model.bind(self._repository, self._write_context, after_write=self._after_write)
        cache[model_cls] = model
        return model

    def __getattr__(self, name: str) -> Any:
        """Reads an attribute from databag.

        Delegate reads of secret-group fields to their sibling model, if any.
        Reading e.g. `server.http_key_password`: this model doesn't actually store that
        field because it's a secret that lives in the sibling model. So we look the name up in
        `_secret_group_fields`, find the sibling class, and read the value off the sibling.
        """
        target_cls = type(self)._secret_group_fields.get(name)
        if target_cls is not None:
            sibling = self.build_sibling_model(target_cls)
            value = getattr(sibling, name) if sibling is not None else None
            if value is None:
                # extract_secrets() overwrites a field with None when the group's Juju
                # secret exists but doesn't hold that key; surface the field's declared
                # default instead so callers never see None on a defaulted field.
                field_info = target_cls.__pydantic_fields__.get(name)
                if field_info is not None:
                    return field_info.get_default(call_default_factory=True)
            return value
        return super().__getattr__(name)  # type: ignore[misc]

    def __setattr__(self, name: str, value: Any) -> None:
        """Updates the model whenever a (non-private) attribute is set.

        Fields split out into a sibling secret-group model (see `_secret_group_fields`)
        are delegated there instead of being updated on this instance.
        """
        target_cls = type(self)._secret_group_fields.get(name)
        if target_cls is not None:
            if sibling := self.build_sibling_model(target_cls):
                setattr(sibling, name, value)
            return

        super().__setattr__(name, value)
        if not name.startswith("_"):
            self._write_to_databag()

    def __delattr__(self, name: str) -> None:
        """Reset the field to its default value and persist."""
        target_cls = type(self)._secret_group_fields.get(name)
        if target_cls is not None:
            if sibling := self.build_sibling_model(target_cls):
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
        `__setattr__` and wouldn't otherwise trigger an update.
        """
        self._update_depth_counter += 1
        try:
            yield self
        finally:
            self._update_depth_counter -= 1
            if self._update_depth_counter == 0:
                self._write_to_databag()

    @contextmanager
    def update_secrets(self, model_cls: type[BaseModel]) -> Iterator[Any]:
        """Batch-update a dedicated secret-group model bound to this same relation."""
        sibling = self.build_sibling_model(model_cls)
        if sibling is None:
            raise ValueError("Cannot update secrets: model is not bound to a relation.")
        with sibling.update() as m:
            yield m

    def _writable_repository(self) -> Any:
        """Return the repository to update to, or None if this write should be skipped.

        Combines every "don't write" guard so `_write_to_databag` stays a straight-line
        write: suspended batch, read-only/never-bound instance, inactive relation,
        a remote (unwritable) databag, or an app databag on a non-leader unit.
        """
        if self._update_depth_counter > 0 or self._read_only:
            # Suspended inside a batch `update()`, or bound to a remote
            # databag, either way stay in-memory only.
            return None

        repository = self._repository
        if repository is None:
            return None

        relation = getattr(repository, "relation", None)
        if relation is not None and not getattr(relation, "active", True):
            return None

        component: Any = getattr(repository, "component", None)
        local_unit: Any = getattr(repository, "_local_unit", None)
        local_app: Any = getattr(repository, "_local_app", None)
        if component is not None and component not in (local_unit, local_app):
            logger.debug(
                "Not updating %s: bound to remote component %s.",
                type(self).__name__,
                component,
            )
            return None

        if (
            component is not None
            and component == local_app
            and local_unit is not None
            and not local_unit.is_leader()
        ):
            return None

        return repository

    def _write_to_databag(self) -> None:
        """Write the current model state back to its bound relation databag."""
        repository = self._writable_repository()
        if repository is None:
            return

        self._update_depth_counter += 1

        try:
            _write_model(repository, self, context=self._write_context)
        except (SecretNotFoundError, PydanticSerializationError) as e:
            logger.warning(
                "Secret unavailable while updating %s -- writing non-secret fields only: %s",
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
            self._update_depth_counter -= 1

        self._sibling_cache = None
        if self._after_write is not None:
            self._after_write()

    def _write_non_secret_fields(self, repository: Any) -> None:
        """Write the model's plain databag fields, leaving Juju secrets untouched."""
        context = {k: v for k, v in (self._write_context or {}).items()}
        dumped = self.model_dump(mode="json", context=context or None, exclude_none=False)
        for field, value in dumped.items():
            if value is None:
                repository.delete_field(field)
                continue
            dumped_value = value if isinstance(value, str) else json.dumps(value)
            repository.write_field(field, dumped_value)


def bind_model_to_repository(
    interface: Any,
    relation_id: int,
    model_cls: type[BaseModel],
    component: Any | None = None,
    write_context: dict | None = None,
    read_only: bool = False,
    after_write: Any = None,
) -> Any:
    """Build a model through `interface` and bind it to its repository for data manipulations.

    `interface` is one of the `*RepositoryInterface` classes. If the built
    model is a RelationModel, it is bound so that setting any of its fields (or
    using `.update()`) writes it straight back to the relation databag.

    Pass `read_only=True` when `component` is a remote app/unit whose databag we cannot write.
    """
    repository = interface.repository(relation_id, component)
    model = _lib_build_model(repository, model_cls)
    if isinstance(model, RelationModel):
        model.bind(repository, write_context, read_only=read_only, after_write=after_write)
    return model
