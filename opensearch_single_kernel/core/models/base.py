#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base model classes shared across all core models.

Includes:
    - Model: base class for plain (non relation-backed) value objects.
    - PersistentModel: mixin for models fetched from a relation databag through
      ClusterState, which can write themselves back to that databag.
    - Common cluster-wide value objects (App, Node, DeploymentDescription, ...).
"""

import json
import logging
from abc import ABC
from contextlib import contextmanager
from datetime import datetime
from hashlib import md5
from typing import Any, ClassVar, Iterator

from ops.model import SecretNotFoundError
from pydantic import (
    BaseModel,
    Field,
    PrivateAttr,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticSerializationError
from typing_extensions import Annotated, Self

from opensearch_single_kernel.common.constants import (
    SECRET_APP_ADMIN,
    SECRET_PLUGIN,
    SECRET_UNIT_HTTP,
    SECRET_UNIT_TRANSPORT,
    SECRET_USERS,
    DeploymentType,
    Directive,
    StartMode,
    State,
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


def _sort_nested_dicts(obj: Any) -> Any:
    """Recursively sort dict keys so serialized output is deterministic."""
    if isinstance(obj, dict):
        return {k: _sort_nested_dicts(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_sort_nested_dicts(item) for item in obj]
    return obj


def stripped_or_none(value: str | None) -> str | None:
    """Collapse empty or whitespace-only values to None.

    Secret fields use a single-space placeholder to force creation of their backing
    Juju secret (see the models: `initialize_empty_secrets`)
    this normalizes such placeholders and genuinely empty values to None
    before they are copied around or handed to callers.
    """
    return (value or "").strip() or None


class Model(ABC, BaseModel):
    """Base model class."""

    def to_dict(self, by_alias: bool = False) -> dict[str, Any]:
        """Deserialize object into a dict."""
        return self.model_dump(by_alias=by_alias)

    @classmethod
    def from_dict(cls, input_dict: dict[str, Any] | None):
        """Create a new instance of this class from a json/dict repr."""
        if not input_dict:  # to handle when classes defined defaults
            return cls()
        return cls(**input_dict)

    def __eq__(self, other) -> bool:
        """Compare field-by-field, treating list fields as unordered."""
        if other is None:
            return False

        equal = True
        for attr_key, attr_val in self.__dict__.items():
            other_attr_val = getattr(other, attr_key)
            if isinstance(attr_val, list):
                equal = equal and sorted(attr_val) == sorted(other_attr_val)
            else:
                equal = equal and (attr_val == other_attr_val)

        return equal


class PersistentModel(BaseModel):
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

    # Maps field name -> sibling PersistentModel class, for fields split out into a dedicated
    # secret-group model (e.g. TLS/user secrets split out of a plain peer model). Overridden by
    # subclasses (see `peer.py`); empty here means "no delegation, this model is self-contained".
    _secret_group_fields: ClassVar[dict[str, type]] = {}

    def bind(
        self,
        repository: AbstractRepository,
        write_context: dict | None = None,
        read_only: bool = False,
    ) -> "PersistentModel":
        """Attach the repository this instance should persist itself through.

        `read_only` is for models loaded from a databag the charm cannot write
        (a remote app's or remote unit's): field assignments then only mutate the
        in-memory instance instead of triggering a persist.
        """
        self._repository = repository
        self._write_context = write_context
        self._read_only = read_only
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
        model = _lib_build_model(self._repository, model_cls)
        if isinstance(model, PersistentModel):
            model.bind(self._repository, self._write_context)
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
    def update(self) -> Iterator["PersistentModel"]:
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

    def _persist(self) -> None:
        """Write the current model state back to its bound relation databag."""
        if self._suspend_persist_depth > 0:
            return

        if self._read_only:
            # Bound to a remote (unwritable) databag -- mutations stay in-memory only.
            return

        repository = self._repository
        if repository is None:
            # Normal during __init__/validation (secret extraction sets fields before
            # `.bind()` runs) and for plain, never-bound instances -- nothing to persist to.
            # Not logged: models with several secret fields (e.g. PeerClusterAppModel) hit
            # this once per field on every single bind, drowning out real log messages.
            return

        relation = getattr(repository, "relation", None)
        if relation is not None and not getattr(relation, "active", True):
            return

        # Juju never allows writing a remote app's/unit's databag -- if this model is
        # bound to one (e.g. built with remote=True), keep mutations in-memory only.
        component = getattr(repository, "component", None)
        if component is not None and component not in (
            getattr(repository, "_local_unit", None),
            getattr(repository, "_local_app", None),
        ):
            logger.debug(
                "Not persisting %s: bound to remote component %s.",
                type(self).__name__,
                component,
            )
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


class App(Model):
    """Data class representing an application."""

    id: str | None = None
    short_id: str | None = None
    name: str | None = None
    model_uuid: str | None = None

    @model_validator(mode="after")
    def set_props(self) -> Self:
        """Generate the attributes depending on the input."""
        # If all values are already set, we return self
        if all(v is not None for v in [self.id, self.name, self.model_uuid, self.short_id]):
            return self

        if not self.id and (self.name is None or self.model_uuid is None):
            raise ValueError("'id' or 'name and model_uuid' must be set.")

        if self.id:
            full_id_split = self.id.split("/")
            self.name = full_id_split[-1]
            self.model_uuid = full_id_split[0]
        else:
            self.id = f"{self.model_uuid}/{self.name}"
        self.short_id = md5(self.id.encode()).hexdigest()[:3]

        return self


class Node(Model):
    """Data class representing a node in a cluster."""

    name: str
    roles: list[str]
    ip: str
    app: App
    unit_number: int
    temperature: str | None = None

    @field_validator("roles")
    @classmethod
    def roles_set(cls, v):
        """Returns deduplicated sorted list of roles."""
        return sorted(set(v))

    def is_cm_eligible(self):
        """Returns whether this node is a cluster manager eligible member."""
        return "cluster_manager" in self.roles

    def is_voting_only(self):
        """Returns whether this node is a voting member."""
        return "voting_only" in self.roles

    def is_data(self):
        """Returns whether this node is a data* node."""
        for role in self.roles:
            if role.startswith("data"):
                return True

        return False


class DeploymentState(Model):
    """Full state of a deployment, along with the juju status."""

    value: State
    message: str = Field(default="")

    @model_validator(mode="after")
    def prevent_none(self):
        """Validate the message or lack of depending on the state."""
        if self.value == State.ACTIVE:
            self.message = ""
        elif not self.message.strip():
            raise ValueError("The message must be set when state not Active.")

        return self


class PeerClusterConfig(Model):
    """Model class for the multi-clusters related config set by the user."""

    cluster_name: str
    init_hold: bool
    roles: list[str]
    # Derived from a "data.<temperature>" role by the validator below; None when no
    # data-temperature role is configured (also the case for databags written by
    # charm revisions that predate this field).
    data_temperature: str | None = None

    @model_validator(mode="after")
    def set_node_temperature(self):
        """Set and validate the node temperature."""
        allowed_temps = ["hot", "warm", "cold", "frozen", "content"]

        input_temps = set()
        for role in self.roles:
            if not role.startswith("data."):
                continue

            temp = role.split(".")[1]
            if temp not in allowed_temps:
                raise ValueError(f"data.'{temp}' not allowed. Allowed values: {allowed_temps}")

            input_temps.add(temp)

        if len(input_temps) > 1:
            raise ValueError("More than 1 data temperature provided.")
        elif input_temps:
            temperature = input_temps.pop()
            self.data_temperature = temperature

            self.roles.append("data")
            self.roles.remove(f"data.{temperature}")
            self.roles = list(set(self.roles))
        return self


class DeploymentDescription(Model):
    """Model class describing the current state of a deployment / sub-cluster."""

    app: App
    config: PeerClusterConfig
    start: StartMode
    pending_directives: list[Directive]
    typ: DeploymentType
    state: DeploymentState = DeploymentState(value=State.ACTIVE)
    cluster_name_autogenerated: bool = False
    promotion_time: float | None = None

    @model_validator(mode="after")
    def set_promotion_time(self):
        """Set promotion time of a failover to a main CM."""
        if not self.promotion_time and self.typ == DeploymentType.MAIN_ORCHESTRATOR:
            self.promotion_time = datetime.now().timestamp()

        return self


class PluginConfigInfo(Model):
    """Model class for representing data needed to add or remove plugin configuration"""

    relation_name: str | None = None
    secret_name: str | None = None
    cleanup: dict[str, list[str]] = Field(default_factory=dict)

    @field_serializer("cleanup")
    def _sort_cleanup(self, value: dict[str, list[str]]) -> dict[str, list[str]]:
        return _sort_nested_dicts(value)

    def add_cleanup_items(self, cleanup: dict[str, list[str]]) -> None:
        """Merge items into cleanup dictionary avoiding duplicates."""
        for key, items in cleanup.items():
            current = self.cleanup.setdefault(key, [])
            self.cleanup[key] = sorted(list(set(current) | set(items)))


def bind_model(
    interface: Any,
    relation_id: int,
    model_cls: type,
    component: Any | None = None,
    write_context: dict | None = None,
    read_only: bool = False,
) -> Any:
    """Build a model through `interface` and bind it to its repository for self-writes.

    `interface` is one of the `*RepositoryInterface` classes (e.g.
    OpsPeerRepositoryInterface, OpsPeerUnitRepositoryInterface, ...). If the built
    model is a PersistentModel, it is bound so that setting any of its fields (or
    using `.update()`) writes it straight back to the relation databag.

    Pass `read_only=True` when `component` is a remote app/unit whose databag this
    charm cannot write -- field assignments then stay in-memory.
    """
    repository = interface.repository(relation_id, component)
    model = _lib_build_model(repository, model_cls)
    if isinstance(model, PersistentModel):
        model.bind(repository, write_context, read_only=read_only)
    return model
