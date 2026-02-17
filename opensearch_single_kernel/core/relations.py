#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base classes for charm relations."""
import enum
import json
import logging
from abc import ABC, abstractmethod
from ast import literal_eval
from typing import Any

from ops.model import Application, Relation, Unit
from overrides import override

from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.core.models import Model
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    Data,
    ProviderData,
    RequirerData,
)

logger = logging.getLogger(__name__)


class DataStore(ABC):
    """Class representing a data store used in the OPs code of the charm."""

    def __init__(self, charm):
        self._charm = charm

    @abstractmethod
    def put(self, scope: Scope, key: str, value: Any | None) -> None:
        """Put string into the data store."""
        pass

    @abstractmethod
    def put_object(
        self, scope: Scope, key: str, value: dict[str, Any], merge: bool = False
    ) -> None:
        """Put object into the data store."""
        pass

    @abstractmethod
    def has(self, scope: Scope, key: str):
        """Check if the said key is contained in the store."""
        pass

    @abstractmethod
    def get(
        self, scope: Scope, key: str, default: int | float | str | bool | None = None
    ) -> int | float | str | bool | None:
        """Get string from the data store."""
        pass

    @abstractmethod
    def get_object(self, scope: Scope, key: str) -> dict[str, Any] | None:
        """Get dict / json object from the data store."""
        pass

    @abstractmethod
    def delete(self, scope: Scope, key: str):
        """Delete object from the data store."""
        pass

    @staticmethod
    def cast(str_val: str) -> bool | int | float | str:
        """Cast a string to the corresponding primitive type."""
        try:
            typed_val = literal_eval(str_val.capitalize())
            if type(typed_val) not in {bool, int, float, str}:
                return str_val

            return typed_val
        except (ValueError, SyntaxError):
            return str_val

    @staticmethod
    def put_or_delete(data: dict[str, str], key: str, value: str | None):
        """Put data into the key/val data store or delete if value is None."""
        if value is None:
            data.pop(key, None)
            return

        data.update({key: str(value)})


class RelationDataStore(DataStore):
    """Class representing a relation data store for a charm."""

    def __init__(self, charm, relation_name: str):
        super(RelationDataStore, self).__init__(charm)
        self.relation_name = relation_name

    @override
    def put(self, scope: Scope, key: str, value: Any | None) -> None:
        """Put string into the relation data store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._get_relation_data(scope)
        self.put_or_delete(data, key, value)

    @override
    def put_object(
        self, scope: Scope, key: str, value: dict[str, Any], merge: bool = False
    ) -> None:
        """Put dict / json object into relation data store."""
        if merge:
            stored = self.get_object(scope, key)

            if stored is not None:
                stored.update(value)
                value = stored

        sorted_value = Model.sort_payload(value)

        payload_str = None
        if value is not None:
            payload_str = json.dumps(
                sorted_value, default=RelationDataStore._default_encoder, sort_keys=True
            )

        self.put(scope, key, payload_str)

    @override
    def has(self, scope: Scope, key: str):
        """Check if the said key is contained in the relation data."""
        if scope is None:
            raise ValueError("Scope undefined.")

        return key in (self._get_relation_data(scope) or {})

    @override
    def get(
        self,
        scope: Scope,
        key: str,
        default: int | float | str | bool | None = None,
        auto_casting: bool = True,
    ) -> int | float | str | bool | None:
        """Get string from the relation data store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._get_relation_data(scope)

        value = data.get(key)
        if value is None:
            return default

        if not auto_casting:
            return value

        return self.cast(value)

    @override
    def get_object(self, scope: Scope, key: str) -> dict[str, Any] | None:
        """Get dict / json object from the relation data store."""
        data = self.get(scope, key)
        if data is None:
            return None

        return json.loads(data)

    @override
    def delete(self, scope: Scope, key: str):
        """Delete object from the relation data store."""
        self.put(scope, key, None)

    def _get_relation_data(self, scope: Scope) -> dict[str, str]:
        """Relation data object."""
        relation = self._charm.model.get_relation(self.relation_name)
        if relation is None:
            return {}

        relation_scope = self._charm.app if scope == Scope.APP else self._charm.unit

        return relation.data.get(relation_scope)

    @staticmethod
    def _default_encoder(o: Any) -> Any:
        """Default encoder for json dumps."""
        if isinstance(o, enum.Enum):
            return o.value

        if hasattr(o, "__dict__"):
            return vars(o)

        raise TypeError(f"Unserializable {o.__class__.__name__}")


class RelationState:
    """Relation state object."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Unit | Application | None,
    ):
        self.relation = relation
        self.data_interface = data_interface
        self.unit = component
        self.relation_data = self.data_interface.as_dict(self.relation.id) if self.relation else {}

    def __bool__(self) -> bool:
        """Boolean evaluation based on the existence of self.relation."""
        try:
            return bool(self.relation)
        except AttributeError:
            return False

    def update(self, items: dict[str, str]) -> None:
        """Write to relation data."""
        if not self.relation:
            logger.warning(
                f"Fields {list(items.keys())} were attempted to be written on the relation before it exists."
            )
            return

        delete_fields = [key for key in items if not items[key]]
        update_content = {k: items[k] for k in items if k not in delete_fields}

        self.relation_data.update(update_content)

        for field in delete_fields:
            # use del instead of pop here because of error with dataplatform-libs
            try:
                del self.relation_data[field]
            except KeyError:
                pass

    def get_object(self, key: str) -> dict[str, Any] | None:
        """Get dict / json object from the relation data store."""
        data = self.relation_data.get(key)
        if data is None:
            return None

        return json.loads(data)

    def put_object(self, key: str, value: dict[str, Any], merge: bool = False) -> None:
        """Put dict / json object into relation data store."""
        if merge:
            stored = self.get_object(key)

            if stored is not None:
                stored.update(value)
                value = stored

        sorted_value = Model.sort_payload(value)

        payload_str = None
        if value is not None:
            payload_str = json.dumps(
                sorted_value, default=RelationDataStore._default_encoder, sort_keys=True
            )

        self.update({key: payload_str})


class PeerClusterOrchestratorData(ProviderData, RequirerData):
    """Orchestrator provider data model."""

    # This is to bypass the PrematureDataAccessError, which is irrelevant in this case.
    def _update_relation_data(self, relation: Relation, data: dict[str, str]) -> None:
        """Set values for fields not caring whether it's a secret or not."""
        super(ProviderData, self)._update_relation_data(relation, data)


class PeerClusterData(ProviderData, RequirerData):
    """Orchestrator requirer data model."""

    # This is to bypass the PrematureDataAccessError, which is irrelevant in this case.
    def _update_relation_data(self, relation: Relation, data: dict[str, str]) -> None:
        """Set values for fields not caring whether it's a secret or not."""
        super(ProviderData, self)._update_relation_data(relation, data)


class PeerCluster(RelationState):
    """State collection metadata for a peer-cluster application."""

    def __init__(self, relation, data_interface, component):
        super().__init__(relation, data_interface, component)
