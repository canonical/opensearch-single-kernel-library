#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Secrets management, TODO: This needs to be refactored.

The idea is to keep some stuff here to be used in the state, but move the event handling
to an event handler.
"""

from typing import TYPE_CHECKING, Dict, Optional, Union

from ops import Relation, Secret, SecretNotFoundError
from ops.framework import Object
from overrides import override

from opensearch_single_kernel.common.constants import (
    HASH_POSTFIX,
    OPENSEARCH_SYSTEM_USERS,
    PW_POSTFIX,
)
from opensearch_single_kernel.common.exceptions import OpenSearchSecretInsertionError
from opensearch_single_kernel.core.models import RelationDataStore, Scope, SecretCache
from opensearch_single_kernel.utils.logging import WithLogging

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


class OpenSearchSecrets(Object, RelationDataStore, WithLogging):
    """Encapsulating Juju3 secrets handling."""

    LABEL_SEPARATOR = ":"

    def __init__(self, charm: "OpenSearchBaseCharm", peer_relation: str):
        Object.__init__(self, charm, peer_relation)
        RelationDataStore.__init__(self, charm, peer_relation)

        self.cached_secrets = SecretCache()
        self.charm = charm

    def _user_from_hash_key(self, key):
        """Which user is referred to by key?"""
        for user in OPENSEARCH_SYSTEM_USERS:
            if key == self.hash_key(user):
                return user

    def password_key(self, username: str) -> str:
        """Unified key to store password secrets specific to a user."""
        return f"{username}-{PW_POSTFIX}"

    def hash_key(self, username: str) -> str:
        """Unified key to store password secrets specific to a user."""
        return f"{username}-{HASH_POSTFIX}"

    def label(self, scope: Scope, key: str) -> str:
        """Generated keys to be used within relation data to refer to secret IDs."""
        components = [self.charm.app.name, scope.val]
        if scope == Scope.UNIT:
            components.append(str(self.charm.unit_id))
        components.append(key)
        return self.LABEL_SEPARATOR.join(components)

    def breakdown_label(self, label: str) -> Dict[str, str]:
        """Return meaningful components resolved from a secret label."""
        components = label.split(self.LABEL_SEPARATOR)
        if len(components) < 3 or len(components) > 4:
            raise ValueError("Invalid label %s", label)

        scope = Scope[components[1].upper()]

        if scope == Scope.APP:
            key = components[2]
            unit_id = None
        else:
            key = components[3]
            unit_id = int(components[2])

        return {
            "application_name": components[0],
            "scope": scope,
            "unit_id": unit_id,
            "key": key,
        }

    @staticmethod
    def _safe_obj_data(indict: Dict) -> Dict[str, any]:
        return {
            key: str(val) for key, val in indict.items() if val is not None and str(val).strip()
        }

    def _get_juju_secret(self, scope: Scope, key: str) -> Optional[Secret]:
        label = self.label(scope, key)

        cached_secret_meta = self.cached_secrets.get_meta(scope, label)
        if cached_secret_meta:
            return cached_secret_meta

        try:
            secret = self.charm.model.get_secret(label=label)
        except SecretNotFoundError:
            return None

        self.cached_secrets.set_meta(scope, label, secret)
        return secret

    def _get_juju_secret_content(
        self, scope: Scope, key: str, peek: bool = False
    ) -> Optional[Dict[str, str]]:
        cached_secret_content = self.cached_secrets.get_content(scope, self.label(scope, key))
        if cached_secret_content:
            return cached_secret_content

        secret = self._get_juju_secret(scope, key)
        if not secret:
            return None

        if peek:
            content = secret.peek_content()
        else:
            content = secret.get_content()
        self.cached_secrets.put_content(scope, self.label(scope, key), content=content)
        return content

    def _add_juju_secret(self, scope: Scope, key: str, value: Dict[str, str]) -> Optional[Secret]:
        safe_value = self._safe_obj_data(value)

        if not safe_value:
            return None

        scope_obj = self.charm.app if scope == Scope.APP else self.charm.unit

        label = self.label(scope, key)
        try:
            secret = scope_obj.add_secret(safe_value, label=label)
            self.logger.debug(f"Secret added {secret}")
        except ValueError as e:
            self.logger.error("Secret %s:%s couldn't be added", str(scope.val), str(key))
            raise OpenSearchSecretInsertionError(e)

        self.cached_secrets.put(scope, label, secret, safe_value)

        # Keeping a reference of the secret's ID just for sure.
        # May come handy for internal Observer Juju relation.
        if scope == Scope.APP:
            self.charm.state.application.update({label: secret.id})
        else:
            self.charm.state.server.update({label: secret.id})

        return secret

    def _update_juju_secret(
        self, scope: Scope, key: str, value: Dict[str, str], merge: bool = False
    ) -> Optional[Secret]:
        # If the call below occurs for the 2nd time within the same flow,
        # it's hitting on the cache (i.e. cheap)
        secret = self._get_juju_secret(scope, key)

        content = {}
        if merge:
            content = self._get_juju_secret_content(scope, key)

        content.update(value)
        safe_content = self._safe_obj_data(content)

        if not safe_content:
            return self._remove_juju_secret(scope, key)

        try:
            secret.set_content(safe_content)
        except ValueError as e:
            self.logger.error("Secret %s:%s couldn't be updated", str(scope.val), str(key))
            raise OpenSearchSecretInsertionError(e)

        self.cached_secrets.put(scope, self.label(scope, key), content=safe_content)
        return secret

    def _add_or_update_juju_secret(
        self, scope: Scope, key: str, value: Dict[str, str], merge: bool = False
    ):
        # Existing secret?
        if not self._get_juju_secret(scope, key):
            return self._add_juju_secret(scope, key, value)
        return self._update_juju_secret(scope, key, value, merge)

    def _remove_juju_secret(self, scope: Scope, key: str):
        secret = self._get_juju_secret(scope, key)
        if not secret:
            self.logger.warning(f"Secret {scope}:{key} can't be deleted as it doesn't exist")
            return None

        secret.remove_all_revisions()
        self.cached_secrets.delete(scope, self.label(scope, key))

    @override
    def has(self, scope: Scope, key: str):
        """Check if the said key is contained in the relation data."""
        if scope is None:
            raise ValueError("Scope undefined.")

        if not self.charm.state.implements_secrets:
            return super().has(scope, key)

        return bool(self._get_juju_secret(scope, key))

    @override
    def get(
        self,
        scope: Scope,
        key: str,
        default: Optional[Union[int, float, str, bool]] = None,
        auto_casting: bool = True,
    ) -> Optional[Union[int, float, str, bool]]:
        """Getting a secret's value."""
        self.logger.debug(f"Getting secret {scope}:{key}")

        if not self.charm.state.implements_secrets:
            return super().get(scope, key, default, auto_casting)

        content = self._get_juju_secret_content(scope, key)
        if not content:
            return default
        value = content.get(key)

        if not value:
            return None

        if not auto_casting:
            return value

        if not isinstance(value, dict):
            return self.cast(value)
        else:
            raise TypeError(f"Secret {scope}:{key} is to be retrieved with 'get_object()'")

    @override
    def get_object(self, scope: Scope, key: str, peek: bool = False) -> Optional[Dict[str, any]]:
        """Get dict object from the relation data store."""
        if not self.charm.state.implements_secrets:
            return super().get_object(scope, key)

        return self._get_juju_secret_content(scope, key, peek)

    @override
    def put(self, scope: Scope, key: str, value: Optional[Union[any]]) -> None:
        """Adding or updating a secret's value."""
        self.logger.debug(f"Putting secret {scope}:{key}")
        if not self.charm.state.implements_secrets:
            return super().put(scope, key, value)

        # todo: remove when secret-changed not triggered for same content update
        if self.get(scope, key) == value:
            return

        self._add_or_update_juju_secret(scope, key, {key: value})

    @override
    def put_object(
        self, scope: Scope, key: str, value: Dict[str, any], merge: bool = False
    ) -> None:
        """Put a dict object into relation data store."""
        self.logger.debug(f"Putting secret object {scope}:{key}")
        if not self.charm.state.implements_secrets:
            return super().put_object(scope, key, value, merge)

        # todo: remove when secret-changed not triggered for same content update
        if self.get_object(scope, key) == self._safe_obj_data(value):
            return

        self._add_or_update_juju_secret(scope, key, value, merge)

    @override
    def delete(self, scope: Scope, key: str) -> None:
        """Removing a secret."""
        self.logger.debug(f"Removing secret {scope}:{key}")

        if not self.charm.state.implements_secrets:
            return super().delete(scope, key)

        self._remove_juju_secret(scope, key)

        self.logger.debug(f"Deleted secret {scope}:{key}")

    def get_secret_id(self, scope: Scope, key: str) -> Optional[str]:
        """Get the secret ID from the cache."""
        label = self.label(scope, key)
        return self.charm.peers_data.get(scope, label)

    def grant_secret_to_relation(self, secret_id: int, relation: Relation):
        """Grant a secret to a relation."""
        secret = self.charm.model.get_secret(id=secret_id)
        secret.grant(relation)
