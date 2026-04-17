# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Secrets management, TODO: This needs to be refactored.

The idea is to keep some stuff here to be used in the state, but move the event handling
to an event handler.
"""
import logging
from typing import TYPE_CHECKING, Any

from ops import ModelError, Relation, Secret, SecretNotFoundError
from ops.framework import Object
from overrides import override

from opensearch_single_kernel.common.constants import SECRETS_LABEL_SEPARATOR, Scope
from opensearch_single_kernel.common.exceptions import OpenSearchSecretInsertionError
from opensearch_single_kernel.core.relations import RelationDataStore
from opensearch_single_kernel.utils import secrets as secrets_utils

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm


logger = logging.getLogger(__name__)


# TODO this class should be removed when data interfaces v1 is integrated
class OpenSearchSecrets(Object, RelationDataStore):
    """Encapsulating Juju3 secrets handling."""

    def __init__(self, charm: "OpenSearchBaseCharm", peer_relation: str):
        Object.__init__(self, charm, peer_relation)
        RelationDataStore.__init__(self, charm, peer_relation)

        self.cached_secrets = SecretCache()
        self.charm = charm

    def resolve_credential(
        self,
        credential: str,
        *,
        content_key: str | None = None,
        password_key: str | None = None,
        hash_key: str | None = None,
        peek_secrets: bool = False,
    ) -> str | dict[str, str] | None:
        """Resolves credential to its secret value if it's a secret"""
        if not credential.startswith("secret://"):
            return credential

        if not content_key:
            if password_key:
                content_key = secrets_utils.password_key(password_key)
            elif hash_key:
                content_key = secrets_utils.hash_key(hash_key)
            elif peek_secrets:
                return self.charm.model.get_secret(id=credential).peek_content()
            else:
                return self.charm.model.get_secret(id=credential).get_content()
        if peek_secrets:
            return self.charm.model.get_secret(id=credential).peek_content().get(content_key)
        return self.charm.model.get_secret(id=credential).get_content().get(content_key)

    def label(self, scope: Scope, key: str) -> str:
        """Generated keys to be used within relation data to refer to secret IDs."""
        components = [self.charm.app.name, scope.val]
        if scope == Scope.UNIT:
            components.append(str(self.charm.state.server.unit_id))
        components.append(key)
        return SECRETS_LABEL_SEPARATOR.join(components)

    def _get_juju_secret(self, scope: Scope, key: str) -> Secret | None:
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
    ) -> dict[str, str] | None:
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

    def _add_juju_secret(self, scope: Scope, key: str, value: dict[str, str]) -> Secret | None:
        safe_value = secrets_utils.safe_obj_data(value)

        if not safe_value:
            return None

        scope_obj = self.charm.app if scope == Scope.APP else self.charm.unit

        label = self.label(scope, key)
        try:
            secret = scope_obj.add_secret(safe_value, label=label)
            logger.debug("Secret added %s", secret)
        except ValueError as e:
            logger.error("Secret %s:%s couldn't be added", str(scope.val), str(key))
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
        self, scope: Scope, key: str, value: dict[str, str], merge: bool = False
    ) -> Secret | None:
        # If the call below occurs for the 2nd time within the same flow,
        # it's hitting on the cache (i.e. cheap)
        secret = self._get_juju_secret(scope, key)

        content = {}
        if merge:
            content = self._get_juju_secret_content(scope, key)

        content.update(value)
        safe_content = secrets_utils.safe_obj_data(content)

        if not safe_content:
            return self._remove_juju_secret(scope, key)

        try:
            secret.set_content(safe_content)
        except ValueError as e:
            logger.error("Secret %s:%s couldn't be updated", str(scope.val), str(key))
            raise OpenSearchSecretInsertionError(e)

        self.cached_secrets.put(scope, self.label(scope, key), content=safe_content)
        return secret

    def _add_or_update_juju_secret(
        self, scope: Scope, key: str, value: dict[str, str], merge: bool = False
    ):
        # Existing secret?
        if not self._get_juju_secret(scope, key):
            return self._add_juju_secret(scope, key, value)
        return self._update_juju_secret(scope, key, value, merge)

    def _remove_juju_secret(self, scope: Scope, key: str):
        secret = self._get_juju_secret(scope, key)
        if not secret:
            logger.warning(
                "Secret %s:%s can't be deleted as it doesn't exist", str(scope.val), str(key)
            )
            return

        secret.remove_all_revisions()
        self.cached_secrets.delete(scope, self.label(scope, key))

    @override
    def has(self, scope: Scope, key: str) -> bool:
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
        default: float | str | bool | None = None,
        auto_casting: bool = True,
    ) -> int | float | str | bool | None:
        """Getting a secret's value."""
        logger.debug("Getting secret %s:%s", str(scope.val), str(key))

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
    def get_object(self, scope: Scope, key: str, peek: bool = False) -> dict[str, Any] | None:
        """Get dict object from the relation data store."""
        if not self.charm.state.implements_secrets:
            return super().get_object(scope, key)

        return self._get_juju_secret_content(scope, key, peek)

    @override
    def put(self, scope: Scope, key: str, value: Any | None) -> None:
        """Adding or updating a secret's value."""
        logger.debug("Putting secret %s:%s", str(scope.val), str(key))
        if not self.charm.state.implements_secrets:
            return super().put(scope, key, value)

        # todo: remove when secret-changed not triggered for same content update
        if self.get(scope, key) == value:
            return

        self._add_or_update_juju_secret(scope, key, {key: value})

    @override
    def put_object(
        self, scope: Scope, key: str, value: dict[str, Any], merge: bool = False
    ) -> None:
        """Put a dict object into relation data store."""
        logger.debug("Putting secret object %s:%s", str(scope.val), str(key))
        if not self.charm.state.implements_secrets:
            return super().put_object(scope, key, value, merge)

        # todo: remove when secret-changed not triggered for same content update
        if self.get_object(scope, key) == secrets_utils.safe_obj_data(value):
            return

        self._add_or_update_juju_secret(scope, key, value, merge)

    @override
    def delete(self, scope: Scope, key: str) -> None:
        """Removing a secret."""
        logger.debug("Removing secret %s:%s", str(scope.val), str(key))

        if not self.charm.state.implements_secrets:
            return super().delete(scope, key)

        self._remove_juju_secret(scope, key)

        logger.debug("Deleted secret %s:%s", str(scope.val), str(key))

    def get_tracked_secret(self, secret_id: str, scope: Scope, key: str) -> Secret | None:
        """Track a granted secret and add it to the cache"""
        label = self.label(scope, key)
        if cached_secret_meta := self.cached_secrets.get_meta(scope, label):
            # already tracking
            return cached_secret_meta
        try:
            secret = self._charm.model.get_secret(id=secret_id)
        except SecretNotFoundError:
            logger.info("Could not find secret: %s - %s", key, secret_id)
            return None

        self.cached_secrets.set_meta(scope, label, secret)
        self.cached_secrets.put_content(scope, label, secret.get_content(refresh=True))
        return secret

    def get_secret_id(self, scope: Scope, key: str) -> str | None:
        """Get the secret ID from the cache."""
        label = self.label(scope, key)
        return (
            self.charm.state.application.relation_data.get(label)
            if scope == Scope.APP
            else self.charm.state.server.relation_data.get(label)
        )

    def grant_secret_to_relation(self, secret_id: str, relation: Relation):
        """Grant a secret to a relation."""
        try:
            secret = self._charm.model.get_secret(id=secret_id)
            secret.grant(relation)
        except SecretNotFoundError:
            logger.error("Could not find secret: %s", secret_id)
            return False
        except ModelError:
            logger.error("Not owner of secret: %s. Cannot grant to relation", secret_id)
            return False
        return True

    def grant_secret_to_subclusters(self, secret_id: str, is_provider: bool) -> bool:
        """Returns True if secret is successfully granted to all subclusters"""
        for related_peer_cluster in self.charm.state.peer_clusters(is_provider=is_provider):
            if not self.grant_secret_to_relation(secret_id, related_peer_cluster.relation):
                return False
        return True

    def grant_secrets_to_peer_clusters(  # noqa: C901
        self,
        rel_data_secret_content: dict[str, Any] | None,
        is_provider: bool,
    ) -> None:
        """Grant the secrets to all the related apps."""
        # return if rel_data_secret_content was not successfully created
        if not rel_data_secret_content:
            return

        credentials = rel_data_secret_content["credentials"]
        for key, secret_id in credentials.items():
            # admin-username is not secrets
            if key == "admin_username":
                continue

            for related_peer_cluster in self.charm.state.peer_clusters(is_provider=is_provider):
                if relation := related_peer_cluster.relation:
                    if key == "s3":
                        if secret_id["access-key"]:
                            self.grant_secret_to_relation(secret_id["access-key"], relation)
                        if secret_id["secret-key"]:
                            self.grant_secret_to_relation(secret_id["secret-key"], relation)
                        if secret_id.get("s3-tls-ca-chain"):
                            self.grant_secret_to_relation(secret_id["s3-tls-ca-chain"], relation)
                    elif key == "azure":
                        if secret_id["storage-account"]:
                            self.grant_secret_to_relation(secret_id["storage-account"], relation)
                        if secret_id["secret-key"]:
                            self.grant_secret_to_relation(secret_id["secret-key"], relation)

                    elif key == "gcs":
                        if secret_id["secret-key"]:
                            self.grant_secret_to_relation(secret_id["secret-key"], relation)
                    else:
                        self.grant_secret_to_relation(secret_id, relation)


class SecretCache:
    """Internal helper class locally cache secrets.

    The data structure is precisely reusing/simulating as in the actual Secret Storage
    """

    CACHED_META = "meta"
    CACHED_CONTENT = "content"

    def __init__(self):
        # Structure:
        # NOTE: "objects" (i.e. dict-s) and scalar values are handled in a unified way
        # precisely as done for the Secret objects themselves.
        #
        # self.secrets = {
        #   "app": {
        #       "opensearch:app:admin-password": {
        #           "meta": <Secret instance>,
        #           "content": {
        #               "opensearch:app:admin-password": "bla"
        #           }
        #       }
        #   },
        #   "unit": {
        #       "opensearch:unit:0:certificates": {
        #           "meta": <Secret instance>,
        #           "content": {
        #               "ca-cert": "<certificate>",
        #               "cert": "<certificate>",
        #               "chain": "<certificate>"
        #           }
        #       }
        #   }
        # }
        self.secrets = {Scope.APP: {}, Scope.UNIT: {}}

    def get_meta(self, scope: Scope, label: str) -> Secret | None:
        """Getting cached secret meta-information."""
        return self.secrets[scope].get(label, {}).get(self.CACHED_META)

    def set_meta(self, scope: Scope, label: str, secret: Secret) -> None:
        """Setting cached secret meta-information."""
        self.secrets[scope].setdefault(label, {}).update({self.CACHED_META: secret})

    def get_content(self, scope: Scope, label: str) -> dict[str, str]:
        """Getting cached secret content."""
        return self.secrets[scope].get(label, {}).get(self.CACHED_CONTENT)

    def put_content(self, scope: Scope, label: str, content: str | dict[str, str]):
        """Setting cached secret content."""
        self.secrets[scope].setdefault(label, {}).update({self.CACHED_CONTENT: content})

    def put(
        self,
        scope: Scope,
        label: str,
        secret: Secret | None = None,
        content: str | dict[str, str] | None = None,
    ) -> None:
        """Updating cached secret information."""
        if secret:
            self.set_meta(scope, label, secret)
        if content:
            self.put_content(scope, label, content)

    def delete(self, scope: Scope, label: str) -> None:
        """Removing cached secret information."""
        self.secrets[scope].pop(label, None)
