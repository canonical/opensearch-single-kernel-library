# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from ops import CharmBase, ModelError, Secret, SecretNotFoundError
from ops.testing import Harness

from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.core.peer_relation import OpenSearchApplication
from opensearch_single_kernel.core.secrets import OpenSearchSecrets
from opensearch_single_kernel.events.opensearch import OpenSearchEventsHandler


@pytest.mark.parametrize(
    "scope,message",
    [(Scope.APP, "ERROR permission denied"), (Scope.UNIT, "ERROR controller unavailable")],
)
def test_failed_lookup_does_not_mean_secret_absent(harness, mocker, scope, message):
    """Failed reads must not allow replacing or deleting an existing secret."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    with harness.hooks_disabled():
        harness.set_leader(True)
    secrets = harness.charm.state.secrets
    secrets.put_object(scope, "test-key", {"test-key": "original"})
    secret_id = secrets.get_secret_id(scope, "test-key")
    secrets.cached_secrets.delete(scope, secrets.label(scope, "test-key"))
    denied = mocker.patch.object(harness.model, "get_secret", side_effect=ModelError(message))

    with pytest.raises(ModelError, match=message):
        secrets.get_object(scope, "test-key")
    with pytest.raises(ModelError, match=message):
        secrets.has(scope, "test-key")
    with pytest.raises(ModelError, match=message):
        secrets.put_object(scope, "test-key", {"test-key": "replacement"}, merge=True)
    with pytest.raises(ModelError, match=message):
        secrets.delete(scope, "test-key")
    assert secrets.get_secret_id(scope, "test-key") == secret_id

    mocker.stop(denied)
    assert secrets.get_object(scope, "test-key", peek=True) == {"test-key": "original"}
    assert secrets.has(scope, "test-key")


@pytest.mark.parametrize("scope", [Scope.APP, Scope.UNIT])
@pytest.mark.parametrize("empty_content", [False, True])
def test_delete_clears_persisted_secret_id(harness, mocker, scope, empty_content):
    """Deletion must not leave the old operator's label-to-ID reference behind."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    with harness.hooks_disabled():
        harness.set_leader(True)
        secrets = harness.charm.state.secrets
        secrets.put_object(scope, "test-key", {"value": "original"})
        secrets.put_object(scope, "other-key", {"value": "keep"})
        secret_id = secrets.get_secret_id(scope, "test-key")
        assert secret_id is not None

        if empty_content:
            secrets.put_object(scope, "test-key", {"value": None})
        else:
            secrets.delete(scope, "test-key")

        with pytest.raises(SecretNotFoundError):
            harness.model.get_secret(id=secret_id).get_content()
        assert secrets.get_object(scope, "test-key") is None
        assert secrets.get_secret_id(scope, "test-key") is None
        assert secrets.get_object(scope, "other-key") == {"value": "keep"}

        secrets.put_object(scope, "test-key", {"value": "replacement"})
        assert secrets.get_secret_id(scope, "test-key") != secret_id
        assert secrets.get_object(scope, "test-key") == {"value": "replacement"}


@pytest.mark.parametrize("scope", [Scope.APP, Scope.UNIT])
def test_delete_already_removed_secret_clears_reference(harness, mocker, scope):
    """A cached secret can disappear before deletion; finish local cleanup anyway."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    with harness.hooks_disabled():
        harness.set_leader(True)
    secrets = harness.charm.state.secrets
    secrets.put_object(scope, "test-key", {"value": "original"})
    secret_id = secrets.get_secret_id(scope, "test-key")
    harness.model.get_secret(id=secret_id).remove_all_revisions()

    secrets.delete(scope, "test-key")

    assert secrets.get_secret_id(scope, "test-key") is None
    assert secrets.get_object(scope, "test-key") is None
    assert not secrets.has(scope, "test-key")


@pytest.mark.parametrize("scope", [Scope.APP, Scope.UNIT])
def test_failed_delete_preserves_secret_id(harness, mocker, scope):
    """Keep the reference when Juju has not deleted the secret."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    with harness.hooks_disabled():
        harness.set_leader(True)
        secrets = harness.charm.state.secrets
        secrets.put_object(scope, "test-key", {"value": "original"})
        secret_id = secrets.get_secret_id(scope, "test-key")
        mocker.patch.object(Secret, "remove_all_revisions", side_effect=ModelError("unavailable"))

        with pytest.raises(ModelError, match="unavailable"):
            secrets.delete(scope, "test-key")

        assert secrets.get_secret_id(scope, "test-key") == secret_id
        assert harness.model.get_secret(id=secret_id).get_content() == {"value": "original"}


def test_on_secret_changed_app(mocker, harness, context):
    """We want to make sure that the following public methods are always supported."""
    scope = Scope.APP
    harness.charm.state.secrets.put(scope, "key1", "val1")
    assert harness.charm.state.secrets.has(scope, "key1")
    assert harness.charm.state.secrets.get(scope, "key1") == "val1"

    harness.charm.state.secrets.put_object(scope, "obj", {"key1": "val1"})
    assert harness.charm.state.secrets.has(scope, "obj")
    assert harness.charm.state.secrets.get_object(scope, "obj") == {"key1": "val1"}


@pytest.mark.parametrize(
    ("scope"),
    [
        (Scope.APP),
        (Scope.UNIT),
    ],
)
def test_put_get_set_object_implementation_specific_behavior(mocker, harness, context, scope):
    """Test putting and getting objects in/from the secret store."""
    harness.charm.state.secrets.put_object(scope, "key-obj", {"name1": "val1"}, merge=True)
    harness.charm.state.secrets.put_object(
        scope, "key-obj", {"name1": None, "name2": "val2"}, merge=True
    )
    assert harness.charm.state.secrets.get_object(scope, "key-obj") == {
        "name1": None,
        "name2": "val2",
    }


@pytest.mark.parametrize(
    ("scope"),
    [
        (Scope.APP),
        (Scope.UNIT),
    ],
)
def test_nullify_obj(mocker, harness, context, scope):
    """Test iteratively filling up an object with `None` values."""
    with patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=MagicMock(return_value=True),
    ):
        if scope == Scope.APP:
            harness.set_leader(True)
        harness.charm.state.secrets.put_object(scope, "key-obj", {"key1": "val1", "key2": "val2"})
        harness.charm.state.secrets.put_object(
            scope, "key-obj", {"key1": None, "key2": "val2"}, merge=True
        )
        harness.charm.state.secrets.put_object(scope, "key-obj", {"key2": None}, merge=True)
        assert not harness.charm.state.secrets.has(scope, "key-obj")


@pytest.mark.parametrize(
    ("scope"),
    [
        (Scope.APP),
        (Scope.UNIT),
    ],
)
def test_save_secret_id(mocker, harness, context, scope):
    """Test putting and getting objects in/from the secret store."""
    if scope == Scope.APP:
        harness.set_leader(True)
    with patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=MagicMock(return_value=True),
    ):
        harness.charm.state.secrets.put(scope, "key", "val1")
        secret_id = harness.charm.state.secrets._get_relation_data(scope)[
            harness.charm.state.secrets.label(scope, "key")
        ]
        secret_content = harness.charm.model.get_secret(id=secret_id).get_content()
        assert secret_content["key"] == "val1"

        harness.charm.state.secrets.put_object(scope, "key-obj", {"name1": "val1"}, merge=True)
        secret_id2 = harness.charm.state.secrets._get_relation_data(scope)[
            harness.charm.state.secrets.label(scope, "key-obj")
        ]
        secret_content = harness.charm.model.get_secret(id=secret_id2).get_content()
        assert secret_content["name1"] == "val1"


def test_get_secret_id(mocker, harness, context):
    """Test getting secret id from the secret store."""
    harness.set_leader(True)
    # add a secret to the store
    content = {"secret": "value"}
    with patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=MagicMock(return_value=True),
    ):
        harness.charm.state.secrets.put(Scope.APP, "super-secret-key", content)
        # get the secret id
        secret_id = harness.charm.state.secrets.get_secret_id(Scope.APP, "super-secret-key")
        assert secret_id is not None
        # check the secret content
        secret = harness.charm.model.get_secret(id=secret_id)
        secret_content = secret.get_content()
        assert secret_content == {"super-secret-key": str(content)}


class SecretReaderCharm(CharmBase):
    """Minimal charm for real Juju secret revision tracking."""


def test_deleted_secret_notification_is_not_retried():
    """A queued change for a deleted secret must not be deferred indefinitely."""
    harness = Harness(SecretReaderCharm, meta="name: opensearch\n")
    harness.set_leader(True)
    harness.begin()
    try:
        secret = harness.charm.app.add_secret({"password": "original"})
        event_secret = harness.model.get_secret(id=secret.id)
        secret.remove_all_revisions()
        event = SimpleNamespace(secret=event_secret, defer=MagicMock())

        OpenSearchEventsHandler._on_secret_changed(SimpleNamespace(charm=harness.charm), event)

        event.defer.assert_not_called()
    finally:
        harness.cleanup()


@pytest.mark.parametrize(
    "key,reader",
    [
        ("admin-password", OpenSearchApplication.admin_password),
        ("monitor-password", OpenSearchApplication.cos_password),
    ],
)
def test_internal_password_event_refreshes_revision_for_state_readers(key, reader):
    harness = Harness(SecretReaderCharm, meta="name: opensearch\n")
    harness.set_leader(True)
    harness.begin()
    try:
        charm = harness.charm
        charm.state = SimpleNamespace(implements_secrets=True)
        secrets = OpenSearchSecrets(charm, "peer")
        label = secrets.label(Scope.APP, key)
        secret = charm.app.add_secret({key: "original-password"}, label=label)
        secret.set_content({key: "replacement-password"})
        harness.set_leader(False)

        event = SimpleNamespace(
            secret=harness.model.get_secret(id=secret.id, label=label), defer=MagicMock()
        )
        OpenSearchEventsHandler._on_secret_changed(SimpleNamespace(charm=charm), event)

        application = SimpleNamespace(secrets=secrets)
        assert reader.fget(application) == "replacement-password"
        event.defer.assert_not_called()
    finally:
        harness.cleanup()


def test_unlabelled_peer_cluster_secret_refreshes_revision_for_credential_reader():
    harness = Harness(
        SecretReaderCharm,
        meta="name: opensearch\nrequires:\n  peer-cluster:\n    interface: peer_cluster\n",
    )
    harness.begin()
    try:
        harness.add_relation("peer-cluster", "orchestrator")
        secret_id = harness.add_model_secret(
            "orchestrator", {"admin-password": "original-password"}
        )
        harness.grant_secret(secret_id, "opensearch")
        secrets = OpenSearchSecrets(harness.charm, "peer")
        credential = secret_id.replace("secret:", "secret://", 1)
        assert secrets.resolve_credential(credential, password_key="admin") == (
            "original-password"
        )
        harness.set_secret_content(secret_id, {"admin-password": "replacement-password"})
        event = SimpleNamespace(secret=harness.model.get_secret(id=secret_id), defer=MagicMock())
        assert event.secret.label is None

        OpenSearchEventsHandler._on_secret_changed(SimpleNamespace(charm=harness.charm), event)

        assert secrets.resolve_credential(credential, password_key="admin") == (
            "replacement-password"
        )
        event.defer.assert_not_called()
    finally:
        harness.cleanup()
