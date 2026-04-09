# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import MagicMock, patch

import pytest
from parameterized import parameterized

from opensearch_single_kernel.common.constants import Scope


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
