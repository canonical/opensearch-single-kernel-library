# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for internal user management and password actions."""

from unittest.mock import PropertyMock

import bcrypt
import pytest
from ops import ModelError, Secret
from ops.testing import ActionFailed

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    COS_USER,
    USER_ENDPOINT,
    DeploymentType,
    Scope,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.core.models import App, DeploymentDescription, PeerClusterConfig
from opensearch_single_kernel.utils.secrets import password_key


@pytest.fixture
def monitor_deployment(harness):
    """Provide the application identity needed for a real API client's host."""
    with harness.hooks_disabled():
        harness.set_leader(True)
    harness.charm.state.application.deployment_desc = DeploymentDescription(
        app=App(name=harness.charm.app.name, model_uuid="model"),
        config=PeerClusterConfig(cluster_name="cluster", init_hold=False, roles=[]),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
    )


@pytest.mark.parametrize("failure", [None, "PATCH"])
def test_monitor_password_updates_live_user_before_publishing_secret(
    harness, mocker, monkeypatch, monitor_deployment, failure
):
    """Publish a changed password only after updating the existing OpenSearch user."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    secrets = harness.charm.state.secrets
    key = password_key(COS_USER)
    secrets.put(Scope.APP, key, "old-password")
    live_user = {"hash": "old-hash", "opendistro_security_roles": ["readall_and_monitor"]}
    published = []
    original_put = secrets.put

    def put(scope, name, value):
        if name == key:
            published.append(live_user.copy())
        original_put(scope, name, value)

    monkeypatch.setattr(secrets, "put", put)

    def request(client, method, endpoint, payload=None, **kwargs):
        assert endpoint == f"{USER_ENDPOINT}/monitor"
        if method == failure:
            raise OpenSearchHttpError("unavailable", 503)
        assert method == "PATCH"
        for patch in payload:
            live_user[patch["path"].removeprefix("/")] = patch["value"]
        return {"status": "OK"}

    monkeypatch.setattr(OpenSearchClient, "request", request)

    result = harness.charm.internal_users_manager.put_or_update_internal_user_leader(
        COS_USER, pwd="replacement-password"
    )

    if failure:
        assert result is False
        assert published == []
        assert secrets.get(Scope.APP, key) == "old-password"
    else:
        assert result is True
        assert live_user["hash"] != "old-hash"
        assert bcrypt.checkpw(b"replacement-password", live_user["hash"].encode())
        assert live_user["opendistro_security_roles"] == ["readall_and_monitor"]
        assert published == [live_user]
        assert secrets.get(Scope.APP, key) == "replacement-password"


def test_existing_monitor_password_is_preserved_when_updates_disabled(
    harness, mocker, monkeypatch, monitor_deployment
):
    """Stable local saving excludes monitoring users and must not mutate their live hash."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    secrets = harness.charm.state.secrets
    key = password_key(COS_USER)
    secrets.put(Scope.APP, key, "existing-password")

    def request(client, method, endpoint, payload=None, **kwargs):
        raise AssertionError("An existing monitor user must not be updated")

    monkeypatch.setattr(OpenSearchClient, "request", request)

    assert harness.charm.internal_users_manager.put_or_update_internal_user_leader(
        COS_USER, pwd="unused-password", update=False
    )
    assert secrets.get(Scope.APP, key) == "existing-password"


@pytest.mark.parametrize("failure", ["lookup", "content"])
@pytest.mark.parametrize("update", [False, True])
def test_password_read_failure_does_not_change_user(
    harness, mocker, monitor_deployment, failure, update
):
    """A failed read of an existing secret must not become a request to create a user."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    secrets = harness.charm.state.secrets
    key = password_key(COS_USER)
    secrets.put(Scope.APP, key, "existing-password")
    secrets.cached_secrets.delete(Scope.APP, secrets.label(Scope.APP, key))
    failed_read = mocker.patch.object(
        harness.model if failure == "lookup" else Secret,
        "get_secret" if failure == "lookup" else "get_content",
        side_effect=ModelError("secret read failed"),
    )
    request = mocker.patch.object(
        OpenSearchClient, "request", return_value={"status": "OK", "message": "updated"}
    )

    with pytest.raises(ModelError, match="secret read failed"):
        harness.charm.internal_users_manager.put_or_update_internal_user_leader(
            COS_USER, pwd="replacement-password", update=update
        )

    request.assert_not_called()
    mocker.stop(failed_read)
    assert secrets.get(Scope.APP, key) == "existing-password"


@pytest.mark.parametrize("action", ["get-password", "set-password"])
def test_password_action_reports_secret_read_failure(harness, mocker, monitor_deployment, action):
    """A Juju read failure fails the action without publishing or changing credentials."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(
        type(harness.charm.upgrades_manager),
        "in_progress",
        new_callable=PropertyMock,
        return_value=False,
    )
    harness.charm.state.application.is_admin_user_initialized = True
    mocker.patch.object(harness.charm.tls_manager, "is_fully_configured", return_value=True)
    secrets = harness.charm.state.secrets
    key = password_key(COS_USER)
    secrets.put(Scope.APP, key, "existing-password")
    label = secrets.label(Scope.APP, key)
    secrets.cached_secrets.delete(Scope.APP, label)
    lookup = harness.model.get_secret

    def deny_password_read(*args, **kwargs):
        if kwargs.get("label") == label:
            raise ModelError("permission denied")
        return lookup(*args, **kwargs)

    denied = mocker.patch.object(harness.model, "get_secret", side_effect=deny_password_read)
    request = mocker.patch.object(OpenSearchClient, "request")

    with pytest.raises(ActionFailed, match="permission denied"):
        harness.run_action(action, {"username": COS_USER})

    request.assert_not_called()
    mocker.stop(denied)
    assert secrets.get(Scope.APP, key) == "existing-password"
