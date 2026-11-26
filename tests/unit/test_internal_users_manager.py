# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for internal user management and password actions."""

from unittest.mock import Mock, PropertyMock

import bcrypt
import pytest
from ops import ModelError, Secret
from ops.testing import ActionFailed

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    COS_USER,
    INTERNAL_USER_ENDPOINT,
    DeploymentType,
    Scope,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.core.models import App, DeploymentDescription, PeerClusterConfig
from opensearch_single_kernel.managers.internal_users import InternalUsersManager
from opensearch_single_kernel.utils.secrets import password_key
from tests.unit.helpers import deployment_descriptions


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
        assert endpoint == f"{INTERNAL_USER_ENDPOINT}/monitor"
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
        assert method == "GET", "An existing monitor user must not be updated"
        assert endpoint == f"{INTERNAL_USER_ENDPOINT}/{COS_USER}"
        return {COS_USER: {"opendistro_security_roles": ["readall_and_monitor"]}}

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


@pytest.mark.parametrize(
    "user_exists,failure",
    [(True, None), (False, None), (False, "GET"), (False, "PUT"), (False, "PATCH")],
)
def test_monitoring_user_recovery_preserves_stored_password(monkeypatch, user_exists, failure):
    """Recover a missing monitoring user without replacing its existing password."""
    state = Mock(node_host="localhost")
    state.application.admin_password = "admin-password"
    state.application.get_user_password.return_value = "existing-password"
    manager = InternalUsersManager(state, Mock())
    live_user = {"hash": "unchanged-hash"} if user_exists else {}
    requests = []

    def request(client, method, endpoint, payload=None, **kwargs):
        assert endpoint == f"{INTERNAL_USER_ENDPOINT}/{COS_USER}"
        requests.append(method)
        if method == failure:
            raise OpenSearchHttpError("unavailable", 503)
        if method == "GET":
            if not live_user:
                raise OpenSearchHttpError("missing user", 404)
            return {COS_USER: live_user.copy()}
        if method == "PUT":
            live_user.update(payload)
            return {"status": "CREATED"}
        assert method == "PATCH"
        for patch in payload:
            live_user[patch["path"].removeprefix("/")] = patch["value"]
        return {"status": "OK"}

    monkeypatch.setattr(OpenSearchClient, "request", request)

    result = manager.put_or_update_internal_user_leader(
        COS_USER, pwd="must-not-replace-existing-password", update=False
    )

    assert result == (failure is None)
    state.secrets.put.assert_not_called()
    if failure == "GET":
        assert requests == ["GET"]
        assert live_user == {}
    elif user_exists:
        assert requests == ["GET"]
        assert live_user == {"hash": "unchanged-hash"}
    elif failure is None:
        assert bcrypt.checkpw(b"existing-password", live_user["hash"].encode())
        assert live_user["opendistro_security_roles"] == ["readall_and_monitor"]


@pytest.fixture
def monitoring_startup(harness, mocker):
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(
        type(charm.state.application),
        "deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch.object(
        charm.cluster_manager, "should_initialise_security_index", return_value=False
    )
    for method in (
        "wait_for_opensearch_up",
        "assert_current_node_joined_cluster",
        "apply_upstream_fixes",
    ):
        mocker.patch.object(charm.cluster_manager, method)
    mocker.patch.object(charm.exclusions_manager, "delete_current")
    mocker.patch.object(charm.lock_manager, "release")
    mocker.patch.object(charm, "apply_health")
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=False)
    mocker.patch.object(charm.upgrade_events, "_reconcile_upgrade")
    mocker.patch.object(charm.opensearch_events, "post_start_ca_rotation")
    return charm


@pytest.mark.parametrize(
    "stored,user_exists,created,password",
    [
        (None, False, True, "generated"),
        (None, True, True, "generated"),
        ("existing", True, False, "existing"),
        ("existing", False, True, "existing"),
        ("01234", False, True, "01234"),
    ],
)
def test_post_start_only_creates_missing_monitoring_credentials(
    monitoring_startup, mocker, stored, user_exists, created, password
):
    charm = monitoring_startup
    secret = mocker.patch.object(charm.state.secrets, "get", return_value=stored)
    save = mocker.patch.object(charm.state.secrets, "put")
    generate = mocker.patch(
        "opensearch_single_kernel.managers.internal_users.generate_hashed_password",
        side_effect=lambda pwd: ("hash", pwd or "generated"),
    )
    mocker.patch.object(
        OpenSearchClient, "get_user", return_value={COS_USER: {}} if user_exists else None
    )
    create = mocker.patch.object(OpenSearchClient, "create_user")
    patch = mocker.patch.object(OpenSearchClient, "patch_user")

    charm.opensearch_events._post_start_init(mocker.Mock(after_upgrade=False))

    secret.assert_any_call(Scope.APP, password_key(COS_USER))
    if created:
        create.assert_called_once_with("monitor", ["readall_and_monitor"], "hash")
        patch.assert_called_once()
        generate.assert_called_once_with(stored)
    else:
        create.assert_not_called()
        patch.assert_not_called()
        generate.assert_not_called()

    if stored is None:
        save.assert_called_once_with(Scope.APP, "monitor-password", password)
    else:
        save.assert_not_called()


@pytest.mark.parametrize("lookup", ["secret", "user"])
def test_monitoring_lookup_failure_does_not_change_credentials(monitoring_startup, mocker, lookup):
    charm = monitoring_startup
    error = (
        ModelError("Secret unavailable")
        if lookup == "secret"
        else OpenSearchHttpError("User lookup failed")
    )
    mocker.patch.object(
        charm.state.secrets,
        "get",
        return_value="existing",
        side_effect=error if lookup == "secret" else None,
    )
    mocker.patch.object(OpenSearchClient, "get_user", side_effect=error)
    create = mocker.patch.object(OpenSearchClient, "create_user")
    save = mocker.patch.object(charm.state.secrets, "put")

    event = mocker.Mock(after_upgrade=False)
    if lookup == "secret":
        with pytest.raises(ModelError):
            charm.opensearch_events._post_start_init(event)
    else:
        charm.opensearch_events._post_start_init(event)
        event.defer.assert_called_once()

    create.assert_not_called()
    save.assert_not_called()


@pytest.mark.parametrize(
    "leader,deployment_type",
    [
        (False, DeploymentType.MAIN_ORCHESTRATOR),
        (True, DeploymentType.FAILOVER_ORCHESTRATOR),
        (True, DeploymentType.OTHER),
    ],
)
def test_only_main_leader_manages_monitoring_user(
    monitoring_startup, harness, mocker, leader, deployment_type
):
    charm = monitoring_startup
    with harness.hooks_disabled():
        harness.set_leader(leader)
    mocker.patch.object(
        type(charm.state.application),
        "deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"].model_copy(update={"typ": deployment_type}),
    )
    create = mocker.patch.object(OpenSearchClient, "create_user")
    lookup = mocker.patch.object(OpenSearchClient, "get_user")
    secret = mocker.patch.object(charm.state.secrets, "get")

    charm.opensearch_events._post_start_init(mocker.Mock(after_upgrade=False))

    create.assert_not_called()
    lookup.assert_not_called()
    secret.assert_not_called()
