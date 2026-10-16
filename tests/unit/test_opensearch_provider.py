# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, call

import pytest
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import CLIENT_RELATION, KIBANA_SERVER_USER
from opensearch_single_kernel.common.exceptions import (
    OpenSearchHttpError,
    OpenSearchUserMgmtError,
)
from opensearch_single_kernel.common.statuses import ExternalClientsStatuses, GeneralStatuses
from opensearch_single_kernel.core.external_clients_relation import (
    ExternalOpenSearchClient,
)
from opensearch_single_kernel.core.models import ExternalClientRequestedEntity
from opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces import (
    ENTITY_GROUP,
    ENTITY_USER,
)
from opensearch_single_kernel.managers.external_clients import ExternalClientsManager
from opensearch_single_kernel.utils.helpers import validate_entity_name
from opensearch_single_kernel.utils.status import format_status
from tests.unit.helpers import deployment_descriptions

GROUP_ENTITY = ExternalClientRequestedEntity("devs_group", "secret")
GROUP_PERMISSIONS = {
    "index_permissions": [{"index_patterns": ["logs"], "allowed_actions": ["read"]}]
}


def make_client(
    relation_id: int = 1,
    entity_type: str = "",
    groups: list[str] | None = None,
    **attributes,
) -> MagicMock:
    return MagicMock(
        **{
            "relation": MagicMock(id=relation_id),
            "relation_name": CLIENT_RELATION,
            "entity_type": entity_type,
            "extra_user_roles": "",
            "extra_group_roles": groups or [],
            "index": "logs",
            "relation_username": f"{CLIENT_RELATION}_{relation_id}",
            "password": "",
        }
        | attributes
    )


def make_state(
    client_users: dict[str, str] | None = None, client_groups: dict[str, str] | None = None
) -> MagicMock:
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.application.client_users_dict = client_users or {}
    state.application.client_groups_dict = client_groups or {}
    state.application.client_entities_dict = (client_users or {}) | (client_groups or {})
    state.mapped_users = {}
    state.mapped_roles = {}
    return state


@pytest.fixture
def opensearch_client(mocker) -> MagicMock:
    client = MagicMock()
    client.get_role.return_value = None
    client.get_user.return_value = None
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.opensearch_client",
        new_callable=PropertyMock,
        return_value=client,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.generate_password",
        return_value="generated",
    )
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.hash_string",
        side_effect=lambda password: f"hash-of-{password}",
    )
    return client


@pytest.mark.parametrize(
    "secret_content, expected",
    [
        ("alice:secret", ExternalClientRequestedEntity("alice", "secret")),
        ("alice:pass:word", ExternalClientRequestedEntity("alice", "pass:word")),
        ("alice:None", ExternalClientRequestedEntity("alice", None)),
        ("alice", None),
        (":secret", None),
        (None, None),
    ],
    ids=["valid", "colon-in-password", "no-password", "no-separator", "no-name", "absent"],
)
def test_requested_entity_read_from_relation(secret_content, expected):
    relation_data = {"requested-entity-secret": secret_content} if secret_content else {}
    external_client = ExternalOpenSearchClient(
        relation=MagicMock(id=1),
        data_interface=MagicMock(as_dict=MagicMock(return_value=relation_data)),
        component=MagicMock(),
        relation_name=CLIENT_RELATION,
    )

    assert external_client.get_requested_entity() == expected


@pytest.mark.parametrize(
    "entity_permissions, expected",
    [
        (None, None),
        (
            '[{"resource_name":"logs","resource_type":"index_permissions","privileges":["read"]}]',
            GROUP_PERMISSIONS,
        ),
    ],
    ids=["absent", "valid"],
)
def test_entity_permissions_read_from_relation(entity_permissions, expected):
    relation_data = {"entity-permissions": entity_permissions} if entity_permissions else {}
    external_client = ExternalOpenSearchClient(
        relation=MagicMock(id=1),
        data_interface=MagicMock(as_dict=MagicMock(return_value=relation_data)),
        component=MagicMock(),
        relation_name=CLIENT_RELATION,
    )

    assert external_client.entity_permissions == expected


@pytest.mark.parametrize(
    "entity_permissions",
    [
        "not-a-json",
        '[{"resource_name":"logs","resource_type":"unknown","privileges":["read"]}]',
    ],
    ids=["invalid-json", "unknown-resource-type"],
)
def test_invalid_entity_permissions_rejected(entity_permissions):
    external_client = ExternalOpenSearchClient(
        relation=MagicMock(id=1),
        data_interface=MagicMock(
            as_dict=MagicMock(return_value={"entity-permissions": entity_permissions})
        ),
        component=MagicMock(),
        relation_name=CLIENT_RELATION,
    )

    with pytest.raises(ValidationError):
        external_client.entity_permissions


@pytest.mark.parametrize(
    "requested_entity, expected_user, expected_password",
    [
        (None, f"{CLIENT_RELATION}_1", "generated"),
        (ExternalClientRequestedEntity("alice", "secret"), "alice", "secret"),
        (ExternalClientRequestedEntity("alice", None), "alice", "generated"),
    ],
    ids=["generated", "requested", "requested-without-password"],
)
def test_classic_client_gets_user_with_dedicated_role(
    opensearch_client, mocker, requested_entity, expected_user, expected_password
):
    reconcile_role_mappings = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.reconcile_role_mappings"
    )
    state = make_state()
    external_client = make_client(extra_user_roles="admin")
    # The users recorded when the user is created: the relation owns its role by then
    users_on_user_creation = []
    opensearch_client.create_user.side_effect = lambda *_: users_on_user_creation.append(
        dict(state.application.client_users_dict)
    )

    ExternalClientsManager(state, MagicMock()).provide_client_entity(
        external_client, requested_entity
    )

    assert users_on_user_creation == [{"1": expected_user}]
    opensearch_client.create_role.assert_called_once()
    assert opensearch_client.create_role.call_args.args == (expected_user,)
    assert set(opensearch_client.create_role.call_args.kwargs) == {
        "cluster_permissions",
        "index_permissions",
    }
    opensearch_client.create_user.assert_called_once_with(
        expected_user, [expected_user], f"hash-of-{expected_password}"
    )
    assert external_client.username == expected_user
    assert external_client.password == expected_password
    assert state.application.client_users_dict == {"1": expected_user}
    assert state.application.client_groups_dict == {}
    reconcile_role_mappings.assert_called_once()


@pytest.mark.parametrize(
    "client_users, expected_password",
    [({"1": f"{CLIENT_RELATION}_1"}, "provided"), ({}, "generated")],
    ids=["already-provided", "not-provided-yet"],
)
def test_classic_client_keeps_its_password_when_request_is_handled_again(
    opensearch_client, mocker, client_users, expected_password
):
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.reconcile_role_mappings"
    )
    external_client = make_client(password="provided")

    ExternalClientsManager(
        make_state(client_users=client_users), MagicMock()
    ).provide_client_entity(external_client, None)

    opensearch_client.create_user.assert_called_once_with(
        f"{CLIENT_RELATION}_1", [f"{CLIENT_RELATION}_1"], f"hash-of-{expected_password}"
    )
    assert external_client.password == expected_password


@pytest.mark.parametrize("password", ["secret", None], ids=["with-password", "without-password"])
def test_group_client_gets_role_only(opensearch_client, mocker, password):
    reconcile_role_mappings = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.reconcile_role_mappings"
    )
    state = make_state()
    external_client = make_client(entity_type=ENTITY_GROUP, entity_permissions=GROUP_PERMISSIONS)

    ExternalClientsManager(state, MagicMock()).provide_client_entity(
        external_client, ExternalClientRequestedEntity("devs_group", password)
    )

    opensearch_client.create_role.assert_called_once_with("devs_group", **GROUP_PERMISSIONS)
    opensearch_client.create_user.assert_not_called()
    opensearch_client.patch_user.assert_not_called()
    assert external_client.entity_name == "devs_group"
    assert state.application.client_groups_dict == {"1": "devs_group"}
    assert state.application.client_users_dict == {}
    reconcile_role_mappings.assert_called_once()


def test_group_client_without_permissions_gets_role_scoped_to_its_index(opensearch_client, mocker):
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.reconcile_role_mappings"
    )
    external_client = make_client(entity_type=ENTITY_GROUP, entity_permissions=None)

    ExternalClientsManager(make_state(), MagicMock()).provide_client_entity(
        external_client, ExternalClientRequestedEntity("devs_group", None)
    )

    opensearch_client.create_role.assert_called_once()
    assert opensearch_client.create_role.call_args.args == ("devs_group",)
    assert set(opensearch_client.create_role.call_args.kwargs) == {"index_permissions"}
    assert [
        (permissions["index_patterns"], permissions["allowed_actions"])
        for permissions in opensearch_client.create_role.call_args.kwargs["index_permissions"]
    ] == [(["logs"], ["indices_monitor", "data_access"])]


def test_group_client_with_invalid_permissions_not_provided(opensearch_client):
    external_client = make_client(entity_type=ENTITY_GROUP)
    type(external_client).entity_permissions = PropertyMock(
        side_effect=ValidationError.from_exception_data("entity-permissions", [])
    )
    state = make_state()

    with pytest.raises(OpenSearchUserMgmtError):
        ExternalClientsManager(state, MagicMock()).provide_client_entity(
            external_client, ExternalClientRequestedEntity("devs_group", None)
        )

    opensearch_client.create_role.assert_not_called()
    assert state.application.client_groups_dict == {}


def test_dashboards_client_gets_kibanaserver_credentials(opensearch_client):
    state = make_state()
    state.application.kibana_server_password = "kibana-password"
    external_client = make_client(extra_user_roles="kibana_server")

    ExternalClientsManager(state, MagicMock()).provide_client_entity(external_client, None)

    opensearch_client.create_user.assert_not_called()
    assert external_client.username == KIBANA_SERVER_USER
    assert external_client.password == "kibana-password"


def test_removed_client_relations_cleaned_up_by_kind(opensearch_client, mocker):
    reconcile_role_mappings = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.reconcile_role_mappings"
    )
    state = make_state(
        client_users={"1": "app_user", "2": "kept_user", "5": "stuck_user"},
        client_groups={"3": "devs_group", "4": "kept_group", "6": "stuck_group"},
    )
    state.external_client_relations = [MagicMock(id=2), MagicMock(id=4)]

    def fail_for(name: str):
        def remove(entity: str) -> None:
            if entity == name:
                raise OpenSearchHttpError()

        return remove

    opensearch_client.remove_user.side_effect = fail_for("stuck_user")
    opensearch_client.remove_role_mapping.side_effect = fail_for("stuck_group")

    ExternalClientsManager(state, MagicMock()).remove_lingering_relation_users_and_roles()

    assert sorted(opensearch_client.remove_user.call_args_list) == [
        call("app_user"),
        call("stuck_user"),
    ]
    assert sorted(opensearch_client.remove_role.call_args_list) == [
        call("app_user"),
        call("devs_group"),
        call("stuck_group"),
        call("stuck_user"),
    ]
    assert sorted(opensearch_client.remove_role_mapping.call_args_list) == [
        call("app_user"),
        call("devs_group"),
        call("stuck_group"),
        call("stuck_user"),
    ]
    # The entities which failed to be removed are kept for the next cleanup to retry
    assert state.application.client_users_dict == {"2": "kept_user", "5": "stuck_user"}
    assert state.application.client_groups_dict == {"4": "kept_group", "6": "stuck_group"}
    reconcile_role_mappings.assert_called_once()


def test_removed_client_relations_do_not_refresh_mappings_outside_main_orchestrator(
    opensearch_client,
):
    state = make_state(client_users={"1": "app_user"})
    state.is_main_orchestrator = False
    state.external_client_relations = []

    ExternalClientsManager(state, MagicMock()).remove_lingering_relation_users_and_roles()

    opensearch_client.remove_user.assert_called_once_with("app_user")
    assert state.application.client_users_dict == {}
    opensearch_client.get_role_mappings.assert_not_called()
    opensearch_client.put_role_mapping.assert_not_called()


def test_removed_client_relations_cleaned_up_when_mappings_cannot_be_refreshed(opensearch_client):
    state = make_state(client_users={"1": "app_user"})
    state.external_client_relations = []
    opensearch_client.get_role_mappings.side_effect = OpenSearchHttpError()

    ExternalClientsManager(state, MagicMock()).remove_lingering_relation_users_and_roles()

    assert state.application.client_users_dict == {}


def test_reconcile_role_mappings_fails_when_mappings_cannot_be_read(opensearch_client):
    opensearch_client.get_role_mappings.side_effect = OpenSearchHttpError()

    with pytest.raises(OpenSearchUserMgmtError):
        ExternalClientsManager(make_state(), MagicMock()).reconcile_role_mappings()


def test_reconcile_role_mappings_refreshes_the_other_roles_when_one_fails(opensearch_client):
    state = make_state()
    state.managed_roles = ["failing", "new"]
    state.mapped_roles = {"failing": ["a"], "new": ["a"]}
    opensearch_client.get_role_mappings.return_value = {}
    opensearch_client.put_role_mapping.side_effect = [OpenSearchHttpError(), None]

    with pytest.raises(OpenSearchUserMgmtError, match="failing"):
        ExternalClientsManager(state, MagicMock()).reconcile_role_mappings()

    assert opensearch_client.put_role_mapping.call_args_list == [
        call("failing", [], ["a"]),
        call("new", [], ["a"]),
    ]


@pytest.mark.parametrize(
    "name, valid",
    [
        ("devs", True),
        ("Domain Admins", True),
        ("search-admin_1.eu@corp", True),
        ("", False),
        (" devs", False),
        ("devs ", False),
        ("a  b", False),
        ("..", False),
        ("role?pretty", False),
        ("../internalusers/admin", False),
        ("devs*", False),
        ("a" * 256, False),
    ],
)
def test_entity_name_validation(name, valid):
    assert validate_entity_name(name) is valid


@pytest.mark.parametrize(
    "requested_entity, client_users, existing_role, existing_user, expected",
    [
        (ExternalClientRequestedEntity("alice", None), {}, None, None, None),
        (
            ExternalClientRequestedEntity("alice", None),
            {},
            {"alice": {}},
            None,
            ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT,
        ),
        (
            ExternalClientRequestedEntity("alice", None),
            {},
            None,
            {"alice": {}},
            ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT,
        ),
        (ExternalClientRequestedEntity("alice", None), {"1": "alice"}, {"alice": {}}, {}, None),
        (
            ExternalClientRequestedEntity("role?pretty", None),
            {},
            None,
            None,
            ExternalClientsStatuses.USER_ENTITY_GROUP_INVALID,
        ),
        (
            ExternalClientRequestedEntity(f"{CLIENT_RELATION}_9", None),
            {},
            None,
            None,
            ExternalClientsStatuses.ENTITY_NAME_RESERVED,
        ),
        (ExternalClientRequestedEntity(f"{CLIENT_RELATION}_1", None), {}, None, None, None),
        (
            None,
            {"9": f"{CLIENT_RELATION}_1"},
            None,
            None,
            ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT,
        ),
        (None, {}, {f"{CLIENT_RELATION}_1": {}}, {f"{CLIENT_RELATION}_1": {}}, None),
    ],
    ids=[
        "requested-name-free",
        "requested-name-of-existing-role",
        "requested-name-of-existing-user",
        "requested-name-provided-to-the-relation",
        "requested-name-invalid",
        "requested-name-generated-for-another-relation",
        "requested-name-generated-for-the-relation",
        "generated-name-provided-to-another-relation",
        "generated-name-not-looked-up",
    ],
)
def test_classic_client_request_errors(
    opensearch_client, requested_entity, client_users, existing_role, existing_user, expected
):
    external_client = make_client()
    external_client.get_requested_entity.return_value = requested_entity
    opensearch_client.get_role.return_value = existing_role
    opensearch_client.get_user.return_value = existing_user

    manager = ExternalClientsManager(make_state(client_users=client_users), MagicMock())

    assert manager.get_request_error(external_client) is expected


def test_dashboards_client_request_is_not_checked_against_entities(opensearch_client):
    external_client = make_client(extra_user_roles="kibana_server")
    external_client.get_requested_entity.return_value = None

    manager = ExternalClientsManager(
        make_state(client_users={"9": f"{CLIENT_RELATION}_1"}), MagicMock()
    )

    assert manager.get_request_error(external_client) is None


def test_reconcile_role_mappings_touches_only_changed_mappings(opensearch_client):
    state = make_state()
    state.managed_roles = ["unchanged", "changed", "new", "stale", "absent"]
    state.mapped_users = {"unchanged": ["*"]}
    state.mapped_roles = {"unchanged": ["b", "a"], "changed": ["a"], "new": ["a"]}
    opensearch_client.get_role_mappings.return_value = {
        "unchanged": {"users": ["*"], "backend_roles": ["a", "b"]},
        "changed": {"users": [], "backend_roles": ["b"]},
        "stale": {"users": [], "backend_roles": ["a"]},
    }

    ExternalClientsManager(state, MagicMock()).reconcile_role_mappings()

    assert opensearch_client.put_role_mapping.call_args_list == [
        call("changed", [], ["a"]),
        call("new", [], ["a"]),
        call("stale", [], []),
    ]


@pytest.fixture
def client_request_ready(harness, mocker):
    """Leader with a running node and initialised security index."""
    with harness.hooks_disabled():
        harness.set_leader(True)

    # the K8s node host is built from the deployment description
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_descriptions["ok"],
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.admin_secrets",
        new_callable=PropertyMock,
        return_value={"chain": "admin-chain"},
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.BaseWorkload.version",
        new_callable=PropertyMock,
        return_value="2.19.0",
    )
    mocker.patch(
        "opensearch_single_kernel.events.external_clients.ExternalClientsEventsHandler.update_external_client_endpoints"
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_role"
    ).return_value = None
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_user"
    ).return_value = None


@pytest.fixture
def group_client(mocker) -> MagicMock:
    external_client = make_client(entity_type=ENTITY_GROUP)
    external_client.get_requested_entity.return_value = GROUP_ENTITY
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.external_client_by_relation",
        return_value=external_client,
    )
    return external_client


@pytest.fixture
def provide_client_entity(mocker) -> MagicMock:
    return mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.provide_client_entity"
    )


@pytest.fixture
def provide_client_index(mocker) -> MagicMock:
    return mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.provide_client_index"
    )


@pytest.fixture
def refresh_skipped_users(harness, mocker) -> MagicMock:
    """The users skipped by the LDAP authorization are part of the security config."""
    return mocker.patch.object(harness.charm, "reconcile_security_config")


def test_client_request_provides_requested_entity_and_index(
    harness,
    client_request_ready,
    group_client,
    provide_client_entity,
    provide_client_index,
    refresh_skipped_users,
):
    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_called_once_with(group_client, GROUP_ENTITY)
    provide_client_index.assert_called_once_with(group_client)
    assert group_client.tls_ca == "admin-chain"
    refresh_skipped_users.assert_not_called()
    event.defer.assert_not_called()


def test_ldap_skipped_users_refreshed_once_user_provided(
    harness,
    client_request_ready,
    group_client,
    provide_client_entity,
    provide_client_index,
    refresh_skipped_users,
):
    group_client.entity_type = ""
    group_client.get_requested_entity.return_value = None

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_called_once_with(group_client, None)
    refresh_skipped_users.assert_called_once_with(event)


def test_ldap_skipped_users_refreshed_once_client_relation_removed(
    harness, mocker, client_request_ready, refresh_skipped_users
):
    remove_entities = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.remove_lingering_relation_users_and_roles"
    )
    mocker.patch.object(harness.charm, "is_unit_going_away", return_value=False)

    event = MagicMock()
    harness.charm.external_clients_events._on_relation_broken(event)

    remove_entities.assert_called_once()
    refresh_skipped_users.assert_called_once_with(event)


@pytest.mark.parametrize("entity_type", [ENTITY_GROUP, ""], ids=["group", "classic"])
def test_client_index_provided_before_its_entity(
    harness, mocker, client_request_ready, group_client, refresh_skipped_users, entity_type
):
    manager = mocker.patch.object(harness.charm, "external_clients_manager")
    manager.get_request_error.return_value = None
    group_client.entity_type = entity_type

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    assert [name for name, _, _ in manager.method_calls if name.startswith("provide_")] == [
        "provide_client_index",
        "provide_client_entity",
    ]


@pytest.mark.parametrize("entity_type", [ENTITY_GROUP, ""], ids=["group", "classic"])
def test_entity_not_provided_when_index_creation_fails(
    harness,
    client_request_ready,
    group_client,
    provide_client_entity,
    provide_client_index,
    entity_type,
):
    provide_client_index.side_effect = OpenSearchUserMgmtError()
    group_client.entity_type = entity_type

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_called_once()


def test_group_request_without_entity_rejected(
    harness, client_request_ready, group_client, provide_client_entity
):
    group_client.get_requested_entity.return_value = None

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_not_called()


def test_request_rejected_outside_main_orchestrator(
    harness, mocker, client_request_ready, group_client, provide_client_entity
):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.is_main_orchestrator",
        new_callable=PropertyMock,
        return_value=False,
    )

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_not_called()


def test_request_for_reserved_name_rejected(
    harness, client_request_ready, group_client, provide_client_entity
):
    group_client.get_requested_entity.return_value = ExternalClientRequestedEntity("admin", "pwd")

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_not_called()


@pytest.mark.parametrize("registry", ["client_users_dict", "client_groups_dict"])
def test_request_for_entity_of_another_relation_deferred(
    harness, mocker, client_request_ready, group_client, provide_client_entity, registry
):
    mocker.patch(
        f"opensearch_single_kernel.core.peer_relation.OpenSearchApplication.{registry}",
        new_callable=PropertyMock,
        return_value={"2": GROUP_ENTITY.username},
    )

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_called_once()


def test_request_for_existing_role_not_created_for_the_relation_deferred(
    harness,
    mocker,
    client_request_ready,
    group_client,
    provide_client_entity,
    provide_client_index,
):
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_role",
        return_value={GROUP_ENTITY.username: {"index_permissions": []}},
    )

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_index.assert_not_called()
    provide_client_entity.assert_not_called()
    event.defer.assert_called_once()


def test_request_for_role_created_for_the_relation_served(
    harness,
    mocker,
    client_request_ready,
    group_client,
    provide_client_entity,
    provide_client_index,
):
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.client_groups_dict",
        new_callable=PropertyMock,
        return_value={str(group_client.relation.id): GROUP_ENTITY.username},
    )
    get_role = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_role",
        return_value={GROUP_ENTITY.username: {"index_permissions": []}},
    )

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    get_role.assert_not_called()
    provide_client_entity.assert_called_once_with(group_client, GROUP_ENTITY)


def test_request_deferred_when_requested_role_cannot_be_looked_up(
    harness, mocker, client_request_ready, group_client, provide_client_entity
):
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_role",
        side_effect=OpenSearchHttpError(),
    )

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_called_once()


def test_user_entity_request_rejected(
    harness, client_request_ready, group_client, provide_client_entity, provide_client_index
):
    group_client.entity_type = ENTITY_USER
    group_client.get_requested_entity.return_value = ExternalClientRequestedEntity("alice", "pwd")

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    provide_client_index.assert_not_called()
    event.defer.assert_not_called()


def test_user_entity_request_ignored_when_other_requests_are_deferred(
    harness, mocker, client_request_ready, group_client, provide_client_entity
):
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
        return_value=False,
    )
    group_client.entity_type = ENTITY_USER

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_not_called()


@pytest.mark.parametrize("handler", ["_on_relation_changed", "_on_relation_departed"])
@pytest.mark.parametrize("entity_type,endpoints_updated", [(ENTITY_USER, False), ("", True)])
def test_endpoints_not_provided_to_user_entity_client(
    harness, mocker, client_request_ready, group_client, handler, entity_type, endpoints_updated
):
    update_endpoints = mocker.patch(
        "opensearch_single_kernel.events.external_clients.ExternalClientsEventsHandler.update_external_client_endpoints"
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.unit_ip", return_value="1.1.1.1"
    )
    group_client.entity_type = entity_type

    event = MagicMock(relation=group_client.relation)
    event.departing_unit.app = harness.charm.app
    getattr(harness.charm.external_clients_events, handler)(event)

    assert update_endpoints.called == endpoints_updated


def test_request_deferred_until_node_up(
    harness, mocker, client_request_ready, group_client, provide_client_entity
):
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
        return_value=False,
    )

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_called_once()


def test_failed_entity_provisioning_retried(
    harness, client_request_ready, group_client, provide_client_entity, provide_client_index
):
    provide_client_entity.side_effect = OpenSearchUserMgmtError()

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    assert group_client.tls_ca != "admin-chain"
    event.defer.assert_called_once()


def test_mapped_roles_map_ldap_groups_to_group_entity_clients(harness, mocker):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.external_clients",
        new_callable=PropertyMock,
        return_value=[
            make_client(groups=["ignored"]),
            make_client(2, ENTITY_GROUP, groups=["devs", "ops"]),
            make_client(3, ENTITY_GROUP, groups=["devs"]),
            make_client(4, ENTITY_GROUP, groups=["unprovisioned"]),
        ],
    )
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.client_users_dict",
        new_callable=PropertyMock,
        return_value={"1": "app_user"},
    )
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.client_groups_dict",
        new_callable=PropertyMock,
        return_value={"2": "devs_ops_group", "3": "devs_group"},
    )

    mapped_roles = harness.charm.state.mapped_roles

    assert {
        "app_user": ["app_user"],
        "devs_ops_group": ["devs_ops_group"],
        "devs_group": ["devs_group"],
        "devs": ["devs_ops_group", "devs_group"],
        "ops": ["devs_ops_group"],
    }.items() <= mapped_roles.items()
    assert "ignored" not in mapped_roles
    assert "unprovisioned" not in mapped_roles
    assert {"app_user", "devs_ops_group", "devs_group"} <= set(harness.charm.state.managed_roles)


@pytest.mark.parametrize(
    "roles_mapping, expected",
    [
        (
            '{"alice": "readall", "bob": "readall", "carol": "all_access"}',
            {"readall": ["alice", "bob"], "all_access": ["carol"]},
        ),
        ('{"alice": ["readall"], "bob": "readall"}', {"readall": ["bob"]}),
        ('["alice"]', {}),
        ("not-a-json", {}),
    ],
    ids=["valid", "non-string-role-skipped", "not-a-dict", "invalid-json"],
)
def test_mapped_users_from_roles_mapping_config(harness, roles_mapping, expected):
    with harness.hooks_disabled():
        harness.update_config({"roles_mapping": roles_mapping})

    assert harness.charm.state.mapped_users == expected


@pytest.mark.parametrize(
    "entity_type, requested_entity, permissions_valid, client_groups, expected_statuses",
    [
        (
            ENTITY_USER,
            ExternalClientRequestedEntity("alice", "secret"),
            True,
            {},
            [format_status(ExternalClientsStatuses.ENTITY_TYPE_UNSUPPORTED.value, {"id": 1})],
        ),
        (
            ENTITY_GROUP,
            None,
            True,
            {},
            [format_status(ExternalClientsStatuses.USER_ENTITY_GROUP_INVALID.value, {"id": 1})],
        ),
        (
            ENTITY_GROUP,
            GROUP_ENTITY,
            False,
            {},
            [format_status(ExternalClientsStatuses.ENTITY_PERMISSIONS_INVALID.value, {"id": 1})],
        ),
        (
            ENTITY_GROUP,
            ExternalClientRequestedEntity("admin", None),
            True,
            {},
            [format_status(ExternalClientsStatuses.ENTITY_NAME_RESERVED.value, {"id": 1})],
        ),
        (
            "",
            ExternalClientRequestedEntity("kibanaserver", "secret"),
            True,
            {},
            [format_status(ExternalClientsStatuses.ENTITY_NAME_RESERVED.value, {"id": 1})],
        ),
        (
            ENTITY_GROUP,
            ExternalClientRequestedEntity("all_access", None),
            True,
            {},
            [format_status(ExternalClientsStatuses.ENTITY_NAME_RESERVED.value, {"id": 1})],
        ),
        (
            ENTITY_GROUP,
            GROUP_ENTITY,
            True,
            {"2": "devs_group"},
            [format_status(ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT.value, {"id": 1})],
        ),
        (
            ENTITY_GROUP,
            GROUP_ENTITY,
            True,
            {"1": "devs_group"},
            [GeneralStatuses.ACTIVE_IDLE.value],
        ),
    ],
    ids=[
        "user-entity",
        "group-missing-entity",
        "invalid-permissions",
        "system-user-name",
        "system-user-name-on-classic-relation",
        "managed-role-name",
        "name-used-by-other-relation",
        "name-owned-by-relation",
    ],
)
def test_entity_client_statuses(
    opensearch_client,
    entity_type,
    requested_entity,
    permissions_valid,
    client_groups,
    expected_statuses,
):
    relation = MagicMock(id=1)
    relation.data = {relation.app: {"index": "logs"}}
    external_client = make_client(entity_type=entity_type)
    external_client.get_requested_entity.return_value = requested_entity
    if not permissions_valid:
        type(external_client).entity_permissions = PropertyMock(
            side_effect=ValidationError.from_exception_data("entity-permissions", [])
        )

    state = make_state(client_groups=client_groups)
    state.external_client_relations = [relation]
    state.external_client_by_relation.return_value = external_client
    opensearch_client.is_node_up.return_value = False

    statuses = ExternalClientsManager(state, MagicMock()).get_statuses("unit")

    assert statuses == expected_statuses


@pytest.mark.parametrize(
    "client_groups, existing_role, expected_statuses",
    [
        (
            {},
            {"devs_group": {}},
            [format_status(ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT.value, {"id": 1})],
        ),
        ({"1": "devs_group"}, {"devs_group": {}}, [GeneralStatuses.ACTIVE_IDLE.value]),
        (
            {},
            None,
            [format_status(ExternalClientsStatuses.USER_CREATION_FAILED.value, {"id": 1})],
        ),
    ],
    ids=["role-not-created-for-relation", "role-created-for-relation", "role-absent"],
)
def test_group_client_status_for_existing_role(
    opensearch_client, client_groups, existing_role, expected_statuses
):
    relation = MagicMock(id=1)
    relation.data = {relation.app: {"index": "logs"}}
    external_client = make_client(entity_type=ENTITY_GROUP)
    external_client.get_requested_entity.return_value = GROUP_ENTITY
    state = make_state(client_groups=client_groups)
    state.external_client_relations = [relation]
    state.external_client_by_relation.return_value = external_client
    opensearch_client.indices.return_value = ["logs"]
    opensearch_client.get_role.return_value = existing_role

    statuses = ExternalClientsManager(state, MagicMock()).get_statuses("unit")

    assert statuses == expected_statuses


def test_client_entity_not_reported_as_failed_while_node_is_down(opensearch_client):
    relation = MagicMock(id=1)
    relation.data = {relation.app: {"index": "logs"}}
    external_client = make_client()
    external_client.get_requested_entity.return_value = None
    state = make_state()
    state.external_client_relations = [relation]
    state.external_client_by_relation.return_value = external_client
    opensearch_client.is_node_up.return_value = False

    statuses = ExternalClientsManager(state, MagicMock()).get_statuses("unit")

    assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]


def test_client_status_outside_main_orchestrator(opensearch_client):
    relation = MagicMock(id=1)
    relation.data = {relation.app: {"index": "logs"}}
    state = make_state()
    state.is_main_orchestrator = False
    state.external_client_relations = [relation]
    state.external_client_by_relation.return_value = make_client()

    statuses = ExternalClientsManager(state, MagicMock()).get_statuses("unit")

    assert statuses == [format_status(ExternalClientsStatuses.RELATION_INVALID.value, {"id": 1})]


@pytest.mark.parametrize("is_main_orchestrator", [True, False], ids=["main", "non-main"])
def test_role_mappings_reconciled_on_config_changed_by_main_orchestrator_only(
    harness, mocker, client_request_ready, is_main_orchestrator
):
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.is_main_orchestrator",
        new_callable=PropertyMock,
        return_value=is_main_orchestrator,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.reconcile_cluster_config",
        return_value=False,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.profiles.ProfilesManager.check_profile_requirements",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.config.ConfigManager.update_profile_configuration",
        return_value=False,
    )
    reconcile_role_mappings = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.reconcile_role_mappings"
    )
    mocker.patch.object(harness.charm, "reconcile_security_config")

    harness.charm.opensearch_events._on_config_changed(MagicMock())

    assert reconcile_role_mappings.called is is_main_orchestrator
