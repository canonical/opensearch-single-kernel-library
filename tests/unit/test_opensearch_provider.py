# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest

from opensearch_single_kernel.common.constants import CLIENT_RELATION, KIBANA_SERVER_USER
from opensearch_single_kernel.common.exceptions import OpenSearchUserMgmtError
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
from opensearch_single_kernel.utils.status import format_status

GROUP_ENTITY = ExternalClientRequestedEntity("devs_group", "secret")
GROUP_PERMISSIONS = {
    "index_permissions": [{"index_patterns": ["logs"], "allowed_actions": ["read"]}]
}


def make_client(
    relation_id: int = 1,
    entity_type: str = ENTITY_USER,
    groups: list[str] | None = None,
    **attributes,
) -> MagicMock:
    return MagicMock(
        relation=MagicMock(id=relation_id),
        entity_type=entity_type,
        extra_group_roles=groups or [""],
        index="logs",
        relation_username=f"{CLIENT_RELATION}_{relation_id}",
        **attributes,
    )


def make_state(client_users: dict[str, str] | None = None) -> MagicMock:
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.application.client_users_dict = client_users or {}
    state.mapped_users = {}
    state.mapped_roles = {}
    return state


@pytest.fixture
def opensearch_client(mocker) -> MagicMock:
    client = MagicMock()
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
        ("alice", None),
        (None, None),
    ],
    ids=["valid", "colon-in-password", "no-password", "absent"],
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
    "requested_entity, expected_user, expected_password",
    [
        (None, f"{CLIENT_RELATION}_1", "generated"),
        (ExternalClientRequestedEntity("alice", "secret"), "alice", "secret"),
    ],
    ids=["generated", "requested"],
)
def test_user_client_credentials(
    opensearch_client, requested_entity, expected_user, expected_password
):
    state = make_state()
    external_client = make_client(extra_user_roles="admin")

    ExternalClientsManager(state, MagicMock()).provide_client_entity(
        external_client, requested_entity
    )

    opensearch_client.create_user.assert_called_once_with(
        expected_user, [expected_user], f"hash-of-{expected_password}"
    )
    assert external_client.username == expected_user
    assert external_client.password == expected_password
    assert state.application.client_users_dict == {"1": expected_user}


@pytest.mark.parametrize(
    "password, user_created", [("secret", True), ("None", False)], ids=["user", "role-only"]
)
def test_group_client_role_gets_requested_permissions(
    opensearch_client, mocker, password, user_created
):
    reconcile_role_mappings = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.reconcile_role_mappings"
    )
    state = make_state()
    external_client = make_client(entity_type=ENTITY_GROUP, entity_permissions=GROUP_PERMISSIONS)

    ExternalClientsManager(state, MagicMock()).provide_client_entity(
        external_client, ExternalClientRequestedEntity("devs_group", password)
    )

    opensearch_client.create_user_role.assert_called_once_with(
        role_name="devs_group", permissions=GROUP_PERMISSIONS
    )
    assert opensearch_client.create_user.called is user_created
    assert state.application.client_users_dict == {"1": "devs_group"}
    reconcile_role_mappings.assert_called_once()


def test_dashboards_client_gets_kibanaserver_credentials(opensearch_client):
    state = make_state()
    state.application.kibana_server_password = "kibana-password"
    external_client = make_client(extra_user_roles="kibana_server")

    ExternalClientsManager(state, MagicMock()).provide_client_entity(external_client, None)

    opensearch_client.create_user.assert_not_called()
    assert external_client.username == KIBANA_SERVER_USER
    assert external_client.password == "kibana-password"


@pytest.fixture
def client_request_ready(harness, mocker):
    """Leader with a running node and initialised security index."""
    with harness.hooks_disabled():
        harness.set_leader(True)

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


def test_client_request_provides_requested_entity_and_index(
    harness, client_request_ready, group_client, provide_client_entity, provide_client_index
):
    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_called_once_with(group_client, GROUP_ENTITY)
    provide_client_index.assert_called_once_with(group_client)
    assert group_client.tls_ca == "admin-chain"
    event.defer.assert_not_called()


def test_group_request_without_entity_rejected(
    harness, client_request_ready, group_client, provide_client_entity
):
    group_client.get_requested_entity.return_value = None

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_not_called()


def test_request_for_username_of_another_relation_deferred(
    harness, mocker, client_request_ready, group_client, provide_client_entity
):
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.client_users_dict",
        new_callable=PropertyMock,
        return_value={"2": GROUP_ENTITY.username},
    )

    event = MagicMock(index="logs", relation=group_client.relation)
    harness.charm.external_clients_events._on_client_requested(event)

    provide_client_entity.assert_not_called()
    event.defer.assert_called_once()


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

    provide_client_index.assert_not_called()
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
        return_value={"1": "app_user", "2": "devs_ops_group", "3": "devs_group"},
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
    "requested_entity, client_users, expected_statuses",
    [
        (
            None,
            {},
            [format_status(ExternalClientsStatuses.USER_ENTITY_GROUP_INVALID.value, {"id": 1})],
        ),
        (
            GROUP_ENTITY,
            {"2": "devs_group"},
            [format_status(ExternalClientsStatuses.USER_ENTITY_GROUP_CONFLICT.value, {"id": 1})],
        ),
        (
            GROUP_ENTITY,
            {"1": "devs_group"},
            [GeneralStatuses.ACTIVE_IDLE.value],
        ),
    ],
    ids=["missing-entity", "username-used-by-other-relation", "username-owned-by-relation"],
)
def test_group_entity_client_statuses(
    opensearch_client, requested_entity, client_users, expected_statuses
):
    relation = MagicMock(id=1)
    relation.data = {relation.app: {"index": "logs"}}
    external_client = make_client(entity_type=ENTITY_GROUP)
    external_client.get_requested_entity.return_value = requested_entity

    state = make_state(client_users)
    state.external_client_relations = [relation]
    state.external_client_by_relation.return_value = external_client
    opensearch_client.is_node_up.return_value = False

    statuses = ExternalClientsManager(state, MagicMock()).get_statuses("unit")

    assert statuses == expected_statuses
