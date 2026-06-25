# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import MagicMock, PropertyMock

from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

from opensearch_single_kernel.common.constants import (
    CLIENT_RELATION,
    NODE_LOCK_RELATION,
    DeploymentType,
    StartMode,
    State,
)
from opensearch_single_kernel.common.exceptions import OpenSearchUserMgmtError
from opensearch_single_kernel.core.external_clients_relation import (
    ExternalOpenSearchClient,
)
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
)

DASHBOARDS_CHARM = "opensearch-dashboards"

mock_deployment_desc = DeploymentDescription(
    config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
    start=StartMode.WITH_GENERATED_ROLES,
    pending_directives=[],
    typ=DeploymentType.MAIN_ORCHESTRATOR,
    app=App(model_uuid="model-uuid", name="opensearch"),
    state=DeploymentState(value=State.ACTIVE),
)


def relation_username(relation) -> str:
    """Get the relation username key for this relation."""
    return f"{relation.name}_{relation.id}"


def add_relations(harness):
    """Add necessary relations for testing."""
    # Add client relation
    client_rel_id = harness.add_relation(CLIENT_RELATION, "application")
    harness.add_relation_unit(client_rel_id, "application/0")

    # Add node lock relation
    harness.add_relation(NODE_LOCK_RELATION, harness.charm.app.name)


def test_on_index_requested(harness, mocker):
    """Test the on_index_requested event handler."""
    add_relations(harness)

    event = MagicMock()
    event.relation.id = 1
    event.relation.app = harness.charm.app
    username = relation_username(event.relation)
    _, password = ("hashed_pw", "password")

    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.request",
        return_value={"status": "OK"},
    )
    mocker.patch(
        "opensearch_single_kernel.core.secrets.OpenSearchSecrets.get_object",
        return_value={"chain": "tls_chain"},
    )
    mocker.patch(
        "opensearch_single_kernel.events.external_clients.ExternalClientsEventsHandler.update_external_client_endpoints"
    )
    mocker.patch(
        "opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces.OpenSearchProvides._update_relation_data"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.utils.helpers.generate_hashed_password",
        return_value=("hashed_pw", "password"),
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.BaseWorkload.version",
        new_callable=PropertyMock,
        return_value="1",
    )

    is_node_up = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
    )
    create_users = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.provide_client_user",
        return_value=(username, password),
    )
    set_username = mocker.patch(
        "opensearch_single_kernel.core.external_clients_relation.ExternalOpenSearchClient.username",
        new_callable=PropertyMock,
    )
    set_password = mocker.patch(
        "opensearch_single_kernel.core.external_clients_relation.ExternalOpenSearchClient.password",
        new_callable=PropertyMock,
    )
    set_version = mocker.patch(
        "opensearch_single_kernel.core.external_clients_relation.ExternalOpenSearchClient.version",
        new_callable=PropertyMock,
    )

    external_client = ExternalOpenSearchClient(
        relation=event.relation,
        data_interface=MagicMock(as_dict=MagicMock(return_value={})),
        component=harness.charm.app,
        relation_name=CLIENT_RELATION,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.external_client_by_relation",
        return_value=external_client,
    )
    harness.set_leader(False)
    harness.charm.external_clients_events._on_client_requested(event)
    is_node_up.assert_not_called()

    harness.set_leader(True)
    is_node_up.return_value = False
    harness.charm.external_clients_events._on_client_requested(event)
    event.defer.assert_called()

    is_node_up.return_value = True
    event.extra_user_roles = "admin"
    event.index = "test_index"
    external_client.extra_user_roles = event.extra_user_roles
    external_client.index = event.index
    harness.charm.unit.status = ActiveStatus()
    harness.charm.external_clients_events._on_client_requested(event)
    create_users.assert_called_with(
        external_client, event.index, extra_user_roles=event.extra_user_roles
    )
    set_username.assert_called_with(username)
    set_password.assert_called_with(password)
    set_version.assert_called_with("1")
    assert not isinstance(harness.charm.unit.status, BlockedStatus)
    set_username.reset_mock()
    set_password.reset_mock()
    set_version.reset_mock()

    create_users.side_effect = OpenSearchUserMgmtError()
    harness.charm.external_clients_events._on_client_requested(event)
    assert isinstance(harness.charm.unit.status, MaintenanceStatus)
    set_username.assert_not_called()
    set_password.assert_not_called()
    set_version.assert_not_called()


def test_on_index_requested_kibanaserver(harness, mocker):
    add_relations(harness)

    event = MagicMock()
    event.relation.id = 1
    event.relation.app = harness.charm.app
    username = "kibanaserver"
    _, password = ("hashed_pw", "password")

    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.request",
        return_value={"status": "OK"},
    )
    mocker.patch(
        "opensearch_single_kernel.core.secrets.OpenSearchSecrets.get_object",
        return_value={"chain": "tls_chain"},
    )
    mocker.patch(
        "opensearch_single_kernel.events.external_clients.ExternalClientsEventsHandler.update_external_client_endpoints"
    )
    mocker.patch(
        "opensearch_single_kernel.lib.charms.data_platform_libs.v0.data_interfaces.OpenSearchProvides._update_relation_data"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.utils.helpers.generate_hashed_password",
        return_value=("hashed_pw", "password"),
    )
    mocker.patch(
        "opensearch_single_kernel.workload.base.BaseWorkload.version",
        new_callable=PropertyMock,
        return_value="1",
    )

    is_node_up = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
    )
    create_users = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.provide_client_user",
        return_value=(username, password),
    )
    patch_user = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.patch_user",
    )
    set_username = mocker.patch(
        "opensearch_single_kernel.core.external_clients_relation.ExternalOpenSearchClient.username",
        new_callable=PropertyMock,
    )
    set_password = mocker.patch(
        "opensearch_single_kernel.core.external_clients_relation.ExternalOpenSearchClient.password",
        new_callable=PropertyMock,
    )
    set_version = mocker.patch(
        "opensearch_single_kernel.core.external_clients_relation.ExternalOpenSearchClient.version",
        new_callable=PropertyMock,
    )

    external_client = ExternalOpenSearchClient(
        relation=event.relation,
        data_interface=MagicMock(as_dict=MagicMock(return_value={})),
        component=harness.charm.app,
        relation_name=CLIENT_RELATION,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.external_client_by_relation",
        return_value=external_client,
    )

    harness.set_leader(False)
    harness.charm.external_clients_events._on_client_requested(event)
    is_node_up.assert_not_called()

    harness.set_leader(True)
    is_node_up.return_value = False
    harness.charm.external_clients_events._on_client_requested(event)
    event.defer.assert_called()

    is_node_up.return_value = True
    event.extra_user_roles = "kibana_server"
    event.index = ".opensearch-dashboards"
    external_client.extra_user_roles = event.extra_user_roles
    external_client.index = event.index
    harness.charm.unit.status = ActiveStatus()
    harness.charm.external_clients_events._on_client_requested(event)
    create_users.assert_called()
    patch_user.assert_not_called()
    set_username.assert_called_with(username)
    set_password.assert_called_with(password)
    set_version.assert_called_with("1")
    harness.charm.unit.status = ActiveStatus()
    set_username.reset_mock()
    set_password.reset_mock()
    set_version.reset_mock()


def test_provide_client_user(
    harness,
    mocker,
):
    add_relations(harness)
    username = "username"
    password = "password"
    hashed_pw = "my_cool_hash"
    extra_user_roles = "admin"
    index = "test_index"
    roles = [username]
    patches = [
        {"op": "replace", "path": "/opendistro_security_roles", "value": roles},
    ]

    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.generate_password",
        return_value=password,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.hash_string",
        return_value=hashed_pw,
    )
    external_client = ExternalOpenSearchClient(
        relation=harness.charm.model.get_relation(CLIENT_RELATION),
        data_interface=MagicMock(),
        component=harness.charm.app,
        relation_name=CLIENT_RELATION,
    )
    roles_mapped_users = {username: ["test_oidc"]}
    roles_mapped_roles = {username: [username]}
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.roles_mapped_users",
        new_callable=PropertyMock,
        return_value=roles_mapped_users,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.roles_mapped_roles",
        new_callable=PropertyMock,
        return_value=roles_mapped_roles,
    )
    create_user_role = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_user_role",
    )
    create_user = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_user",
    )
    put_role_mapping = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.put_role_mapping",
    )
    patch_user = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.patch_user",
    )
    client_users_dict = mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.client_users_dict",
        new_callable=PropertyMock,
    )

    mocker.patch(
        "opensearch_single_kernel.core.external_clients_relation.ExternalOpenSearchClient.relation_username",
        new_callable=PropertyMock,
        return_value=username,
    )

    harness.charm.external_clients_manager.provide_client_user(
        external_client, index, extra_user_roles=extra_user_roles
    )

    # permissions and action groups are in extra_user_roles, so we create a new role.
    create_user_role.assert_called_with(
        role_name=username,
        permissions=harness.charm.external_clients_manager.get_extra_user_role_permissions(
            extra_user_roles, index
        ),
    )
    create_user.assert_called_with(username, roles, hashed_pw)
    put_role_mapping.assert_called_with(
        username, roles_mapped_users[username], roles_mapped_roles[username]
    )
    patch_user.assert_called_with(username, patches)
    client_users_dict.assert_called()
