# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import MagicMock, PropertyMock

from ops.model import ActiveStatus, BlockedStatus

from opensearch_single_kernel.common.constants import (
    CLIENT_RELATION,
    NODE_LOCK_RELATION,
    DeploymentType,
    StartMode,
    State,
)
from opensearch_single_kernel.common.exceptions import OpenSearchUserMgmtError
from opensearch_single_kernel.core.plain_base import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
)

DASHBOARDS_CHARM = "opensearch-dashboards"

mock_deployment_description = DeploymentDescription(
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
    """Test the on_resource_requested event handler."""
    add_relations(harness)

    event = MagicMock()
    event.relation.id = 1
    event.relation.app = harness.charm.app
    event.request.resource = "test_index"
    event.request.extra_user_roles = "admin"
    event.request.request_id = "req-1"
    event.request.salt = "salt"
    username = relation_username(event.relation)
    _, password = ("hashed_pw", "password")

    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.request",
        return_value={"status": "OK"},
    )
    harness.set_leader(True)
    harness.charm.state.application.admin_chain = "tls_chain"
    mocker.patch(
        "opensearch_single_kernel.events.external_clients.ExternalClientsEventsHandler.update_external_client_endpoints"
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
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_index",
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.get_nodes",
        return_value=[],
    )
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.get_relation_endpoints",
        return_value="",
    )
    create_users = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.create_opensearch_users",
        return_value=(username, password),
    )
    set_response = mocker.patch(
        "opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces.ResourceProviderEventHandler.set_response"
    )

    harness.set_leader(False)
    harness.charm.external_clients_events._on_resource_requested(event)
    is_node_up.assert_not_called()

    harness.set_leader(True)
    is_node_up.return_value = False
    harness.charm.external_clients_events._on_resource_requested(event)
    event.defer.assert_called()

    is_node_up.return_value = True
    harness.charm.unit.status = ActiveStatus()
    harness.charm.external_clients_events._on_resource_requested(event)
    create_users.assert_called_with(
        event.request.resource, event.relation, extra_user_roles=event.request.extra_user_roles
    )
    set_response.assert_called()
    assert not isinstance(harness.charm.unit.status, BlockedStatus)

    create_users.reset_mock()
    set_response.reset_mock()

    create_users.side_effect = OpenSearchUserMgmtError()
    harness.charm.external_clients_events._on_resource_requested(event)
    set_response.assert_not_called()


def test_on_index_requested_kibanaserver(harness, mocker):
    add_relations(harness)

    event = MagicMock()
    event.relation.id = 1
    event.relation.app = harness.charm.app
    event.request.resource = ".opensearch-dashboards"
    event.request.extra_user_roles = "kibana_server"
    event.request.request_id = "req-2"
    event.request.salt = "salt"
    username = "kibanaserver"
    _, password = ("hashed_pw", "password")

    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.request",
        return_value={"status": "OK"},
    )
    harness.set_leader(True)
    harness.charm.state.application.admin_chain = "tls_chain"
    mocker.patch(
        "opensearch_single_kernel.events.external_clients.ExternalClientsEventsHandler.update_external_client_endpoints"
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
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_index",
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.get_nodes",
        return_value=[],
    )
    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.get_relation_endpoints",
        return_value="",
    )
    create_users = mocker.patch(
        "opensearch_single_kernel.managers.external_clients.ExternalClientsManager.create_opensearch_users",
        return_value=(username, password),
    )
    set_response = mocker.patch(
        "opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces.ResourceProviderEventHandler.set_response"
    )

    harness.set_leader(False)
    harness.charm.external_clients_events._on_resource_requested(event)
    is_node_up.assert_not_called()

    harness.set_leader(True)
    is_node_up.return_value = False
    harness.charm.external_clients_events._on_resource_requested(event)
    event.defer.assert_called()

    is_node_up.return_value = True
    harness.charm.unit.status = ActiveStatus()
    harness.charm.external_clients_events._on_resource_requested(event)
    create_users.assert_called()
    set_response.assert_called()


def test_create_opensearch_users(
    harness,
    mocker,
):
    add_relations(harness)
    hashed_pw = "my_cool_hash"
    extra_user_roles = "admin"
    index = "test_index"

    mocker.patch(
        "opensearch_single_kernel.managers.external_clients.generate_hashed_password",
        return_value=(hashed_pw, "password"),
    )
    relation = harness.charm.model.get_relation(CLIENT_RELATION)
    mapped_users = ["test_oidc"]
    get_relation_mapped_users = mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.get_relation_mapped_users",
        return_value=mapped_users,
    )
    create_user_role = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_user_role",
    )
    create_user = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_user",
    )
    create_role_mapping = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_user_role_mapping",
    )
    patch_user = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.patch_user",
    )
    client_users_dict = mocker.patch(
        "opensearch_single_kernel.core.peer_app.OpenSearchAppPeerModel.client_relation_users",
        create=True,
        new_callable=PropertyMock,
        return_value={},
    )

    # username for this relation would be f"{relation.name}_{relation.id}"
    expected_username = f"{relation.name}_{relation.id}"
    expected_patches = [
        {"op": "replace", "path": "/opendistro_security_roles", "value": [expected_username]},
    ]

    harness.charm.external_clients_manager.create_opensearch_users(
        index, relation, extra_user_roles=extra_user_roles
    )

    # permissions and action groups are in extra_user_roles, so we create a new role.
    create_user_role.assert_called_with(
        role_name=expected_username,
        permissions=harness.charm.external_clients_manager.get_extra_user_role_permissions(
            extra_user_roles, index
        ),
    )
    create_user.assert_called_with(expected_username, [expected_username], hashed_pw)
    get_relation_mapped_users.assert_called_with(expected_username)
    create_role_mapping.assert_called_with(expected_username, mapped_users)
    patch_user.assert_called_with(expected_username, expected_patches)
    client_users_dict.assert_called()
