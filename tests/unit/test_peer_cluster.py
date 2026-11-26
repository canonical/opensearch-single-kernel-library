# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the peer-cluster relation."""

import json
from unittest.mock import MagicMock

import pytest
from ops import ModelError
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import (
    AZURE_CREDENTIALS,
    GCS_CREDENTIALS,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    S3_CREDENTIALS,
    SMTP_RELATION,
    DeploymentType,
    Directive,
    Scope,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    HealthStatuses,
    PeerClusterErrorDataStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.core.models import (
    App,
    Node,
    PeerClusterApp,
    PeerClusterOrchestrators,
    PeerClusterRelData,
    PeerClusterRelDataCredentials,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.core.peer_cluster_relation import PeerCluster
from tests.unit.helpers import deployment_descriptions


def test_peer_cluster_data_when_relation_is_gone():
    relation = MagicMock(data={})
    peer_cluster = PeerCluster(relation, MagicMock(), MagicMock(), MagicMock())

    assert peer_cluster.data() is None


@pytest.fixture
def consumer(harness, mocker):
    """A data application with registered main and failover providers."""
    harness.disable_hooks()
    harness.set_leader(True)
    charm = harness.charm
    charm.state.application.deployment_desc = deployment_descriptions["data-only"].model_copy(
        deep=True
    )
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    relations = {}
    # Put main last, matching the order that let its stale failover metadata win in CI.
    for role in ("failover", "main"):
        relation_id = harness.add_relation(PEER_CLUSTER_RELATION, role)
        harness.add_relation_unit(relation_id, f"{role}/0")
        relations[role] = harness.model.get_relation(PEER_CLUSTER_RELATION, relation_id)
        harness.update_relation_data(
            relation_id,
            role,
            {
                "trigger": role,
                "orchestrators": json.dumps(
                    {f"{role}_app": App(model_uuid="model-uuid", name=role).to_dict()}
                ),
            },
        )
    charm.state.application.orchestrators = PeerClusterOrchestrators(
        main_app=App(model_uuid="model-uuid", name="main"),
        main_rel_id=relations["main"].id,
        failover_app=App(model_uuid="model-uuid", name="failover"),
        failover_rel_id=relations["failover"].id,
    )
    return relations


@pytest.fixture
def revoked_provider_secret(harness, consumer, mocker):
    """Set up provider data and deny access to its admin secret."""
    charm = harness.charm
    app = App(model_uuid="model-uuid", name="main")
    node = Node(name="main-0", roles=["cluster_manager"], ip="10.0.0.10", app=app, unit_number=0)
    data = PeerClusterRelData(
        cluster_name="test-cluster",
        cm_nodes=[node],
        credentials=PeerClusterRelDataCredentials(
            admin_username="admin",
            admin_password="secret://revoked-provider-secret",
            admin_password_hash="hash",
            kibana_password="password",
            kibana_password_hash="hash",
            monitor_password=None,
            admin_tls=None,
            s3=None,
            azure=None,
            gcs=None,
        ),
        deployment_desc=deployment_descriptions["cm-only"],
    )
    harness.update_relation_data(consumer["main"].id, "main", {"data": data.to_str()})
    get_secret = charm.model.get_secret

    def read_secret(*args, **kwargs):
        if kwargs.get("id") == "secret://revoked-provider-secret":
            raise ModelError("ERROR permission denied")
        return get_secret(*args, **kwargs)

    mocker.patch.object(charm.model, "get_secret", side_effect=read_secret)
    current_app = charm.state.application.deployment_desc.app
    charm.state.application.cluster_fleet_apps = {
        current_app.id: PeerClusterApp(app=current_app, planned_units=1, units=[], roles=["data"]),
        app.id: PeerClusterApp(app=app, planned_units=1, units=[], roles=["cluster_manager"]),
    }
    return node


def test_health_collection_when_provider_secret_is_revoked(
    harness, revoked_provider_secret, mocker
):
    charm = harness.charm
    charm.state.application.is_security_index_initialised = True
    client = mocker.Mock()
    client.get_health.return_value = {
        "status": "red",
        "initializing_shards": 0,
        "relocating_shards": 0,
    }
    mocker.patch.object(
        type(charm.health_manager),
        "opensearch_client",
        new_callable=mocker.PropertyMock,
        return_value=client,
    )

    assert charm.health_manager.get_statuses("app") == [HealthStatuses.CLUSTER_HEALTH_RED.value]
    assert "10.0.0.10" in client.get_health.call_args.args[2]


@pytest.mark.parametrize("other_cm_available", [False, True])
def test_removal_safety_when_provider_secret_is_revoked(
    harness, revoked_provider_secret, mocker, other_cm_available
):
    manager = harness.charm.cluster_manager
    node = revoked_provider_secret
    client = mocker.Mock()
    client.is_node_up.return_value = other_cm_available
    client.get_nodes.return_value = {
        "nodes": {
            "remote": {
                "name": node.name,
                "roles": node.roles,
                "ip": node.ip,
                "host": node.ip,
                "attributes": {"app_id": node.app.id},
            }
        }
    }
    mocker.patch.object(
        type(manager),
        "opensearch_client",
        new_callable=mocker.PropertyMock,
        return_value=client,
    )

    assert manager.no_cluster_manager_left == (not other_cm_available)
    if other_cm_available:
        assert "10.0.0.10" in client.get_nodes.call_args.args[1]


@pytest.mark.parametrize("peek_secrets", [False, True])
def test_full_provider_data_still_requires_secret_access(
    harness, revoked_provider_secret, peek_secrets
):
    with pytest.raises(ModelError, match="permission denied"):
        harness.charm.state.get_rel_data_from_main_orchestrator(peek_secrets=peek_secrets)


@pytest.mark.parametrize("peek_secrets", [False, True])
def test_full_provider_data_preserves_startup_and_backup_fields(
    harness, consumer, revoked_provider_secret, peek_secrets
):
    charm = harness.charm
    relation_id = consumer["main"].id
    data = json.loads(harness.get_relation_data(relation_id, "main")["data"])
    secret_id = harness.add_model_secret("main", {"admin-password": "admin-password"})
    harness.grant_secret(secret_id, charm.app.name)
    data["credentials"]["admin_password"] = secret_id.replace("secret:", "secret://", 1)
    data["credentials"]["s3"] = {"access-key": "access", "secret-key": "secret"}
    data["first_data_node"] = "opensearch-0"
    harness.update_relation_data(relation_id, "main", {"data": json.dumps(data)})

    result = charm.state.get_rel_data_from_main_orchestrator(peek_secrets=peek_secrets)

    assert result.credentials.admin_password == "admin-password"
    assert result.first_data_node == "opensearch-0"
    assert result.cm_nodes == [revoked_provider_secret]
    assert result.credentials.s3.access_key == "access"
    assert result.credentials.s3.secret_key == "secret"
    assert charm.snapshots_manager.s3_info_from_peer_cluster == {
        "access_key": "access",
        "secret_key": "secret",
        "s3_tls_ca_chain": None,
    }


@pytest.mark.parametrize("missing", ["relation", "remote_app", "orchestrators"])
def test_main_provider_lookup_during_teardown(harness, consumer, revoked_provider_secret, missing):
    if missing == "relation":
        harness.remove_relation(consumer["main"].id)
    elif missing == "remote_app":
        consumer["main"].app = None
    else:
        harness.charm.state.application.orchestrators = PeerClusterOrchestrators()

    assert harness.charm.state.get_cm_nodes_from_main_orchestrator() == []
    assert harness.charm.state.get_rel_data_from_main_orchestrator() is None


def test_provider_node_metadata_does_not_resolve_secrets(
    harness, consumer, revoked_provider_secret
):
    peer = harness.charm.state.peer_cluster_by_relation_id(False, consumer["main"].id, remote=True)
    with pytest.raises(ModelError, match="permission denied"):
        peer.data()

    assert peer.cm_nodes == [revoked_provider_secret]


@pytest.mark.parametrize("payload", [None, {"cm_nodes": []}])
def test_missing_provider_nodes(harness, consumer, payload):
    if payload is not None:
        harness.update_relation_data(consumer["main"].id, "main", {"data": json.dumps(payload)})

    assert harness.charm.state.get_cm_nodes_from_main_orchestrator() == []


@pytest.mark.parametrize(
    "payload, error", [({}, KeyError), ({"cm_nodes": [{"ip": "10.0.0.10"}]}, ValidationError)]
)
def test_invalid_provider_nodes_are_not_silently_discarded(harness, consumer, payload, error):
    harness.update_relation_data(consumer["main"].id, "main", {"data": json.dumps(payload)})

    with pytest.raises(error):
        harness.charm.state.get_cm_nodes_from_main_orchestrator()


@pytest.mark.parametrize("is_provider", [False, True])
def test_peer_cluster_lookup_without_remote_app_preserves_local_data(harness, is_provider):
    harness.disable_hooks()
    harness.set_leader(True)
    state = harness.charm.state
    endpoint = PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
    relation_id = harness.add_relation(endpoint, "remote")
    relation = harness.model.get_relation(endpoint, relation_id)

    assert (
        state.peer_cluster_by_relation_id(is_provider, relation_id, remote=True).app
        == relation.app
    )
    relation.app = None

    assert state.peer_cluster_by_relation_id(is_provider, relation_id, remote=True) is None
    local = state.peer_cluster_by_relation_id(is_provider, relation_id)
    local.first_data_node = "opensearch-0"
    assert (
        harness.get_relation_data(relation_id, harness.charm.app.name)["first_data_node"]
        == "opensearch-0"
    )


@pytest.mark.parametrize("is_provider", [False, True])
@pytest.mark.parametrize("must_have_units", [False, True])
def test_peer_cluster_list_skips_missing_remote_apps(harness, is_provider, must_have_units):
    harness.disable_hooks()
    endpoint = PEER_CLUSTER_ORCHESTRATOR_RELATION if is_provider else PEER_CLUSTER_RELATION
    live_id = harness.add_relation(endpoint, "live")
    harness.add_relation_unit(live_id, "live/0")
    departed_id = harness.add_relation(endpoint, "departed")
    harness.model.get_relation(endpoint, departed_id).app = None

    remote = harness.charm.state.peer_clusters(is_provider, must_have_units, remote=True)
    assert [peer.relation.id for peer in remote] == [live_id]
    local = harness.charm.state.peer_clusters(is_provider, must_have_units, remote=False)
    assert {peer.relation.id for peer in local} == (
        {live_id} if must_have_units else {live_id, departed_id}
    )


def test_health_status_after_main_relation_removal(harness, consumer, mocker):
    charm = harness.charm
    charm.state.application.is_security_index_initialised = True
    app = charm.state.application.deployment_desc.app
    charm.state.application.cluster_fleet_apps = {
        app.id: PeerClusterApp(app=app, planned_units=1, units=[], roles=["data"])
    }
    client = mocker.Mock()
    client.get_health.return_value = {
        "status": "green",
        "initializing_shards": 0,
        "relocating_shards": 0,
    }
    mocker.patch.object(
        type(charm.health_manager),
        "opensearch_client",
        new_callable=mocker.PropertyMock,
        return_value=client,
    )
    harness.remove_relation(consumer["main"].id)

    assert charm.state.get_rel_data_from_main_orchestrator() is None
    assert charm.health_manager.get_statuses("app") == [GeneralStatuses.ACTIVE_IDLE.value]
    client.get_health.assert_called_once()


def test_first_data_node_after_main_relation_removal(harness, consumer):
    harness.remove_relation(consumer["main"].id)

    assert harness.charm.cluster_manager.get_cluster_first_data_node() is None


def test_cm_nodes_after_main_relation_removal(harness, consumer, mocker):
    harness.remove_relation(consumer["main"].id)
    manager = harness.charm.peer_cluster_manager
    mocker.patch.object(type(manager), "opensearch_client", new_callable=mocker.PropertyMock)
    nodes = mocker.patch.object(manager, "_nodes", return_value=[])

    assert manager.cm_nodes(harness.charm.state.application.orchestrators) == []
    nodes.assert_called_once()


def test_fleet_update_skips_missing_remote_app(harness, consumer):
    consumer["main"].app = None
    charm = harness.charm
    original_fleet = charm.state.application.cluster_fleet_apps
    original_data = dict(harness.get_relation_data(consumer["main"].id, charm.app.name))

    charm.peer_cluster_manager.set_current_app_in_cluster_fleet(
        consumer["main"].id, charm.state.application.deployment_desc, is_provider=False
    )

    assert charm.state.application.cluster_fleet_apps == original_fleet
    assert harness.get_relation_data(consumer["main"].id, charm.app.name) == original_data


@pytest.fixture
def provider_departure(harness, mocker):
    harness.disable_hooks()
    harness.set_leader(True)
    harness.set_planned_units(2)
    charm = harness.charm
    charm.state.application.deployment_desc = deployment_descriptions["cm-only"].model_copy(
        deep=True
    )
    relation_id = harness.add_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, "data")
    harness.add_relation_unit(relation_id, "data/0")
    relation = harness.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, relation_id)
    remote_app = PeerClusterApp(
        app=App(model_uuid="model-uuid", name="data"),
        planned_units=1,
        units=["data-0"],
        roles=["data"],
    )
    charm.state.application.cluster_fleet_apps_rels = {str(relation_id): remote_app}
    client_property = mocker.patch.object(
        type(charm.cluster_manager), "opensearch_client", new_callable=mocker.PropertyMock
    )
    client_property.return_value.is_node_up.return_value = True
    event = mocker.Mock(relation=relation, app=relation.app)
    return event, client_property, remote_app


def test_provider_departure_without_local_peer_relation_is_discarded(harness, provider_departure):
    event, client_property, _ = provider_departure
    harness.remove_relation(harness.model.get_relation(PEER_RELATION).id)

    harness.charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_departed(event)

    client_property.assert_not_called()
    event.defer.assert_not_called()


def test_departing_leader_with_peer_relation_still_publishes_fleet(
    harness, provider_departure, mocker
):
    event, _, remote_app = provider_departure
    charm = harness.charm
    mocker.patch.object(
        type(charm.state), "unit_dying", new_callable=mocker.PropertyMock, return_value=True
    )
    assert charm.is_unit_going_away(event)
    other_relation_id = harness.add_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, "other")
    harness.add_relation_unit(other_relation_id, "other/0")

    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_departed(event)

    fleet = charm.state.application.cluster_fleet_apps
    assert fleet[remote_app.app.id] == remote_app
    assert fleet[charm.state.application.deployment_desc.app.id].planned_units == 2
    for relation_id in (event.relation.id, other_relation_id):
        published = json.loads(
            harness.get_relation_data(relation_id, charm.app.name)["cluster_fleet_apps"]
        )
        assert published == {app_id: app.to_dict() for app_id, app in fleet.items()}
    event.defer.assert_not_called()


def test_provider_departure_defers_while_opensearch_is_down(harness, provider_departure):
    event, client_property, _ = provider_departure
    client_property.return_value.is_node_up.return_value = False
    original_fleet = harness.charm.state.application.cluster_fleet_apps

    harness.charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_departed(event)

    event.defer.assert_called_once()
    assert harness.charm.state.application.cluster_fleet_apps == original_fleet


def test_restored_failover_keeps_its_identity_while_waiting(harness, consumer, mocker):
    """A main's stale failover hint must not replace the restored provider's identity."""
    charm = harness.charm
    main, failover = consumer["main"], consumer["failover"]
    original = charm.state.application.orchestrators
    harness.update_relation_data(
        main.id,
        main.app.name,
        {
            "orchestrators": PeerClusterOrchestrators(
                main_app=original.main_app, failover_app=original.main_app
            ).to_str()
        },
    )
    waiting = PeerClusterErrorDataStatuses.WAITING_FOR_PEER_RELATION_CREATED.value
    harness.update_relation_data(
        failover.id,
        failover.app.name,
        {
            "error_data": PeerClusterRelErrorData(
                cluster_name="",
                should_sever_relation=False,
                should_wait=True,
                blocked_message=waiting.message.format(
                    message_suffix="in related 'failover-orchestrator'"
                ),
                deployment_desc=None,
            ).to_str()
        },
    )

    charm.peer_cluster_events._on_peer_cluster_relation_changed(
        mocker.Mock(relation=failover, app=failover.app)
    )

    assert charm.state.application.orchestrators == original
    assert (
        harness.get_relation_data(failover.id, charm.app.name)["main_orchestrator_registered"]
        == "True"
    )
    statuses = charm.peer_cluster_manager.get_statuses("app")
    assert [status.short_message for status in statuses] == [waiting.short_message]


@pytest.mark.parametrize("departure_first", [False, True])
def test_failover_promotion_converges_across_departure_order(
    harness, consumer, mocker, departure_first
):
    """An early announcement is retried without replacing a still-registered main."""
    charm = harness.charm
    main, failover = consumer["main"], consumer["failover"]
    original = charm.state.application.orchestrators
    harness.update_relation_data(
        failover.id,
        failover.app.name,
        {
            "trigger": "main",
            "orchestrators": PeerClusterOrchestrators(main_app=original.failover_app).to_str(),
        },
    )
    changed = mocker.Mock(relation=failover, app=failover.app)
    if not departure_first:
        charm.peer_cluster_events._on_peer_cluster_relation_changed(changed)
        assert charm.state.application.orchestrators == original
        changed.defer.assert_called_once()
        changed.defer.reset_mock()

    harness.remove_relation_unit(main.id, "main/0")
    charm.peer_cluster_events._on_peer_cluster_relation_departed(
        mocker.Mock(relation=main, app=main.app)
    )
    assert charm.state.application.orchestrators.main_app is None

    # A deferred event reads current relation data on its next delivery.
    charm.peer_cluster_events._on_peer_cluster_relation_changed(changed)

    assert charm.state.application.orchestrators == PeerClusterOrchestrators(
        main_app=original.failover_app, main_rel_id=failover.id
    )
    changed.defer.assert_not_called()


@pytest.mark.parametrize("trigger", ["main", "failover"])
def test_unregistered_provider_cannot_replace_an_orchestrator(harness, consumer, mocker, trigger):
    """Retrying a known failover must not permit unrelated provider claims."""
    charm = harness.charm
    original = charm.state.application.orchestrators
    relation_id = harness.add_relation(PEER_CLUSTER_RELATION, "third")
    harness.add_relation_unit(relation_id, "third/0")
    harness.update_relation_data(
        relation_id,
        "third",
        {
            "trigger": trigger,
            "orchestrators": json.dumps(
                {f"{trigger}_app": App(model_uuid="model-uuid", name="third").to_dict()}
            ),
        },
    )
    relation = harness.model.get_relation(PEER_CLUSTER_RELATION, relation_id)
    event = mocker.Mock(relation=relation, app=relation.app)

    charm.peer_cluster_events._on_peer_cluster_relation_changed(event)

    assert charm.state.application.orchestrators == original
    event.defer.assert_not_called()


@pytest.mark.parametrize("provider_departed", [False, True])
def test_promotion_retry_stops_when_announcement_is_withdrawn(
    harness, consumer, mocker, provider_departed
):
    """Deferred events must respect a provider's current role and remaining units."""
    charm = harness.charm
    relation = consumer["failover"]
    original = charm.state.application.orchestrators
    harness.update_relation_data(relation.id, relation.app.name, {"trigger": "main"})
    event = mocker.Mock(relation=relation, app=relation.app)
    charm.peer_cluster_events._on_peer_cluster_relation_changed(event)
    event.defer.assert_called_once()
    event.defer.reset_mock()
    if provider_departed:
        harness.remove_relation_unit(relation.id, "failover/0")
        event.relation = harness.model.get_relation(PEER_CLUSTER_RELATION, relation.id)
    else:
        harness.update_relation_data(relation.id, relation.app.name, {"trigger": "failover"})

    charm.peer_cluster_events._on_peer_cluster_relation_changed(event)

    assert charm.state.application.orchestrators == original
    event.defer.assert_not_called()


@pytest.mark.parametrize("promotion_event", ["departed", "changed"])
@pytest.mark.parametrize(
    "credentials", [None, "plugin", S3_CREDENTIALS, AZURE_CREDENTIALS, GCS_CREDENTIALS]
)
def test_promotion_publishes_main_role_and_tracks_missing_relations(
    harness, mocker, monkeypatch, promotion_event, credentials
):
    """Both promotion paths announce the main deployment type and record missing relations."""
    monkeypatch.setenv("JUJU_VERSION", "3.6.0")
    harness.disable_hooks()
    harness.set_leader(True)
    harness.set_planned_units(1)
    charm = harness.charm
    desc = deployment_descriptions["cm-only"].model_copy(deep=True)
    desc.typ = DeploymentType.FAILOVER_ORCHESTRATOR
    desc.promotion_time = None
    charm.state.application.deployment_desc = desc
    main_id = harness.add_relation(PEER_CLUSTER_RELATION, "main")
    data_id = harness.add_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, "data")
    harness.add_relation_unit(data_id, "data/0")
    harness.update_relation_data(data_id, "data", {"main_orchestrator_registered": "False"})
    charm.state.application.orchestrators = PeerClusterOrchestrators(
        main_app=App(model_uuid="model-uuid", name="main"),
        main_rel_id=main_id,
        failover_app=desc.app,
    )
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(charm.tls_manager, "is_fully_configured", return_value=True)

    # Start with the wrong flag value to check that promotion updates it.
    charm.state.application.missing_relations = credentials is None
    if credentials == "plugin":
        plugin_secret_id = harness.add_model_secret("main", {"password": "smtp-password"})
        charm.plugin_manager.put_plugin_config(
            Scope.APP, "smtp-config", secret_id=plugin_secret_id, relation_name=SMTP_RELATION
        )
    elif credentials:
        charm.state.secrets.put(Scope.APP, credentials, "inherited-backup-credentials")

    if promotion_event == "departed":
        relation = harness.model.get_relation(PEER_CLUSTER_RELATION, main_id)
        handler = charm.peer_cluster_events._on_peer_cluster_relation_departed
    else:
        # This application has already seen the main leave.
        # The data application now reports that it has lost the main too.
        charm.state.application.orchestrators = PeerClusterOrchestrators(failover_app=desc.app)
        relation = harness.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, data_id)
        handler = charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed

    event = mocker.Mock(relation=relation, app=relation.app)
    handler(event)

    assert charm.state.application.deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
    assert charm.state.application.deployment_desc.promotion_time is not None
    assert charm.state.application.orchestrators == PeerClusterOrchestrators(main_app=desc.app)
    published = harness.get_relation_data(data_id, charm.app.name)
    assert published["trigger"] == "main"
    assert json.loads(published["orchestrators"])["main_app"] == desc.app.to_dict()
    assert charm.state.application.missing_relations is (credentials is not None)
    if credentials == "plugin":
        plugin = charm.state.application.plugin_config_info["smtp-config"]
        assert plugin.relation_name == SMTP_RELATION
        assert plugin.secret_id is None
    elif credentials:
        assert charm.state.secrets.get(Scope.APP, credentials) == "inherited-backup-credentials"

    # Retry the relation update until the admin credentials are ready.
    if promotion_event == "changed":
        event.defer.assert_called_once()


def test_unregistered_provider_departure_preserves_orchestrators(harness, consumer, mocker):
    """Removing an unrelated provider must not delete the elected failover or fleet entry."""
    charm = harness.charm
    original = charm.state.application.orchestrators
    fleet = {
        app.id: PeerClusterApp(app=app, planned_units=1, units=[], roles=["cluster_manager"])
        for app in (original.main_app, original.failover_app)
    }
    charm.state.application.cluster_fleet_apps = fleet
    relation_id = harness.add_relation(PEER_CLUSTER_RELATION, "third")
    relation = harness.model.get_relation(PEER_CLUSTER_RELATION, relation_id)

    charm.peer_cluster_events._on_peer_cluster_relation_departed(
        mocker.Mock(relation=relation, app=relation.app)
    )

    assert charm.state.application.orchestrators == original
    assert charm.state.application.cluster_fleet_apps == fleet


def test_demoted_provider_clears_its_previous_main_role(harness, consumer, mocker):
    """A provider's demotion clears its old role until the new main announces itself."""
    charm = harness.charm
    main, failover = consumer["main"], consumer["failover"]
    original = charm.state.application.orchestrators
    charm.state.application.orchestrators = PeerClusterOrchestrators(
        main_app=original.failover_app, main_rel_id=failover.id
    )
    event = mocker.Mock(relation=failover, app=failover.app)

    charm.peer_cluster_events._on_peer_cluster_relation_changed(event)

    assert charm.state.application.orchestrators == PeerClusterOrchestrators(
        failover_app=original.failover_app, failover_rel_id=failover.id
    )
    event.defer.assert_called_once()

    charm.peer_cluster_events._on_peer_cluster_relation_changed(
        mocker.Mock(relation=main, app=main.app)
    )

    assert charm.state.application.orchestrators == original


@pytest.mark.parametrize("provider", ["main", "failover"])
def test_security_conf_set_from_main(harness, consumer, mocker, provider):
    """Security settings come from the main orchestrator's data."""
    charm = harness.charm
    for name, relation in consumer.items():
        harness.update_relation_data(relation.id, relation.app.name, {"data": name})
    mocker.patch.object(charm.peer_cluster_manager, "requirer_errors", return_value=None)
    payloads = {name: mocker.MagicMock() for name in consumer}
    mocker.patch.object(
        PeerClusterRelData,
        "peer_cluster_rel_data_from_str",
        side_effect=lambda _secrets, content, **_: payloads[content],
    )
    set_security_conf = mocker.patch.object(charm.peer_cluster_events, "_set_security_conf")

    relation = consumer[provider]
    charm.peer_cluster_events._on_peer_cluster_relation_changed(
        mocker.Mock(relation=relation, app=relation.app)
    )

    set_security_conf.assert_called_once_with(payloads["main"])


@pytest.mark.parametrize("scope", ["app", "unit"])
@pytest.mark.parametrize("configured", [False, True])
def test_provider_error_remains_visible_with_missing_profile_requirements(
    harness, consumer, scope, configured
):
    charm = harness.charm
    main = consumer["main"]
    waiting = PeerClusterErrorDataStatuses.TLS_NOT_FULLY_CONFIGURED.value
    error = PeerClusterRelErrorData(
        cluster_name="",
        should_sever_relation=False,
        should_wait=True,
        blocked_message=waiting.message.format(message_suffix="in related 'main-orchestrator'"),
        deployment_desc=None,
    )
    harness.update_relation_data(main.id, main.app.name, {"error_data": error.to_str()})
    if not configured:
        charm.state.application.update({"deployment-description": None})
    assert error.get_status() in charm.peer_cluster_manager.get_statuses(scope)
    harness.update_relation_data(main.id, main.app.name, {"error_data": ""})
    assert error.get_status() not in charm.peer_cluster_manager.get_statuses(scope)


def test_profile_warning_and_provider_error_are_collected_together(harness, consumer, mocker):
    charm = harness.charm
    main = consumer["main"]
    waiting = PeerClusterErrorDataStatuses.TLS_NOT_FULLY_CONFIGURED.value
    error = PeerClusterRelErrorData(
        cluster_name="",
        should_sever_relation=False,
        should_wait=True,
        blocked_message=waiting.message.format(message_suffix="in related 'main-orchestrator'"),
        deployment_desc=None,
    )
    harness.update_relation_data(main.id, main.app.name, {"error_data": error.to_str()})
    mocker.patch.object(
        charm.profiles_manager,
        "get_missing_requirements",
        return_value=["At least 1 cluster manager nodes are required."],
    )
    charm.status_handler.components = (charm.profiles_manager, charm.peer_cluster_manager)
    statuses = charm.status_handler._get_sorted_statuses("unit")
    assert {component for component, status in statuses if status.status != "active"} == {
        "profiles_manager",
        "peer_cluster_manager",
    }
    event = mocker.Mock()
    charm.status_handler._on_collect_unit_status(event)
    assert "additional statuses" in event.add_status.call_args.args[0].message


@pytest.mark.parametrize("scope", ["unit", "app"])
def test_unknown_provider_error_does_not_add_an_invalid_status(harness, consumer, scope):
    error = PeerClusterRelErrorData(
        cluster_name="",
        should_sever_relation=False,
        should_wait=True,
        blocked_message="A message from a different charm revision",
        deployment_desc=None,
    )
    relation = consumer["main"]
    harness.update_relation_data(relation.id, relation.app.name, {"error_data": error.to_str()})

    assert None not in harness.charm.peer_cluster_manager.get_statuses(scope)


@pytest.mark.parametrize("main_present", [True, False])
@pytest.mark.parametrize("majority", [True, False])
def test_main_advertisement_distinguishes_bootstrap_from_departure(
    harness, consumer, mocker, main_present, majority
):
    charm = harness.charm
    description = deployment_descriptions["cm-only"].model_copy(deep=True)
    description.typ = DeploymentType.FAILOVER_ORCHESTRATOR
    description.pending_directives = [Directive.VALIDATE_CLUSTER_NAME]
    charm.state.application.deployment_desc = description
    charm.state.application.orchestrators = PeerClusterOrchestrators(failover_app=description.app)
    if not main_present:
        harness.remove_relation(consumer["main"].id)
    promotion = mocker.patch.object(
        charm.peer_cluster_manager, "should_promote_failover_to_main", return_value=majority
    )
    original = charm.state.application.orchestrators

    statuses = charm.peer_cluster_manager.get_statuses("app")

    if main_present:
        assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]
        promotion.assert_not_called()
    else:
        expected = (
            PeerClusterStatuses.PEER_CLUSTER_WAITING_FOR_FAILOVER_PROMOTION
            if majority
            else PeerClusterStatuses.PEER_CLUSTER_MAIN_ORCHESTRATOR_REMOVED_WITHOUT_MAJORITY
        )
        assert expected.value in statuses
    assert charm.state.application.orchestrators == original

    if main_present:
        original.main_app = App(model_uuid="model-uuid", name="main")
        original.main_rel_id = consumer["main"].id
        charm.state.application.orchestrators = original
        assert charm.peer_cluster_manager.get_statuses("app") == [
            GeneralStatuses.ACTIVE_IDLE.value
        ]


@pytest.mark.parametrize("main_has_units", [False, True])
def test_departing_main_and_stale_failover_hint_do_not_hide_departure(
    harness, consumer, mocker, main_has_units
):
    charm = harness.charm
    orchestrators = charm.state.application.orchestrators
    main_app = orchestrators.main_app
    orchestrators.main_app = None
    orchestrators.main_rel_id = -1
    charm.state.application.orchestrators = orchestrators
    main = consumer["main"]
    if main_has_units:
        harness.update_relation_data(main.id, main.app.name, {"orchestrators": "{}"})
    else:
        harness.remove_relation_unit(main.id, f"{main.app.name}/0")
    failover = consumer["failover"]
    harness.update_relation_data(
        failover.id,
        failover.app.name,
        {"orchestrators": json.dumps({"main_app": main_app.to_dict()})},
    )
    mocker.patch.object(
        charm.peer_cluster_manager, "should_promote_failover_to_main", return_value=False
    )

    assert (
        PeerClusterStatuses.PEER_CLUSTER_MAIN_ORCHESTRATOR_REMOVED_WITHOUT_MAJORITY.value
        in charm.peer_cluster_manager.get_statuses("app")
    )


def test_all_orchestrators_removed_status_is_preserved(harness, consumer):
    for relation in consumer.values():
        harness.remove_relation(relation.id)
    harness.charm.state.application.orchestrators = PeerClusterOrchestrators()

    assert PeerClusterStatuses.PEER_CLUSTER_ORCHESTRATORS_REMOVED.value in (
        harness.charm.peer_cluster_manager.get_statuses("app")
    )


def test_waiting_for_peer_relation_does_not_report_main_removed(harness, consumer, mocker):
    charm = harness.charm
    harness.remove_relation(consumer["main"].id)
    description = charm.state.application.deployment_desc
    description.pending_directives = [Directive.WAIT_FOR_PEER_CLUSTER_RELATION]
    charm.state.application.deployment_desc = description
    charm.state.application.orchestrators = PeerClusterOrchestrators(
        failover_app=App(model_uuid="model-uuid", name="failover")
    )
    promotion = mocker.patch.object(charm.peer_cluster_manager, "should_promote_failover_to_main")

    assert charm.peer_cluster_manager.get_statuses("app") == [GeneralStatuses.ACTIVE_IDLE.value]
    promotion.assert_not_called()


@pytest.mark.parametrize(
    "directive", [Directive.VALIDATE_CLUSTER_NAME, Directive.INHERIT_CLUSTER_NAME]
)
def test_provider_still_installing_does_not_report_main_removed(
    harness, consumer, mocker, directive
):
    charm = harness.charm
    description = deployment_descriptions["cm-only"].model_copy(deep=True)
    description.typ = DeploymentType.FAILOVER_ORCHESTRATOR
    description.pending_directives = [directive]
    charm.state.application.deployment_desc = description
    charm.state.application.orchestrators = PeerClusterOrchestrators(failover_app=description.app)
    main = consumer["main"]
    harness.update_relation_data(main.id, main.app.name, {"trigger": "", "orchestrators": ""})
    promotion = mocker.patch.object(
        charm.peer_cluster_manager, "should_promote_failover_to_main", return_value=True
    )

    assert charm.peer_cluster_manager.get_statuses("app") == [GeneralStatuses.ACTIVE_IDLE.value]
    promotion.assert_not_called()

    harness.remove_relation(main.id)

    assert PeerClusterStatuses.PEER_CLUSTER_WAITING_FOR_FAILOVER_PROMOTION.value in (
        charm.peer_cluster_manager.get_statuses("app")
    )


def test_unidentified_provider_does_not_hide_departure_after_setup(harness, consumer, mocker):
    charm = harness.charm
    description = charm.state.application.deployment_desc
    description.pending_directives = []
    charm.state.application.deployment_desc = description
    orchestrators = charm.state.application.orchestrators
    orchestrators.delete("main")
    charm.state.application.orchestrators = orchestrators
    harness.remove_relation(consumer["main"].id)
    replacement = harness.add_relation(PEER_CLUSTER_RELATION, "replacement")
    harness.add_relation_unit(replacement, "replacement/0")
    mocker.patch.object(
        charm.peer_cluster_manager, "should_promote_failover_to_main", return_value=False
    )

    assert (
        PeerClusterStatuses.PEER_CLUSTER_MAIN_ORCHESTRATOR_REMOVED_WITHOUT_MAJORITY.value
        in charm.peer_cluster_manager.get_statuses("app")
    )


@pytest.mark.parametrize(
    "role,registered,promoting",
    [
        ("main", False, False),
        ("failover", False, False),
        ("main", True, False),
        ("failover", True, False),
        ("main", True, True),
    ],
)
def test_provider_status_checks_role_conflicts_without_registering(
    harness, consumer, mocker, role, registered, promoting
):
    charm = harness.charm
    original = charm.state.application.orchestrators
    if not registered:
        original.delete(role)
        charm.state.application.orchestrators = original
    if promoting:
        relation_id = consumer["failover"].id
        app = original.failover_app
    else:
        relation_id = harness.add_relation(PEER_CLUSTER_RELATION, "joining")
        harness.add_relation_unit(relation_id, "joining/0")
        app = App(model_uuid="model-uuid", name="joining")
    harness.update_relation_data(
        relation_id,
        app.name,
        {"trigger": role, "orchestrators": json.dumps({f"{role}_app": app.to_dict()})},
    )
    peer = charm.state.peer_cluster_by_relation_id(False, relation_id, remote=True)
    description = deployment_descriptions["data-only"].model_copy(deep=True)
    description.app = app
    data = PeerClusterRelData(
        cluster_name=charm.state.application.deployment_desc.config.cluster_name,
        cm_nodes=[],
        credentials=PeerClusterRelDataCredentials(
            admin_username="admin",
            admin_password="password",
            admin_password_hash="hash",
            kibana_password="password",
            kibana_password_hash="hash",
            monitor_password=None,
            admin_tls=None,
            s3=None,
            azure=None,
            gcs=None,
        ),
        deployment_desc=description,
    )
    harness.update_relation_data(relation_id, app.name, {"data": data.to_str()})
    mocker.patch.object(charm.state, "peer_clusters", return_value=[peer])
    before = dict(harness.get_relation_data(charm.state.peer_relation.id, charm.app.name))

    statuses = charm.peer_cluster_manager.get_statuses("app", recompute=True)

    conflict = PeerClusterErrorDataStatuses.CLUSTER_CAN_ONLY_HAVE_ONE_MAIN_OR_FAILOVER.value
    assert (conflict in statuses) == (registered and not promoting)
    assert charm.state.application.orchestrators == original
    assert dict(harness.get_relation_data(charm.state.peer_relation.id, charm.app.name)) == before


@pytest.mark.parametrize("provider_waiting", [False, True])
def test_provider_status_priority_preserves_profile_details(
    harness, consumer, mocker, provider_waiting
):
    from opensearch_single_kernel.common.statuses import ProfileStatuses

    charm = harness.charm
    provider = (
        PeerClusterErrorDataStatuses.TLS_NOT_FULLY_CONFIGURED.value
        if provider_waiting
        else PeerClusterErrorDataStatuses.CANNOT_RELATE_TO_CLUSTER_WITH_DIFFERENT_NAME.value
    )
    profile = ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value
    for component in charm.status_handler.components:
        mocker.patch.object(component, "get_statuses", return_value=[])
    charm.peer_cluster_manager.get_statuses.return_value = [provider]
    charm.profiles_manager.get_statuses.return_value = [profile]

    statuses = charm.status_handler._get_sorted_statuses("unit")
    expected = (
        [charm.profiles_manager.name, charm.peer_cluster_manager.name]
        if provider_waiting
        else [charm.peer_cluster_manager.name, charm.profiles_manager.name]
    )
    assert [component for component, _ in statuses] == expected
    event = mocker.Mock()
    charm.status_handler._on_collect_unit_status(event)
    assert "additional statuses" in event.add_status.call_args.args[0].message


def test_provider_wait_precedes_local_tls_wait_without_hiding_it(harness, mocker):
    from opensearch_single_kernel.common.statuses import TlsStatuses

    charm = harness.charm
    provider = PeerClusterErrorDataStatuses.SECURITY_INDEX_NOT_INITIALIZED.value
    tls = TlsStatuses.TLS_NOT_FULLY_CONFIGURED.value
    for component in charm.status_handler.components:
        mocker.patch.object(component, "get_statuses", return_value=[])
    charm.peer_cluster_manager.get_statuses.return_value = [provider]
    charm.tls_manager.get_statuses.return_value = [tls]

    statuses = charm.status_handler._get_sorted_statuses("unit")

    assert statuses == [
        (charm.peer_cluster_manager.name, provider),
        (charm.tls_manager.name, tls),
    ]
    event = mocker.Mock()
    charm.status_handler._on_collect_unit_status(event)
    displayed = event.add_status.call_args.args[0]
    assert displayed.name == "waiting"
    assert displayed.message.startswith("Security index not ready.")
    assert "1 additional statuses" in displayed.message


def test_provider_relation_log_does_not_include_credentials(harness, consumer, mocker, caplog):
    charm = harness.charm
    relation = consumer["main"]
    credentials = {"password": "private-password-marker", "key": "private-key-marker"}
    harness.update_relation_data(relation.id, relation.app.name, {"data": json.dumps(credentials)})
    mocker.patch.object(charm.peer_cluster_manager, "set_current_app_in_cluster_fleet")
    mocker.patch.object(
        charm.peer_cluster_manager,
        "reconcile_orchestrators_from_provider_data",
        return_value=PeerClusterOrchestrators(
            failover_app=App(model_uuid="model-uuid", name="failover")
        ),
    )
    with caplog.at_level("DEBUG"):
        charm.peer_cluster_events._on_peer_cluster_relation_changed(
            mocker.Mock(relation=relation, app=relation.app)
        )
    assert "PeerClusterRelationChanged" in caplog.text
    assert all(value not in caplog.text for value in credentials.values())


@pytest.mark.parametrize("different_cluster", [False, True])
def test_provider_status_validation_does_not_read_secrets(
    harness, consumer, mocker, different_cluster
):
    from ops import ModelError

    charm = harness.charm
    description = deployment_descriptions["cm-only"].model_copy(deep=True)
    description.app = App(model_uuid="model-uuid", name="main")
    cluster_name = charm.state.application.deployment_desc.config.cluster_name
    if different_cluster:
        cluster_name += "-different"
    description.config.cluster_name = cluster_name
    harness.update_relation_data(
        consumer["main"].id,
        "main",
        {
            "data": json.dumps(
                {
                    "cluster_name": cluster_name,
                    "deployment_desc": description.to_dict(),
                    "cm_nodes": [],
                    "credentials": {"admin_password": "secret:unavailable"},
                }
            )
        },
    )
    resolve = mocker.patch.object(
        charm.state.secrets,
        "resolve_credential",
        side_effect=ModelError("Kubernetes secret request timed out"),
    )

    statuses = charm.peer_cluster_manager.get_statuses("app", recompute=True)

    resolve.assert_not_called()
    assert (
        PeerClusterErrorDataStatuses.CANNOT_RELATE_TO_CLUSTER_WITH_DIFFERENT_NAME.value in statuses
    ) == different_cluster
