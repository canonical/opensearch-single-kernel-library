# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the peer-cluster relation."""

import json
from unittest.mock import MagicMock, PropertyMock

import pytest

from opensearch_single_kernel.common.constants import (
    AZURE_CREDENTIALS,
    GCS_CREDENTIALS,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    S3_CREDENTIALS,
    SMTP_RELATION,
    DeploymentType,
    Scope,
)
from opensearch_single_kernel.common.statuses import PeerClusterErrorDataStatuses
from opensearch_single_kernel.core.models import (
    App,
    PeerClusterApp,
    PeerClusterOrchestrators,
    PeerClusterRelErrorData,
)
from opensearch_single_kernel.core.peer_cluster_relation import PeerCluster
from tests.unit.helpers import deployment_descriptions


def test_peer_cluster_data_when_relation_is_gone():
    relation = MagicMock(data={})
    peer_cluster = PeerCluster(relation, MagicMock(), MagicMock(), MagicMock())

    assert peer_cluster.data() is None


@pytest.mark.parametrize("main_data", [MagicMock(), None], ids=["main", "non-main"])
def test_backup_credentials_updated_from_main(harness, mocker, main_data):
    charm = harness.charm
    mocker.patch.object(charm.peer_cluster_manager, "update_admin_secrets_from_relation")
    mocker.patch.object(charm.tls_manager, "store_new_tls_resources")
    mocker.patch.object(charm.internal_users_manager, "put_internal_user")
    mocker.patch.object(
        type(charm.state), "ca_rotation_complete_in_cluster", new_callable=PropertyMock
    ).return_value = False
    mocker.patch.object(charm.state, "get_rel_data_from_main_orchestrator", return_value=main_data)
    update_credentials = mocker.patch.object(
        charm.snapshots_manager, "update_backup_credentials_from_peer_relation"
    )

    charm.peer_cluster_events._set_security_conf(MagicMock())

    if main_data:
        update_credentials.assert_called_once_with(main_data)
    else:
        update_credentials.assert_not_called()


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
