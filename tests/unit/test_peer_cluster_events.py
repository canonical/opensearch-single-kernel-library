# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for peer-cluster provider and consumer events."""

import json
from unittest.mock import MagicMock, PropertyMock

import pytest
from ops import ModelError, Secret
from ops.framework import BoundEvent
from ops.testing import ActionFailed

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    ADMIN_USER,
    COS_USER,
    KIBANA_SERVER_USER,
    PEER_CLUSTER_ORCHESTRATOR_RELATION,
    PEER_CLUSTER_RELATION,
    S3_RELATION,
    SMTP_RELATION,
    CertType,
    DeploymentType,
    Directive,
    HealthColors,
    PClusterRefreshRelDataRes,
    Scope,
    StartMode,
)
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    PeerClusterApp,
    PeerClusterConfig,
    PeerClusterOrchestrators,
    PeerClusterRelErrorData,
    PluginConfigInfo,
)
from opensearch_single_kernel.utils.secrets import hash_key, password_key


@pytest.fixture
def peer_provider(harness, mocker):
    """Real provider relation, credential storage and publication; no running OpenSearch."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.implements_secrets",
        new_callable=PropertyMock,
        return_value=True,
    )
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
        charm.state.application.deployment_desc = DeploymentDescription(
            app=App(name=charm.app.name, model_uuid=harness.model.uuid),
            config=PeerClusterConfig(cluster_name="cluster", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
        )
        relation_id = harness.add_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, "data")
        harness.add_relation_unit(relation_id, "data/0")
        remote = PeerClusterApp(
            app=App(name="data", model_uuid=harness.model.uuid),
            planned_units=1,
            units=["data/0"],
            roles=["data"],
        )
        harness.update_relation_data(relation_id, "data", {"app": remote.to_str()})
        charm.state.application.is_admin_user_initialized = True
        for user in (ADMIN_USER, KIBANA_SERVER_USER):
            charm.state.secrets.put(Scope.APP, password_key(user), "original-password")
            charm.state.secrets.put(Scope.APP, hash_key(user), "original-hash")
        charm.state.secrets.put_object(
            Scope.APP, CertType.APP_ADMIN.val, {"truststore-password": "existing-password"}
        )
    secrets = charm.state.secrets
    secrets.put_object(Scope.APP, "jwt", {"signing-key": "existing-signing-key"})
    charm.state.application.plugin_config_info = {
        "jwt": PluginConfigInfo(
            secret_id=secrets.get_secret_id(Scope.APP, "jwt"), relation_name="jwt-configuration"
        )
    }
    manager = charm.peer_cluster_orchestrator_manager
    mocker.patch.object(manager, "fetch_current_app_cm_nodes", return_value=[])
    mocker.patch.object(manager, "build_peer_cluster_rel_err_data", return_value=None)
    mocker.patch.object(charm.tls_manager, "is_fully_configured", return_value=False)
    assert manager.refresh_relation_data(relation_id) == PClusterRefreshRelDataRes.COMPLETED
    return charm, harness.model.get_relation(PEER_CLUSTER_ORCHESTRATOR_RELATION, relation_id)


@pytest.mark.parametrize(
    "handler_name",
    [
        "refresh_relation_data",
        "_on_peer_cluster_orchestrator_relation_joined",
        "_on_peer_cluster_orchestrator_relation_changed",
    ],
)
@pytest.mark.parametrize("failure", ["read", "grant", "plugin-grant"])
def test_provider_retries_credentials_without_publishing_incomplete_data(
    peer_provider, harness, mocker, handler_name, failure, caplog
):
    charm, relation = peer_provider
    secrets = charm.state.secrets
    key = password_key(ADMIN_USER)
    label = secrets.label(Scope.APP, key)
    secret_id = secrets.get_secret_id(Scope.APP, key)
    previous_data = relation.data[charm.app]["data"]
    previous_hash = relation.data[charm.app]["rel_data_hash"]
    secrets.put(Scope.APP, key, "updated-password")
    secrets.cached_secrets.delete(Scope.APP, label)
    harness.model.get_secret(id=secret_id).get_content(refresh=True)
    get_secret = harness.model.get_secret
    grant = Secret.grant
    denied_id = secrets.get_secret_id(Scope.APP, "jwt") if failure == "plugin-grant" else secret_id

    def lookup(*args, **kwargs):
        if kwargs.get("label") == label:
            raise ModelError("Juju temporarily unavailable")
        return get_secret(*args, **kwargs)

    def grant_secret(secret, target, **kwargs):
        if secret.id == denied_id:
            raise ModelError("Juju temporarily unavailable")
        return grant(secret, target, **kwargs)

    failed = (
        mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
        if failure == "read"
        else mocker.patch.object(Secret, "grant", grant_secret)
    )
    event = MagicMock(relation=relation, app=relation.app)

    def refresh():
        if handler_name == "refresh_relation_data":
            return charm.peer_cluster_orchestrator_manager.refresh_relation_data(relation.id)
        return getattr(charm.peer_cluster_events, handler_name)(event)

    result = refresh()
    if handler_name == "refresh_relation_data":
        assert result == PClusterRefreshRelDataRes.FAILED
    else:
        event.defer.assert_called_once()
    assert "Juju temporarily unavailable" in caplog.text
    assert relation.data[charm.app]["data"] == previous_data
    assert relation.data[charm.app]["rel_data_hash"] == previous_hash

    mocker.stop(failed)
    event.reset_mock()
    result = refresh()
    if handler_name == "refresh_relation_data":
        assert result == PClusterRefreshRelDataRes.COMPLETED
    event.defer.assert_not_called()
    assert relation.data[charm.app]["rel_data_hash"] != previous_hash
    assert secrets.get_secret_id(Scope.APP, key) == secret_id
    assert relation.app.name in harness.get_secret_grants(secret_id, relation.id)


def test_password_action_reports_incomplete_peer_publication(peer_provider, harness, mocker):
    """A changed password must not be reported as fully synced when a secret grant fails."""
    charm, relation = peer_provider
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    key = password_key(COS_USER)
    charm.state.secrets.put(Scope.APP, key, "old-password")
    previous_data = relation.data[charm.app]["data"]
    mocker.patch.object(OpenSearchClient, "request", return_value={"status": "OK"})
    failed = mocker.patch.object(Secret, "grant", side_effect=ModelError("grant unavailable"))
    params = {"username": COS_USER, "password": "replacement-password"}

    with pytest.raises(ActionFailed, match="peer-cluster"):
        harness.run_action("set-password", params)

    assert charm.state.secrets.get(Scope.APP, key) == "replacement-password"
    assert relation.data[charm.app]["data"] == previous_data

    mocker.stop(failed)
    result = harness.run_action("set-password", params)
    assert result.results[key] == "replacement-password"
    assert relation.data[charm.app]["data"] != previous_data


def test_failover_provider_retries_tls_read_before_promotion(peer_provider, harness, mocker):
    """Failover readiness consumes credentials before normal relation publication."""
    charm, relation = peer_provider
    desc = charm.state.application.deployment_desc
    desc.typ = DeploymentType.FAILOVER_ORCHESTRATOR
    charm.state.application.deployment_desc = desc
    mocker.stop(charm.tls_manager.is_fully_configured)
    secrets = charm.state.secrets
    label = secrets.label(Scope.APP, CertType.APP_ADMIN.val)
    secrets.cached_secrets.delete(Scope.APP, label)
    promote = mocker.patch.object(charm.cluster_manager, "promote_deployment_type")
    get_secret = harness.model.get_secret

    def lookup(*args, **kwargs):
        if kwargs.get("label") == label:
            raise ModelError("Juju temporarily unavailable")
        return get_secret(*args, **kwargs)

    failed = mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
    event = MagicMock(relation=relation, app=relation.app)
    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)
    event.defer.assert_called_once()
    promote.assert_not_called()
    mocker.stop(failed)
    event.reset_mock()
    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)
    event.defer.assert_not_called()


def test_consumer_retries_unreadable_provider_credentials(harness, mocker):
    """A consumer waits for a grant instead of treating an unreadable credential as absent."""
    charm = harness.charm
    provider_app = App(name="main", model_uuid=harness.model.uuid)
    with harness.hooks_disabled():
        harness.set_leader(True)
        desc = DeploymentDescription(
            app=App(name=charm.app.name, model_uuid=harness.model.uuid),
            config=PeerClusterConfig(cluster_name="cluster", init_hold=True, roles=["data"]),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[],
            typ=DeploymentType.OTHER,
        )
        charm.state.application.deployment_desc = desc
        rel_id = harness.add_relation(PEER_CLUSTER_RELATION, "main")
        harness.add_relation_unit(rel_id, "main/0")
        secret_id = harness.add_model_secret("main", {"admin-password": "provider-password"})
        harness.grant_secret(secret_id, charm.app)
        data = {
            "cluster_name": "cluster",
            "cm_nodes": [],
            "security_index_initialised": True,
            "deployment_desc": None,
            "credentials": {
                "admin_username": "admin",
                "admin_password": secret_id.replace("secret:", "secret://"),
                "admin_password_hash": "admin-hash",
                "kibana_password": "kibana-password",
                "kibana_password_hash": "kibana-hash",
                "monitor_password": None,
                "admin_tls": {"truststore-password": "existing-password"},
                "s3": None,
                "azure": None,
                "gcs": None,
            },
        }
        harness.update_relation_data(
            rel_id,
            "main",
            {
                "data": json.dumps(data),
                "trigger": "main",
                "orchestrators": PeerClusterOrchestrators(
                    main_app=provider_app, main_rel_id=rel_id
                ).to_str(),
            },
        )
    relation = harness.model.get_relation(PEER_CLUSTER_RELATION, rel_id)
    event = MagicMock(relation=relation, app=relation.app)
    # Workload writes happen only after credentials have been resolved.
    configure = mocker.patch.object(charm.peer_cluster_events, "_set_security_conf")
    mocker.patch.object(charm.tls_manager, "peer_cluster_error_from_tls", return_value=None)
    mocker.patch.object(
        charm.peer_cluster_events, "_reconcile_deployment_desc_from_peer_cluster_data"
    )
    get_secret = harness.model.get_secret

    def lookup(*args, **kwargs):
        if kwargs.get("id") == secret_id.replace("secret:", "secret://"):
            raise ModelError("ERROR permission denied")
        return get_secret(*args, **kwargs)

    failed = mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
    charm.peer_cluster_events._on_peer_cluster_relation_changed(event)
    event.defer.assert_called_once()
    configure.assert_not_called()
    assert not charm.state.application.is_security_index_initialised

    mocker.stop(failed)
    event.reset_mock()
    charm.peer_cluster_events._on_peer_cluster_relation_changed(event)
    event.defer.assert_not_called()
    configure.assert_called_once()
    assert configure.call_args.args[0].credentials.admin_password == "provider-password"
    assert charm.state.application.is_security_index_initialised


@pytest.mark.parametrize("waiting_for_relation", [False, True])
def test_provider_readiness_wait_preserves_joining_node_progress(
    peer_provider, mocker, waiting_for_relation
):
    """Process joining data nodes while waiting for the cluster, unless the relation is missing."""
    charm, relation = peer_provider
    if waiting_for_relation:
        desc = charm.state.application.deployment_desc
        desc.pending_directives = [Directive.WAIT_FOR_PEER_CLUSTER_RELATION]
        charm.state.application.deployment_desc = desc
    charm.peer_cluster_orchestrator_manager.build_peer_cluster_rel_err_data.return_value = (
        PeerClusterRelErrorData(
            cluster_name="cluster",
            should_sever_relation=False,
            should_wait=True,
            blocked_message="Waiting for cluster readiness",
            deployment_desc=None,
        )
    )
    charm.tls_manager.is_fully_configured.return_value = True
    joining = mocker.patch.object(charm.peer_cluster_events, "handle_joining_data_node")
    event = MagicMock(relation=relation, app=relation.app)

    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)

    error_data = json.loads(relation.data[charm.app]["error_data"])
    assert error_data["should_wait"] is True
    if waiting_for_relation:
        event.defer.assert_not_called()
        joining.assert_not_called()
    else:
        event.defer.assert_called()
        joining.assert_called_once()
        assert charm.state.application.cluster_fleet_apps


def test_promoted_provider_does_not_try_to_grant_previous_main_plugin_secrets(
    peer_provider, harness
):
    """Both promotion paths must drop plugin IDs owned by the previous main orchestrator."""
    charm, relation = peer_provider
    desc = charm.state.application.deployment_desc
    desc.typ = DeploymentType.FAILOVER_ORCHESTRATOR
    charm.state.application.deployment_desc = desc
    charm.state.application.orchestrators = PeerClusterOrchestrators(
        failover_app=desc.app, failover_rel_id=relation.id
    )
    with harness.hooks_disabled():
        harness.update_relation_data(
            relation.id, relation.app.name, {"main_orchestrator_registered": "false"}
        )
    with harness.hooks_disabled():
        harness.add_relation(PEER_CLUSTER_RELATION, "previous-main")
    secret_id = harness.add_model_secret("previous-main", {"signing-key": "existing-key"})
    harness.grant_secret(secret_id, charm.app)
    charm.state.application.plugin_config_info = {
        "jwt": PluginConfigInfo(secret_id=secret_id, relation_name="jwt-configuration")
    }
    charm.tls_manager.is_fully_configured.return_value = True
    event = MagicMock(relation=relation, app=relation.app)

    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)

    event.defer.assert_not_called()
    assert charm.state.application.deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
    assert charm.state.application.plugin_config_info["jwt"].secret_id is None
    assert charm.state.application.missing_relations
    assert json.loads(relation.data[charm.app]["data"])["plugins"] == {}


@pytest.mark.parametrize("failure", ["read", "grant", "waiting"])
def test_peer_change_stops_on_publication_failure_before_counting_contributors(
    peer_provider, harness, mocker, failure
):
    """Failed publication must not reread secrets or count a contributor on every retry."""
    charm, _ = peer_provider
    peer = charm.state.peer_relation
    with harness.hooks_disabled():
        harness.update_relation_data(peer.id, charm.unit.name, {"bootstrap_contributor": "true"})
    mocker.patch.object(charm.upgrade_events, "_reconcile_upgrade")
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(OpenSearchClient, "is_node_up", return_value=True)
    mocker.patch.object(charm, "apply_health", return_value=HealthColors.GREEN)
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[])
    mocker.patch.object(
        charm.external_clients_manager, "update_all_external_clients_relation_endpoints"
    )
    mocker.patch.object(charm.cluster_manager, "compute_and_broadcast_updated_topology")
    mocker.patch.object(charm.config_manager, "update_seeds_config", return_value=True)
    mocker.patch.object(charm.exclusions_manager, "cleanup")
    secrets = charm.state.secrets
    if failure == "read":
        label = secrets.label(Scope.APP, password_key(ADMIN_USER))
        secrets.cached_secrets.delete(Scope.APP, label)
        get_secret = harness.model.get_secret

        def lookup(*args, **kwargs):
            if kwargs.get("label") == label:
                raise ModelError("admin secret unavailable")
            return get_secret(*args, **kwargs)

        failed = mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
    elif failure == "grant":
        failed = mocker.patch.object(Secret, "grant", side_effect=ModelError("grant unavailable"))
    else:
        charm.peer_cluster_orchestrator_manager.build_peer_cluster_rel_err_data.return_value = (
            PeerClusterRelErrorData(
                cluster_name="cluster",
                should_sever_relation=False,
                should_wait=True,
                blocked_message="Waiting for cluster readiness",
                deployment_desc=None,
            )
        )
    event = MagicMock(relation=peer, app=charm.app, unit=charm.unit)

    if failure == "waiting":
        charm.opensearch_events._on_peer_relation_changed(event)
        assert charm.state.application.bootstrap_contributors_count == 1
        event.defer.assert_not_called()
        return

    for _ in range(2):
        charm.opensearch_events._on_peer_relation_changed(event)
        assert charm.state.application.bootstrap_contributors_count == 0
    assert event.defer.call_count == 2

    mocker.stop(failed)
    event.reset_mock()
    charm.opensearch_events._on_peer_relation_changed(event)
    assert charm.state.application.bootstrap_contributors_count == 1
    event.defer.assert_not_called()


@pytest.mark.parametrize("waiting_for_relation", [False, True])
def test_provider_publication_failure_stops_startup_and_failover_registration(
    peer_provider, harness, mocker, waiting_for_relation
):
    """A failed grant must defer even while waiting, without advancing provider state."""
    charm, relation = peer_provider
    with harness.hooks_disabled():
        harness.update_relation_data(
            relation.id, relation.app.name, {"is_candidate_failover_orchestrator": "true"}
        )
    if waiting_for_relation:
        desc = charm.state.application.deployment_desc
        desc.pending_directives = [Directive.WAIT_FOR_PEER_CLUSTER_RELATION]
        charm.state.application.deployment_desc = desc
    charm.tls_manager.is_fully_configured.return_value = True
    mocker.patch.object(charm.profiles_manager, "check_profile_requirements", return_value=True)
    mocker.patch.object(type(charm.workload), "memtotal", return_value=8 * 1024**3)
    mocker.patch.object(charm.config_manager, "_update_jvm_heap_size")
    # Observe start requests without executing the workload lifecycle.
    emit = mocker.patch.object(BoundEvent, "emit")
    previous_data = relation.data[charm.app]["data"]
    mocker.patch.object(Secret, "grant", side_effect=ModelError("grant unavailable"))
    event = MagicMock(relation=relation, app=relation.app)

    charm.peer_cluster_events._on_peer_cluster_orchestrator_relation_changed(event)

    event.defer.assert_called_once()
    emit.assert_not_called()
    assert charm.state.application.orchestrators.failover_app is None
    assert not json.loads(relation.data[charm.app]["orchestrators"]).get("failover_app")
    assert relation.data[charm.app]["data"] == previous_data


def test_password_action_succeeds_when_credentials_publish_but_cluster_is_waiting(
    peer_provider, harness, mocker
):
    """Cluster readiness must not turn a successful password publication into an action failure."""
    charm, relation = peer_provider
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(OpenSearchClient, "request", return_value={"status": "OK"})
    charm.peer_cluster_orchestrator_manager.build_peer_cluster_rel_err_data.return_value = (
        PeerClusterRelErrorData(
            cluster_name="cluster",
            should_sever_relation=False,
            should_wait=True,
            blocked_message="Waiting for cluster readiness",
            deployment_desc=None,
        )
    )
    previous_hash = relation.data[charm.app]["rel_data_hash"]
    charm.state.secrets.put(Scope.APP, password_key(COS_USER), "previous-password")

    result = harness.run_action("set-password", {"username": COS_USER, "password": "replacement"})

    key = password_key(COS_USER)
    assert result.results[key] == "replacement"
    secret_id = charm.state.secrets.get_secret_id(Scope.APP, key)
    assert relation.app.name in harness.get_secret_grants(secret_id, relation.id)
    assert relation.data[charm.app]["rel_data_hash"] != previous_hash


@pytest.mark.parametrize("has_smtp_account", [False, True])
def test_smtp_cleanup_retries_failed_publication(peer_provider, harness, mocker, has_smtp_account):
    """Retry removing SMTP data from peer relations after a failed update."""
    charm, peer_relation = peer_provider
    with harness.hooks_disabled():
        rel_id = harness.add_relation(SMTP_RELATION, "smtp")
    relation = harness.model.get_relation(SMTP_RELATION, rel_id)
    label = charm.notifications_manager.label(rel_id)
    charm.plugin_manager.put_plugin_config(
        Scope.UNIT,
        label,
        cleanup={"smtp_account_id": ["account"]} if has_smtp_account else None,
    )
    charm.plugin_manager.store_plugin_secret(
        content={"keys": {"smtp-password": "password"}},
        label=label,
        relation_name=SMTP_RELATION,
    )
    charm.peer_cluster_orchestrator_manager.refresh_relation_data()
    assert label in json.loads(peer_relation.data[charm.app]["data"])["plugins"]
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(OpenSearchClient, "delete_notification_config")
    failed = mocker.patch.object(Secret, "grant", side_effect=ModelError("grant unavailable"))
    event = MagicMock(relation=relation)

    charm.notifications_events._on_smtp_credentials_gone(event)

    event.defer.assert_called_once()
    assert label in json.loads(peer_relation.data[charm.app]["data"])["plugins"]
    mocker.stop(failed)
    event.reset_mock()
    charm.notifications_events._on_smtp_credentials_gone(event)

    event.defer.assert_not_called()
    assert label not in json.loads(peer_relation.data[charm.app]["data"])["plugins"]
    assert label not in charm.state.server.plugin_config_info
    assert label not in charm.state.application.plugin_config_info


@pytest.mark.parametrize("failure", ["grant", "read"])
def test_snapshot_cleanup_reloads_keystore_despite_publication_failure(
    peer_provider, harness, mocker, failure
):
    """A failed grant must not leave removed storage credentials loaded in OpenSearch."""
    charm, _ = peer_provider
    with harness.hooks_disabled():
        rel_id = harness.add_relation(S3_RELATION, "s3")
    relation = harness.model.get_relation(S3_RELATION, rel_id)
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(charm.snapshots_manager, "remove_repository", return_value=True)
    mocker.patch.object(charm.snapshots_manager, "is_custom_s3_ca_stored", return_value=False)
    credentials = {"disk": True, "loaded": True}

    def cleanup(_):
        credentials["disk"] = False
        return True

    def reload_settings(*args, **kwargs):
        credentials["loaded"] = credentials["disk"]
        return True

    mocker.patch.object(charm.keystore_manager, "cleanup_storage_credentials", side_effect=cleanup)
    mocker.patch.object(charm.keystore_manager, "_create_if_needed")
    mocker.patch.object(type(charm.workload), "run_cmd")
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(OpenSearchClient, "reload_secure_settings", side_effect=reload_settings)
    publish = mocker.spy(charm.peer_cluster_orchestrator_manager, "refresh_relation_data")
    reload_event = mocker.spy(charm.keystore_events, "_on_reload")
    if failure == "grant":
        failed = mocker.patch.object(Secret, "grant", side_effect=ModelError("grant unavailable"))
    else:
        label = charm.state.secrets.label(Scope.APP, password_key(ADMIN_USER))
        charm.state.secrets.cached_secrets.delete(Scope.APP, label)
        get_secret = harness.model.get_secret

        def lookup(*args, **kwargs):
            if kwargs.get("label") == label:
                raise ModelError("admin secret unavailable")
            return get_secret(*args, **kwargs)

        failed = mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
    event = MagicMock(relation=relation)

    charm.snapshots_events._on_snapshots_credentials_gone(event)

    event.defer.assert_called_once()
    publish.assert_called_once()
    assert credentials == {"disk": False, "loaded": failure == "read"}
    assert reload_event.call_args.args[0].deferred == (failure == "read")
    mocker.stop(failed)
    if failure == "read":
        # The deferred reload can finish independently of the storage cleanup event.
        charm.keystore_events._on_reload(MagicMock())
    assert credentials == {"disk": False, "loaded": False}
    event.reset_mock()
    charm.snapshots_events._on_snapshots_credentials_gone(event)
    event.defer.assert_not_called()


def test_keystore_reload_retries_unreadable_admin_secret(peer_provider, harness, mocker):
    """Retry the keystore reload when the admin password becomes readable."""
    charm, _ = peer_provider
    mocker.patch.object(charm.keystore_manager, "_create_if_needed")
    mocker.patch.object(type(charm.workload), "run_cmd")
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    reloaded = mocker.patch.object(OpenSearchClient, "reload_secure_settings", return_value=True)
    secrets = charm.state.secrets
    label = secrets.label(Scope.APP, password_key(ADMIN_USER))
    secrets.cached_secrets.delete(Scope.APP, label)
    get_secret = harness.model.get_secret

    def lookup(*args, **kwargs):
        if kwargs.get("label") == label:
            raise ModelError("admin secret unavailable")
        return get_secret(*args, **kwargs)

    failed = mocker.patch.object(harness.model, "get_secret", side_effect=lookup)
    event = MagicMock()

    charm.keystore_events._on_reload(event)

    event.defer.assert_called_once()
    reloaded.assert_not_called()
    mocker.stop(failed)
    event.reset_mock()
    charm.keystore_events._on_reload(event)
    event.defer.assert_not_called()
    reloaded.assert_called_once()
