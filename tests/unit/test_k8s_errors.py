# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes API failures must not bypass upgrade checks or crash unrelated hooks."""

from unittest.mock import MagicMock, PropertyMock

import httpx2
import pytest
from lightkube.core.exceptions import ApiError
from lightkube.models.meta_v1 import Status
from ops import ActionEvent
from ops.testing import ActionFailed

from opensearch_single_kernel.common import exceptions
from opensearch_single_kernel.common.constants import DeploymentType, ObjectStorageType
from opensearch_single_kernel.common.k8s import K8sClient
from opensearch_single_kernel.core.models import ProductionProfile, UpgradeVersions
from opensearch_single_kernel.managers.upgrades_k8s import UpgradesManagerK8s


@pytest.fixture
def api(mocker):
    client = MagicMock()
    mocker.patch.object(K8sClient, "client", new_callable=PropertyMock, return_value=client)
    return client


@pytest.mark.parametrize(
    "failure",
    [
        httpx2.ConnectTimeout("API connection timed out"),
        httpx2.ReadTimeout("API response timed out"),
        httpx2.ConnectError("API connection refused"),
        httpx2.RemoteProtocolError("API disconnected"),
        ApiError(status=Status(code=503, message="Unavailable", reason="ServiceUnavailable")),
        httpx2.HTTPStatusError(
            "Bad gateway",
            request=httpx2.Request("GET", "https://kubernetes.invalid"),
            response=httpx2.Response(502),
        ),
    ],
)
@pytest.mark.parametrize(
    "operation, api_method, args",
    [
        ("get_partition", "get", ()),
        ("get_revision", "get", ()),
        ("set_partition", "patch", (1,)),
        ("list_revisions", "list", ()),
        ("check_if_deployed_without_trust", "create", ()),
    ],
)
def test_api_failures_keep_their_cause(api, failure, operation, api_method, args):
    getattr(api, api_method).side_effect = failure

    with pytest.raises(exceptions.OpenSearchError) as raised:
        getattr(K8sClient("opensearch-0", "testing"), operation)(*args)

    assert type(raised.value).__name__ == "OpenSearchK8sError"
    assert raised.value.__cause__ is failure


def test_pod_list_failure_during_iteration_is_wrapped(api):
    def pods():
        raise httpx2.ReadTimeout("API response timed out")
        yield

    api.list.return_value = pods()
    with pytest.raises(exceptions.OpenSearchError) as raised:
        K8sClient("opensearch-0", "testing").list_revisions()
    assert isinstance(raised.value.__cause__, httpx2.ReadTimeout)


@pytest.mark.parametrize("allowed", [False, True])
def test_permission_review_uses_the_returned_decision(api, allowed):
    api.create.return_value.status.allowed = allowed
    client = K8sClient("opensearch-0", "testing")

    if allowed:
        client.check_if_deployed_without_trust()
    else:
        with pytest.raises(exceptions.OpenSearchK8sDeployedWithoutTrustError):
            client.check_if_deployed_without_trust()


def test_forbidden_permission_review_reports_a_failed_check(api):
    failure = ApiError(status=Status(code=403, message="Forbidden", reason="Forbidden"))
    api.create.side_effect = failure

    with pytest.raises(exceptions.OpenSearchK8sError) as raised:
        K8sClient("opensearch-0", "testing").check_if_deployed_without_trust()

    assert not isinstance(raised.value, exceptions.OpenSearchK8sDeployedWithoutTrustError)
    assert raised.value.__cause__ is failure


@pytest.mark.parametrize(
    "operation, api_method, args",
    [
        ("get_partition", "get", ()),
        ("get_revision", "get", ()),
        ("set_partition", "patch", (1,)),
        ("list_revisions", "list", ()),
    ],
)
def test_forbidden_api_response_preserves_operation_error(api, operation, api_method, args):
    failure = ApiError(status=Status(code=403, message="Forbidden", reason="Forbidden"))
    getattr(api, api_method).side_effect = failure
    with pytest.raises(exceptions.OpenSearchK8sError) as raised:
        getattr(K8sClient("opensearch-0", "testing"), operation)(*args)
    assert not isinstance(raised.value, exceptions.OpenSearchK8sDeployedWithoutTrustError)
    assert raised.value.__cause__ is failure


def test_constructor_does_not_require_kubernetes(api):
    api.get.side_effect = httpx2.ConnectTimeout("API connection timed out")
    manager = UpgradesManagerK8s(MagicMock(), MagicMock())
    assert manager.name == "upgrades_manager"
    api.get.assert_not_called()


@pytest.mark.parametrize("scope", ["unit", "app"])
@pytest.mark.parametrize("code", [503, 403])
@pytest.mark.parametrize("api_method", ["get", "create"])
def test_status_reports_api_failure_and_recovers(api, scope, code, api_method):
    state = MagicMock()
    state.statuses.get.return_value.root = []
    manager = UpgradesManagerK8s(state, MagicMock())
    # Use the real K8sClient and mock its Lightkube calls when checking status.
    manager.state.substrate = "k8s"
    manager.state.pod_name = "opensearch-0"
    manager.state.namespace = "testing"
    api.create.return_value.status.allowed = True
    getattr(api, api_method).side_effect = ApiError(
        status=Status(code=code, message="Unavailable")
    )
    statuses = manager.get_statuses(scope)
    assert any(s.status == "waiting" for s in statuses)
    assert not any(s.status == "active" for s in statuses)
    assert not any(s.status == "blocked" for s in statuses)

    getattr(api, api_method).side_effect = None
    api.list.return_value = []
    assert all(s.status == "active" for s in manager.get_statuses(scope))


@pytest.mark.parametrize("scope", ["unit", "app"])
def test_status_checks_trust_before_other_api_calls_and_recovers(api, scope):
    state = MagicMock()
    state.substrate = "k8s"
    state.pod_name = "opensearch-0"
    state.namespace = "testing"
    state.statuses.get.return_value.root = []
    manager = UpgradesManagerK8s(state, MagicMock())
    api.create.return_value.status.allowed = False
    api.get.side_effect = ApiError(status=Status(code=403, message="Forbidden"))

    statuses = manager.get_statuses(scope)

    assert any(s.status == "blocked" and "juju trust opensearch" in s.message for s in statuses)
    api.get.assert_not_called()
    api.list.assert_not_called()
    api.create.assert_called_once()

    api.create.return_value.status.allowed = True
    api.get.side_effect = None
    api.list.return_value = []

    assert all(s.status == "active" for s in manager.get_statuses(scope))
    assert api.create.call_count == 2


@pytest.fixture
def unavailable_kubernetes(harness, mocker, substrate):
    if substrate != "k8s":
        pytest.skip("Kubernetes API failures")
    mocker.patch.object(
        type(harness.charm.upgrades_manager),
        "in_progress",
        new_callable=PropertyMock,
        side_effect=exceptions.OpenSearchK8sError("Cannot read Kubernetes revisions"),
    )
    return harness.charm


def test_config_change_defers_without_changing_configuration(unavailable_kubernetes, mocker):
    charm = unavailable_kubernetes
    configure = mocker.patch.object(charm.config_manager, "update_opensearch_config")
    event = mocker.Mock()
    charm.opensearch_events._on_config_changed(event)
    event.defer.assert_called_once_with()
    configure.assert_not_called()


def test_client_validation_handles_api_failure(unavailable_kubernetes, mocker):
    event = mocker.Mock()

    valid = unavailable_kubernetes.external_clients_events._validate_client_request(
        event, mocker.Mock()
    )

    assert valid is False
    event.defer.assert_called_once_with()


def test_snapshot_prerequisites_handles_api_failure(
    unavailable_kubernetes, harness, mocker, patch_deployment_desc, caplog
):
    charm = unavailable_kubernetes
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(
        type(charm.state),
        "storage_type",
        new_callable=PropertyMock,
        return_value=ObjectStorageType.S3,
    )

    error = charm.snapshots_events._action_missing_pre_requisites()

    assert error
    assert "Cannot read Kubernetes revisions" in caplog.text


def test_security_reconciliation_handles_api_failure(
    unavailable_kubernetes, harness, mocker, patch_deployment_desc
):
    charm = unavailable_kubernetes
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    reconcile = mocker.patch.object(charm.config_manager, "reconcile_security_config")
    event = mocker.Mock()

    charm.reconcile_security_config(event)

    event.defer.assert_called_once_with()
    reconcile.assert_not_called()


def test_client_removal_still_cleans_up_after_advisory_api_failure(
    unavailable_kubernetes, harness, mocker, patch_deployment_desc
):
    charm = unavailable_kubernetes
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    cleanup = mocker.patch.object(
        charm.external_clients_manager, "remove_lingering_relation_users_and_roles"
    )
    security = mocker.patch.object(charm.config_manager, "reconcile_security_config")
    event = mocker.Mock()

    charm.external_clients_events._on_relation_broken(event)

    cleanup.assert_called_once_with()
    security.assert_not_called()
    event.defer.assert_called_once_with()


@pytest.mark.parametrize(
    "handler, method",
    [
        ("opensearch_events", "_on_peer_relation_created"),
        ("opensearch_events", "_on_peer_relation_joined"),
        ("tls_events", "_on_tls_relation_broken"),
    ],
)
def test_advisory_handlers_do_not_defer_for_api_failure(
    unavailable_kubernetes, mocker, handler, method
):
    event = mocker.Mock()

    getattr(getattr(unavailable_kubernetes, handler), method)(event)

    event.defer.assert_not_called()


def test_kubernetes_upgrade_preparation_handles_api_failure(unavailable_kubernetes, mocker):
    charm = unavailable_kubernetes
    mocker.patch.object(charm.config_manager, "update_opensearch_config")
    restore = mocker.patch.object(charm.snapshots_events, "restore_stored_credentials")
    event = mocker.Mock()

    charm.upgrade_events.kubernetes_upgrade(event)

    event.defer.assert_called_once_with()
    restore.assert_not_called()


@pytest.mark.parametrize("promote", [False, True])
def test_late_api_failure_preserves_config_changes(
    harness, mocker, substrate, patch_deployment_desc, promote
):
    """Complete promotion and request the required restart while security reconciliation retries."""
    if substrate != "k8s":
        pytest.skip("Kubernetes API failures")
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
    upgrade_check = mocker.patch.object(
        type(charm.upgrades_manager),
        "in_progress",
        new_callable=PropertyMock,
        side_effect=[
            False,
            exceptions.OpenSearchK8sError("Cannot read Kubernetes revisions"),
            False,
            False,
        ],
    )
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    reconcile = mocker.patch.object(
        charm.cluster_manager, "reconcile_cluster_config", return_value=False
    )
    admin = mocker.patch.object(charm.internal_users_manager, "put_or_update_internal_user_leader")
    certificate = mocker.patch.object(charm.opensearch_events, "request_new_admin_certificate")
    if promote:
        main = charm.state.application.deployment_desc
        previous = main.model_copy(deep=True)
        previous.typ = DeploymentType.OTHER
        description = [previous]
        mocker.patch.object(
            type(charm.state.application),
            "deployment_desc",
            new_callable=PropertyMock,
            side_effect=lambda: description[0],
        )

        def promote_to_main():
            description[0] = main
            return True

        reconcile.side_effect = promote_to_main
        mocker.patch.object(charm.opensearch_events, "apply_status_from_deployment_desc")
        mocker.patch.object(
            type(charm.state.application),
            "is_admin_user_initialized",
            new_callable=PropertyMock,
            return_value=False,
        )
        mocker.patch.object(charm.tls_manager, "all_tls_resources_stored", return_value=False)
        mocker.patch.object(
            type(charm.state),
            "tls_relation",
            new_callable=PropertyMock,
            return_value=mocker.Mock(),
        )
    mocker.patch.object(
        charm.profiles_manager, "get_config_profile", return_value=ProductionProfile()
    )
    mocker.patch.object(charm.profiles_manager, "check_profile_requirements", return_value=True)
    mocker.patch.object(type(charm.workload), "memtotal", return_value=8 * 1024 * 1024)
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    heap = mocker.patch.object(charm.config_manager, "_update_jvm_heap_size")
    mocker.patch.object(charm.external_clients_manager, "reconcile_role_mappings")
    security = mocker.patch.object(
        charm.config_manager, "reconcile_security_config", return_value=True
    )
    restart = mocker.patch.object(charm.opensearch_events, "_on_restart_opensearch")
    event = mocker.Mock()

    charm.opensearch_events._on_config_changed(event)

    event.defer.assert_called_once_with()
    assert charm.state.server.profile == ProductionProfile()
    heap.assert_called_once()
    security.assert_not_called()
    restart.assert_called_once()
    if promote:
        admin.assert_called_once()
        certificate.assert_called_once_with()

    charm.opensearch_events._on_config_changed(mocker.Mock())

    security.assert_called_once_with(False)
    restart.assert_called_once()
    assert upgrade_check.call_count == 4


def test_resume_action_fails_when_upgrade_state_is_unknown(unavailable_kubernetes, harness):
    with harness.hooks_disabled():
        harness.set_leader(True)
    with pytest.raises(ActionFailed, match="Cannot read Kubernetes revisions"):
        harness.run_action("resume-upgrade")


def test_stop_still_stops_observer_when_api_is_unavailable(unavailable_kubernetes, mocker):
    charm = unavailable_kubernetes
    stop = mocker.patch.object(charm.pebble_observer, "stop")
    event = mocker.Mock()
    charm.opensearch_events._on_stop(event)
    stop.assert_called_once_with()
    event.defer.assert_not_called()


@pytest.mark.parametrize(
    "handler, method",
    [
        ("tls_events", "_on_set_private_key"),
        ("tls_events", "_on_set_password_action"),
        ("snapshots_events", "_on_create_backup_action"),
        ("snapshots_events", "_on_list_backups_action"),
        ("snapshots_events", "_on_restore_action"),
        ("upgrade_events", "_on_pre_upgrade_check_action"),
        ("upgrade_events", "_on_refresh_force_start_action"),
    ],
)
def test_actions_fail_instead_of_treating_unknown_state_as_safe(
    unavailable_kubernetes, harness, mocker, patch_deployment_desc, handler, method, caplog
):
    charm = unavailable_kubernetes
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(
        type(charm.state),
        "storage_type",
        new_callable=PropertyMock,
        return_value=ObjectStorageType.S3,
    )
    event = mocker.Mock(spec=ActionEvent)
    event.params = {}
    getattr(getattr(charm, handler), method)(event)
    event.fail.assert_called_once()
    assert event.fail.call_args.args[0]
    assert "Cannot read Kubernetes revisions" in caplog.text
    event.set_results.assert_not_called()
    event.defer.assert_not_called()


@pytest.mark.parametrize(
    "handler, method",
    [
        ("tls_events", "_on_tls_relation_created"),
        ("opensearch_events", "_on_start"),
        ("opensearch_events", "_on_start_opensearch"),
        ("opensearch_events", "_on_peer_relation_changed"),
        ("ldap_events", "_on_ldap_ready"),
    ],
)
def test_relation_and_start_flows_defer_when_upgrade_state_is_unknown(
    unavailable_kubernetes, harness, mocker, patch_deployment_desc, handler, method
):
    charm = unavailable_kubernetes
    with harness.hooks_disabled():
        harness.set_leader(True)
        # Set the saved versions so upgrade reconciliation reaches the Kubernetes checks.
        charm.state.application_upgrade.versions = UpgradeVersions(charm="1", workload="2.19.5")
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    event = mocker.Mock()
    event.after_upgrade = False
    getattr(getattr(charm, handler), method)(event)
    event.defer.assert_called_once_with()


def test_resume_action_does_not_report_success_after_failed_partition_write(
    harness, mocker, substrate
):
    if substrate != "k8s":
        pytest.skip("Kubernetes partition")
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=True
    )
    mocker.patch.object(charm.upgrades_manager, "_determine_partition", return_value=0)
    mocker.patch.object(K8sClient, "get_partition", return_value=1)
    mocker.patch.object(
        K8sClient,
        "set_partition",
        side_effect=exceptions.OpenSearchK8sError("Partition write failed"),
    )
    with pytest.raises(ActionFailed, match="Partition write failed"):
        harness.run_action("resume-upgrade")


def test_force_refresh_start_reports_request_when_startup_is_deferred(harness, mocker, substrate):
    if substrate != "k8s":
        pytest.skip("Kubernetes startup")
    charm = harness.charm
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=True
    )
    mocker.patch.object(charm.upgrades_manager, "override_version")
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(
        type(charm.cluster_manager),
        "is_opensearch_started",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(
        charm.opensearch_events,
        "_post_start_init",
        side_effect=exceptions.OpenSearchK8sError("Cannot read Kubernetes revisions"),
    )
    result = harness.run_action("force-refresh-start", {"check-compatibility": False})
    assert "Requested startup" in result.results["result"]
    assert "forcefully upgraded" not in result.results["result"]


def test_restart_waits_for_kubernetes_before_stopping_and_recovers(
    harness, mocker, substrate, patch_deployment_desc
):
    """Keep the running node and lock untouched until the restart can check Kubernetes."""
    if substrate != "k8s":
        pytest.skip("Kubernetes restart")
    charm = harness.charm
    revision = mocker.patch.object(
        K8sClient,
        "get_revision",
        side_effect=exceptions.OpenSearchK8sError("Cannot read Kubernetes revisions"),
    )
    acquire = mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    stop = mocker.patch.object(charm, "stop_opensearch")
    start = mocker.patch.object(charm.opensearch_events, "_on_start_opensearch")

    charm.restart_opensearch_event.emit()

    acquire.assert_not_called()
    stop.assert_not_called()
    start.assert_not_called()

    revision.side_effect = None
    revision.return_value = "revision-0"
    harness.framework.reemit()

    acquire.assert_called_once_with()
    stop.assert_called_once_with(restart=True)
    start.assert_called_once()
    assert start.call_args.args[0].after_upgrade is False

    harness.framework.reemit()
    stop.assert_called_once_with(restart=True)


def test_restart_defers_before_stopping_during_rollback(
    harness, mocker, substrate, patch_deployment_desc
):
    """An ordinary restart must respect the rollback guard before stopping the node."""
    if substrate != "k8s":
        pytest.skip("Kubernetes rollback")
    charm = harness.charm
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=True
    )
    acquire = mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    stop = mocker.patch.object(charm, "stop_opensearch")
    start = mocker.patch.object(charm.opensearch_events, "_on_start_opensearch")
    event = mocker.Mock()

    charm.opensearch_events._on_restart_opensearch(event)

    acquire.assert_not_called()
    stop.assert_not_called()
    start.assert_not_called()
    event.defer.assert_called_once_with()


def test_deferred_start_resumes_when_kubernetes_recovers(harness, mocker, substrate):
    """A failed rollback check must leave startup queued for a later event."""
    if substrate != "k8s":
        pytest.skip("Kubernetes startup")
    charm = harness.charm
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(
        type(charm.upgrades_manager),
        "is_rollback",
        new_callable=PropertyMock,
        side_effect=[exceptions.OpenSearchK8sError("Cannot read Kubernetes revisions"), False],
    )
    mocker.patch.object(
        type(charm.cluster_manager),
        "is_opensearch_started",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(type(charm.workload), "is_failed", return_value=False)
    post_start = mocker.patch.object(charm.opensearch_events, "_post_start_init")

    charm.start_opensearch_event.emit(ignore_lock=True, after_upgrade=False)
    post_start.assert_not_called()

    harness.framework.reemit()

    post_start.assert_called_once()
    event = post_start.call_args.args[0]
    assert event.ignore_lock is True
    assert event.after_upgrade is False

    harness.framework.reemit()
    post_start.assert_called_once()


def test_removal_continues_past_optional_upgrade_check(
    unavailable_kubernetes, harness, mocker, patch_deployment_desc
):
    charm = unavailable_kubernetes
    harness.set_planned_units(0)
    flush = mocker.patch.object(charm.cluster_manager, "flush_translog_to_disk")
    stop = mocker.patch.object(charm, "stop_opensearch")
    mocker.patch.object(
        type(charm.cluster_manager), "alt_hosts", new_callable=PropertyMock, return_value=[]
    )
    event = mocker.Mock()
    charm.opensearch_events._on_opensearch_data_storage_detaching(event)
    flush.assert_called_once_with()
    stop.assert_called_once_with()
    event.defer.assert_not_called()


def test_peer_departure_continues_cleanup_when_upgrade_check_fails(
    unavailable_kubernetes, harness, mocker, patch_deployment_desc
):
    charm = unavailable_kubernetes
    with harness.hooks_disabled():
        harness.set_leader(True)
    harness.set_planned_units(0)
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=True
    )
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[])
    endpoints = mocker.patch.object(
        charm.external_clients_manager, "update_all_external_clients_relation_endpoints"
    )
    health = mocker.patch.object(charm, "apply_health")
    topology = mocker.patch.object(charm.cluster_manager, "compute_and_broadcast_updated_topology")
    cleanup = mocker.patch.object(charm.exclusions_manager, "add_to_cleanup_list")
    event = mocker.Mock()
    event.relation.units = {harness.model.get_unit(f"{charm.app.name}/1")}
    event.departing_unit = harness.model.get_unit(f"{charm.app.name}/2")

    charm.opensearch_events._on_peer_relation_departed(event)

    endpoints.assert_called_once_with([])
    health.assert_called_once_with(wait_for_green_first=True, unit=False)
    topology.assert_called_once_with([])
    cleanup.assert_called_once()
    event.defer.assert_not_called()
