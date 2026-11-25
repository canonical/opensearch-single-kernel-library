# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for upgrade manager statuses."""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest
from ops import ActiveStatus, BlockedStatus, MaintenanceStatus

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    STATUS_PEERS_RELATION,
    UPGRADE_RELATION,
    HealthColors,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchHAError,
    OpenSearchHttpError,
    OpenSearchStartError,
    OpenSearchStartTimeoutError,
    OpenSearchStopError,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    HealthStatuses,
    LockStatuses,
    UpgradesStatuses,
)
from opensearch_single_kernel.core.models import UnitUpgradesState
from opensearch_single_kernel.managers.upgrades_base import UpgradesManagerBase
from opensearch_single_kernel.managers.upgrades_k8s import UpgradesManagerK8s
from opensearch_single_kernel.managers.upgrades_vm import UpgradesManagerVM
from opensearch_single_kernel.utils.status import format_status, unit_operation


class _UpgradesManager(UpgradesManagerBase):
    """Minimal concrete upgrades manager for unit tests."""

    def __init__(self, state, workload, unit_status=None, unit_params=None, app_status=None):
        # Skip base __init__ reconcile of compatibility matrix.
        self.state = state
        self.workload = workload
        self.name = "upgrades_manager"
        self._unit_status = unit_status
        self._unit_params = unit_params
        self._app_status = app_status

    @property
    def in_progress(self) -> bool:
        return bool(self._app_status)

    @property
    def unit_status(self):
        return self._unit_status, self._unit_params

    @property
    def app_status(self):
        return self._app_status

    @property
    def unit_state(self):
        return None

    @property
    def upgrade_resumed(self):
        return False

    def reconcile_partition(self, *, action_event=None, force=False) -> None:
        return None

    def save_upgrades_versions(self) -> None:
        return None

    @property
    def _unit_workload_container_versions(self) -> dict[str, str]:
        return {}

    @property
    def _app_workload_container_version(self) -> str:
        return ""


def test_upgrades_unit_status_merged_with_running():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    mgr = _UpgradesManager(
        state,
        MagicMock(),
        unit_status=UpgradesStatuses.UPGRADES_UPGRADING.value,
        unit_params=None,
    )

    statuses = mgr.get_statuses("unit")

    assert UpgradesStatuses.UPGRADES_UPGRADING.value in statuses


@pytest.fixture
def upgrade_status_managers(harness, mocker, patch_deployment_desc):
    charm = harness.charm
    charm.state.server.started = "previous-start"
    with harness.hooks_disabled():
        harness.add_relation(STATUS_PEERS_RELATION, charm.app.name)
        harness.update_relation_data(
            charm.state.upgrade_relation.id,
            charm.app.name,
            {"versions": '{"charm": "1", "workload": "2.19.5"}'},
        )
    mocker.patch.object(
        type(charm.state.application),
        "is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=True,
    )
    manager = _UpgradesManager(
        charm.state,
        charm.cluster_manager.workload,
        unit_status=UpgradesStatuses.K8S_UPGRADES_ACTIVE.value,
        unit_params={"workload_version": "2.19.6", "charm_version": "1"},
    )
    charm.status_handler.components = (manager, charm.cluster_manager)
    # the start applies the profile, which writes jvm.options
    mocker.patch.object(charm.profiles_manager, "write_jvm_heap_size", return_value=True)
    return charm


@pytest.mark.parametrize(
    "service_started,reachable", [(False, False), (True, False), (True, True)]
)
def test_upgrade_status_waits_for_the_service_to_accept_connections(
    upgrade_status_managers, mocker, service_started, reachable
):
    charm = upgrade_status_managers
    mocker.patch.object(
        charm.cluster_manager.workload, "is_service_started", return_value=service_started
    )
    mocker.patch.object(charm.cluster_manager.workload, "is_reachable", return_value=reachable)
    event = mocker.Mock()

    charm.status_handler._on_collect_unit_status(event)

    status = event.add_status.call_args.args[0]
    assert status.name == ("active" if service_started and reachable else "waiting")
    if not (service_started and reachable):
        assert "start" not in status.message.lower()
        assert "additional statuses" not in status.message


def test_upgrade_does_not_hide_a_failed_start(upgrade_status_managers, mocker):
    charm = upgrade_status_managers
    mocker.patch.object(charm.cluster_manager.workload, "is_service_started", return_value=False)
    charm.state.add_status_if_not_present(
        GeneralStatuses.SERVICE_START_ERROR.value, "unit", charm.cluster_manager.name
    )
    event = mocker.Mock()

    charm.status_handler._on_collect_unit_status(event)

    status = event.add_status.call_args.args[0]
    assert status.name == "blocked"
    assert status.message == GeneralStatuses.SERVICE_START_ERROR.value.message
    assert GeneralStatuses.SERVICE_UNAVAILABLE.value not in charm.cluster_manager.get_statuses(
        "unit"
    )


@pytest.mark.parametrize("error", [OpenSearchStartError, OpenSearchStartTimeoutError])
@pytest.mark.parametrize("after_upgrade", [False, True])
def test_start_failure_replaces_waiting_and_survives_status_recompute(
    upgrade_status_managers, mocker, error, after_upgrade
):
    charm = upgrade_status_managers
    if after_upgrade:
        charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(charm.state, "is_peer_cluster_consumer", return_value=False)
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=False)
    mocker.patch.object(
        type(charm.cluster_manager),
        "is_opensearch_started",
        new_callable=PropertyMock,
        return_value=False,
    )
    mocker.patch.object(charm.workload, "is_service_started", return_value=False)
    mocker.patch.object(charm.workload, "is_failed", return_value=False)
    mocker.patch.object(charm.profiles_manager, "check_profile_requirements", return_value=True)
    allowed = mocker.patch.object(
        charm.opensearch_events, "unit_allowed_to_start", return_value=True
    )
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    release = mocker.patch.object(charm.lock_manager, "release")
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[])
    mocker.patch.object(charm.state, "computed_roles", return_value=[])
    mocker.patch.object(charm.cluster_manager, "configure_bootstrap_contributors")
    mocker.patch.object(charm.config_manager, "update_opensearch_config")

    def failed_start(**kwargs):
        assert charm.unit.status.message == GeneralStatuses.WAITING_TO_START.value.message
        raise error("Start failed in this test")

    start = mocker.patch.object(charm.cluster_manager, "start", side_effect=failed_start)
    event = mocker.Mock(ignore_lock=False, after_upgrade=after_upgrade)

    charm.opensearch_events._on_start_opensearch(event)

    start.assert_called_once()
    release.assert_called_once()
    event.defer.assert_called_once()
    assert GeneralStatuses.WAITING_TO_START.value not in charm.cluster_manager.get_statuses("unit")
    for retry in (False, True):
        if retry:
            allowed.return_value = False
            charm.opensearch_events._on_start_opensearch(event)
        charm.status_handler._recompute_statuses()
        collect = mocker.Mock()
        charm.status_handler._on_collect_unit_status(collect)
        status = collect.add_status.call_args.args[0]
        assert status.name == "blocked"
        assert status.message == GeneralStatuses.SERVICE_START_ERROR.value.message


def test_initialised_cluster_reports_stopped_workload(harness, mocker, patch_deployment_desc):
    charm = harness.charm
    charm.state.server.started = "previous-start"
    mocker.patch.object(
        type(charm.state.application),
        "is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=True,
    )
    service = mocker.patch.object(
        charm.cluster_manager.workload, "is_service_started", return_value=False
    )
    reachable = mocker.patch.object(
        charm.cluster_manager.workload, "is_reachable", return_value=False
    )

    assert GeneralStatuses.SERVICE_UNAVAILABLE.value in charm.cluster_manager.get_statuses("unit")

    service.return_value = True
    assert GeneralStatuses.SERVICE_UNAVAILABLE.value in charm.cluster_manager.get_statuses("unit")
    reachable.return_value = True
    assert GeneralStatuses.SERVICE_UNAVAILABLE.value not in charm.cluster_manager.get_statuses(
        "unit"
    )


@pytest.mark.parametrize("tls_configured", [False, True])
def test_recompute_preserves_initial_start_wait_after_tls_configuration(
    upgrade_status_managers, mocker, tls_configured
):
    charm = upgrade_status_managers
    del charm.state.server.started
    charm.state.server.start_pending = True
    mocker.patch.object(
        type(charm.state.application),
        "is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=False,
    )
    charm.state.server.tls_configured = tls_configured
    mocker.patch.object(charm.cluster_manager.workload, "is_service_started", return_value=False)
    charm.state.add_status_if_not_present(
        GeneralStatuses.WAITING_TO_START.value, "unit", charm.cluster_manager.name
    )

    charm.status_handler._recompute_statuses()
    collect = mocker.Mock()
    charm.status_handler._on_collect_unit_status(collect)

    assert collect.add_status.call_args.args[0].name == ("waiting" if tls_configured else "active")
    assert (
        GeneralStatuses.WAITING_TO_START.value.message
        in [status.message for status in charm.cluster_manager.get_statuses("unit")]
    ) == tls_configured
    assert GeneralStatuses.SERVICE_UNAVAILABLE.value not in charm.cluster_manager.get_statuses(
        "unit"
    )


@pytest.mark.parametrize(
    "service_started,reachable", [(False, False), (True, False), (True, True)]
)
def test_initial_start_waits_for_this_unit_even_after_the_cluster_is_initialized(
    upgrade_status_managers, mocker, service_started, reachable
):
    charm = upgrade_status_managers
    del charm.state.server.started
    charm.state.server.start_pending = True
    mocker.patch.object(
        type(charm.state.server), "tls_configured", new_callable=PropertyMock, return_value=True
    )
    mocker.patch.object(
        charm.cluster_manager.workload, "is_service_started", return_value=service_started
    )
    mocker.patch.object(charm.cluster_manager.workload, "is_reachable", return_value=reachable)

    statuses = charm.cluster_manager.get_statuses("unit")

    assert GeneralStatuses.WAITING_TO_START.value.message in [s.message for s in statuses]
    assert GeneralStatuses.SERVICE_UNAVAILABLE.value not in statuses


def test_initial_start_status_clears_without_hiding_later_failure(upgrade_status_managers, mocker):
    charm = upgrade_status_managers
    del charm.state.server.started
    charm.state.server.start_pending = True
    mocker.patch.object(
        type(charm.state.server), "tls_configured", new_callable=PropertyMock, return_value=True
    )
    service = mocker.patch.object(
        charm.cluster_manager.workload, "is_service_started", return_value=True
    )
    mocker.patch.object(charm.cluster_manager.workload, "is_reachable", return_value=True)
    collect = mocker.Mock()

    charm.status_handler._recompute_statuses()
    charm.status_handler._on_collect_unit_status(collect)
    assert (
        collect.add_status.call_args.args[0].message
        == GeneralStatuses.WAITING_TO_START.value.message
    )

    charm.state.server.started = "completed-start"
    charm.state.server.start_pending = False
    charm.status_handler._on_collect_unit_status(collect)
    assert collect.add_status.call_args.args[0].name == "active"

    service.return_value = False
    charm.status_handler._on_collect_unit_status(collect)
    assert (
        collect.add_status.call_args.args[0].message
        == GeneralStatuses.SERVICE_UNAVAILABLE.value.message
    )

    charm.state.server.start_failed = True
    charm.status_handler._on_collect_unit_status(collect)
    assert (
        collect.add_status.call_args.args[0].message
        == GeneralStatuses.SERVICE_START_ERROR.value.message
    )
    charm.status_handler._recompute_statuses()
    charm.status_handler._on_collect_unit_status(collect)
    assert (
        collect.add_status.call_args.args[0].message
        == GeneralStatuses.SERVICE_START_ERROR.value.message
    )


@pytest.mark.parametrize("stop_fails", [False, True])
def test_stopping_replaces_upgrade_version_before_waiting(
    upgrade_status_managers, mocker, stop_fails
):
    charm = upgrade_status_managers
    service = mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    reachable = mocker.patch.object(type(charm.workload), "is_reachable", return_value=True)
    mocker.patch.object(OpenSearchClient, "is_node_up", return_value=False)
    mocker.patch.object(charm.cluster_manager, "get_nodes", return_value=[])
    mocker.patch.object(charm.cluster_manager, "can_restart_node", return_value=True)
    charm.unit.status = ActiveStatus("OpenSearch old version running")

    def wait_for_shards():
        assert charm.unit.status.name == "waiting"
        assert charm.unit.status.message == "The OpenSearch service is stopping."
        if stop_fails:
            raise OpenSearchHAError("Shards are still moving")

    def stop_workload():
        service.return_value = False
        reachable.return_value = False

    mocker.patch.object(
        charm.health_manager, "wait_for_shards_relocation", side_effect=wait_for_shards
    )
    mocker.patch.object(charm.cluster_manager, "stop_workload", side_effect=stop_workload)
    if stop_fails:
        with pytest.raises(OpenSearchStopError):
            charm.stop_opensearch(restart=True)
    else:
        charm.stop_opensearch(restart=True)
        assert charm.unit.status.name == "waiting"
        assert "not running" in charm.unit.status.message
    assert not charm.state.unit_operation_in_progress


@pytest.mark.parametrize("state", [UnitUpgradesState.UPGRADING, UnitUpgradesState.RESTARTING])
def test_reachable_unit_does_not_hide_pending_upgrade_readiness(
    upgrade_status_managers, mocker, state
):
    charm = upgrade_status_managers
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(type(charm.workload), "is_reachable", return_value=True)
    charm.state.server_upgrade.unit_state = state
    charm.state.statuses.add(
        GeneralStatuses.WAITING_TO_START.value, "unit", charm.cluster_manager.name
    )

    event = mocker.Mock()
    charm.status_handler._on_collect_unit_status(event)
    status = event.add_status.call_args.args[0]
    assert status.name == "waiting"
    assert status.message == "Waiting for OpenSearch to start..."

    charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    charm.state.statuses.delete(
        GeneralStatuses.WAITING_TO_START.value, "unit", charm.cluster_manager.name
    )
    charm.status_handler._on_collect_unit_status(event)
    assert event.add_status.call_args.args[0].name == "active"


def test_reachable_unit_does_not_hide_a_failed_start(upgrade_status_managers, mocker):
    charm = upgrade_status_managers
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(type(charm.workload), "is_reachable", return_value=True)
    charm.state.statuses.add(
        GeneralStatuses.SERVICE_START_ERROR.value, "unit", charm.cluster_manager.name
    )
    event = mocker.Mock()

    charm.status_handler._on_collect_unit_status(event)

    assert event.add_status.call_args.args[0].name == "blocked"


def test_operation_preserves_critical_upgrade_failure(upgrade_status_managers, mocker):
    charm = upgrade_status_managers
    manager = charm.status_handler.components[0]
    manager._unit_status = UpgradesStatuses.UPGRADES_ROLLBACK_UNSUPPORTED.value
    manager._unit_params = None
    event = mocker.Mock()
    with unit_operation(charm.state):
        with unit_operation(charm.state):
            charm.status_handler._on_collect_unit_status(event)
            assert event.add_status.call_args.args[0].name == "blocked"
        assert charm.state.unit_operation_in_progress
    assert not charm.state.unit_operation_in_progress


def test_startup_can_publish_progress_while_process_is_reachable(upgrade_status_managers, mocker):
    charm = upgrade_status_managers
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(type(charm.workload), "is_reachable", return_value=True)
    mocker.patch.object(type(charm.workload), "is_failed", return_value=False)
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(charm.state, "is_peer_cluster_consumer", return_value=False)
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=False)
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    charm.unit.status = ActiveStatus("OpenSearch old version running")

    def post_start(event):
        assert charm.unit.status.name == "waiting"
        assert charm.unit.status.message == "Waiting for OpenSearch to start..."

    mocker.patch.object(charm.opensearch_events, "_post_start_init", side_effect=post_start)
    charm.opensearch_events._on_start_opensearch(mocker.Mock(after_upgrade=False))
    assert not charm.state.unit_operation_in_progress


@pytest.mark.parametrize("leader", [False, True])
def test_vm_install_publishes_progress_before_blocking(harness, mocker, substrate, leader):
    if substrate != "vm":
        pytest.skip("Snap installation is specific to machines")
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(leader)
        harness.add_relation(STATUS_PEERS_RELATION, charm.app.name)
        harness.update_relation_data(
            charm.state.upgrade_relation.id,
            charm.app.name,
            {"versions": '{"charm": "1", "workload": "2.19.5"}'},
        )
    charm.status_handler.components = (charm.upgrades_manager,)
    mocker.patch.object(
        type(charm.upgrades_manager),
        "unit_status",
        new_callable=PropertyMock,
        return_value=(
            UpgradesStatuses.UPGRADES_ACTIVE_OUTDATED.value,
            {"workload_version": "2.18.0", "snap_revision": "66", "charm_version": "1"},
        ),
    )
    mocker.patch.object(
        type(charm.upgrades_manager),
        "app_status",
        new_callable=PropertyMock,
        return_value=UpgradesStatuses.UPGRADES_UPGRADING.value,
    )
    mocker.patch.object(
        type(charm.upgrades_manager),
        "is_rollback",
        new_callable=PropertyMock,
        return_value=False,
    )
    mocker.patch.object(
        type(charm.upgrades_manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=SimpleNamespace(workload="2.19.6"),
    )
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    mocker.patch.object(OpenSearchClient, "disable_shard_allocation")
    mocker.patch.object(OpenSearchClient, "flush_translog")
    mocker.patch.object(charm, "stop_opensearch")

    mocker.patch.object(charm.opensearch_events, "_on_start_opensearch")
    charm.unit.status = ActiveStatus("OpenSearch old version running")
    if leader:
        charm.app.status = ActiveStatus("Previously healthy")

    def install():
        assert charm.unit.status.name == "maintenance"
        assert charm.unit.status.message == "Installing OpenSearch..."
        assert charm.state.server_upgrade.unit_state == UnitUpgradesState.UPGRADING
        if leader:
            assert charm.app.status.name == "maintenance"
            assert charm.app.status.message == "Upgrading."

    mocker.patch.object(type(charm.workload), "install", side_effect=install)
    charm.upgrade_events._upgrade_opensearch(
        mocker.Mock(ignore_lock=False, override_version=False)
    )


def test_vm_resume_keeps_the_existing_action_and_relation_flow(harness, mocker, substrate):
    if substrate != "vm":
        pytest.skip("Machine upgrade action")
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
        relation = harness.model.get_relation(UPGRADE_RELATION)
        harness.add_relation_unit(relation.id, f"{charm.app.name}/1")
        harness.update_relation_data(
            relation.id, f"{charm.app.name}/1", {"state": "healthy", "snap_revision": "new"}
        )
    mocker.patch.object(
        type(charm.upgrades_manager), "in_progress", new_callable=PropertyMock, return_value=True
    )
    mocker.patch(
        "opensearch_single_kernel.managers.upgrades_vm.pinned_snap_revision", return_value="new"
    )

    result = harness.run_action("resume-upgrade")

    assert result.results["result"] == "Upgrade resumed."
    assert charm.state.application_upgrade.upgrade_resumed is True
    assert charm.state.application_upgrade.resume_request is None


def test_upgrades_app_incompatible():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    mgr = _UpgradesManager(
        state,
        MagicMock(),
        app_status=UpgradesStatuses.UPGRADES_INCOMPATIBLE.value,
    )

    statuses = mgr.get_statuses("app")

    assert UpgradesStatuses.UPGRADES_INCOMPATIBLE.value in statuses


def test_upgrades_merges_cached_precheck_failed():
    cached = format_status(
        UpgradesStatuses.UPGRADES_PRE_UPGRADE_CHECK_FAILED.value,
        {"message": "Cluster health is yellow"},
    )
    state = MagicMock()
    state.statuses.get.side_effect = lambda *a, **k: SimpleNamespace(
        root=[] if k.get("running_status_only") else [cached]
    )
    mgr = _UpgradesManager(state, MagicMock())

    statuses = mgr.get_statuses("unit")

    assert cached in statuses


@pytest.mark.parametrize(
    "manager_class,substrate,partition,resumed,expected",
    [
        (
            UpgradesManagerK8s,
            Substrates.K8S,
            2,
            True,
            UpgradesStatuses.UPGRADES_WAITING_FOR_RESUME,
        ),
        (UpgradesManagerK8s, Substrates.K8S, 1, False, UpgradesStatuses.UPGRADES_UPGRADING),
        (UpgradesManagerK8s, Substrates.K8S, 0, False, UpgradesStatuses.UPGRADES_UPGRADING),
        (
            UpgradesManagerVM,
            Substrates.VM,
            None,
            False,
            UpgradesStatuses.UPGRADES_WAITING_FOR_RESUME,
        ),
        (UpgradesManagerVM, Substrates.VM, None, True, UpgradesStatuses.UPGRADES_UPGRADING),
    ],
)
def test_app_upgrade_resume_status(mocker, manager_class, substrate, partition, resumed, expected):
    """K8s status follows its partition; VM status follows the stored resume flag."""
    manager = manager_class.__new__(manager_class)
    manager.state = MagicMock()
    manager.state.substrate = substrate
    manager.state.application_upgrade.upgrade_resumed = resumed
    manager.state.application_upgrade.resume_request = None
    manager.state.upgrade_membership_complete = True
    manager.state.sorted_upgrades_units = [
        SimpleNamespace(
            unit_number=i,
            unit=SimpleNamespace(name=f"opensearch/{i}"),
            unit_state=UnitUpgradesState.HEALTHY,
            unit_state_revision="new",
        )
        for i in (2, 1, 0)
    ]
    mocker.patch.object(
        manager_class,
        "_app_workload_container_version",
        new_callable=PropertyMock,
        return_value="new",
    )
    mocker.patch.object(
        manager_class,
        "_unit_workload_container_versions",
        new_callable=PropertyMock,
        return_value={"opensearch/2": "new", "opensearch/1": "old", "opensearch/0": "old"},
    )
    mocker.patch.object(manager_class, "in_progress", new_callable=PropertyMock, return_value=True)
    mocker.patch.object(
        manager_class, "is_compatible", new_callable=PropertyMock, return_value=True
    )
    k8s_client = MagicMock()
    k8s_client.get_partition.return_value = partition
    mocker.patch.object(
        manager_class, "k8s_client", new_callable=PropertyMock, return_value=k8s_client
    )

    assert manager.app_status == expected.value


@pytest.mark.parametrize("manager_class", [UpgradesManagerK8s, UpgradesManagerVM])
@pytest.mark.parametrize(
    "healthy_revision,current_revision,expected",
    [
        ("old", "new", UpgradesStatuses.UPGRADES_UPGRADING.value),
        ("new", "new", None),
        (None, "new", None),
        ("old", None, None),
    ],
)
def test_app_waits_for_health_checks_on_the_final_revision(
    mocker, manager_class, healthy_revision, current_revision, expected
):
    manager = manager_class.__new__(manager_class)
    manager.state = MagicMock()
    manager.state.sorted_upgrades_units = [
        SimpleNamespace(
            unit=SimpleNamespace(name="opensearch/0"),
            unit_state_revision=healthy_revision,
            unit_state=UnitUpgradesState.HEALTHY,
        )
    ]
    mocker.patch.object(
        manager_class, "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(
        manager_class,
        "_unit_workload_container_versions",
        new_callable=PropertyMock,
        return_value={"opensearch/0": current_revision} if current_revision else {},
    )

    assert manager.app_status == expected


@pytest.mark.parametrize(
    "health,expected",
    [
        (
            HealthColors.RED,
            "1 or more 'primary' shards are not assigned in the cluster. Fix unhealthy units",
        ),
        (HealthColors.YELLOW_TEMP, HealthStatuses.WAITING_FOR_BUSY_SHARDS.value.message),
        (HealthColors.UNKNOWN, UpgradesStatuses.UPGRADES_UNHEALTHY.value.message),
    ],
)
def test_upgrade_health_failure_remains_visible_until_recovery(
    upgrade_status_managers, health, expected
):
    charm = upgrade_status_managers
    manager = charm.status_handler.components[0]
    charm.state.server_upgrade.unit_state = UnitUpgradesState.UPGRADING
    manager.record_upgrade_health(health)
    assert expected in [status.message for status in manager.get_statuses("unit")]
    charm.status_handler._recompute_statuses_for_scope("unit", manager)
    assert expected in [status.message for status in manager.get_statuses("unit")]
    manager.record_upgrade_health(HealthColors.GREEN)
    assert expected not in [status.message for status in manager.get_statuses("unit")]
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.UPGRADING


def test_restart_waiting_for_lock_does_not_report_running(upgrade_status_managers, mocker):
    charm = upgrade_status_managers
    charm.status_handler.components += (charm.lock_manager,)
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(type(charm.workload), "is_reachable", return_value=True)
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(charm.lock_manager, "acquire", return_value=False)
    stop = mocker.patch.object(charm, "stop_opensearch")
    charm.unit.status = ActiveStatus("Old version running")
    event = mocker.Mock()

    charm.opensearch_events._on_restart_opensearch(event)

    event.defer.assert_called_once()
    stop.assert_not_called()
    assert charm.unit.status.message == "Requesting lock on operation: start"
    collect = mocker.Mock()
    charm.status_handler._on_collect_unit_status(collect)
    assert collect.add_status.call_args.args[0].name == "waiting"


@pytest.mark.parametrize("state", [UnitUpgradesState.UPGRADING, UnitUpgradesState.RESTARTING])
def test_recompute_cannot_mark_pending_upgrade_ready(upgrade_status_managers, mocker, state):
    charm = upgrade_status_managers
    mocker.patch.object(type(charm.workload), "is_service_started", return_value=True)
    mocker.patch.object(type(charm.workload), "is_reachable", return_value=True)
    charm.state.server_upgrade.unit_state = state
    charm.status_handler._recompute_statuses()
    collect = mocker.Mock()
    charm.status_handler._on_collect_unit_status(collect)
    assert collect.add_status.call_args.args[0].name == "waiting"
    charm.state.server_upgrade.unit_state = UnitUpgradesState.HEALTHY
    charm.status_handler._on_collect_unit_status(collect)
    assert collect.add_status.call_args.args[0].name == "active"


@pytest.mark.parametrize("state", [UnitUpgradesState.UPGRADING, UnitUpgradesState.RESTARTING])
def test_pending_upgrade_has_one_startup_message_after_recompute(
    upgrade_status_managers, mocker, state
):
    charm = upgrade_status_managers
    charm.state.server_upgrade.unit_state = state
    mocker.patch.object(charm.workload, "is_service_started", return_value=False)

    charm.status_handler._recompute_statuses()
    collect = mocker.Mock()
    charm.status_handler._on_collect_unit_status(collect)

    assert collect.add_status.call_args.args[0].message == (
        GeneralStatuses.WAITING_TO_START.value.message
    )
    assert GeneralStatuses.SERVICE_UNAVAILABLE.value not in charm.cluster_manager.get_statuses(
        "unit"
    )


def test_unavailable_service_is_reported_before_upgrade_versions_are_known(
    upgrade_status_managers, harness, mocker
):
    charm = upgrade_status_managers
    charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
    with harness.hooks_disabled():
        harness.update_relation_data(
            charm.state.upgrade_relation.id, charm.app.name, {"versions": ""}
        )
    mocker.patch.object(charm.workload, "is_service_started", return_value=False)

    charm.status_handler._recompute_statuses()
    collect = mocker.Mock()
    charm.status_handler._on_collect_unit_status(collect)

    assert collect.add_status.call_args.args[0].message == (
        GeneralStatuses.SERVICE_UNAVAILABLE.value.message
    )


@pytest.mark.parametrize("start_failed", [False, True])
def test_pre_start_health_check_reports_the_check_and_preserves_start_failure(
    upgrade_status_managers, mocker, start_failed
):
    charm = upgrade_status_managers
    charm.state.server.start_failed = start_failed
    charm.unit.status = (
        BlockedStatus(GeneralStatuses.SERVICE_START_ERROR.value.message)
        if start_failed
        else MaintenanceStatus(GeneralStatuses.INSTALL_IN_PROGRESS.value.message)
    )

    def health_check(**kwargs):
        assert charm.unit.status.message == (
            GeneralStatuses.SERVICE_START_ERROR.value.message
            if start_failed
            else "Checking cluster health before starting OpenSearch."
        )
        return HealthColors.YELLOW_TEMP

    mocker.patch.object(charm, "apply_health", side_effect=health_check)
    with unit_operation(charm.state):
        assert not charm.opensearch_events.is_cluster_healthy_to_start()


@pytest.mark.parametrize("state", [None, UnitUpgradesState.RESTARTING])
def test_start_waiting_for_lock_reports_lock_request(upgrade_status_managers, mocker, state):
    charm = upgrade_status_managers
    charm.status_handler.components += (charm.lock_manager,)
    if state:
        charm.state.server_upgrade.unit_state = state
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(charm.state, "is_peer_cluster_consumer", return_value=False)
    mocker.patch.object(
        type(charm.cluster_manager),
        "is_opensearch_started",
        new_callable=PropertyMock,
        return_value=False,
    )
    mocker.patch.object(charm.profiles_manager, "check_profile_requirements", return_value=True)
    mocker.patch.object(charm.opensearch_events, "unit_allowed_to_start", return_value=True)
    mocker.patch.object(charm.lock_manager, "acquire", return_value=False)
    start = mocker.patch.object(charm.cluster_manager, "start")
    event = mocker.Mock(ignore_lock=False, after_upgrade=bool(state))

    charm.opensearch_events._on_start_opensearch(event)

    event.defer.assert_called_once()
    start.assert_not_called()
    assert charm.unit.status.message == LockStatuses.REQUEST_LOCK_ON_START.value.message
    collect = mocker.Mock()
    charm.status_handler._on_collect_unit_status(collect)
    assert collect.add_status.call_args.args[0].name == "waiting"
    statuses = [
        status
        for manager in charm.status_handler.components
        for status in manager.get_statuses("unit")
    ]
    assert LockStatuses.REQUEST_LOCK_ON_START.value in statuses
    assert GeneralStatuses.WAITING_TO_START.value.message not in [
        status.message for status in statuses
    ]


def test_final_start_updates_app_before_waiting_for_unit_health(
    upgrade_status_managers, harness, mocker
):
    charm = upgrade_status_managers
    with harness.hooks_disabled():
        harness.set_leader(True)
    manager = charm.status_handler.components[0]
    manager._app_status = UpgradesStatuses.UPGRADES_UPGRADING.value
    mocker.patch.object(charm.upgrades_manager, "get_statuses", return_value=[manager._app_status])
    charm.app.status = BlockedStatus(UpgradesStatuses.UPGRADES_WAITING_FOR_RESUME.value.message)

    def starting(event):
        assert charm.app.status.message == UpgradesStatuses.UPGRADES_UPGRADING.value.message

    mocker.patch.object(charm.opensearch_events, "_start_opensearch", side_effect=starting)
    charm.opensearch_events._on_start_opensearch(mocker.Mock())


@pytest.mark.parametrize("manager_class", [UpgradesManagerK8s, UpgradesManagerVM])
@pytest.mark.parametrize(
    "state,installed_revision,healthy_revision,complete,expected",
    [
        (UnitUpgradesState.HEALTHY, "old", "old", True, UpgradesStatuses.UPGRADES_UPGRADING),
        (UnitUpgradesState.RESTARTING, "new", "old", True, UpgradesStatuses.UPGRADES_UPGRADING),
        (UnitUpgradesState.UPGRADING, "new", "old", True, UpgradesStatuses.UPGRADES_UPGRADING),
        (UnitUpgradesState.HEALTHY, "new", "old", True, UpgradesStatuses.UPGRADES_UPGRADING),
        (UnitUpgradesState.HEALTHY, "new", None, True, UpgradesStatuses.UPGRADES_UPGRADING),
        (UnitUpgradesState.HEALTHY, "new", "new", False, UpgradesStatuses.UPGRADES_UPGRADING),
        (
            UnitUpgradesState.HEALTHY,
            "new",
            "new",
            True,
            UpgradesStatuses.UPGRADES_WAITING_FOR_RESUME,
        ),
    ],
)
def test_resume_instruction_waits_for_first_unit_health(
    mocker, manager_class, state, installed_revision, healthy_revision, complete, expected
):
    manager = manager_class.__new__(manager_class)
    manager.state = MagicMock()
    manager.state.upgrade_membership_complete = complete
    manager.state.application_upgrade.resume_request = None
    manager.state.sorted_upgrades_units = [
        SimpleNamespace(
            unit=SimpleNamespace(name="opensearch/2"),
            unit_state=state,
            unit_state_revision=healthy_revision,
            post_upgrade_health=None,
        ),
        SimpleNamespace(
            unit=SimpleNamespace(name="opensearch/1"), unit_state=UnitUpgradesState.HEALTHY
        ),
    ]
    for name, value in {
        "in_progress": True,
        "is_compatible": True,
        "upgrade_resumed": False,
        "_app_workload_container_version": "new",
        "_unit_workload_container_versions": {"opensearch/2": installed_revision},
    }.items():
        mocker.patch.object(manager_class, name, new_callable=PropertyMock, return_value=value)

    assert manager.app_status == expected.value


@pytest.mark.parametrize("manager_class", [UpgradesManagerK8s, UpgradesManagerVM])
@pytest.mark.parametrize("in_progress", [False, True])
@pytest.mark.parametrize(
    "health",
    [HealthColors.RED, HealthColors.UNKNOWN, HealthColors.IGNORE, HealthColors.YELLOW_TEMP],
)
def test_app_keeps_upgrade_progress_until_validation_succeeds(
    mocker, manager_class, in_progress, health
):
    manager = manager_class.__new__(manager_class)
    manager.state = MagicMock()
    manager.state.application_upgrade.resume_request = None
    unit = SimpleNamespace(
        unit=SimpleNamespace(name="opensearch/0"),
        unit_state=UnitUpgradesState.RESTARTING,
        unit_state_revision="old",
        post_upgrade_health=health,
    )
    manager.state.sorted_upgrades_units = [unit]
    for name, value in {
        "in_progress": in_progress,
        "is_compatible": True,
        "upgrade_resumed": True,
        "_unit_workload_container_versions": {"opensearch/0": "new"},
    }.items():
        mocker.patch.object(manager_class, name, new_callable=PropertyMock, return_value=value)

    assert manager.app_status == UpgradesStatuses.UPGRADES_UPGRADING.value
    unit.post_upgrade_health = None
    assert manager.app_status == UpgradesStatuses.UPGRADES_UPGRADING.value
    unit.unit_state = UnitUpgradesState.HEALTHY
    unit.unit_state_revision = "new"
    assert manager.app_status == (
        UpgradesStatuses.UPGRADES_UPGRADING.value if in_progress else None
    )


@pytest.mark.parametrize(
    "guidance",
    [
        UpgradesStatuses.UPGRADES_ROLLBACK_INCOMPATIBLE,
        UpgradesStatuses.UPGRADES_ROLLBACK_UNSUPPORTED,
    ],
)
def test_rollback_guidance_precedes_previous_health_failure(
    upgrade_status_managers, mocker, guidance
):
    charm = upgrade_status_managers
    manager = charm.status_handler.components[0]
    manager._unit_status = guidance.value
    manager._unit_params = None
    charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
    charm.state.server_upgrade.post_upgrade_health = HealthColors.RED
    event = mocker.Mock()

    charm.status_handler._on_collect_unit_status(event)

    assert event.add_status.call_args.args[0].message == guidance.value.message


@pytest.mark.parametrize(
    "guidance",
    [
        UpgradesStatuses.UPGRADES_ROLLBACK_INCOMPATIBLE,
        UpgradesStatuses.UPGRADES_ROLLBACK_UNSUPPORTED,
        UpgradesStatuses.UPGRADES_INCOMPATIBLE,
    ],
)
@pytest.mark.parametrize("health", [None, HealthColors.RED])
def test_blocked_upgrade_does_not_report_startup_progress(
    upgrade_status_managers, guidance, health
):
    charm = upgrade_status_managers
    manager = charm.status_handler.components[0]
    manager._unit_status = guidance.value
    manager._unit_params = None
    charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
    charm.state.server_upgrade.post_upgrade_health = health

    assert manager.get_statuses("unit") == [guidance.value]


@pytest.mark.parametrize("stop_fails", [False, True])
def test_vm_override_restarts_validation_only_after_stopping(
    harness, mocker, substrate, stop_fails
):
    if substrate != "vm":
        pytest.skip("Machine rollback recovery")
    charm = harness.charm
    charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
    charm.state.server_upgrade.post_upgrade_health = HealthColors.RED
    mocker.patch.object(charm.upgrade_events, "_publish_app_upgrade_status")
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    mocker.patch.object(charm.lock_manager, "release")
    mocker.patch.object(OpenSearchClient, "disable_shard_allocation")
    mocker.patch.object(OpenSearchClient, "flush_translog")
    mocker.patch.object(
        charm, "stop_opensearch", side_effect=OpenSearchStopError() if stop_fails else None
    )
    mocker.patch.object(
        type(charm.upgrades_manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=SimpleNamespace(workload="2.19.4"),
    )
    override = mocker.patch.object(charm.upgrades_manager, "override_version")
    start = mocker.patch.object(charm.opensearch_events, "_on_start_opensearch")
    event = mocker.Mock(ignore_lock=False, override_version=True)

    charm.upgrade_events._upgrade_opensearch(event)

    if stop_fails:
        override.assert_not_called()
        start.assert_not_called()
        assert charm.state.server_upgrade.post_upgrade_health == HealthColors.RED
        event.defer.assert_called_once()
    else:
        override.assert_called_once()
        start.assert_called_once()
        assert start.call_args.args[0].after_upgrade
        assert not start.call_args.args[0].ignore_lock
        assert charm.state.server_upgrade.unit_state == UnitUpgradesState.UPGRADING
        assert charm.state.server_upgrade.post_upgrade_health is None


def test_vm_rollback_can_prepare_cluster_while_local_node_is_stopped(harness, mocker, substrate):
    if substrate != "vm":
        pytest.skip("Machine rollback recovery")
    charm = harness.charm
    charm.state.server_upgrade.snap_revision = "193"
    charm.state.server_upgrade.workload_version = "2.19.6"
    mocker.patch.object(charm.upgrade_events, "_publish_app_upgrade_status")
    mocker.patch.object(charm.lock_manager, "acquire", return_value=True)
    mocker.patch.object(charm.lock_manager, "release")
    mocker.patch.object(charm, "stop_opensearch")
    mocker.patch.object(
        type(charm.cluster_manager),
        "alt_hosts",
        new_callable=PropertyMock,
        return_value=["10.0.0.2", "10.0.0.3"],
    )

    def request(method, endpoint, **kwargs):
        if not kwargs.get("alt_hosts"):
            raise OpenSearchHttpError(response_text="Local node is stopped")
        assert endpoint in ("/_cluster/settings", "/_flush/synced")
        return {}

    mocker.patch.object(OpenSearchClient, "request", side_effect=request)
    mocker.patch.object(charm.upgrades_manager, "override_version")
    mocker.patch.object(
        type(charm.upgrades_manager),
        "current_versions",
        new_callable=PropertyMock,
        return_value=SimpleNamespace(workload="2.19.5"),
    )
    mocker.patch(
        "opensearch_single_kernel.events.upgrades.pinned_snap_revision", return_value="114"
    )
    start = mocker.patch.object(charm.opensearch_events, "_on_start_opensearch")
    event = mocker.Mock(ignore_lock=False, override_version=True)

    charm.upgrade_events._upgrade_opensearch(event)

    assert charm.state.server_upgrade.snap_revision == "114"
    assert charm.state.server_upgrade.workload_version == "2.19.5"
    assert start.call_args.args[0].after_upgrade
    event.defer.assert_not_called()


@pytest.mark.parametrize("stream", ["out", "err"])
@pytest.mark.parametrize(
    "output,expected_version",
    [
        ("This data was last written by OpenSearch version [2.19.6]", "2.19.6"),
        ("The versions are compatible, so there is no need to override the version checks", None),
    ],
)
def test_rollback_version_check_reads_both_command_streams(
    harness, mocker, substrate, stream, output, expected_version
):
    manager = harness.charm.upgrades_manager
    mocker.patch.object(manager.workload, "is_service_started", return_value=False)
    mocker.patch.object(
        manager.workload,
        "run_cmd" if substrate == "vm" else "run_script",
        side_effect=OpenSearchCmdError(cmd="override-version", **{stream: output}),
    )

    version = manager.get_version_before_override()

    assert (str(version) if version is not None else None) == expected_version


def test_red_upgrade_health_is_reported_on_unit_while_app_keeps_progress(
    upgrade_status_managers, mocker
):
    charm = upgrade_status_managers
    manager = charm.status_handler.components[0]
    manager._app_status = UpgradesStatuses.UPGRADES_UPGRADING.value
    charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
    manager.record_upgrade_health(HealthColors.RED)
    mocker.patch.object(charm.cluster_manager.workload, "is_service_started", return_value=True)
    mocker.patch.object(
        type(charm.cluster_manager),
        "is_opensearch_started",
        new_callable=PropertyMock,
        return_value=True,
    )
    unit_event = mocker.Mock()
    app_event = mocker.Mock()

    charm.status_handler._on_collect_unit_status(unit_event)
    charm.status_handler._on_collect_app_status(app_event)

    assert unit_event.add_status.call_args.args[0] == BlockedStatus(
        "Post-upgrade checks failed. Check logs. Consider rollback to the previous revision "
        "with `juju refresh` if needed."
    )
    assert HealthStatuses.CLUSTER_HEALTH_RED_UPGRADE.value in manager.get_statuses("unit")
    assert len(unit_event.add_status.call_args.args[0].message) <= 120
    assert app_event.add_status.call_args.args[0] == MaintenanceStatus("Upgrading.")
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING


@pytest.mark.parametrize(
    "health", [HealthColors.RED, HealthColors.UNKNOWN, HealthColors.YELLOW_TEMP]
)
def test_retry_of_post_upgrade_checks_preserves_failure_status(
    upgrade_status_managers, mocker, health
):
    charm = upgrade_status_managers
    manager = charm.status_handler.components[0]
    charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
    manager.record_upgrade_health(health)
    mocker.patch.object(charm, "is_unit_going_away", return_value=False)
    mocker.patch.object(charm.state, "is_peer_cluster_consumer", return_value=False)
    mocker.patch.object(
        type(charm.upgrades_manager), "is_rollback", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(
        type(charm.cluster_manager),
        "is_opensearch_started",
        new_callable=PropertyMock,
        return_value=True,
    )
    mocker.patch.object(type(charm.workload), "is_failed", return_value=False)
    mocker.patch.object(charm.state, "is_peer_cluster_provider", return_value=False)
    publish = mocker.patch.object(charm.status_handler, "set_running_status")
    post_start = mocker.patch.object(charm.opensearch_events, "_post_start_init")

    charm.opensearch_events._on_start_opensearch(mocker.Mock(after_upgrade=True))

    post_start.assert_called_once()
    publish.assert_not_called()
    assert charm.state.server_upgrade.post_upgrade_health == health


@pytest.mark.parametrize("scope", ["unit", "app"])
def test_application_removal_clears_upgrade_progress(harness, scope):
    harness.set_planned_units(0)
    harness.charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING

    assert harness.charm.upgrades_manager.get_statuses(scope) == [
        GeneralStatuses.ACTIVE_IDLE.value
    ]


@pytest.mark.parametrize("goal_status", ["active", "dying", None])
def test_removed_unit_does_not_wait_for_upgrade_restart(
    harness, upgrade_status_managers, mocker, goal_status
):
    charm = upgrade_status_managers
    manager = charm.status_handler.components[0]
    harness.set_planned_units(2)
    charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING
    manager._unit_status = None
    manager._app_status = UpgradesStatuses.UPGRADES_UPGRADING.value
    mocker.patch(
        "opensearch_single_kernel.core.state.hookcmds.goal_state",
        return_value=SimpleNamespace(
            units={charm.unit.name: SimpleNamespace(status=goal_status)} if goal_status else {}
        ),
    )

    messages = [status.message for status in manager.get_statuses("unit")]
    assert (GeneralStatuses.WAITING_TO_START.value.message in messages) == (
        goal_status == "active"
    )
    assert manager.get_statuses("app") == [UpgradesStatuses.UPGRADES_UPGRADING.value]
    assert charm.state.server_upgrade.unit_state == UnitUpgradesState.RESTARTING


@pytest.mark.parametrize("scope", ["unit", "app"])
def test_upgrade_status_waits_for_application_versions(harness, mocker, scope):
    manager = harness.charm.upgrades_manager
    harness.set_planned_units(1)
    assert harness.charm.state.application_upgrade.versions is None
    mocker.patch.object(type(manager), "in_progress", new_callable=PropertyMock, return_value=True)

    assert manager.get_statuses(scope) == [GeneralStatuses.ACTIVE_IDLE.value]


def test_upgrade_progress_returns_when_application_has_units_again(
    harness, upgrade_status_managers
):
    manager = upgrade_status_managers.status_handler.components[0]
    manager._app_status = UpgradesStatuses.UPGRADES_UPGRADING.value
    harness.set_planned_units(0)
    assert manager.get_statuses("app") == [GeneralStatuses.ACTIVE_IDLE.value]

    harness.set_planned_units(2)
    assert manager.get_statuses("app") == [UpgradesStatuses.UPGRADES_UPGRADING.value]


def test_removal_does_not_need_kubernetes_access(harness, mocker, substrate):
    if substrate != "k8s":
        pytest.skip("Kubernetes API access")
    harness.set_planned_units(0)
    manager = harness.charm.upgrades_manager
    check = mocker.patch.object(manager.k8s_client, "check_if_deployed_without_trust")

    assert manager.get_statuses("app") == [GeneralStatuses.ACTIVE_IDLE.value]
    check.assert_not_called()


@pytest.mark.parametrize("manager_class", [UpgradesManagerK8s, UpgradesManagerVM])
@pytest.mark.parametrize("checked_revision", [None, "old", "current"])
def test_restart_only_counts_as_upgrade_when_revision_needs_validation(
    mocker, manager_class, checked_revision
):
    manager = manager_class.__new__(manager_class)
    manager.state = MagicMock()
    manager.state.sorted_upgrades_units = [
        SimpleNamespace(
            unit=SimpleNamespace(name="opensearch/0"),
            unit_state=UnitUpgradesState.RESTARTING,
            unit_state_revision=checked_revision,
            workload_version="2.19.6",
        )
    ]
    mocker.patch.object(
        manager_class, "in_progress", new_callable=PropertyMock, return_value=False
    )
    mocker.patch.object(
        manager_class,
        "_unit_workload_container_versions",
        new_callable=PropertyMock,
        return_value={"opensearch/0": "current"},
    )

    mocker.patch.object(
        manager_class,
        "current_versions",
        new_callable=PropertyMock,
        return_value=SimpleNamespace(workload="2.19.6"),
    )

    assert manager.upgrade_checks_pending == (checked_revision != "current")
    assert manager.app_status == (
        UpgradesStatuses.UPGRADES_UPGRADING.value if checked_revision != "current" else None
    )
    if checked_revision == "current":
        assert not manager.should_check_rollback()
