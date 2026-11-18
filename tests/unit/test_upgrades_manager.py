# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for upgrade manager statuses."""

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock

import pytest
from ops import ActiveStatus, BlockedStatus, MaintenanceStatus

from opensearch_single_kernel.common.constants import (
    STATUS_PEERS_RELATION,
    HealthColors,
    Substrates,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchStartError,
    OpenSearchStartTimeoutError,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
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
    manager.state.sorted_upgrades_units = [SimpleNamespace(unit_number=i) for i in (2, 1, 0)]
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


@pytest.mark.parametrize("scope", ["unit", "app"])
def test_application_removal_clears_upgrade_progress(harness, scope):
    harness.set_planned_units(0)
    harness.charm.state.server_upgrade.unit_state = UnitUpgradesState.RESTARTING

    assert harness.charm.upgrades_manager.get_statuses(scope) == [
        GeneralStatuses.ACTIVE_IDLE.value
    ]


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
