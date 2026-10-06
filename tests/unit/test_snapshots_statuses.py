# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for snapshots status compute (cached failure merge)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from opensearch_single_kernel.common.constants import (
    STATUS_PEERS_RELATION,
    DeploymentType,
    ObjectStorageType,
)
from opensearch_single_kernel.common.statuses import GeneralStatuses, SnapshotsStatuses
from opensearch_single_kernel.managers.snapshots import SnapshotsManager
from opensearch_single_kernel.utils.status import format_status
from tests.unit.constants import DEFAULT_AZURE_INFO, DEFAULT_GCS_INFO, DEFAULT_S3_INFO
from tests.unit.test_backup import _mock_backup

STORAGE = {
    "s3": (ObjectStorageType.S3, DEFAULT_S3_INFO, "verify_s3_credentials"),
    "azure": (ObjectStorageType.AZURE, DEFAULT_AZURE_INFO, "verify_azure_credentials"),
    "gcs": (ObjectStorageType.GCS, DEFAULT_GCS_INFO, "verify_gcs_credentials"),
}


def _mgr(state) -> SnapshotsManager:
    mgr = SnapshotsManager.__new__(SnapshotsManager)
    mgr.state = state
    mgr.workload = MagicMock()
    mgr.name = "snapshots_manager"
    return mgr


def test_get_statuses_merges_cached_repo_misconfigured():
    cached = format_status(
        SnapshotsStatuses.BACKUP_REPOSITORY_MISCONFIGURED.value,
        {"storage_type": "s3", "integrator": "s3 integrator"},
    )
    state = MagicMock()
    # running_statuses uses running_status_only; failure merge uses full get
    state.statuses.get.side_effect = lambda *a, **k: SimpleNamespace(
        root=[] if k.get("running_status_only") else [cached]
    )
    state.application.deployment_desc = None

    statuses = _mgr(state).get_statuses("app")

    assert cached in statuses


def test_get_statuses_merges_cached_cleanup_failed():
    cached = SnapshotsStatuses.BACKUP_CREDENTIALS_CLEANUP_FAILED.value
    state = MagicMock()
    state.statuses.get.side_effect = lambda *a, **k: SimpleNamespace(
        root=[] if k.get("running_status_only") else [cached]
    )
    state.application.deployment_desc = None

    statuses = _mgr(state).get_statuses("app")

    assert cached in statuses


def test_get_statuses_unit_scope_idle():
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])

    assert _mgr(state).get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]


def _main_mgr(backend: str, cached=(), connection_info=None) -> SnapshotsManager:
    storage_type, info, _ = STORAGE[backend]
    state = MagicMock()
    state.statuses.get.side_effect = lambda *a, **k: SimpleNamespace(
        root=[] if k.get("running_status_only") else list(cached)
    )
    state.application.deployment_desc.typ = DeploymentType.MAIN_ORCHESTRATOR
    state.storage_type = storage_type
    state.get_storage_connection_info_from_relation.return_value = (
        info if connection_info is None else connection_info
    )
    return _mgr(state)


def _verify(mocker, backend: str, valid: bool) -> MagicMock:
    return mocker.patch(
        f"opensearch_single_kernel.managers.snapshots.{STORAGE[backend][2]}", return_value=valid
    )


@pytest.mark.parametrize("backend", STORAGE)
def test_get_statuses_without_recompute_does_not_validate_credentials(mocker, backend):
    verify = _verify(mocker, backend, valid=True)

    statuses = _main_mgr(backend).get_statuses("app")

    assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]
    verify.assert_not_called()


@pytest.mark.parametrize("backend", STORAGE)
def test_get_statuses_without_recompute_returns_cached_status(mocker, backend):
    cached = SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value
    verify = _verify(mocker, backend, valid=True)

    statuses = _main_mgr(backend, cached=[cached]).get_statuses("app")

    assert statuses == [cached]
    verify.assert_not_called()


@pytest.mark.parametrize("backend", STORAGE)
@pytest.mark.parametrize(
    "valid, expected",
    [
        (True, GeneralStatuses.ACTIVE_IDLE.value),
        (False, SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value),
    ],
)
def test_get_statuses_with_recompute_validates_credentials(mocker, backend, valid, expected):
    verify = _verify(mocker, backend, valid=valid)

    statuses = _main_mgr(backend).get_statuses("app", recompute=True)

    assert statuses == [expected]
    verify.assert_called_once()


@pytest.mark.parametrize("backend", STORAGE)
def test_get_statuses_before_integrator_fills_connection_info(mocker, backend):
    verify = _verify(mocker, backend, valid=True)

    statuses = _main_mgr(backend, connection_info={}).get_statuses("app")

    assert statuses == [SnapshotsStatuses.BACKUP_WAITING_FOR_CONNECTION_INFO.value]
    verify.assert_not_called()


@pytest.mark.parametrize("backend", STORAGE)
@pytest.mark.parametrize(
    "recompute, cached",
    [(True, ()), (False, [SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value])],
    ids=["update-status", "cached"],
)
def test_get_statuses_when_connection_info_empty_on_recompute(mocker, backend, recompute, cached):
    verify = _verify(mocker, backend, valid=True)
    manager = _main_mgr(backend, cached=cached, connection_info={})

    statuses = manager.get_statuses("app", recompute=recompute)

    assert statuses == [SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value]
    verify.assert_not_called()


@pytest.mark.parametrize(
    "info, expected",
    [
        ({"bucket": "relation-0"}, SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value),
        (
            {k: v for k, v in DEFAULT_S3_INFO.items() if k != "region"},
            SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value,
        ),
        (DEFAULT_S3_INFO | {"bucket": 2024}, SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value),
    ],
    ids=["no-keys", "no-region", "malformed"],
)
def test_get_statuses_invalid_connection_info(mocker, info, expected):
    _verify(mocker, "s3", valid=True)

    assert _main_mgr("s3", connection_info=info).get_statuses("app") == [expected]


def _relate_backups(harness, relation):
    with harness.hooks_disabled():
        harness.set_leader(is_leader=True)
        harness.add_relation(STATUS_PEERS_RELATION, harness.charm.app.name)
        rel_id = harness.add_relation(relation.endpoint, relation.remote_app_name)
        # azure/s3 integrators needs "version" to use non-legacy lib
        harness.update_relation_data(rel_id, relation.remote_app_name, {"version": "1"})
    return rel_id


def _cached_statuses(harness):
    return harness.charm.state.statuses.get("app", harness.charm.snapshots_manager.name)


def _get_statuses(harness):
    return harness.charm.snapshots_manager.get_statuses("app")


def test_credentials_changed_sets_then_clears_credentials_incorrect(
    mocker, harness, backend_setup
):
    backend, (relation,) = backend_setup
    _mock_backup(mocker)
    mocker.patch(
        "opensearch_single_kernel.events.snapshots.SnapshotsEventsHandler.update_stored_credentials"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.snapshots.SnapshotsManager.ensure_repository",
        return_value=False,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.peer_cluster_orchestrator."
        "PeerClusterOrchestratorManager.refresh_relation_data"
    )
    verify = _verify(mocker, backend, valid=False)
    rel_id = _relate_backups(harness, relation)

    harness.update_relation_data(rel_id, relation.remote_app_name, {"trigger": "1"})
    assert _get_statuses(harness) == [SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value]

    verify.return_value = True
    harness.update_relation_data(rel_id, relation.remote_app_name, {"trigger": "2"})
    assert _get_statuses(harness) == [GeneralStatuses.ACTIVE_IDLE.value]


def test_credentials_gone_clears_credentials_incorrect(mocker, harness, backend_setup):
    _, (relation,) = backend_setup
    _mock_backup(mocker)
    mocker.patch(
        "opensearch_single_kernel.managers.keystore.KeystoreManager.cleanup_storage_credentials",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.snapshots.SnapshotsManager.remove_repository",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.snapshots.SnapshotsManager.is_custom_s3_ca_stored",
        return_value=False,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.peer_cluster_orchestrator."
        "PeerClusterOrchestratorManager.refresh_relation_data"
    )
    rel_id = _relate_backups(harness, relation)
    harness.charm.state.add_status_if_not_present(
        SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value,
        "app",
        harness.charm.snapshots_manager.name,
    )
    assert _get_statuses(harness) == [SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value]

    harness.remove_relation(rel_id)

    assert _cached_statuses(harness).root == []
