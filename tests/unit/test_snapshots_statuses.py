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
from opensearch_single_kernel.common.exceptions import (
    OpenSearchBackupCredentialsIncorrectError,
    OpenSearchObjectStorageConfigValidationError,
)
from opensearch_single_kernel.common.statuses import GeneralStatuses, SnapshotsStatuses
from opensearch_single_kernel.managers.snapshots import SnapshotsManager
from opensearch_single_kernel.utils.object_storage import storage_config_from_connection_info
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
@pytest.mark.parametrize(
    "recompute, cached",
    [(False, ()), (True, ()), (False, [SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value])],
    ids=["no-recompute", "recompute", "cached"],
)
def test_get_statuses_with_empty_connection_info(mocker, backend, recompute, cached):
    verify = _verify(mocker, backend, valid=True)
    manager = _main_mgr(backend, cached=cached, connection_info={})

    statuses = manager.get_statuses("app", recompute=recompute)

    assert statuses == [SnapshotsStatuses.BACKUP_WAITING_FOR_CONNECTION_INFO.value]
    verify.assert_not_called()


REQUIRED_FIELDS = {
    "s3": ["access-key", "secret-key", "endpoint", "bucket", "region"],
    "azure": ["storage-account", "secret-key"],
    "gcs": ["secret-key", "bucket"],
}
MISSING_FIELD_CASES = [
    (backend, field) for backend, fields in REQUIRED_FIELDS.items() for field in fields
]


def _info_missing(field: str, backend: str) -> dict:
    return {k: v for k, v in STORAGE[backend][1].items() if k != field}


@pytest.mark.parametrize("backend, field", MISSING_FIELD_CASES)
def test_get_statuses_missing_field(mocker, backend, field):
    verify = _verify(mocker, backend, valid=True)

    manager = _main_mgr(backend, connection_info=_info_missing(field, backend))

    statuses = manager.get_statuses("app")

    assert statuses == [SnapshotsStatuses.BACKUP_RELATION_DATA_INCOMPLETE.value]
    verify.assert_not_called()


@pytest.mark.parametrize("backend, field", MISSING_FIELD_CASES)
def test_validation_error_lists_missing_field(backend, field):
    with pytest.raises(OpenSearchObjectStorageConfigValidationError) as e:
        storage_config_from_connection_info(STORAGE[backend][0], _info_missing(field, backend))

    assert e.value.missing_fields == [field]


def _relate_backups(harness, relation):
    with harness.hooks_disabled():
        harness.set_leader(is_leader=True)
        harness.add_relation(STATUS_PEERS_RELATION, harness.charm.app.name)
        rel_id = harness.add_relation(relation.endpoint, relation.remote_app_name)
    return rel_id


def _cached_statuses(harness):
    return harness.charm.state.statuses.get("app", harness.charm.snapshots_manager.name)


def test_credentials_changed_sets_credentials_incorrect(mocker, harness, backend_setup):
    _, (relation,) = backend_setup
    _mock_backup(mocker)
    _relate_backups(harness, relation)
    mocker.patch(
        "opensearch_single_kernel.managers.snapshots.SnapshotsManager.validate_storage_config",
        side_effect=OpenSearchBackupCredentialsIncorrectError(),
    )

    harness.charm.snapshots_events._on_snapshots_credentials_changed(MagicMock())

    assert _cached_statuses(harness).root == [SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value]


def test_credentials_changed_clears_credentials_incorrect(mocker, harness, backend_setup):
    _, (relation,) = backend_setup
    _mock_backup(mocker)
    _relate_backups(harness, relation)
    mocker.patch(
        "opensearch_single_kernel.managers.snapshots.SnapshotsManager.validate_storage_config"
    )
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
    harness.charm.state.add_status_if_not_present(
        SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value,
        "app",
        harness.charm.snapshots_manager.name,
    )

    assert _cached_statuses(harness).root == [SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value]

    harness.charm.snapshots_events._on_snapshots_credentials_changed(MagicMock())

    assert _cached_statuses(harness).root == []


def test_credentials_gone_clears_cached_status(mocker, harness, backend_setup):
    cached_status = SnapshotsStatuses.BACKUP_CREDENTIALS_INCORRECT.value
    _, (relation,) = backend_setup
    _mock_backup(mocker)
    mocker.patch.object(harness.charm, "is_unit_going_away", return_value=False)
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
        cached_status,
        "app",
        harness.charm.snapshots_manager.name,
    )
    assert _cached_statuses(harness).root == [cached_status]

    harness.remove_relation(rel_id)

    assert _cached_statuses(harness).root == []
