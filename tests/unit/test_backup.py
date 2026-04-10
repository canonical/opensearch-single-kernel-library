# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock, PropertyMock

import pytest
from azure.core.exceptions import AzureError, ResourceNotFoundError
from botocore.exceptions import ClientError
from google.api_core.exceptions import Conflict, Forbidden
from ops import testing

from opensearch_single_kernel.common.client import OpenSearchClient
from opensearch_single_kernel.common.constants import (
    DeploymentType,
    HealthColors,
    ObjectStorageType,
)
from opensearch_single_kernel.common.exceptions import OpenSearchHttpError
from opensearch_single_kernel.utils import object_storage
from tests.unit.conftest import azure_relation, s3_relation, use_s3
from tests.unit.constants import S3_CONN_INFO_WITH_CA


def _mock_backup(
    mocker,
    deployment_desc_return_value=SimpleNamespace(typ=DeploymentType.MAIN_ORCHESTRATOR),
    backup_running_return_value=False,
    restore_running_return_value=False,
):
    # Mocks
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=deployment_desc_return_value,
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.snapshots.SnapshotsManager.alt_hosts",
        new_callable=PropertyMock,
        return_value=[],
    )
    mocker.patch(
        "opensearch_single_kernel.managers.health.HealthManager.get",
        return_value=HealthColors.GREEN,
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_snapshot_in_progress",
        return_value=backup_running_return_value,
    )

    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_restore_in_progress",
        return_value=restore_running_return_value,
    )


def test_create_backup_when_manager_raises_http_error_then_action_fails(
    mocker, harness, backend_setup, context
):
    # Given
    create_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_snapshot",
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    create_snapshot.side_effect = OpenSearchHttpError(
        response_text="server error", response_code=500
    )
    _mock_backup(mocker)

    backend, rels = backend_setup
    st = testing.State(leader=True, relations=rels)
    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    # Assert
    msg = err.value.message.lower()
    assert "backup request failed" in msg
    assert "server error" in msg or "500" in msg


def test_create_backup_when_all_ok_then_success_result_is_returned(
    mocker, harness, backend_setup, context
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_snapshot",
        return_value="2025-01-01T10:00:00Z",
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
        return_value={"snapshot": "2025-01-01T10:00:00Z", "state": "SUCCESS"},
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup
    st = testing.State(leader=True, relations=rels)
    # When
    context.run(context.on.action("create-backup"), st)

    # Assert
    assert context.action_results == {
        "backup-id": "2025-01-01T10:00:00Z",
        "status": "success",
    }


def test_create_backup_when_s3_repo_missing_and_ca_present_then_raise_repository_missing_error(
    mocker, harness, backend_setup, context
):
    # Given
    _mock_backup(mocker)
    ca = "-----BEGIN CERT-----\nMIIB...==\n-----END CERT-----\n"
    use_s3(ca=ca, mocker=mocker)
    patch_create_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_snapshot",
        return_value="2025-01-01T10:00:00Z",
    )
    is_repository_created = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
    )
    is_repository_created.return_value = False

    # When
    st = testing.State(
        leader=True,
        relations={s3_relation()},
    )
    # Assert
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)

    assert "The opensearch repository could not be created yet." in str(err.value)
    patch_create_snapshot.assert_not_called()


def test_create_backup_when_s3_has_no_ca_then_operations_still_succeed(mocker, harness, context):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_snapshot",
        return_value="2025-01-01T10:00:00Z",
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
        return_value={"snapshot": "2025-01-01T10:00:00Z", "state": "SUCCESS"},
    )
    _mock_backup(mocker)
    s3_no_ca = {k: v for k, v in S3_CONN_INFO_WITH_CA.items() if k != "tls_ca_chain"}
    use_s3(mocker=mocker, info=s3_no_ca)
    st = testing.State(leader=True, relations={s3_relation()})

    # When
    context.run(context.on.action("create-backup"), st)

    # Assert
    assert context.action_results == {
        "backup-id": "2025-01-01T10:00:00Z",
        "status": "success",
    }


def test_list_backups_when_json_requested_then_json_is_returned(
    harness, mocker, backend_setup, context
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)
    snapshots = {
        "2025-01-01T10:00:00Z": {"state": "success", "indices": []},
        "2025-01-01T09:00:00Z": {"state": "failed", "indices": []},
    }

    original = OpenSearchClient.list_snapshots
    OpenSearchClient.list_snapshots = lambda *_a, **_k: snapshots

    # When
    try:
        context.run(context.on.action("list-backups", params={"output": "json"}), st)
    finally:
        OpenSearchClient.list_snapshots = original
    # Assert
    assert json.loads(context.action_results["backups"]) == snapshots


def test_list_backups_when_table_requested_then_table_is_returned(
    harness, mocker, backend_setup, context
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup
    st = testing.State(leader=True, relations=rels)
    snapshots = {
        "2025-01-01T10:00:00Z": {"state": "success", "indices": []},
        "2025-01-01T09:00:00Z": {"state": "in_progress", "indices": []},
    }

    original = OpenSearchClient.list_snapshots
    OpenSearchClient.list_snapshots = lambda *_a, **_k: snapshots
    # When
    try:
        context.run(context.on.action("list-backups", params={"output": "table"}), st)
    finally:
        OpenSearchClient.list_snapshots = original

    # Assert
    table = context.action_results["backups"]
    assert "backup-id" in table and "backup-status" in table
    assert "2025-01-01T10:00:00Z" in table
    assert "success" in table


def test_list_backups_when_manager_raises_http_error_then_action_fails(
    harness, mocker, backend_setup, context
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    get_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
        return_value={"snapshot": "2025-01-01T10:00:00Z", "state": "SUCCESS"},
    )
    backend, rels = backend_setup
    st = testing.State(leader=True, relations=rels)

    get_snapshot.side_effect = None
    original = OpenSearchClient.list_snapshots

    def return_error(*_a, **_k):
        raise OpenSearchHttpError(response_text="server error", response_code=503)

    OpenSearchClient.list_snapshots = return_error

    # When
    try:
        with pytest.raises(testing.ActionFailed) as err:
            context.run(context.on.action("list-backups", params={"output": "json"}), st)
    finally:
        OpenSearchClient.list_snapshots = original

    # Assert
    msg = err.value.message.lower()
    assert "server error" in msg or "503" in msg


def test_list_backups_when_not_leader_then_action_fails(harness, mocker, backend_setup, context):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=False, relations=rels)
    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("list-backups", params={"output": "json"}), st)
    # Assert
    assert "leader" in err.value.message.lower()


def test_restore_when_prereqs_missing_then_action_fails(
    harness, mocker, backend_setup, monkeypatch, context
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)

    mocker.patch(
        "opensearch_single_kernel.events.snapshots.SnapshotsEventsHandler._action_missing_pre_requisites",
        return_value="cluster not ready",
    )

    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st)

    assert "cluster not ready" in err.value.message.lower()


def test_restore_when_snapshot_not_found_then_action_fails(
    harness, mocker, backend_setup, context
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
        return_value=None,
    )

    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("restore", params={"backup-id": "X"}), st)

    assert "not found" in err.value.message.lower()


def test_restore_when_get_snapshot_http_error_then_action_fails(
    harness, mocker, backend_setup, context
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)
    get_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
    )
    get_snapshot.side_effect = OpenSearchHttpError(response_text="server error", response_code=500)
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st)

    assert "server error" in err.value.message.lower()


@pytest.mark.parametrize(
    "close_result, expect_fail, expect_msg",
    [
        ((None, None), False, None),
        ((["idx1", "idx2"], None), False, None),
        ((["idx1"], {"idx2": {"closed": False}}), True, "failed to close"),
    ],
)
def test_restore_when_closing_indices_varies_then_paths_are_handled(
    context, harness, mocker, backend_setup, close_result, expect_fail, expect_msg, monkeypatch
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)
    get_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
    )
    get_snapshot.return_value = {
        "snapshot": "2025-01-01T10:00:00Z",
        "state": "SUCCESS",
    }

    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.close_snapshot_indices_open_in_cluster",
        lambda *_a, **_k: close_result,
    )
    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.restore_snapshot",
        lambda *_a, **_k: None,
    )

    if expect_fail:
        with pytest.raises(testing.ActionFailed) as err:
            context.run(
                context.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
            )
        assert expect_msg in err.value.message.lower()
    else:
        context.run(context.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st)


def test_restore_when_start_fails_then_action_fails_with_message(
    context, harness, mocker, backend_setup, monkeypatch
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)
    get_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
    )
    get_snapshot.return_value = {
        "snapshot": "2025-01-01T10:00:00Z",
        "state": "SUCCESS",
    }

    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.close_snapshot_indices_open_in_cluster",
        lambda *_a, **_k: (None, None),
    )

    def return_error(*_a, **_k):
        raise OpenSearchHttpError(response_text="restore failed", response_code=409)

    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.restore_snapshot",
        return_error,
    )

    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st)
    assert "restore failed" in err.value.message.lower()


def test_restore_when_non_restored_indices_exist_then_action_fails_with_count(
    context, harness, mocker, backend_setup, monkeypatch
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    get_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
    )
    get_snapshot.return_value = {"snapshot": "S", "state": "SUCCESS"}
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)

    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.close_snapshot_indices_open_in_cluster",
        lambda *_a, **_k: (None, None),
    )
    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.restore_snapshot",
        lambda *_a, **_k: {"a", "b"},
    )

    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("restore", params={"backup-id": "S"}), st)

    # Assert
    assert "failed to restore 2 indices" in err.value.message.lower()


def test_restore_when_http_error_on_close_indices_then_action_fails(
    context, harness, mocker, backend_setup, monkeypatch
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)
    get_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
    )
    get_snapshot.return_value = {
        "snapshot": "S",
        "state": "SUCCESS",
        "indices": ["idx"],
    }

    def return_error(*_a, **_k):
        raise OpenSearchHttpError(response_text="close-error", response_code=500)

    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.close_snapshot_indices_open_in_cluster",
        return_error,
    )

    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("restore", params={"backup-id": "S"}), st)
    # Assert
    assert "close" in err.value.message.lower()


def test_restore_when_all_ok_then_health_apply_is_called(
    context, mocker, harness, backend_setup, monkeypatch
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    get_snapshot = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
    )
    st = testing.State(leader=True, relations=rels)
    get_snapshot.return_value = {
        "snapshot": "2025-01-01T10:00:00Z",
        "state": "SUCCESS",
        "indices": ["idx1"],
    }

    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.close_snapshot_indices_open_in_cluster",
        lambda *_a, **_k: (None, None),
    )
    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.restore_snapshot",
        lambda *_a, **_k: set(),
    )

    called = {"ok": False}

    def fake_apply(*_a, **_k):
        called["ok"] = True

    monkeypatch.setattr(
        "opensearch_single_kernel.charms.base.OpenSearchBaseCharm.apply_health",
        lambda *_a, **_k: fake_apply(),
    )
    # When
    context.run(context.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st)
    # Assert
    assert called["ok"]


def test_restore_when_not_leader_then_action_fails(mocker, context, harness, backend_setup):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=False, relations=rels)

    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st)
    # Assert
    assert "leader" in err.value.message.lower()


def test_prereq_when_not_leader_then_action_fails(context, mocker, harness, backend_setup):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=False, relations=rels)

    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)

    # Assert
    assert "leader" in err.value.message.lower()


def test_prereq_when_deployment_not_ready_then_action_fails(
    context, mocker, harness, backend_setup, monkeypatch
):

    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )

    _mock_backup(mocker, deployment_desc_return_value=None)
    backend, rels = backend_setup
    if backend == "s3":
        object_storage_type = ObjectStorageType.S3
    elif backend == "azure":
        object_storage_type = ObjectStorageType.AZURE
    else:
        object_storage_type = ObjectStorageType.GCS

    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.storage_type",
        new_callable=PropertyMock,
        return_value=object_storage_type,
    )

    st = testing.State(leader=True, relations=rels)

    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    # Assert
    assert "deployment not ready" in err.value.message.lower()


def test_prereq_when_upgrade_in_progress_then_action_fails(
    context, mocker, harness, backend_setup, monkeypatch
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.managers.upgrades_vm.UpgradesManagerVM.in_progress",
        new_callable=PropertyMock(return_value=True),
    )

    _mock_backup(mocker)
    backend, rels = backend_setup
    if backend == "s3":
        object_storage_type = ObjectStorageType.S3
    elif backend == "azure":
        object_storage_type = ObjectStorageType.AZURE
    else:
        object_storage_type = ObjectStorageType.GCS

    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.storage_type",
        new_callable=PropertyMock,
        return_value=object_storage_type,
    )

    st = testing.State(leader=True, relations=rels)

    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    # Assert
    assert "upgrade in-progress" in err.value.message.lower()


def test_prereq_when_storage_relation_missing_then_action_fails(
    context, mocker, harness, monkeypatch
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    st = testing.State(leader=True)

    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    # Assert
    assert "missing relation" in err.value.message.lower()


def test_prereq_when_conflict_detected_from_two_relations_then_action_fails(
    mocker, context, harness, monkeypatch
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    st = testing.State(leader=True, relations={s3_relation(), azure_relation()})
    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    # Assert
    assert "conflict" in err.value.message.lower()


def test_prereq_when_repo_missing_and_cannot_create_then_action_fails(
    context, mocker, harness, backend_setup, monkeypatch
):
    # Given
    is_repository_created = mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)

    is_repository_created.side_effect = [False, False]
    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.create_repository",
        lambda *_a, **_k: None,
    )
    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    # Assert
    assert "repository could not be created" in err.value.message.lower()


def test_prereq_when_http_error_during_repo_check_then_error_message_displayed(
    context, mocker, harness, backend_setup, monkeypatch
):
    # Given
    _mock_backup(mocker)
    backend, rels = backend_setup

    st = testing.State(leader=True, relations=rels)

    def return_error(*_a, **_k):
        raise OpenSearchHttpError(response_text="precheck-failed", response_code=500)

    monkeypatch.setattr(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_error,
    )
    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    # Assert
    assert "precheck-failed" in err.value.message.lower()


@pytest.mark.parametrize(
    "color", [HealthColors.RED, HealthColors.YELLOW_TEMP, HealthColors.UNKNOWN]
)
def test_prereq_when_health_not_green_then_action_fails_with_specific_message(
    context, harness, mocker, color
):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    _mock_backup(mocker)
    use_s3(mocker=mocker)
    st = testing.State(leader=True, relations={s3_relation()})
    mocker.patch(
        "opensearch_single_kernel.managers.health.HealthManager.get",
        return_value=color,
    )
    # When
    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)

    # Assert
    msg = err.value.message.lower()
    assert any(k in msg for k in ["red", "relocating", "unknown"])


def test_prereq_when_snapshot_running_then_action_fails(context, mocker, harness):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.health.HealthManager.get",
        return_value=HealthColors.GREEN,
    )
    _mock_backup(mocker, backup_running_return_value=True)
    use_s3(mocker=mocker)
    st = testing.State(leader=True, relations={s3_relation()})

    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    assert "operation in progress" in err.value.message.lower()


def test_prereq_when_restore_running_then_action_fails(context, mocker, harness):
    # Given
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_repository_created",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.health.HealthManager.get",
        return_value=HealthColors.GREEN,
    )
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.get_snapshot",
    )
    _mock_backup(mocker, restore_running_return_value=True)
    use_s3(mocker=mocker)
    st = testing.State(leader=True, relations={s3_relation()})

    with pytest.raises(testing.ActionFailed) as err:
        context.run(context.on.action("create-backup"), st)
    assert "operation in progress" in err.value.message.lower()


def _client_error(code: str, status: int = 400) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": "err"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        operation_name="Test",
    )


def test_create_s3_bucket_when_region_non_us_east_1_but_no_aws_endpoint_then_does_not_call_location_constraint(
    mocker, harness, context, monkeypatch
):
    # Given
    bucket = Mock()
    bucket.wait_until_exists = Mock()

    get_bucket = Mock(return_value=bucket)
    monkeypatch.setattr(object_storage, "get_s3_bucket_resource", get_bucket)

    params = {
        "access-key": "a",
        "secret-key": "s",
        "bucket": "b",
        "endpoint": "https://s3.example",
        "region": "eu-north-1",
    }

    # When
    object_storage.create_s3_bucket(params, verify=True)

    # Assert
    get_bucket.assert_called_once()
    bucket.create.assert_called_once_with()
    bucket.wait_until_exists.assert_called_once()


def test_create_s3_bucket_when_region_non_us_east_1_with_aws_endpoint_then_call_location_constraint(
    context, mocker, harness, monkeypatch
):
    # Given
    bucket = Mock()
    bucket.wait_until_exists = Mock()

    get_bucket = Mock(return_value=bucket)
    monkeypatch.setattr(object_storage, "get_s3_bucket_resource", get_bucket)

    params = {
        "access-key": "a",
        "secret-key": "s",
        "bucket": "b",
        "endpoint": "amazonaws.com",
        "region": "eu-north-1",
    }
    # When
    object_storage.create_s3_bucket(params, verify=True)

    # Assert
    get_bucket.assert_called_once()
    bucket.create.assert_called_once_with(
        CreateBucketConfiguration={"LocationConstraint": "eu-north-1"}
    )
    bucket.wait_until_exists.assert_called_once()


def test_create_s3_bucket_when_region_us_east_1_then_calls_create_without_location_constraint(
    context, harness, mocker, monkeypatch
):
    # Given
    bucket = Mock()
    bucket.wait_until_exists = Mock()

    monkeypatch.setattr(object_storage, "get_s3_bucket_resource", lambda *_a, **_k: bucket)

    params = {
        "access-key": "a",
        "secret-key": "s",
        "bucket": "b",
        "endpoint": "https://s3.example",
        "region": "us-east-1",
    }
    # When
    object_storage.create_s3_bucket(params, verify=True)
    # Assert
    bucket.create.assert_called_once_with()
    bucket.wait_until_exists.assert_called_once()


@pytest.mark.parametrize(
    "code", ["BucketAlreadyOwnedByYou", "BucketAlreadyExists", "BucketNameUnavailable"]
)
def test_create_s3_bucket_when_bucket_already_exists_then_it_does_not_raise(
    harness, mocker, context, monkeypatch, code
):
    # Given
    bucket = Mock()
    bucket.create.side_effect = _client_error(code)

    monkeypatch.setattr(object_storage, "get_s3_bucket_resource", lambda *_a, **_k: bucket)

    params = {
        "access-key": "a",
        "secret-key": "s",
        "bucket": "b",
        "endpoint": "https://s3.example",
        "region": "us-east-1",
    }
    # When
    object_storage.create_s3_bucket(params, verify=True)


def test_create_s3_bucket_when_access_denied_then_other_clienterror_raises(
    context, harness, mocker, monkeypatch
):
    # Given
    bucket = Mock()
    bucket.create.side_effect = _client_error("AccessDenied", status=403)

    monkeypatch.setattr(object_storage, "get_s3_bucket_resource", lambda *_a, **_k: bucket)

    params = {
        "access-key": "a",
        "secret-key": "s",
        "bucket": "b",
        "endpoint": "https://s3.example",
        "region": "us-east-1",
    }
    # When
    with pytest.raises(ClientError):
        object_storage.create_s3_bucket(params, verify=True)


def test_verify_s3_credentials_when_bucket_missing_then_triggers_create_and_probe(
    harness, mocker, context, monkeypatch
):
    # Given
    cfg = Mock()
    cfg.s3 = Mock()
    cfg.s3.credentials = Mock()
    cfg.s3.tls_ca_chain = None
    cfg.s3.credentials.access_key = "a"
    cfg.s3.credentials.secret_key = "s"
    cfg.s3.bucket = "mybucket"
    cfg.s3.endpoint = "https://s3.example"
    cfg.s3.region = "us-east-1"
    cfg.s3.base_path = "base/path"

    bucket = Mock()
    bucket.meta = Mock()
    bucket.meta.client = Mock()

    # head_bucket returns 404 (NoSuchBucket)
    bucket.meta.client.head_bucket.side_effect = _client_error("NoSuchBucket", status=404)

    # probe write/delete
    bucket.put_object = Mock()
    bucket.Object.return_value.delete = Mock()

    monkeypatch.setattr(object_storage, "get_s3_bucket_resource", lambda *_a, **_k: bucket)

    mock_create = Mock(return_value=None)
    monkeypatch.setattr(object_storage, "create_s3_bucket", mock_create)
    # When
    ok = object_storage.verify_s3_credentials(cfg)
    # Assert
    assert ok is True

    mock_create.assert_called_once()
    bucket.put_object.assert_called_once()
    bucket.Object.return_value.delete.assert_called_once()


def test_create_azure_container_when_create_bucket_then_create_container_is_called(
    harness, mocker, context, monkeypatch
):
    # Given
    client = Mock()
    monkeypatch.setattr(object_storage, "get_azure_container_client", lambda _params: client)

    params = {
        "storage-account": "acc",
        "secret-key": "key",
        "container": "cont",
        "account-url": "https://acc.blob.core.windows.net",
    }
    # When
    object_storage.create_azure_container(params)
    # Assert
    client.create_container.assert_called_once()


def test_create_azure_container_when_container_exists_and_we_run_create_container_then_it_does_not_raise(
    context, mocker, harness, monkeypatch
):
    # Given
    client = Mock()
    client.create_container.side_effect = AzureError("boom")
    monkeypatch.setattr(object_storage, "get_azure_container_client", lambda _params: client)

    params = {
        "storage-account": "acc",
        "secret-key": "key",
        "container": "cont",
        "account-url": "https://acc.blob.core.windows.net",
    }
    # When/Assert
    with pytest.raises(AzureError):
        object_storage.create_azure_container(params)


def test_create_azure_container_when_create_container_then_other_azure_error_raises(
    context, harness, mocker, monkeypatch
):
    client = Mock()
    client.create_container.side_effect = AzureError("boom")
    monkeypatch.setattr(object_storage, "get_azure_container_client", lambda _params: client)

    params = {
        "storage-account": "acc",
        "secret-key": "key",
        "container": "cont",
        "account-url": "https://acc.blob.core.windows.net",
    }

    with pytest.raises(AzureError):
        object_storage.create_azure_container(params)


def test_create_azure_container_when_container_missing_then_triggers_create_and_probe(
    context, mocker, harness, monkeypatch
):
    # Given
    cfg = Mock()
    cfg.azure = Mock()
    cfg.azure.credentials = Mock()
    cfg.azure.connection_protocol = "https"
    cfg.azure.credentials.storage_account = "acc"
    cfg.azure.credentials.secret_key = "key"
    cfg.azure.container = "cont"
    cfg.azure.base_path = "base/path"
    cfg.azure.endpoint = "https://account.blob.core.windows.net/container"

    container_client = Mock()
    container_client.get_container_properties.side_effect = ResourceNotFoundError("missing")

    blob_client = Mock()
    container_client.get_blob_client.return_value = blob_client

    monkeypatch.setattr(
        object_storage, "get_azure_container_client", lambda _params: container_client
    )

    mock_create = Mock(return_value=None)
    monkeypatch.setattr(object_storage, "create_azure_container", mock_create)
    # When
    ok = object_storage.verify_azure_credentials(cfg)
    # Assert
    assert ok is True

    mock_create.assert_called_once()
    blob_client.upload_blob.assert_called_once()
    blob_client.delete_blob.assert_called_once()


def _cfg(*, secret_key: str = "{}", bucket: str = "bkt", base_path: str = "base/path"):
    """Build an ObjectStorageConfig mock for GCS."""
    cfg = Mock()
    cfg.gcs = Mock()
    cfg.gcs.credentials = Mock()
    cfg.gcs.credentials.secret_key = secret_key
    cfg.gcs.bucket = bucket
    cfg.gcs.base_path = base_path
    return cfg


def test_create_gcs_bucket_when_credentials_block_missing_then_return_false():
    cfg = Mock()
    cfg.gcs = Mock()
    cfg.gcs.credentials = None

    assert object_storage.verify_gcs_credentials(cfg) is False


def test_create_gcs_bucket_when_secret_key_empty_then_return_false():
    cfg = _cfg(secret_key="")
    assert object_storage.verify_gcs_credentials(cfg) is False


def test_create_gcs_bucket_when_bucket_name_empty_then_return_false():
    cfg = _cfg(bucket="")
    assert object_storage.verify_gcs_credentials(cfg) is False


def test_create_gcs_bucket_when_secret_key_is_invalid_json_then_return_false():
    cfg = _cfg(secret_key="not-json")
    assert object_storage.verify_gcs_credentials(cfg) is False


def test_create_gcs_bucket_when_bucket_missing_then_create_bucket_test_write_access(monkeypatch):
    cfg = _cfg(
        secret_key='{"project_id":"p"}',
        bucket="mybucket",
        base_path="base/path",
    )

    client = Mock()
    bucket = Mock()
    blob = Mock()

    bucket.exists.return_value = False
    bucket.blob.return_value = blob

    client.bucket.return_value = bucket
    monkeypatch.setattr(object_storage, "get_gcs_client", lambda _json: client)

    create_bucket = Mock(return_value=None)
    monkeypatch.setattr(object_storage, "create_gcs_bucket", create_bucket)

    monkeypatch.setattr(object_storage.uuid, "uuid4", lambda: Mock(hex="abc"))

    ok = object_storage.verify_gcs_credentials(cfg)
    assert ok is True

    create_bucket.assert_called_once_with(client, bucket)
    bucket.blob.assert_called_once_with("base/path/.opensearch-verify-abc")
    blob.upload_from_string.assert_called_once()
    blob.delete.assert_called_once()


def test_create_gcs_bucket_when_exists_check_forbidden_then_attempt_to_create(monkeypatch):
    cfg = _cfg(secret_key='{"project_id":"p"}', bucket="mybucket")

    client = Mock()
    bucket = Mock()
    blob = Mock()

    bucket.exists.side_effect = Forbidden("no buckets.get")
    bucket.blob.return_value = blob

    client.bucket.return_value = bucket
    monkeypatch.setattr(object_storage, "get_gcs_client", lambda _json: client)

    create_bucket = Mock(return_value=None)
    monkeypatch.setattr(object_storage, "create_gcs_bucket", create_bucket)

    ok = object_storage.verify_gcs_credentials(cfg)
    assert ok is True
    create_bucket.assert_called_once_with(client, bucket)


@pytest.mark.parametrize("exc", [Conflict("taken"), Forbidden("denied")])
def test_create_gcs_bucket_when_bucket_creation_fails_then_return_false(monkeypatch, exc):
    cfg = _cfg(secret_key='{"project_id":"p"}', bucket="mybucket")

    client = Mock()
    bucket = Mock()
    bucket.exists.return_value = False

    client.bucket.return_value = bucket
    monkeypatch.setattr(object_storage, "get_gcs_client", lambda _json: client)

    def _raise(*_a, **_k):
        raise exc

    monkeypatch.setattr(object_storage, "create_gcs_bucket", _raise)

    assert object_storage.verify_gcs_credentials(cfg) is False


def test_create_gcs_bucket_when_probe_upload_forbidden_then_return_false(monkeypatch):
    cfg = _cfg(
        secret_key='{"project_id":"p"}',
        bucket="mybucket",
        base_path="base/path",
    )
    client = Mock()
    bucket = Mock()
    blob = Mock()
    bucket.exists.return_value = True
    bucket.blob.return_value = blob
    blob.upload_from_string.side_effect = Forbidden("no objects.create")

    client.bucket.return_value = bucket
    monkeypatch.setattr(object_storage, "get_gcs_client", lambda _json: client)

    assert object_storage.verify_gcs_credentials(cfg) is False
    blob.delete.assert_not_called()
