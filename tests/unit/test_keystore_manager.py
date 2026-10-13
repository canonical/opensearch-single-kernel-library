# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Keystore cleanup must distinguish absent entries from failed reads."""

from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from opensearch_single_kernel.common.constants import ObjectStorageType
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
)
from opensearch_single_kernel.managers.keystore import KeystoreManager


@pytest.fixture
def manager():
    workload = Mock()
    workload.exists.return_value = True
    workload.paths.opensearch_keystore_binary = "opensearch-keystore"
    workload.run_cmd.return_value = SimpleNamespace(out="keystore.seed\nsmtp.password\n")
    return KeystoreManager(Mock(), workload)


def test_remove_absent_entries_does_not_run_remove(manager):
    assert manager.remove_entries(["s3.client.default.access_key", "keystore.seed"])
    manager.workload.run_cmd.assert_called_once_with("opensearch-keystore", "list")


def test_remove_only_present_requested_entries(manager):
    manager.workload.run_cmd.return_value.out += "s3.client.default.access_key\n"

    assert manager.remove_entries(
        ["s3.client.default.access_key", "s3.client.default.secret_key", "keystore.seed"]
    )

    assert manager.workload.run_cmd.call_args_list == [
        call("opensearch-keystore", "list"),
        call("opensearch-keystore", "remove s3.client.default.access_key"),
    ]


def test_missing_keystore_needs_no_cleanup(manager):
    manager.workload.exists.return_value = False

    assert manager.remove_entries(["s3.client.default.access_key"])
    manager.workload.run_cmd.assert_not_called()


def test_stored_storage_types_includes_partial_credentials(manager):
    manager.workload.run_cmd.return_value.out += (
        "azure.client.default.account\ngcs.client.default.credentials_file\n"
    )

    assert manager.stored_storage_types == [ObjectStorageType.AZURE, ObjectStorageType.GCS]


@pytest.mark.parametrize(
    "error",
    [OpenSearchCmdError("list", err="unavailable"), OpenSearchFileOperationError("unavailable")],
)
def test_failed_keystore_read_is_not_successful_cleanup(manager, error):
    manager.workload.run_cmd.side_effect = error

    assert not manager.remove_entries(["s3.client.default.access_key"])
    with pytest.raises(type(error)):
        _ = manager.stored_storage_types


def test_failed_removal_is_not_successful_cleanup(manager):
    manager.workload.run_cmd.side_effect = [
        SimpleNamespace(out="s3.client.default.access_key\n"),
        OpenSearchCmdError("remove", err="unavailable"),
    ]

    assert not manager.remove_entries(["s3.client.default.access_key"])
