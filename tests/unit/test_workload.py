# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for filesystem error handling at the workload boundary."""

from unittest.mock import Mock

import pytest
from charmlibs.pathops import LocalPath, PathProtocol, PebbleConnectionError
from ops import ModelError
from ops.pebble import APIError, PathError

from opensearch_single_kernel.common.exceptions import (
    OpenSearchFileOperationError,
    OpenSearchStartError,
)


@pytest.mark.parametrize("operation", ["exists", "write_text", "unlink"])
@pytest.mark.parametrize(
    "error",
    [
        APIError({}, 403, "Forbidden", "access denied"),
        ModelError("container unavailable"),
    ],
)
def test_workload_file_operations_normalize_errors(harness, operation, error):
    """An inaccessible path raises a workload error, never a missing-file result."""
    path = Mock(spec=PathProtocol)
    getattr(path, operation).side_effect = error

    with pytest.raises(OpenSearchFileOperationError, match=str(error)) as raised:
        if operation == "write_text":
            harness.charm.workload.write_text("data", path)
        else:
            getattr(harness.charm.workload, operation)(path)

    assert raised.value.__cause__ is error


@pytest.mark.real_fs
def test_workload_file_operations_preserve_missing_files(harness, tmp_path):
    """Only a genuinely absent file produces a missing-file result."""
    path = LocalPath(tmp_path / "missing.yml")
    workload = harness.charm.workload

    assert workload.exists(path) is False
    workload.unlink(path, missing_ok=True)
    with pytest.raises(OpenSearchFileOperationError) as raised:
        workload.unlink(path)
    assert isinstance(raised.value.__cause__, FileNotFoundError)


@pytest.mark.skip_if_substrate("vm")
@pytest.mark.parametrize("method", ["start_service", "start_service_only"])
@pytest.mark.parametrize("service_active", [False, True])
def test_start_fails_when_pebble_plan_cannot_be_configured(
    harness, mocker, method, service_active
):
    """A failed plan update must abort startup, even when an existing service is active."""
    workload = harness.charm.workload
    container = workload.container
    container.add_layer("opensearch", workload._build_pebble_layer(), combine=True)
    if service_active:
        container.start("opensearch")
    start = mocker.spy(container, "start")
    error = APIError({}, 403, "Forbidden", "access denied")
    mocker.patch.object(container, "add_layer", side_effect=error)

    with pytest.raises(OpenSearchStartError) as raised:
        getattr(workload, method)()

    assert raised.value.__cause__ is error
    start.assert_not_called()


@pytest.mark.skip_if_substrate("vm")
@pytest.mark.parametrize(
    "error, cause_type",
    [
        (APIError({}, 403, "Forbidden", "access denied"), APIError),
        (PathError("permission-denied", "permission denied"), PermissionError),
        (PebbleConnectionError("container disconnected"), PebbleConnectionError),
    ],
)
def test_temp_file_normalizes_pebble_write_failure(harness, mocker, error, cause_type):
    """Pebble push failures reach temporary-file callers as workload errors."""
    mocker.patch.object(harness.charm.workload.container, "push", side_effect=error)

    with pytest.raises(OpenSearchFileOperationError) as raised:
        with harness.charm.workload.temp_file(data="certificate"):
            pytest.fail("A failed write must not yield a temporary file")

    assert isinstance(raised.value.__cause__, cause_type)


@pytest.mark.real_fs
@pytest.mark.skip_if_substrate("vm")
def test_temp_file_normalizes_local_write_failure(harness, mocker, tmp_path):
    """Charm-local writes use the same error contract as remote writes."""
    error = PermissionError("permission denied")
    mocker.patch.object(LocalPath, "write_text", side_effect=error)

    with pytest.raises(OpenSearchFileOperationError) as raised:
        with harness.charm.workload.temp_file(dir=LocalPath(tmp_path), data="certificate"):
            pytest.fail("A failed write must not yield a temporary file")

    assert raised.value.__cause__ is error


@pytest.mark.real_fs
@pytest.mark.skip_if_substrate("vm")
@pytest.mark.parametrize("local", [False, True])
def test_temp_file_preserves_destination_and_caller_exception(harness, tmp_path, local):
    """The path selects the filesystem; exceptions from the with-body remain unchanged."""
    workload = harness.charm.workload
    directory = LocalPath(tmp_path) if local else workload.paths.tmp
    error = ValueError("caller failed")

    with pytest.raises(ValueError, match="caller failed") as raised:
        with workload.temp_file(dir=directory, data="certificate") as path:
            assert type(path) is type(directory)
            assert path.parent == directory
            assert path.read_text() == "certificate"
            raise error

    assert raised.value is error
    assert not path.exists()
