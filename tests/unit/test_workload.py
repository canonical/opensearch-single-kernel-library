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
from opensearch_single_kernel.managers.cluster import ClusterManager
from opensearch_single_kernel.managers.config import ConfigManager


@pytest.fixture
def command_runner(harness, mocker, substrate):
    """Keep the workload runners real and replace only process execution."""
    workload = harness.charm.workload
    if substrate == "vm":
        mocker.patch("opensearch_single_kernel.workload.vm.os.access", return_value=True)
        backend = mocker.patch("opensearch_single_kernel.workload.vm.subprocess.run")
        backend.return_value = Mock(stdout="done", stderr="", returncode=0)
    else:
        backend = mocker.patch.object(workload.container, "exec")
        backend.return_value.wait_output.return_value = ("done", "")
    return workload, backend


@pytest.mark.parametrize("timeout", [None, 60])
@pytest.mark.parametrize(
    "method, replace_errors", [("run_cmd", False), ("run_cmd", True), ("run_script", False)]
)
def test_command_timeout_reaches_execution_backend(
    command_runner, timeout, method, replace_errors
):
    """Commands default to 30 seconds and honor an explicit per-call override."""
    workload, backend = command_runner
    kwargs = {} if timeout is None else {"timeout": timeout}
    if method == "run_cmd":
        kwargs["use_errors_replace"] = replace_errors

    getattr(workload, method)("test-command", **kwargs)

    assert backend.call_args.kwargs["timeout"] == (30 if timeout is None else timeout)


@pytest.mark.parametrize("initialise", [False, True])
def test_security_initialisation_has_longer_timeout_than_config_updates(
    command_runner, initialise
):
    """Only initial security-index creation gets a 60-second execution deadline."""
    workload, backend = command_runner
    state = Mock()
    state.application.admin_secrets = {"truststore-password": "trust", "keystore-password": "key"}
    state.application.is_security_index_initialised = False

    if initialise:
        ClusterManager(state, workload).initialise_security_index()
        assert state.application.is_security_index_initialised is True
    else:
        assert ConfigManager(state, workload).apply_security_config(
            state.application.admin_secrets, "opensearch-security/config.yml"
        )

    assert backend.call_args.kwargs["timeout"] == (60 if initialise else 30)


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
