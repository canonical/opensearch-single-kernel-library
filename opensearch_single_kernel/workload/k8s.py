#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes Workload."""

import logging
import shlex
import uuid
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Literal

from charmlibs import pathops
from charmlibs.pathops import LocalPath, PathProtocol
from ops import Container
from ops.model import ModelError
from ops.pebble import ConnectionError as PebbleConnectionError
from ops.pebble import Error as PebbleError
from ops.pebble import (
    Layer,
    ServiceInfo,
    ServiceStatus,
)
from overrides import override

from opensearch_single_kernel.common.constants import (
    DIR_PERMISSIONS_READONLY,
    MAX_HEAP_SIZE_IN_KB,
    OPENSEARCH_PEBBLE_SERVICE_NAME,
    PEBBLE_SERVICE_GROUP,
    PEBBLE_SERVICE_USER,
    OpenSearchPaths,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
    OpenSearchStartError,
    OpenSearchStopError,
)
from opensearch_single_kernel.utils.helpers import (
    build_command_list,
    mask_sensitive_information,
    wait_for_process_output,
)
from opensearch_single_kernel.workload.base import BaseWorkload
from opensearch_single_kernel.workload.base import Paths as BasePaths

logger = logging.getLogger(__name__)


class K8sPaths(BasePaths):
    """K8s specific paths implementation for container filesystem.

    For K8s rock images, uses standard Linux paths instead of snap paths:
    - /etc/opensearch (config)
    - /var/lib/opensearch (data)
    - /var/log/opensearch (logs)
    - /usr/share/opensearch (home/bin)
    """

    def __init__(self, root: PathProtocol, charm_root: PathProtocol):
        super().__init__(root, charm_root)

    @property
    def home(self) -> PathProtocol:
        """Return path to OpenSearch home directory.

        For K8s rock image: /usr/share/opensearch

        Returns:
            PathProtocol: path to OpenSearch home directory.
        """
        return self.root / OpenSearchPaths.HOME.val

    @property
    def conf(self) -> PathProtocol:
        """Return path to OpenSearch config directory.

        For K8s rock image: /etc/opensearch

        Returns:
            PathProtocol: path to OpenSearch config directory.
        """
        return self.root / OpenSearchPaths.CONF.val

    @property
    def data(self) -> PathProtocol:
        """Return path to OpenSearch data directory.

        For K8s rock image: /var/lib/opensearch

        Returns:
            PathProtocol: path to OpenSearch data directory.
        """
        return self.root / OpenSearchPaths.DATA.val

    @property
    def logs(self) -> PathProtocol:
        """Return path to OpenSearch logs directory.

        For K8s rock image: /var/log/opensearch
        """
        return self.root / OpenSearchPaths.LOGS.val

    @property
    def jdk(self) -> PathProtocol:
        """Return path to the jdk directory.

        For K8s containers, JDK is installed at /usr/lib/jvm/java-21-openjdk-amd64

        Returns:
            PathProtocol: path to JDK installation directory.
        """
        return self.root / OpenSearchPaths.JDK.val

    @property
    def tmp(self) -> PathProtocol:
        """Return path to the tmp directory.

        For K8s rock image: /usr/share/tmp

        Returns:
            PathProtocol: path to temp directory.
        """
        return self.root / OpenSearchPaths.TMP.val

    @property
    def bin(self) -> PathProtocol:
        """Return path to the bin directory.

        For K8s rock image: /usr/share/opensearch/bin

        Returns:
            PathProtocol: path to OpenSearch bin directory.
        """
        return self.root / OpenSearchPaths.BIN.val

    @property
    def opensearch_key_store_binary(self) -> str:
        """Name of the opensearch-keystore binary."""
        return (self.bin / "opensearch-keystore").as_posix()


class K8sWorkload(BaseWorkload):
    """Kubernetes OpenSearch Workload."""

    def __init__(self, charm_root: Path, container: Container | None = None):
        """Initialize K8s workload.

        Args:
            charm_root: the root path of the charm.
            container: the Container instance.
        """
        super().__init__()
        if not container:
            raise ValueError("Container is required.")
        self.charm_root = LocalPath(charm_root)
        self.container = container
        self._paths: BasePaths | None = None

    def _get_service(self) -> ServiceInfo | None:
        """Return current service info, if present."""
        try:
            services = self.container.get_services()
        except (PebbleConnectionError, PebbleError, ModelError, TypeError):
            return None

        target = OPENSEARCH_PEBBLE_SERVICE_NAME
        if isinstance(services, Mapping):
            return services.get(target)
        return None

    @property
    @override
    def workload_present(self) -> bool:
        """Check if the container is ready and connected.

        Returns:
            bool: True if container is ready and can connect, False otherwise.
        """
        try:
            container = self.container
            return container.can_connect()
        except (RuntimeError, ModelError):
            return False

    @property
    @override
    def can_connect(self) -> bool:
        """Check if the workload container is connectable."""
        return self.container.can_connect()

    def _configure_pebble_plan(self, *, enable_checks: bool = False) -> None:
        """Configure the Pebble plan with the OpenSearch service definition.

        This must be called before starting the service. The plan defines:
        - Service name: opensearch
        - Command: OpenSearch executable path (using standard Linux paths, not snap paths)
        - Environment variables: OPENSEARCH_HOME, OPENSEARCH_PATH_CONF, JAVA_HOME, PATH
        - Uses system Java at /usr/lib/jvm/java-21-openjdk-amd64 (JAVA_HOME is set explicitly)
        - Runs OpenSearch as a non-root user/group defined in the Pebble layer
        """
        try:
            # The K8s image exposes the OpenSearch launcher directly as `opensearch`.
            layer = self._build_pebble_layer()
            self.container.add_layer(OPENSEARCH_PEBBLE_SERVICE_NAME, layer, combine=True)

            logger.info("Configured pebble plan for %s service", OPENSEARCH_PEBBLE_SERVICE_NAME)

        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.warning("Failed to configure pebble plan: %s", e)
            # this might be called before container is ready

    def _build_pebble_layer(self) -> Layer:
        """Build Pebble layer for OpenSearch service."""
        opensearch_cmd = (self.paths.bin / "opensearch").as_posix()
        opensearch_home = self.paths.home.as_posix()
        opensearch_conf = self.paths.conf.as_posix()
        java_home = self.paths.jdk.as_posix()

        # build PATH with Java bin, OpenSearch bin, and system paths
        path_value = (
            "%s/bin:/usr/share/opensearch/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            % java_home
        )

        layer_dict = {
            "summary": "OpenSearch service layer",
            "description": "Pebble plan layer for OpenSearch",
            "services": {
                OPENSEARCH_PEBBLE_SERVICE_NAME: {
                    "override": "replace",
                    "summary": "OpenSearch service",
                    "command": opensearch_cmd,
                    # The charm will start it explicitly once TLS and other
                    # prerequisites are ready, so startup is disabled.
                    "startup": "disabled",
                    "user": PEBBLE_SERVICE_USER,
                    "group": PEBBLE_SERVICE_GROUP,
                    "environment": {
                        "OPENSEARCH_HOME": opensearch_home,
                        "OPENSEARCH_PATH_CONF": opensearch_conf,
                        "JAVA_HOME": java_home,
                        "PATH": path_value,
                    },
                }
            },
        }

        return Layer(layer_dict)

    @override
    def install(self) -> None:
        """No-op for K8s where workload bits come from the container image."""
        return

    @contextmanager
    def temp_file(
        self,
        mode: str = "w+b",
        data: str | None = None,
        encoding: str | None = None,
        dir: PathProtocol | None = None,
        delete: bool = True,
        chown: str | None = None,
        *,
        errors: str | None = None,
        suffix: str | None = None,
    ) -> Generator[PathProtocol, None, None]:
        """Create a temporary file in the container and return the file path.

        Args:
            mode: file mode
            data: Optional string data to write to the file.
            encoding: encoding for data writing (defaults to utf-8).
            dir: Optional directory path.
            delete: If True, delete the file when context exits.
            errors: Error handling mode
            suffix: Optional suffix to append to filename.

        Yields:
            PathProtocol: Path object representing the temporary file.

        Raises:
            PebbleError: if file operations fail.
        """
        # PathProtocol exposes text operations.
        temp_dir_path = dir or self.paths.tmp
        self.mkdir(
            temp_dir_path,
            mode=DIR_PERMISSIONS_READONLY,
            parents=True,
            exist_ok=True,
        )

        temp_filename = "temp_%s%s" % (uuid.uuid4().hex, suffix or "")
        file_path = temp_dir_path / temp_filename

        try:
            if data is not None:
                file_path.write_text(data)
            yield file_path
        finally:
            if not delete:
                return
            try:
                file_path.unlink()
            except FileNotFoundError:
                pass
            except PebbleConnectionError as e:
                logger.warning("Failed to delete temp file %s: %s", file_path, e)
            except (PebbleError, ModelError, OSError, ValueError) as e:
                logger.warning("Failed to delete temp file %s: %s", file_path, e)

    @override
    def run_script(self, script_name: str, args: str | None = None):
        """Run script provided by OpenSearch in the container.

        Args:
            script_name: the name of script file to execute.
            args: arguments passed to the script as a space-separated string.

        Returns:
            SimpleNamespace: command result with cmd, out, err, returncode attributes.

        Raises:
            OpenSearchCmdError: if container is not connected or script execution fails.
        """
        script_path = f"{self.paths.home}/{script_name}"
        bash_cmd = f"bash {script_path}"
        full_command = f"{bash_cmd} {args}" if args is not None else bash_cmd
        env_setup = self._build_script_environment(full_command)
        result = self.run_cmd("bash -c", shlex.quote(env_setup))
        return SimpleNamespace(cmd=env_setup, out=result.out, err=result.err, returncode=0)

    def _build_script_environment(self, command: str) -> str:
        """Build environment setup string for script execution.

        Sets up environment variables needed by OpenSearch scripts:
        - OPENSEARCH_HOME: OpenSearch installation directory
        - OPENSEARCH_PATH_CONF: Configuration directory
        - JAVA_HOME: Java installation directory
        - PATH: Includes Java bin and OpenSearch bin directories

        Args:
            command: script command to execute after environment setup.

        Returns:
            str: environment setup string with exports and command.
        """
        java_home = self.paths.jdk
        opensearch_home = self.paths.home
        opensearch_bin = self.paths.bin
        opensearch_conf = self.paths.conf

        # build PATH with Java bin, OpenSearch bin, and system paths
        path_value = "%s/bin:%s:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" % (
            java_home,
            opensearch_bin,
        )

        # use export to make variables available to the script
        # bash -c expects a single string argument, and the shell will handle
        # argument parsing correctly.
        return (
            'export OPENSEARCH_HOME="%s" && '
            'export OPENSEARCH_PATH_CONF="%s" && '
            'export JAVA_HOME="%s" && '
            'export PATH="%s" && '
            "%s"
        ) % (opensearch_home, opensearch_conf, java_home, path_value, command)

    @property
    @override
    def keytool_cmd(self) -> str:
        """Return keytool command path from the workload JDK."""
        return (self.paths.jdk / "bin" / "keytool").as_posix()

    def _get_pod_fqdn(self) -> str | None:
        """Get pod FQDN using hostname -f command.

        In K8s, hostname -f returns the pods FQDN that resolves via DNS.

        Returns:
            str or None: FQDN if successful, None otherwise.
        """
        try:
            if (
                (result := self.run_cmd("hostname", args="-f"))
                and result.returncode == 0
                and isinstance(result.out, str)
                and result.out.strip()
            ):
                return result.out.strip()
        except OpenSearchCmdError as e:
            logger.debug("Failed to get FQDN via 'hostname -f', will try fallback. Error: %s", e)
        return None

    def _verify_hostname_resolves(self, hostname: str) -> bool:
        """Verify that hostname resolves via DNS using getent.

        Args:
            hostname: hostname to verify.

        Returns:
            bool: True if hostname resolves, False otherwise.
        """
        try:
            fqdn_result = self.run_cmd("getent", args="hosts %s" % hostname)
            return fqdn_result.returncode == 0
        except OpenSearchCmdError as e:
            logger.debug("Failed to get FQDN via 'getent hosts', using hostname. Error: %s", e)
            return False

    @override
    def is_service_started(self, paused: bool | None = False) -> bool:
        """Check if the OpenSearch service is running in the container.

        Args:
            paused: set to True if the process was intentionally paused.

        Returns:
            True if service is running, False otherwise.
        """
        try:
            if not self.container.can_connect():
                return False

            service = self._get_service()
            if service is None:
                return False

            if service.current == ServiceStatus.ACTIVE:
                return True
            if paused and service.current == ServiceStatus.INACTIVE:
                return True

            return False
        except (PebbleConnectionError, PebbleError, ModelError, TypeError) as e:
            logger.debug("Error checking service status: %s", e)
            return False

    @override
    def start_service_only(self):
        """Start the actual pebble service.

        Raises:
            OpenSearchStartError: if container is not ready or service start fails.
        """
        try:
            if not self.container.can_connect():
                raise OpenSearchStartError("Container is not ready")

            # ensure plan is present and readiness checks are enabled when starting intentionally.
            self._configure_pebble_plan(enable_checks=True)
            self.container.start(OPENSEARCH_PEBBLE_SERVICE_NAME)
        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.error("Failed to start the %s service: %s", OPENSEARCH_PEBBLE_SERVICE_NAME, e)
            raise OpenSearchStartError() from e

    @override
    def is_failed(self) -> bool:
        """Check if pebble service failed.

        Returns:
            bool: True if service status is ERROR, False otherwise.
        """
        try:
            if not self.container.can_connect():
                return False

            service = self._get_service()
            if service is None:
                return False

            return service.current == ServiceStatus.ERROR
        except (PebbleConnectionError, PebbleError, ModelError, KeyError, TypeError) as e:
            logger.warning("Failed to check if service is failed: %s", e)
            return False

    @override
    def start_service(self):
        """Start the OpenSearch service.

        Ensures pebble plan is configured before starting.
        If service is already active, returns without error.

        Raises:
            OpenSearchStartError: if container is not ready or service start fails.
        """
        try:
            if not self.container.can_connect():
                raise OpenSearchStartError("Container is not ready")

            # ensure pebble plan is configured before starting
            self._configure_pebble_plan(enable_checks=True)

            service = self._get_service()
            if service is not None and service.current == ServiceStatus.ACTIVE:
                logger.info("The %s service is already started.", OPENSEARCH_PEBBLE_SERVICE_NAME)
                return

            self.container.start(OPENSEARCH_PEBBLE_SERVICE_NAME)
        except (PebbleConnectionError, PebbleError, ModelError, TypeError) as e:
            logger.error("Failed to start the %s service: %s", OPENSEARCH_PEBBLE_SERVICE_NAME, e)
            raise OpenSearchStartError() from e

    @override
    def check_missing_system_requirements(self) -> list[str]:
        """Checks the system requirements for K8s.

        If a sysctl cannot be read, the charm will be blocked
        as this indicates a configuration issue.

        Returns:
            list[str]: List of missing requirement error messages.
        """
        missing_requirements = []

        # hard requirements (block if unmet).
        for property_name, required_value, comparison_op, config_method in [
            ("vm.max_map_count", 262144, "<", "node level: sysctl -w"),
            ("vm.swappiness", 0, ">", "node level: sysctl -w"),
        ]:
            if error_message := self._check_kernel_property_requirement(
                property_name, required_value, comparison_op, config_method
            ):
                missing_requirements.append(error_message)

        # Currently, soft requirement (warn-only): tcp_retries2 should be
        # lowered for better stability. Do not block charm execution if this is not set.
        # TODO: deploy the K8s admission webhook mutator to the K8s environment
        #  and put the charm to blocked when tcp_retries2 values is not lowered
        tcp_retries2_config_method = (
            "recommended net.ipv4.tcp_retries2=5 (configure at kubelet/node level as appropriate)"
        )
        if warn_message := self._check_kernel_property_requirement(
            "net.ipv4.tcp_retries2",
            5,
            ">",
            tcp_retries2_config_method,
        ):
            logger.warning("Non-blocking system recommendation: %s", warn_message)

        return missing_requirements

    def _check_kernel_property_requirement(
        self,
        property_name: str,
        required_value: int,
        comparison_op: Literal["<", ">"],
        config_method: str,
    ) -> str | None:
        """Check if a kernel property meets the required value.

        Args:
            property_name: Kernel property name (e.g. "vm.max_map_count").
            required_value: Required value for the property.
            comparison_op: Comparison operator ("<" or ">") to check
             if current value does not meet the requirement.
            config_method: Description of how to configure this property in K8s.

        Raises:
            OpenSearchCmdError: If the kernel property value cannot be read.

        Returns:
            str or None: Error message if requirement is not met, None otherwise.
        """
        current_value = self._get_kernel_property_value(property_name)
        violates = False
        if comparison_op == "<":
            violates = current_value < required_value
        elif comparison_op == ">":
            violates = current_value > required_value
        else:
            logger.error(
                "Invalid comparison operator '%s' for kernel property check", comparison_op
            )
            raise ValueError("Invalid comparison operator: %s" % comparison_op)

        if violates:
            comparison_text = "below" if comparison_op == "<" else "above"
            fix_instruction = "%s=%s" % (property_name, required_value)
            return (
                "%s=%s is %s recommended %s. " "For K8s deployments, configure via %s: %s."
            ) % (
                property_name,
                current_value,
                comparison_text,
                required_value,
                config_method,
                fix_instruction,
            )

        return None

    @override
    def run_cmd(
        self,
        command: str,
        args: str | None = None,
        use_errors_replace: bool = False,
        stdin: str | None = None,
    ) -> SimpleNamespace:
        """Run command in the container.

        Args:
            command: command to run, can contain arguments
            args: additional command line arguments
            stdin: string input to be passed on the standard input
            use_errors_replace: ignored in K8s (kept for interface compatibility)

        Returns:
            SimpleNamespace with cmd, out, err, return code attributes

        Raises:
            OpenSearchCmdError: If command execution fails or container is not ready
        """
        command_with_args = "%s %s" % (command, args) if args is not None else command
        masked_command = mask_sensitive_information(command_with_args)
        logger.debug("Executing command in container: %s", masked_command)

        try:
            if not self.container.can_connect():
                raise OpenSearchCmdError(cmd=command, out="", err="Container not connected")

            cmd_list = build_command_list(command_with_args)
            logger.debug("Executing command list: %s", cmd_list)

            process = self.container.exec(
                cmd_list, stdin=stdin, encoding="utf-8", combine_stderr=True, timeout=30
            )

            stdout, stderr = wait_for_process_output(process, masked_command, command)
            logger.debug(
                "%s:\nstdout: %s\nstderr: %s\nreturncode: 0", masked_command, stdout, stderr
            )

            # err is typically empty because combine_stderr=True merges stderr into stdout
            return SimpleNamespace(cmd=command, out=stdout, err=stderr, returncode=0)

        except (PebbleConnectionError, PebbleError, ModelError, OSError, ValueError) as e:
            logger.warning(
                "Error executing command %s: %s: %s", masked_command, type(e).__name__, e
            )
            raise OpenSearchCmdError(cmd=command, out="", err=str(e)) from e

    @override
    def stop(self) -> None:
        """Stop the OpenSearch service.

        Raises:
            OpenSearchStopError: If container is not ready or service stop fails.
        """
        try:
            if not self.container.can_connect():
                raise OpenSearchStopError("Container is not ready")

            self.container.stop(OPENSEARCH_PEBBLE_SERVICE_NAME)
        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.error("Failed to stop the %s service: %s", OPENSEARCH_PEBBLE_SERVICE_NAME, e)
            raise OpenSearchStopError() from e

    @property
    @override
    def paths(self) -> BasePaths:
        """Return Workload's paths.

        This is cached to avoid recreating K8sPaths on every access, since self.root
        is a ContainerPath bound to self.container.
        """
        if self._paths is None:
            # access self.root which depends on self.container
            # this may raise RuntimeError if container isn't set, which is expected
            # during initialization before container is available
            root_path = self.root
            self._paths = K8sPaths(root_path, self.charm_root)
        return self._paths

    @property
    @override
    def root(self) -> PathProtocol:
        """Return the root path for container filesystem.

        For K8s containers, use PathOps ContainerPath for container API.
        ContainerPath handles pull/push operations internally via its read_text/write_text methods.

        Returns:
            PathProtocol: ContainerPath instance bound to the container.
        """
        return pathops.ContainerPath("/", container=self.container)

    @override
    def chain_path(self) -> str:
        """Copy chain.pem from the workload container to charm-local /tmp and return the path.

        Requests runs in the charm container, so chain.pem must be staged locally.
        """
        staged_dir = pathops.LocalPath("/tmp") / "opensearch-certs"
        staged_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        staged_path = staged_dir / "chain.pem"

        try:
            if self.exists(self.paths.certs_chain):
                staged_path.write_text(self.read_text(self.paths.certs_chain), mode=0o644)
                return staged_path.as_posix()
        except OpenSearchFileOperationError as e:
            logger.warning(
                "Failed to read chain.pem from %s (%s); falling back to staged copy if present",
                self.paths.certs_chain.as_posix(),
                e,
            )

        if staged_path.exists():
            return staged_path.as_posix()

        raise OpenSearchFileOperationError("chain.pem not available yet")

    @override
    def get_workload_version(self) -> str:
        """Get the workload version."""
        return self.run_cmd(
            f"{self.paths.bin}/opensearch", args="--version 2>/dev/null"
        ).out.strip()

    @property
    def opensearch_keystore_binary(self) -> str:
        """Return the path to the opensearch-keystore binary."""
        return (self.paths.bin / "opensearch-keystore").as_posix()

    @override
    def memtotal(self) -> float:
        """Return memory size from cgroup memory info in kbytes.

        Returns:
            float: The total memory of the system in bytes.

        Raises:
            OpenSearchCmdError: If there is an error reading the memory information.
        """
        cgroup1_path = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
        cgroup2_path = "/sys/fs/cgroup/memory.max"

        for path in [cgroup2_path, cgroup1_path]:
            try:
                result = self.run_cmd("cat", args=path)
                # result can be int or max for cgroup v2, check if it's a digit before converting
                if result.returncode == 0:
                    if result.out.strip().isdigit():
                        return float(result.out.strip()) / 1024  # convert bytes to kbytes
                    elif result.out.strip() == "max":
                        logger.debug("Memory limit is 'max' in cgroup v2, treating as unlimited")
                        return MAX_HEAP_SIZE_IN_KB
                    else:
                        raise OpenSearchCmdError(
                            cmd=f"cat {path}",
                            out=result.out,
                            err="Unexpected output format for memory info",
                        )
            except OpenSearchCmdError as e:
                logger.debug("Failed to read memory info from %s: %s", path, e)
        raise OpenSearchCmdError(
            cmd="cat",
            out="",
            err="Failed to read memory info from both cgroup v1 and v2 paths",
        )
