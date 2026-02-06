#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes Workload."""

import logging
from contextlib import contextmanager
from pathlib import PurePath
from types import SimpleNamespace
from typing import TYPE_CHECKING, Optional

from charmlibs.pathops import PathProtocol
from ops import Container
from ops.model import ModelError
from ops.pebble import ConnectionError as PebbleConnectionError
from ops.pebble import Error as PebbleError
from ops.pebble import ServiceStatus
from overrides import override

from opensearch_single_kernel.common.constants import (
    BASE_SNAP_DIR,
    SNAP,
    SNAP_COMMON,
    SNAP_DATA,
    OpenSearchPaths,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchInstallError,
    OpenSearchStartError,
    OpenSearchStopError,
)
from opensearch_single_kernel.utils.helpers import mask_sensitive_information
from opensearch_single_kernel.workload.base import BaseWorkload, Paths

if TYPE_CHECKING:
    from typing import Callable

logger = logging.getLogger(__name__)


CONTAINER_NAME = "opensearch"


class ContainerPathProtocol(PathProtocol):
    """PathProtocol implementation for container filesystem operations."""

    def __init__(self, path: str, container: Container):
        """Initialize container path.

        Args:
            path: Path string (e.g., "/var/snap/opensearch/current/etc/opensearch")
            container: Container instance for file operations
        """
        self._path = PurePath(path)
        self._container = container

    def __truediv__(self, other):
        """Support path / operator."""
        new_path = self._path / str(other)
        return ContainerPathProtocol(str(new_path), self._container)

    def __str__(self):
        """Return string representation."""
        return str(self._path)

    def __repr__(self):
        """Return representation."""
        return f"ContainerPathProtocol('{self._path}')"

    @property
    def parent(self):
        """Return parent path."""
        return ContainerPathProtocol(str(self._path.parent), self._container)

    def as_posix(self) -> str:
        """Return the string representation of the path with forward slashes."""
        if self._path is None:
            raise ValueError("Path is None")
        return self._path.as_posix()

    def exists(self) -> bool:
        """Check if path exists in container."""
        try:
            if not self._container.can_connect():
                return False
            # try to list the path, if it exists, list_files won't raise an error
            self._container.list_files(str(self._path), itself=True)
            return True
        except (PebbleConnectionError, PebbleError, ModelError, OSError) as e:
            logger.warning(f"Failed to check if path exists: {self._path}. Error: {e}")
            return False

    def read_text(self, encoding: str = "utf-8") -> str:
        """Read text from file in container."""
        if not self._container.can_connect():
            raise OSError("Container not connected")
        try:
            # container.pull() can return a file or a string
            content = self._container.pull(str(self._path), encoding=encoding)
            if hasattr(content, "read"):
                # content is a file-like object, read from it to get the string
                return content.read()
            # content is already a string
            return content
        except (PebbleConnectionError, PebbleError, ModelError, FileNotFoundError) as e:
            logger.warning(f"Failed to read file from container: {self._path}. Error: {e}")
            raise OSError(f"Failed to read {self._path}: {e}") from e

    def write_text(self, data: str, encoding: str = "utf-8") -> int:
        """Write text to file in container."""
        if not self._container.can_connect():
            raise OSError("Container not connected")
        try:
            self._container.push(str(self._path), data, encoding=encoding, make_dirs=True)
            return len(data.encode(encoding))
        except (PebbleConnectionError, PebbleError, ModelError, OSError, PermissionError) as e:
            logger.warning(f"Failed to write file to container: {self._path}. Error: {e}")
            raise OSError(f"Failed to write {self._path}: {e}") from e

    def mkdir(self, parents: bool = False, exist_ok: bool = False) -> None:
        """Create directory in container."""
        if not self._container.can_connect():
            raise OSError("Container not connected")
        try:
            self._container.make_dir(str(self._path), make_parents=parents)
        except (PebbleConnectionError, PebbleError, ModelError, OSError, FileExistsError) as e:
            if exist_ok and ("already exists" in str(e).lower() or isinstance(e, FileExistsError)):
                logger.debug(f"Directory already exists (ignored): {self._path}")
            else:
                logger.warning(
                    f"Failed to create directory in container: {self._path}. Error: {e}"
                )
                raise OSError(f"Failed to create directory {self._path}: {e}") from e

    def unlink(self, missing_ok: bool = False) -> None:
        """Remove file in container."""
        if not self._container.can_connect():
            if missing_ok:
                return
            raise OSError("Container not connected")
        try:
            self._container.remove_path(str(self._path), recursive=False)
        except (PebbleConnectionError, PebbleError, ModelError, FileNotFoundError) as e:
            if missing_ok or isinstance(e, FileNotFoundError):
                logger.debug(f"File not found during removal (ignored): {self._path}")
            else:
                logger.warning(f"Failed to remove file from container: {self._path}. Error: {e}")
                raise OSError(f"Failed to remove {self._path}: {e}") from e


class K8sPaths(Paths):
    """K8s-specific paths implementation for container filesystem."""

    def __init__(self, root: PathProtocol):
        super().__init__(root)

    @property
    def base_snap_dir(self) -> PathProtocol:
        """Return path to the Base snap directory."""
        return self.root / BASE_SNAP_DIR

    @property
    def snap_data(self) -> PathProtocol:
        """Return path to the snap data directory."""
        return self.base_snap_dir / SNAP_DATA

    @property
    def snap_common(self) -> PathProtocol:
        """Return path to the snap common directory."""
        return self.base_snap_dir / SNAP_COMMON

    @property
    def snap(self) -> PathProtocol:
        """Return path to the snap directory."""
        return self.root / SNAP

    @property
    def home(self) -> PathProtocol:
        """Return path to the home snap directory."""
        return self.snap_data / OpenSearchPaths.HOME.val

    @property
    def conf(self) -> PathProtocol:
        """Return path to the conf snap directory."""
        return self.snap_data / OpenSearchPaths.CONF.val

    @property
    def data(self) -> PathProtocol:
        """Return path to the data snap directory."""
        return self.snap_common / OpenSearchPaths.DATA.val

    @property
    def logs(self) -> PathProtocol:
        """Return path to the logs snap directory."""
        return self.snap_common / OpenSearchPaths.LOGS.val

    @property
    def jdk(self) -> PathProtocol:
        """Return path to the jdk directory."""
        return self.snap / OpenSearchPaths.JDK.val

    @property
    def tmp(self) -> PathProtocol:
        """Return path to the tmp directory."""
        return self.snap_common / OpenSearchPaths.TMP.val

    @property
    def bin(self) -> PathProtocol:
        """Return path to the bin directory."""
        return self.snap / OpenSearchPaths.BIN.val


class K8sWorkload(BaseWorkload):
    """Kubernetes OpenSearch Workload."""

    SERVICE_NAME = "opensearch"

    def __init__(self, container_getter: Optional["Callable[[], Container]"] = None):
        """Initialize K8s workload.

        Args:
            container_getter: Callable that returns the Container instance.
                If None, container will need to be set via set_container().
        """
        super().__init__()
        self._container_getter = container_getter
        self._container: Optional[Container] = None

    def set_container(self, container: Container) -> None:
        """Set the container instance.

        Args:
            container: The Container instance to use.
        """
        self._container = container

    @property
    def container(self) -> Container:
        """Get the container instance."""
        if self._container is not None:
            return self._container
        if self._container_getter is not None:
            return self._container_getter()
        raise RuntimeError(
            "Container not set. Use set_container() or provide container_getter in __init__"
        )

    @property
    @override
    def workload_present(self) -> bool:
        """Check if the container is ready and connected."""
        try:
            container = self.container
            return container.can_connect()
        except (RuntimeError, ModelError):
            return False

    @override
    def install(self) -> None:
        """Install the workload.

        For K8s, installation is handled by the container image.
        This method ensures the container is ready.
        """
        try:
            # check if container is ready
            if not self.container.can_connect():
                raise OpenSearchInstallError("Container is not ready")
        except (PebbleConnectionError, ModelError) as e:
            logger.error(f"Failed to verify container readiness: {e}")
            raise OpenSearchInstallError() from e

    @contextmanager
    def temp_file(
        self,
        mode="w+b",
        data: str | None = None,
        encoding: str | None = None,
        dir: PathProtocol | None = None,
        delete: bool = True,
        *,
        errors: str | None = None,
        suffix: str | None = None,
    ):
        """Create a temporary file in the container and return the file path."""
        import uuid

        # determine directory for temp file
        temp_dir = str(self.paths.tmp) if dir is None else str(dir)

        # ensure directory exists
        try:
            self.container.make_dir(temp_dir, make_parents=True, permissions=0o755)
        except (PebbleError, FileExistsError) as e:
            logger.debug(f"Directory might already exist (ignored): {temp_dir}. Error: {e}")

        temp_filename = f"temp_{uuid.uuid4().hex}{suffix or ''}"
        file_path_str = f"{temp_dir}/{temp_filename}"
        file_path = self.root / file_path_str.lstrip("/")

        try:
            if data:
                self.container.push(
                    file_path_str, data, encoding=encoding or "utf-8", make_dirs=True
                )
            yield file_path
        finally:
            if delete:
                try:
                    self.container.remove_path(file_path_str, recursive=True)
                except (PebbleError, ModelError, FileNotFoundError) as e:
                    logger.warning(f"Failed to delete temp file {file_path_str}: {e}")

    @override
    def run_script(self, script_name: str, args: str = None):
        """Run script provided by OpenSearch in the container.

        Args:
            script_name: The name of script file to execute.
            args: Arguments passed to the script.
        """
        script_path = f"{self.paths.home}/{script_name}"
        full_command = f"{script_path}"
        if args:
            full_command = f"{full_command} {args}"

        self.run_cmd("bash", args=f"-c '{full_command}'")

    @override
    def get_host_public_ip(self) -> str | None:  # noqa: C901
        """Fetches the Public IP address of the current unit.

        For K8s, this returns the pod's DNS name instead of IP address.
        DNS names are stable and resolve to the current pod IP via K8s DNS.

        This DNS name is used for:
        - OpenSearch http.publish_host configuration
        - TLS certificate SANs (Subject Alternative Names)
        - Any other configuration requiring a stable address

        Returns:
            DNS name (FQDN or hostname) for K8s, or None if unavailable
        """
        try:
            # Get pod FQDN
            # In K8s, hostname -f returns the pod's FQDN that resolves via DNS
            result = self.run_cmd("hostname", args="-f")
            if result.returncode == 0 and result.out.strip():
                return result.out.strip()
        except OpenSearchCmdError as e:
            logger.debug(f"Failed to get FQDN via 'hostname -f', will try fallback. Error: {e}")

        # fallback: try to get pod hostname
        # This will still resolve via K8s DNS
        try:
            result = self.run_cmd("hostname")
            if result.returncode == 0 and result.out.strip():
                hostname = result.out.strip()
                # If hostname doesn't contain dots, try to get FQDN via getent
                if "." not in hostname:
                    try:
                        fqdn_result = self.run_cmd("getent", args=f"hosts {hostname}")
                        if fqdn_result.returncode == 0:
                            # Return the hostname itself, it will resolve via K8s DNS
                            return hostname
                    except OpenSearchCmdError as e:
                        logger.debug(
                            f"Failed to get FQDN via 'getent hosts', using hostname. Error: {e}"
                        )
                return hostname
        except OpenSearchCmdError as e:
            logger.warning(
                f"Failed to get pod hostname, cannot determine stable DNS name. Error: {e}"
            )

        return None

    @override
    def is_service_started(self, paused: bool | None = False) -> bool:
        """Check if the OpenSearch service is running in the container.

        Args:
            paused: Set to True if the process was intentionally paused.

        Returns:
            True if service is running, False otherwise.
        """
        try:
            if not self.container.can_connect():
                return False

            services = self.container.get_services([self.SERVICE_NAME])
            if self.SERVICE_NAME not in services:
                return False

            service = services[self.SERVICE_NAME]
            if service.current == ServiceStatus.ACTIVE:
                return True
            if paused and service.current == ServiceStatus.INACTIVE:
                return True

            return False
        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.debug(f"Error checking service status: {e}")
            return False

    @override
    def start_pebble_service(self):
        """Start the actual pebble service."""
        try:
            if not self.container.can_connect():
                raise OpenSearchStartError("Container is not ready")

            self.container.start(self.SERVICE_NAME)
        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.error(f"Failed to start the {self.SERVICE_NAME} service: {e}")
            raise OpenSearchStartError() from e

    @override
    def is_failed(self) -> bool:
        """Check if pebble service failed."""
        try:
            if not self.container.can_connect():
                return False

            services = self.container.get_services([self.SERVICE_NAME])
            if self.SERVICE_NAME not in services:
                return False

            service = services[self.SERVICE_NAME]
            return service.current == ServiceStatus.ERROR
        except (PebbleConnectionError, PebbleError, ModelError, KeyError) as e:
            logger.warning(f"Failed to check if service is failed: {e}")
            return False

    @override
    def start_service(self):
        """Start the OpenSearch service."""
        try:
            if not self.container.can_connect():
                raise OpenSearchStartError("Container is not ready")

            services = self.container.get_services([self.SERVICE_NAME])
            if self.SERVICE_NAME in services:
                service = services[self.SERVICE_NAME]
                if service.current == ServiceStatus.ACTIVE:
                    logger.info(f"The {self.SERVICE_NAME} service is already started.")
                    return

            self.container.start(self.SERVICE_NAME)
        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.error(f"Failed to start the {self.SERVICE_NAME} service: {e}")
            raise OpenSearchStartError() from e

    @override
    def meminfo(self) -> dict[str, float]:
        """Read the /proc/meminfo file and return the values.

        Returns:
            meminfo: The memory info values in kB.
        """
        try:
            # Use cat command directly with the file path
            result = self.run_cmd("cat /proc/meminfo")
            meminfo_lines = result.out.split("\n")
            meminfo = [line.split() for line in meminfo_lines if line.strip()]

            return {line[0][:-1]: float(line[1]) for line in meminfo if len(line) >= 2}
        except OpenSearchCmdError as e:
            # try to parse the output from the error
            if e.out:
                try:
                    meminfo_lines = e.out.split("\n")
                    meminfo = [line.split() for line in meminfo_lines if line.strip()]
                    parsed = {line[0][:-1]: float(line[1]) for line in meminfo if len(line) >= 2}
                    if parsed:
                        logger.debug(
                            f"Successfully parsed meminfo from command output despite non-zero exit code: {parsed}"
                        )
                        return parsed
                except (ValueError, IndexError, AttributeError) as parse_error:
                    logger.warning(f"Failed to parse meminfo output: {parse_error}")
            logger.warning(f"Failed to read meminfo: {e}")
            return {}
        except OSError as e:
            logger.warning(f"Failed to read meminfo: {e}")
            return {}

    @override
    def _apply_system_requirement(self, system_requirement: str, value: int) -> bool:
        """Apply a system requirement.

        For K8s, system requirements are typically handled at the pod/container level
        via security contexts and init containers. This method attempts to set sysctl
        values if possible.

        Args:
            system_requirement: Kernel parameter to update.
            value: Value of the kernel parameter.

        Returns:
            applied: Whether the kernel value is applied successfully.
        """
        try:
            # try to apply sysctl in container, may require privileged container
            self.run_cmd("sysctl", args=f"-w {system_requirement}={value}")
            result = self.run_cmd("sysctl", args=f"-n {system_requirement}")
            return int(result.out.rstrip()) == value
        except OpenSearchCmdError:
            # In K8s, sysctl changes may require privileged containers or init containers
            logger.warning(
                f"Cannot set {system_requirement}={value} in container. "
                "Ensure container has necessary privileges or configure via pod security context."
            )
            return False

    @override
    def check_missing_system_requirements(self) -> list[str]:
        """Checks the system requirements for K8s.

        In Kubernetes, vm.* and fs.* sysctls cannot be set from within containers
        and must be configured at the node level. Missing requirements will block
        the charm.
        """
        missing_requirements = []

        # Check vm.max_map_count
        prop, val = "vm.max_map_count", 262144
        current_val = self._get_kernel_property_value(prop)
        if current_val < val:
            error_msg = (
                f"vm.max_map_count={current_val} is below recommended {val}. "
                "For K8s deployments, configure at node level: "
                "sysctl -w vm.max_map_count=262144"
            )
            logger.warning(error_msg)
            missing_requirements.append(error_msg)

        # Check vm.swappiness
        prop, val = "vm.swappiness", 0
        current_val = self._get_kernel_property_value(prop)
        if current_val > val:
            error_msg = (
                f"vm.swappiness={current_val} is above recommended {val}. "
                "For K8s deployments, configure at node level: "
                "sysctl -w vm.swappiness=0"
            )
            logger.warning(error_msg)
            missing_requirements.append(error_msg)

        # Check net.ipv4.tcp_retries2
        prop, val = "net.ipv4.tcp_retries2", 5
        current_val = self._get_kernel_property_value(prop)
        if current_val > val:
            error_msg = (
                f"net.ipv4.tcp_retries2={current_val} is above recommended {val}. "
                "This should be configured via pod securityContext."
            )
            logger.warning(error_msg)
            missing_requirements.append(error_msg)

        return missing_requirements

    @override
    def _get_kernel_property_value(self, prop: str) -> int:
        """Get the value of a kernel parameter.

        Args:
            prop: Kernel property name.

        Returns:
            value: Kernel property value.
        """
        try:
            result = self.run_cmd("sysctl", args=f"-n {prop}")
            return int(result.out.rstrip())
        except OpenSearchCmdError:
            # Return a default value if we can't read it
            logger.warning(f"Cannot read kernel property {prop} from container")
            return 0

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
            command: Command to run, can contain arguments
            args: Additional command line arguments
            stdin: String input to be passed on the standard input
            use_errors_replace: Ignored in K8s (kept for interface compatibility)

        Returns:
            SimpleNamespace with cmd, out, err, returncode attributes
        """
        command_with_args = command
        if args is not None:
            command_with_args = f"{command} {args}"

        # Mask sensitive information for logging
        masked_command = mask_sensitive_information(command_with_args)
        logger.debug(f"Executing command in container: {masked_command}")

        try:
            if not self.container.can_connect():
                raise OpenSearchCmdError(cmd=command, out="", err="Container not connected")

            # split command into list for exec
            # handle shell commands by wrapping in bash -c
            if " " in command_with_args or "|" in command_with_args or ">" in command_with_args:
                cmd_list = ["bash", "-c", command_with_args]
            else:
                cmd_list = command_with_args.split()

            process = self.container.exec(
                cmd_list,
                stdin=stdin.encode("utf-8") if stdin else None,
                encoding="utf-8",
                combine_stderr=True,
            )

            # wait_output() waits for the process and returns (stdout, stderr)
            # wait() returns the exit code
            stdout, stderr = process.wait_output()
            returncode = process.wait()

            logger.debug(f"{masked_command}:\n{stdout}")

            if returncode != 0:
                logger.debug(f"{masked_command}:\n Stderr: {stderr}\n Stdout: {stdout}")
                raise OpenSearchCmdError(cmd=command, out=stdout, err=stderr)

            return SimpleNamespace(cmd=command, out=stdout, err=stderr, returncode=returncode)
        except (PebbleConnectionError, PebbleError, ModelError, OSError, ValueError) as e:
            if isinstance(e, OpenSearchCmdError):
                raise
            logger.error(f"Error executing command {masked_command}: {e}")
            raise OpenSearchCmdError(cmd=command, out="", err=str(e)) from e

    @override
    def stop(self) -> None:
        """Stop the OpenSearch service."""
        try:
            if not self.container.can_connect():
                raise OpenSearchStopError("Container is not ready")

            self.container.stop(self.SERVICE_NAME)
        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.error(f"Failed to stop the {self.SERVICE_NAME} service: {e}")
            raise OpenSearchStopError() from e

    @property
    @override
    def paths(self) -> Paths:
        """Return Workload's paths."""
        return K8sPaths(self.root)

    @property
    @override
    def root(self) -> PathProtocol:
        """Return the root path for container filesystem."""
        # For K8s containers, use ContainerPathProtocol for container API
        return ContainerPathProtocol("/", self.container)
