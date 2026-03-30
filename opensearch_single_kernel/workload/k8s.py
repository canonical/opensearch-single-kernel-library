# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes Workload."""

import logging
import shlex
import uuid
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from types import SimpleNamespace

from charmlibs import pathops
from charmlibs.pathops import PathProtocol
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
    DIR_PERMISSIONS_CERTIFICATES,
    DIR_PERMISSIONS_READONLY,
    DIR_PERMISSIONS_SECURE,
    OPENSEARCH_PEBBLE_SERVICE_NAME,
    PEBBLE_SERVICE_GROUP,
    PEBBLE_SERVICE_USER,
    OpenSearchPaths,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchContainerPrepareError,
    OpenSearchFileOperationError,
    OpenSearchStartError,
    OpenSearchStopError,
)
from opensearch_single_kernel.utils.helpers import (
    build_command_list,
    mask_sensitive_information,
    path_as_posix,
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

    def __init__(self, root: PathProtocol):
        super().__init__(root)

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


class K8sWorkload(BaseWorkload):
    """Kubernetes OpenSearch Workload."""

    SERVICE_NAME = OPENSEARCH_PEBBLE_SERVICE_NAME

    def __init__(self, container_getter: Callable[[], Container] | None = None):
        """Initialize K8s workload.

        Args:
            container_getter: callable that returns the Container instance.
                If None, accessing container property will raise RuntimeError.
        """
        super().__init__()
        self._container_getter = container_getter
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
    def container(self) -> Container:
        """Get the container instance.

        Returns:
            Container: the Container instance.

        Raises:
            RuntimeError: if container_getter was not provided in constructor.
        """
        if self._container_getter is not None:
            return self._container_getter()
        raise RuntimeError("Container not available. Provide container_getter in __init__")

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

    def _ensure_required_directories(self) -> None:
        """Ensure required directories exist for OpenSearch to run.

        This method is idempotent and is intended to be called from the
        K8s pebble-ready hook before starting the service.
        """
        # Pebble file API resolves user/group by *name*, not numeric UID/GID.
        user = str(PEBBLE_SERVICE_USER)
        group = str(PEBBLE_SERVICE_GROUP)
        root_group = "root"
        required_dirs: list[tuple[PathProtocol, int]] = [
            (self.paths.data, DIR_PERMISSIONS_SECURE),
            (self.paths.logs, DIR_PERMISSIONS_SECURE),
            (self.paths.conf, DIR_PERMISSIONS_READONLY),
            (self.paths.certs, DIR_PERMISSIONS_CERTIFICATES),
            (self.paths.home / "logs", DIR_PERMISSIONS_READONLY),
        ]

        for dir_path, mode in required_dirs:
            try:
                dir_group = root_group if dir_path == self.paths.certs else group
                dir_path.mkdir(mode=mode, parents=True, exist_ok=True, user=user, group=dir_group)
            except (PebbleConnectionError, PebbleError, ModelError, OSError, ValueError) as e:
                logger.warning("Failed to ensure directory %s exists: %s", dir_path, e)

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

            logger.info("Configured pebble plan for %s service", self.SERVICE_NAME)

        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.warning("Failed to configure pebble plan: %s", e)
            # this might be called before container is ready

    def prepare_container(self) -> None:
        """Prepare the K8s workload container once it is connectable.

        This is the only place where we apply:
        - directory ownership/permissions
        - pebble plan configuration
        """
        try:
            self._ensure_required_directories()
            self._configure_pebble_plan(enable_checks=False)
        except ModelError as e:
            logger.error("Failed to prepare container on pebble-ready: %s", e)
            raise OpenSearchContainerPrepareError() from e

    def _build_pebble_layer(self) -> Layer:
        """Build Pebble layer for OpenSearch service."""
        opensearch_cmd = path_as_posix(self.paths.bin / "opensearch")
        opensearch_home = path_as_posix(self.paths.home)
        opensearch_conf = path_as_posix(self.paths.conf)
        java_home = path_as_posix(self.paths.jdk)

        # build PATH with Java bin, OpenSearch bin, and system paths
        path_value = (
            "%s/bin:/usr/share/opensearch/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            % java_home
        )

        service_name = OPENSEARCH_PEBBLE_SERVICE_NAME
        layer_dict = {
            "summary": "OpenSearch service layer",
            "description": "Pebble plan layer for OpenSearch",
            "services": {
                service_name: {
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
        mode="w+b",
        data: str | None = None,
        encoding: str | None = None,
        dir: PathProtocol | None = None,
        delete: bool = True,
        *,
        errors: str | None = None,
        suffix: str | None = None,
    ):
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
            if delete:
                try:
                    file_path.unlink()
                except FileNotFoundError:
                    pass
                except PebbleConnectionError as e:
                    logger.warning("Failed to delete temp file %s: %s", file_path, e)
                except (PebbleError, ModelError, OSError, ValueError) as e:
                    logger.warning("Failed to delete temp file %s: %s", file_path, e)

    @override
    def run_script(self, script_name: str, args: str = None):
        """Run script provided by OpenSearch in the container.

        Args:
            script_name: the name of script file to execute.
            args: arguments passed to the script as a space-separated string.

        Returns:
            SimpleNamespace: command result with cmd, out, err, returncode attributes.

        Raises:
            OpenSearchCmdError: if container is not connected or script execution fails.
        """
        script_path = "%s/%s" % (self.paths.home, script_name)
        bash_cmd = "bash %s" % script_path
        full_command = "%s %s" % (bash_cmd, args) if args is not None else bash_cmd
        env_setup = self._build_script_environment(full_command)
        quoted = shlex.quote(env_setup)
        result = self.run_cmd(f"bash -c {quoted}")
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
        java_home = path_as_posix(self.paths.jdk)
        opensearch_home = path_as_posix(self.paths.home)
        opensearch_bin = path_as_posix(self.paths.bin)
        opensearch_conf = path_as_posix(self.paths.conf)

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

    @override
    def get_publish_host(self) -> str | None:
        """Return the pod DNS name used for OpenSearch `http.publish_host`.

        For K8s, this returns the pod DNS name instead of an IP address.
        DNS names are stable and resolve to the current pod IP via K8s DNS.
        """
        # Only attempt container-derived names when the workload container is connectable.
        # In unit tests run_cmd is patched with a MagicMock.
        # When we can't obtain a real string value,
        # return None so callers fall back to state.host_ip / ingress address.
        try:
            if not self.container.can_connect():
                return None
        except Exception:
            return None

        # Pebble is connectable: try to get pod FQDN first, most reliable method.
        if fqdn := self._get_pod_fqdn():
            return fqdn

        # fallback: try to get pod hostname
        return self._get_pod_hostname_with_fallback()

    @property
    @override
    def keytool_cmd(self) -> str:
        """Return keytool command path from the workload JDK."""
        return path_as_posix(self.paths.jdk / "bin" / "keytool")

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

    def _get_pod_hostname_with_fallback(self) -> str | None:
        """Get pod hostname with FQDN fallback attempt.

        Returns:
            str or None: Hostname or FQDN if successful, None otherwise.

        """
        try:
            if (
                (result := self.run_cmd("hostname"))
                and result.returncode == 0
                and isinstance(result.out, str)
                and result.out.strip()
            ):
                hostname = result.out.strip()
                # if hostname doesn't contain dots, verify it resolves via DNS
                if "." not in hostname:
                    if self._verify_hostname_resolves(hostname):
                        return hostname
                return hostname
        except OpenSearchCmdError as e:
            logger.warning(
                "Failed to get pod hostname, cannot determine stable DNS name. Error: %s", e
            )
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
            logger.error("Failed to start the %s service: %s", self.SERVICE_NAME, e)
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
                logger.info("The %s service is already started.", self.SERVICE_NAME)
                return

            self.container.start(OPENSEARCH_PEBBLE_SERVICE_NAME)
        except (PebbleConnectionError, PebbleError, ModelError, TypeError) as e:
            logger.error("Failed to start the %s service: %s", self.SERVICE_NAME, e)
            raise OpenSearchStartError() from e

    @override
    def meminfo(self) -> dict[str, float]:
        """Read the /proc/meminfo file and return the values.

        Returns:
            dict[str, float]: The memory info values in kB. Returns empty dict on error.
        """
        try:
            result = self.run_cmd("cat /proc/meminfo")
            return self._parse_meminfo_output(result.out)
        except OpenSearchCmdError as e:
            # try to parse output from error message if it exists
            if e.out:
                if parsed := self._parse_meminfo_output(e.out):
                    logger.debug(
                        "Successfully parsed meminfo from command output despite non-zero exit code: %s",
                        parsed,
                    )
                    return parsed
            logger.warning("Failed to read meminfo: %s", e)
            return {}
        except OSError as e:
            logger.warning("Failed to read meminfo: %s", e)
            return {}

    @override
    def _apply_system_requirement(self, system_requirement: str, value: int) -> bool:
        """Apply a system requirement.

        This method is kept only to satisfy the BaseWorkload interface.
        """
        logger.debug("Skipping sysctl apply for %s=%s on K8s workload", system_requirement, value)
        return False

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
        hard_requirements = [
            ("vm.max_map_count", 262144, "<", "node level: sysctl -w"),
            ("vm.swappiness", 0, ">", "node level: sysctl -w"),
        ]
        for property_name, required_value, comparison_op, config_method in hard_requirements:
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
        self, property_name: str, required_value: int, comparison_op: str, config_method: str
    ) -> str | None:
        """Check if a kernel property meets the required value.

        Args:
            property_name: Kernel property name (e.g. "vm.max_map_count").
            required_value: Required value for the property.
            comparison_op: Comparison operator ("<" or ">") to check
             if current value does not meet the requirement.
            config_method: Description of how to configure this property in K8s.

        Returns:
            str or None: Error message if requirement is not met, None otherwise.
        """
        current_value = self._get_kernel_property_value(property_name)

        if current_value is None:
            return (
                "Cannot read %s from container. "
                "This may indicate missing permissions or node-level configuration issue. "
                "For K8s deployments, configure via %s."
            ) % (property_name, config_method)

        violates = False
        if comparison_op == "<":
            violates = current_value < required_value
        elif comparison_op == ">":
            violates = current_value > required_value

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
    def _get_kernel_property_value(self, prop: str) -> int | None:
        """Get the value of a kernel parameter.

        Try 3 methods in order to get the value of a kernel parameter:
        1. sysctl -n (most reliable)
        2. sysctl without -n (parse output)
        3. Read directly from /proc/sys/ (fallback)

        Args:
            prop: Kernel property name (e.g., "vm.max_map_count").

        Returns:
            int | None: Kernel property value, or None if cannot be read.
        """
        # try sysctl -n first, most reliable method
        if (property_value := self._read_kernel_property_via_sysctl_n(prop)) is not None:
            return property_value

        # fallback: try sysctl without -n flag
        if (property_value := self._read_kernel_property_via_sysctl(prop)) is not None:
            return property_value

        # final fallback: read directly from /proc/sys/
        return self._read_kernel_property_via_procfs(prop)

    def _read_kernel_property_via_sysctl_n(self, property_name: str) -> int | None:
        """Read kernel property using sysctl -n command.

        Args:
            property_name: Kernel property name.

        Returns:
            int | None: Property value if successful, None otherwise.

        """
        try:
            result = self.run_cmd("sysctl", args="-n %s" % property_name)
            return int(result.out.rstrip())
        except OpenSearchCmdError as e:
            error_message = e.err or e.out or str(e)
            logger.warning("sysctl -n %s failed: %s", property_name, error_message)
            return None

    def _read_kernel_property_via_sysctl(self, property_name: str) -> int | None:
        """Read kernel property using sysctl command and parse output.

        Output format: "vm.max_map_count = 262144"

        Args:
            property_name: Kernel property name.

        Returns:
            int | None: Property value if successful, None otherwise.
        """
        try:
            result = self.run_cmd("sysctl", args=property_name)
            # parse output: "property_name = value" -> extract value
            value_string = result.out.split("=")[-1].strip()
            return int(value_string)
        except OpenSearchCmdError as e:
            error_message = e.err or e.out or str(e)
            logger.warning("sysctl %s failed: %s", property_name, error_message)
            return None
        except (ValueError, IndexError) as e:
            logger.warning("sysctl %s parsing failed: %s", property_name, e)
            return None

    def _read_kernel_property_via_procfs(self, property_name: str) -> int | None:
        """Read kernel property directly from /proc/sys/ filesystem.

        Converts property name to file path:
        "vm.max_map_count" -> "/proc/sys/vm/max_map_count"

        Args:
            property_name: Kernel property name.

        Returns:
            int or None: Property value if successful, None otherwise.

        """
        procfs_path = "/proc/sys/%s" % property_name.replace(".", "/")
        try:
            result = self.run_cmd("cat %s" % procfs_path)
            return int(result.out.strip())
        except (OpenSearchCmdError, ValueError) as e:
            logger.warning("Failed to read %s from /proc/sys/: %s", property_name, e)
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
                cmd_list,
                stdin=stdin.encode("utf-8") if stdin else None,
                encoding="utf-8",
                combine_stderr=True,
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
            logger.error("Failed to stop the %s service: %s", self.SERVICE_NAME, e)
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
            self._paths = K8sPaths(root_path)
        return self._paths

    @override
    def write_text(self, content: str, path: pathops.PathProtocol) -> None:  # type: ignore[override]
        """K8s-safe write, ensure parent dir exists and handle pebble readiness.

        Overrides BaseWorkload.write_text() to ensure parent directories exist
        before writing, which is critical for K8s where directories may not exist
        yet or may disappear during container restarts.

        Args:
            content: Content to write to the file
            path: PathProtocol object representing the file path

        Raises:
            OpenSearchFileOperationError: If container is not ready or file operation fails.
        """
        try:
            path.parent.mkdir(
                mode=DIR_PERMISSIONS_READONLY,
                parents=True,
                exist_ok=True,
            )
            path.write_text(content)
        except (PebbleConnectionError, PebbleError, ModelError, OSError, ValueError) as e:
            raise OpenSearchFileOperationError(e) from e

    @property
    @override
    def root(self) -> PathProtocol:
        """Return the root path for container filesystem.

        For K8s containers, use PathOps ContainerPath for container API.
        ContainerPath handles pull/push operations internally via its read_text/write_text methods.

        Returns:
            PathProtocol: ContainerPath instance bound to the container.
        """
        # for K8s containers, use PathOps ContainerPath for container API
        # containerPath handles pull/push operations internally
        # via its read_text/write_text methods
        return pathops.ContainerPath("/", container=self.container)
