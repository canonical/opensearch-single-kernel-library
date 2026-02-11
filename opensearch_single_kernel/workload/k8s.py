#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes Workload."""

import logging
import uuid
from contextlib import contextmanager
from types import SimpleNamespace
from typing import TYPE_CHECKING, Optional

from charmlibs import pathops
from charmlibs.pathops import PathProtocol
from ops import Container
from ops.model import ModelError
from ops.pebble import (
    CheckDict,
)
from ops.pebble import ConnectionError as PebbleConnectionError
from ops.pebble import Error as PebbleError
from ops.pebble import (
    Layer,
    ServiceStatus,
)
from overrides import override

from opensearch_single_kernel.common.constants import (
    CHMOD_CERTIFICATES,
    CHMOD_SECURE,
    CHMOD_WRITABLE,
    DIR_PERMISSIONS_CERTIFICATES,
    DIR_PERMISSIONS_READONLY,
    DIR_PERMISSIONS_WRITABLE,
    OPENSEARCH_SERVICE_NAME,
    PEBBLE_SERVICE_GROUP,
    PEBBLE_SERVICE_USER,
    OpenSearchPaths,
)
from opensearch_single_kernel.common.exceptions import (
    ContainerNotReadyError,
    OpenSearchCmdError,
    OpenSearchFileOperationError,
    OpenSearchInstallError,
    OpenSearchStartError,
    OpenSearchStopError,
)
from opensearch_single_kernel.utils.helpers import mask_sensitive_information
from opensearch_single_kernel.workload.base import BaseWorkload
from opensearch_single_kernel.workload.base import Paths as BasePaths

if TYPE_CHECKING:
    from typing import Callable

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
        return self.root / "etc" / "opensearch"

    @property
    def data(self) -> PathProtocol:
        """Return path to OpenSearch data directory.

        For K8s rock image: /var/lib/opensearch
        The actual data subdirectory is /var/lib/opensearch/data

        Returns:
            PathProtocol: path to OpenSearch data directory.
        """
        return self.root / "var" / "lib" / "opensearch"

    @property
    def logs(self) -> PathProtocol:
        """Return path to OpenSearch logs directory.

        For K8s rock image: /var/log/opensearch
        Note: The actual logs subdirectory is /var/log/opensearch/logs

        Returns:
            PathProtocol: path to OpenSearch logs directory.
        """
        return self.root / "var" / "log" / "opensearch"

    @property
    def jdk(self) -> PathProtocol:
        """Return path to the jdk directory.

        For K8s containers, JDK is installed at /usr/lib/jvm/java-21-openjdk-amd64
        Hardcoded to ensure correct path regardless of OpenSearchPaths.JDK.val value.

        Returns:
            PathProtocol: path to JDK installation directory.
        """
        return self.root / "usr" / "lib" / "jvm" / "java-21-openjdk-amd64"

    @property
    def tmp(self) -> PathProtocol:
        """Return path to the tmp directory.

        For K8s rock image: /tmp

        Returns:
            PathProtocol: path to /tmp directory.
        """
        return self.root / "tmp"

    @property
    def bin(self) -> PathProtocol:
        """Return path to the bin directory.

        For K8s rock image: /usr/share/opensearch/bin

        Returns:
            PathProtocol: path to OpenSearch bin directory.
        """
        return self.home / "bin"


class K8sWorkload(BaseWorkload):
    """Kubernetes OpenSearch Workload."""

    SERVICE_NAME = OPENSEARCH_SERVICE_NAME

    def __init__(self, container_getter: Optional["Callable[[], Container]"] = None):
        """Initialize K8s workload.

        Args:
            container_getter: callable that returns the Container instance.
                If None, accessing container property will raise RuntimeError.
        """
        super().__init__()
        self._container_getter = container_getter
        self._paths: Optional[BasePaths] = None

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

        Creates:
        - /var/lib/opensearch/data (data directory)
        - /var/log/opensearch/logs (logs directory)
        - /etc/opensearch (config directory, if not exists)
        - /etc/opensearch/certificates (certificates directory - critical for TLS)
        - /usr/share/opensearch/logs (OpenSearch home logs directory)

        This method is idempotent and should be called:
        - During install
        - During start_service
        - During _configure_pebble_plan
        - After container restarts
        """
        if not self.container.can_connect():
            logger.debug("Container not ready, skipping directory creation")
            return

        try:
            self._ensure_data_directory()
            self._ensure_logs_directory()
            self._ensure_config_directory()
            self._ensure_certificates_directory()
            self._ensure_home_logs_directory()
            self._attempt_set_directory_ownership()
        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.warning("Failed to create required directories: %s", e)
            # don't raise, directories might already exist

    def _ensure_data_directory(self) -> None:
        """Create data directory: /var/lib/opensearch/data.

        Raises:
            PebbleError: if directory creation fails.
        """
        data_dir = str(self.paths.data / "data")
        self.container.make_dir(data_dir, make_parents=True, permissions=0o755)
        logger.debug("Ensured data directory exists: %s", data_dir)

    def _ensure_logs_directory(self) -> None:  # noqa C901
        """Create logs directory (/var/log/opensearch/logs) with writable permissions.

        Uses 777 permissions as a workaround until fsGroup is applied.
        Once fsGroup changes parent to 584792:584792, permissions can be reduced to 775.
        """
        logs_dir = str(self.paths.logs / "logs")
        logs_parent = str(self.paths.logs)

        # ensure parent directory exists with writable permissions
        try:
            self.container.make_dir(
                logs_parent, make_parents=True, permissions=DIR_PERMISSIONS_WRITABLE
            )
        except (PebbleError, FileExistsError):
            # parent might already exist, try to fix permissions
            try:
                self.run_cmd("chmod %s %s" % (CHMOD_WRITABLE, logs_parent))
            except OpenSearchCmdError:
                pass

        # create logs subdirectory with 777 permissions
        # this allows UID 584792 to write even if parent is root:root
        try:
            self.container.make_dir(
                logs_dir, make_parents=True, permissions=DIR_PERMISSIONS_WRITABLE
            )
            # ensure parent is writable as make_parents might not set parent permissions
            try:
                self.run_cmd("chmod %s %s" % (CHMOD_WRITABLE, logs_parent))
            except OpenSearchCmdError:
                pass
        except (PebbleError, FileExistsError):
            # directory might already exist, ensure both parent and child have correct permissions
            try:
                self.run_cmd("chmod %s %s %s" % (CHMOD_WRITABLE, logs_parent, logs_dir))
            except OpenSearchCmdError:
                # if chmod fails, try to at least ensure directory exists
                # initContainer should handle permissions, but 777 is a fallback
                try:
                    self.run_cmd("mkdir -p %s" % logs_dir)
                    self.run_cmd("chmod %s %s" % (CHMOD_WRITABLE, logs_dir))
                except OpenSearchCmdError:
                    logger.warning(
                        "Could not set permissions on %s, initContainer should handle this",
                        logs_dir,
                    )

        logger.debug("Ensured logs directory exists with writable permissions 777: %s", logs_dir)

    def _ensure_config_directory(self) -> None:
        """Create config directory: /etc/opensearch."""
        conf_dir = str(self.paths.conf)
        self.container.make_dir(conf_dir, make_parents=True, permissions=DIR_PERMISSIONS_READONLY)
        logger.debug("Ensured config directory exists: %s", conf_dir)

    def _ensure_certificates_directory(self) -> None:
        """Create certificates directory: /etc/opensearch/certificates.

        TLS manager writes *.p12 and chain.pem files here.
        This is important for TLS certificate storage.

        """
        certs_dir = str(self.paths.certs)

        # try using container.make_dir first
        try:
            self.container.make_dir(
                certs_dir, make_parents=True, permissions=DIR_PERMISSIONS_CERTIFICATES
            )
            logger.debug("Created certificates directory via make_dir: %s", certs_dir)
            return
        except (PebbleError, FileExistsError) as e:
            # directory might already exist, verify it
            try:
                if self.container.exists(certs_dir):
                    logger.debug("Certificates directory already exists: %s", certs_dir)
                    return
                logger.debug("make_dir failed and directory doesn't exist, trying fallback: %s", e)
            except Exception as check_error:
                logger.debug(
                    "Could not verify directory existence, trying fallback: %s", check_error
                )

        # fallback: use mkdir command if make_dir failed
        self._create_certificates_directory_fallback(certs_dir)

    def _create_certificates_directory_fallback(self, certs_dir: str) -> None:
        """Create certificates directory using mkdir command as fallback.

        Args:
            certs_dir: path to certificates directory.
        """
        try:
            # get current user's UID/GID to set ownership
            try:
                uid_process = self.container.exec(
                    ["id", "-u"], encoding="utf-8", combine_stderr=True
                )
                gid_process = self.container.exec(
                    ["id", "-g"], encoding="utf-8", combine_stderr=True
                )
                uid, _ = uid_process.wait_output()
                gid, _ = gid_process.wait_output()
                uid = uid.strip()
                gid = gid.strip()

                # create directory and set ownership
                self.run_cmd("mkdir -p %s" % certs_dir)
                self.run_cmd("chmod %s %s" % (CHMOD_CERTIFICATES, certs_dir))
                # try to set ownership, may fail if not root
                try:
                    self.run_cmd("chown %s:%s %s" % (uid, gid, certs_dir))
                    logger.debug("Set ownership of certificates directory to %s:%s", uid, gid)
                except OpenSearchCmdError:
                    # expected if running as non-root, fsGroup should handle permissions
                    logger.debug(
                        "Could not chown certificates directory (non-root), fsGroup should handle this"
                    )

                logger.info("Created certificates directory via fallback mkdir: %s", certs_dir)
            except Exception as id_error:
                # if we can't get UID/GID, just create the directory
                logger.debug("Could not get UID/GID for ownership: %s", id_error)
                self.run_cmd("mkdir -p %s" % certs_dir)
                self.run_cmd("chmod %s %s" % (CHMOD_CERTIFICATES, certs_dir))
                logger.info(
                    "Created certificates directory via fallback mkdir (no ownership set): %s",
                    certs_dir,
                )
        except Exception as fallback_error:
            logger.warning(
                "Failed to create certificates directory even with fallback: %s", fallback_error
            )
            # don't raise, directory creation will be retried on next hook

    def _ensure_home_logs_directory(self) -> None:
        """Create OpenSearch home logs directory: /usr/share/opensearch/logs.

        OpenSearch JVM options reference logs/gc.log relative to OPENSEARCH_HOME.
        This directory must exist and be writable for GC logging to work.

        Raises:
            PebbleError: if directory creation fails.
        """
        opensearch_home_logs = str(self.paths.home / "logs")
        self.container.make_dir(
            opensearch_home_logs, make_parents=True, permissions=DIR_PERMISSIONS_READONLY
        )
        logger.debug("Ensured OpenSearch home logs directory exists: %s", opensearch_home_logs)

    def _attempt_set_directory_ownership(self) -> None:
        """Attempt to set directory ownership for data/log directories (best-effort).

        Note: Once running as non-root (via pod securityContext), chown will fail.
        Directory permissions are handled by fsGroup in the pod securityContext for volume mounts.
        This chown is only useful during initial setup if the container temporarily runs as root.

        """
        try:
            # get current user's UID/GID dynamically
            uid_process = self.container.exec(["id", "-u"], encoding="utf-8", combine_stderr=True)
            gid_process = self.container.exec(["id", "-g"], encoding="utf-8", combine_stderr=True)
            uid, _ = uid_process.wait_output()
            gid, _ = gid_process.wait_output()
            uid = uid.strip()
            gid = gid.strip()

            # only chown data and log directories, not /etc/opensearch config
            data_dir = str(self.paths.data / "data")
            logs_dir = str(self.paths.logs / "logs")
            opensearch_home_logs = str(self.paths.home / "logs")
            chown_paths = [data_dir, logs_dir, opensearch_home_logs]

            # try chown, may fail if not root, that's expected and handled by initContainer/fsGroup
            try:
                chown_cmd = ["chown", "-R", "%s:%s" % (uid, gid)] + chown_paths
                self.container.exec(chown_cmd, encoding="utf-8", combine_stderr=True).wait_output()
                logger.debug("Changed ownership of data/log directories to %s:%s", uid, gid)
                # after successful chown, we can reduce permissions to 775 for better security
                try:
                    chmod_cmd = ["chmod", CHMOD_SECURE, logs_dir]
                    self.container.exec(
                        chmod_cmd, encoding="utf-8", combine_stderr=True
                    ).wait_output()
                    logger.debug(
                        "Reduced logs directory permissions to 775 after successful chown: %s",
                        logs_dir,
                    )
                except OpenSearchCmdError:
                    # chmod failed, but that's ok, 777 is still fine
                    pass
            except OpenSearchCmdError as chown_error:
                # chown failed, expected if non-root, keep 777 permissions
                # initContainer or fsGroup will fix ownership, then we can reduce to 775
                logger.debug(
                    "chown failed (expected if non-root, initContainer/fsGroup will handle): %s",
                    chown_error,
                )
        except (OpenSearchCmdError, Exception) as e:
            # expected to fail once running as non-root, fsGroup handles permissions for volumes
            # also expected if id command fails or container not ready
            logger.debug(
                "Could not change ownership (non-critical, initContainer/fsGroup handles this): %s",
                e,
            )

    def _configure_pebble_plan(self) -> None:
        """Configure the Pebble plan with the OpenSearch service definition.

        This must be called before starting the service. The plan defines:
        - Service name: opensearch
        - Command: OpenSearch executable path (using standard Linux paths, not snap paths)
        - Environment variables: OPENSEARCH_HOME, OPENSEARCH_PATH_CONF, JAVA_HOME, PATH
        - Uses system Java at /usr/lib/jvm/java-21-openjdk-amd64 (JAVA_HOME is set explicitly)
        - Non-root execution enforced via pod securityContext (runAsUser=584792, runAsGroup=584792)
        """
        try:
            if not self.container.can_connect():
                logger.debug("Container not ready to configure pebble plan")
                return

            self._ensure_required_directories()

            opensearch_cmd = self._determine_opensearch_command()
            health_check = self._build_readiness_check()
            layer_dict = self._build_pebble_layer_dict(opensearch_cmd, health_check)

            layer = Layer(layer_dict)
            self.container.add_layer(self.SERVICE_NAME, layer, combine=True)

            self._verify_certificates_directory_after_plan_update()

            logger.info("Configured pebble plan for %s service", self.SERVICE_NAME)

        except (PebbleConnectionError, PebbleError, ModelError) as e:
            logger.warning("Failed to configure pebble plan: %s", e)
            # don't raise,this might be called before container is ready

    def _determine_opensearch_command(self) -> str:
        """Determine OpenSearch executable command.

        Tries opensearch.sh script first, falls back to direct opensearch binary.

        Returns:
            str: command string to execute OpenSearch.

        Raises:
            PebbleError: if container.exists() check fails.
        """
        opensearch_bin = str(self.paths.bin)
        opensearch_script = "%s/opensearch.sh" % opensearch_bin

        if self.container.exists(opensearch_script):
            return "bash %s" % opensearch_script

        # fallback to direct opensearch binary if script doesn't exist
        opensearch_cmd = "%s/opensearch" % opensearch_bin
        logger.debug("opensearch.sh not found, using direct binary: %s", opensearch_cmd)
        return opensearch_cmd

    def _build_readiness_check(self) -> CheckDict | None:
        """Build readiness check for OpenSearch service.

        Readiness check verifies HTTPS is actually working, not just port open.
        This ensures OpenSearch Security plugin has fully initialized TLS.

        Returns:
            CheckDict or None: readiness check configuration, or None if DNS name unavailable.

        """
        dns_name = self.get_host_public_ip()
        if not dns_name:
            logger.warning(
                "Could not get DNS name for readiness check, skipping health check configuration"
            )
            return None

        # check HTTP status code from HTTPS endpoint using DNS name
        # curl -k skips certificate verification for health check
        # curl -s suppresses progress output
        # curl -w "%{http_code}" writes only the HTTP status code
        # curl -o /dev/null discards response body
        # curl --max-time 2 limits the check to 2 seconds
        # exit code 0 = ready with status codes 200, 401, or 403, non-zero = not ready
        # critical: Pebble exec checks do not support args field
        # use a single command string with sh -c to execute shell syntax like $(), ||, etc.
        command = (
            'sh -c \'code=$(curl -ks --max-time 2 -o /dev/null -w "%%{http_code}" '
            "https://%s:%s || echo 000); "
            'test "$code" = "200" -o "$code" = "401" -o "$code" = "403"\''
        ) % dns_name

        return {
            "override": "replace",
            "level": "ready",
            "exec": {
                "command": command,
                "service-context": OPENSEARCH_SERVICE_NAME,
            },
        }

    def _build_pebble_layer_dict(
        self, opensearch_cmd: str, health_check: CheckDict | None
    ) -> dict:
        """Build Pebble layer dictionary with OpenSearch service configuration.

        Args:
            opensearch_cmd: command to execute OpenSearch.
            health_check: Optional readiness check configuration.

        Returns:
            dict: pebble layer dictionary ready for Layer() constructor.
        """
        opensearch_home = str(self.paths.home)
        opensearch_conf = str(self.paths.conf)
        java_home = str(self.paths.jdk)

        # build PATH with Java bin, OpenSearch bin, and system paths
        path_value = (
            "%s/bin:/usr/share/opensearch/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            % java_home
        )

        layer_dict = {
            "summary": "OpenSearch service layer",
            "description": "Pebble plan layer for OpenSearch",
            "services": {
                self.SERVICE_NAME: {
                    "override": "replace",
                    "summary": "OpenSearch service",
                    "command": opensearch_cmd,
                    "startup": "enabled",
                    "user": PEBBLE_SERVICE_USER,  # UID 584792, created/ensured in rockcraft.yaml
                    "group": PEBBLE_SERVICE_GROUP,  # GID 584792, created/ensured in rockcraft.yaml
                    "environment": {
                        "OPENSEARCH_HOME": opensearch_home,
                        "OPENSEARCH_PATH_CONF": opensearch_conf,
                        "JAVA_HOME": java_home,
                        "PATH": path_value,
                    },
                    # don't restart on readiness check failure, let the
                    # charm decide when to restart
                    # automatic restarts can cause restart loops during temporary conditions
                    "on-check-failure": {"readiness": "ignore"},
                }
            },
        }

        # only add checks section if health_check is configured, DNS name must be available
        if health_check is not None:
            layer_dict["checks"] = {"readiness": health_check}

        return layer_dict

    def _verify_certificates_directory_after_plan_update(self) -> None:
        """Verify certificates directory exists after pebble plan update.

        Container restarts can cause directories to disappear, so we re-check.
        This is especially important for /etc/opensearch/certificates which is created dynamically.
        """
        certs_dir = str(self.paths.certs)
        try:
            if not self.container.exists(certs_dir):
                logger.warning(
                    "Certificates directory %s missing after pebble plan update, recreating.",
                    certs_dir,
                )
                if self._recreate_certificates_directory(certs_dir):
                    logger.info(
                        "Recreated certificates directory after pebble plan update: %s", certs_dir
                    )
        except Exception as verify_error:
            logger.debug(
                "Could not verify certificates directory after pebble plan update: %s",
                verify_error,
            )

    def _recreate_certificates_directory(self, certs_dir: str) -> bool:
        """Recreate certificates directory using multiple fallback methods.

        Args:
            certs_dir: path to certificates directory.

        Returns:
            bool: True if directory was successfully created, False otherwise.

        """
        # try container.make_dir first
        try:
            self.container.make_dir(
                certs_dir, make_parents=True, permissions=DIR_PERMISSIONS_CERTIFICATES
            )
            return True
        except (PebbleError, FileExistsError):
            pass

        # fallback: use mkdir command
        try:
            self.run_cmd("mkdir -p %s" % certs_dir)
            self.run_cmd("chmod %s %s" % (CHMOD_CERTIFICATES, certs_dir))
            return True
        except Exception:
            return False

    @override
    def install(self) -> None:
        """Install the workload.

        For K8s, installation is handled by the container image.
        This method ensures the container is ready and configures the pebble plan.

        Raises:
            OpenSearchInstallError: if container readiness verification fails.
        """
        try:
            # check if container is ready
            if not self.container.can_connect():
                raise OpenSearchInstallError("Container is not ready")

            # ensure required directories exist
            self._ensure_required_directories()

            # configure pebble plan so the service can be started
            self._configure_pebble_plan()
        except (PebbleConnectionError, ModelError) as e:
            logger.error("Failed to verify container readiness: %s", e)
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
        temp_dir = self._get_temp_directory(dir)
        self._ensure_temp_directory_exists(temp_dir)

        file_path_str, file_path = self._build_temp_file_path(temp_dir, suffix)

        try:
            if data:
                self._write_temp_file_data(file_path, data, encoding)
            # temp_file yields the PathProtocol object so callers can use it within the with block,
            # and cleanup happens automatically when the block exits.
            yield file_path
        finally:
            if delete:
                self._cleanup_temp_file(file_path_str)

    def _get_temp_directory(self, dir: PathProtocol | None) -> str:
        """Get temporary directory path.

        Args:
            dir: Optional directory path. If None, uses default tmp directory.

        Returns:
            str: temporary directory path as string.
        """
        if dir is None:
            return str(self.paths.tmp)
        return str(dir)

    def _ensure_temp_directory_exists(self, temp_dir: str) -> None:
        """Ensure temporary directory exists in container.

        Args:
            temp_dir: directory path to ensure exists.
        """
        try:
            self.container.make_dir(
                temp_dir, make_parents=True, permissions=DIR_PERMISSIONS_READONLY
            )
        except (PebbleError, FileExistsError) as e:
            logger.debug("Directory might already exist (ignored): %s. Error: %s", temp_dir, e)

    def _build_temp_file_path(self, temp_dir: str, suffix: str | None) -> tuple[str, PathProtocol]:
        """Build temporary file path.

        Args:
            temp_dir: directory path for temporary file.
            suffix: Optional suffix to append to filename.

        Returns:
            tuple[str, PathProtocol]: (file_path_str, file_path) tuple.
        """
        temp_filename = "temp_%s%s" % (uuid.uuid4().hex, suffix or "")
        file_path_str = "%s/%s" % (temp_dir, temp_filename)
        file_path = self.root / file_path_str.lstrip("/")
        return file_path_str, file_path

    def _write_temp_file_data(
        self, file_path: PathProtocol, data: str, encoding: str | None
    ) -> None:
        """Write data to temporary file in container.

        Uses pathops ContainerPath.write_text() which handles push internally.

        Args:
            file_path: PathProtocol object representing the file path.
            data: string data to write.
            encoding: encoding for data writing.
        """
        # ensure parent directory exists (consistent with write_text() pattern)
        self._ensure_parent_dir(file_path)
        file_path.write_text(data, encoding=encoding or "utf-8")

    def _cleanup_temp_file(self, file_path_str: str) -> None:
        """Delete temporary file from container.

        Args:
            file_path_str: file path as string.

        """
        try:
            self.container.remove_path(file_path_str, recursive=True)
        except (PebbleError, ModelError, FileNotFoundError) as e:
            logger.warning("Failed to delete temp file %s: %s", file_path_str, e)

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
        if not self.container.can_connect():
            raise OpenSearchCmdError(cmd=script_name, out="", err="Container not connected")

        script_path = "%s/%s" % (self.paths.home, script_name)
        full_command = self._build_script_command(script_path, args)
        env_setup = self._build_script_environment(full_command)

        logger.debug("Executing script via bash -c with environment: %s", script_name)
        process = self.container.exec(
            ["bash", "-c", env_setup],
            encoding="utf-8",
            combine_stderr=True,
        )

        try:
            stdout, stderr = process.wait_output()
            return SimpleNamespace(cmd=env_setup, out=stdout, err=stderr or "", returncode=0)
        except Exception as e:
            raise OpenSearchCmdError(cmd=env_setup, out="", err=str(e)) from e

    def _build_script_command(self, script_path: str, args: str | None) -> str:
        """Build bash command to execute script.

        Args:
            script_path: full path to the script file.
            args: Optional arguments to pass to the script.

        Returns:
            str: full bash command string.
        """
        command = "bash %s" % script_path
        if args:
            command = "%s %s" % (command, args)
        return command

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
        java_home = str(self.paths.jdk)
        opensearch_home = str(self.paths.home)
        opensearch_bin = str(self.paths.bin)
        opensearch_conf = str(self.paths.conf)

        # build PATH with Java bin, OpenSearch bin, and system paths
        path_value = "%s/bin:%s:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" % (
            java_home,
            opensearch_bin,
        )

        # use export to make variables available to the script
        # bash -c expects a single string argument, and the shell will handle
        # argument parsing correctly. Adding quotes causes bash to treat the quotes
        # as literal characters, leading to "No such file" errors.
        return (
            'export OPENSEARCH_HOME="%s" && '
            'export OPENSEARCH_PATH_CONF="%s" && '
            'export JAVA_HOME="%s" && '
            'export PATH="%s" && '
            "%s"
        ) % (opensearch_home, opensearch_conf, java_home, path_value, command)

    @override
    def get_host_public_ip(self) -> str | None:
        """Fetches the Public IP address of the current unit.

        For K8s, this returns the pods DNS name instead of IP address.
        DNS names are stable and resolve to the current pod IP via K8s DNS.

        This DNS name is used for:
        - OpenSearch http.publish_host configuration
        - TLS certificate SANs (Subject Alternative Names)
        - Any other configuration requiring a stable address

        Returns:
            str | None: dns name (FQDN or hostname) for K8s, or None if unavailable.
        """
        # try to get pod FQDN first, most reliable method
        if fqdn := self._get_pod_fqdn():
            return fqdn

        # fallback: try to get pod hostname
        return self._get_pod_hostname_with_fallback()

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

    def _get_services_dict(self) -> dict:
        """Get services as a dictionary handling different return types from get_services().

        Returns:
            dict: dictionary mapping service names to ServiceInfo objects.
        """
        all_services = self.container.get_services()
        services = {}
        for svc in all_services:
            if hasattr(svc, "name"):
                # normal case: service is a ServiceInfo object
                services[svc.name] = svc
            elif isinstance(svc, str):
                # fallback:if it is a string, try to get the service by name
                try:
                    svc_info = self.container.get_services([svc])
                    if svc_info and len(svc_info) > 0:
                        services[svc] = svc_info[0]
                except Exception:
                    continue
        return services

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

            services = self._get_services_dict()
            if (service := services.get(self.SERVICE_NAME)) is None:
                return False

            if service.current == ServiceStatus.ACTIVE:
                return True
            if paused and service.current == ServiceStatus.INACTIVE:
                return True

            return False
        except (PebbleConnectionError, PebbleError, ModelError) as e:
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

            self.container.start(self.SERVICE_NAME)
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

            # get services dict
            services = self._get_services_dict()
            if (service := services.get(self.SERVICE_NAME)) is None:
                return False

            return service.current == ServiceStatus.ERROR
        except (PebbleConnectionError, PebbleError, ModelError, KeyError) as e:
            logger.warning("Failed to check if service is failed: %s", e)
            return False

    @override
    def start_service(self):
        """Start the OpenSearch service.

        Ensures required directories exist and pebble plan is configured before starting.
        If service is already active, returns without error.

        Raises:
            OpenSearchStartError: if container is not ready or service start fails.
        """
        try:
            if not self.container.can_connect():
                raise OpenSearchStartError("Container is not ready")

            # ensure required directories exist
            self._ensure_required_directories()

            # ensure pebble plan is configured before starting
            self._configure_pebble_plan()

            # get services
            services = self._get_services_dict()
            if (
                service := services.get(self.SERVICE_NAME)
            ) and service.current == ServiceStatus.ACTIVE:
                logger.info("The %s service is already started.", self.SERVICE_NAME)
                return

            self.container.start(self.SERVICE_NAME)
        except (PebbleConnectionError, PebbleError, ModelError) as e:
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

    def _parse_meminfo_output(self, output: str) -> dict[str, float]:
        """Parse meminfo output into dictionary.

        Args:
            output: raw output from /proc/meminfo or cat command.

        Returns:
            dict[str, float]: Parsed memory info values, empty dict if parsing fails.

        """
        try:
            meminfo_lines = output.split("\n")
            meminfo = [line.split() for line in meminfo_lines if line.strip()]
            return {line[0][:-1]: float(line[1]) for line in meminfo if len(line) >= 2}
        except (ValueError, IndexError, AttributeError) as parse_error:
            logger.warning("Failed to parse meminfo output: %s", parse_error)
            return {}

    @override
    def _apply_system_requirement(self, system_requirement: str, value: int) -> bool:
        """Apply a system requirement.

        Args:
            system_requirement: kernel parameter to update.
            value: value of the kernel parameter.

        Returns:
            bool: True if the kernel value was applied successfully, False otherwise.
        """
        try:
            if not self._set_sysctl_value(system_requirement, value):
                return False

            if self._verify_sysctl_value(system_requirement, value):
                logger.info("Successfully set %s=%s", system_requirement, value)
                return True

            logger.warning(
                "Failed to set %s: expected %s, got different value. "
                "sysctl -w may have executed but value was not changed (likely missing NET_ADMIN capability).",
                system_requirement,
                value,
            )
            return False

        except OpenSearchCmdError as e:
            error_message = e.err or e.out or str(e)
            logger.warning(
                "Cannot set %s=%s in container: %s. "
                "Ensure container has necessary privileges or configure via pod security context.",
                system_requirement,
                value,
                error_message,
            )
            return False

    def _set_sysctl_value(self, system_requirement: str, value: int) -> bool:
        """Attempt to set sysctl value using sysctl -w.

        Args:
            system_requirement: kernel parameter to update.
            value: value to set.

        Returns:
            bool: True if sysctl command succeeded without permission errors, False otherwise.

        Raises:
            OpenSearchCmdError: if sysctl command fails.
        """
        logger.debug("Attempting to set %s=%s using sysctl -w", system_requirement, value)
        sysctl_result = self.run_cmd("sysctl", args="-w %s=%s" % (system_requirement, value))

        # check if sysctl -w failed with permission errors
        # note: combine_stderr=True merges stderr into stdout, so check both out and err
        output_to_check = sysctl_result.err or sysctl_result.out
        if output_to_check:
            error_message_lowercase = output_to_check.lower()
            if (
                "permission denied" in error_message_lowercase
                or "read-only" in error_message_lowercase
            ):
                logger.debug("sysctl -w failed with error: %s", output_to_check)
                return False

        return True

    def _verify_sysctl_value(self, system_requirement: str, expected_value: int) -> bool:
        """Verify that sysctl value was actually set to the expected value.

        Args:
            system_requirement: kernel parameter name.
            expected_value: expected value to verify.

        Returns:
            bool: True if current value matches expected value, False otherwise.

        Raises:
            OpenSearchCmdError: if sysctl command fails.
            ValueError: If sysctl output cannot be parsed as integer.
        """
        result = self.run_cmd("sysctl", args="-n %s" % system_requirement)
        current_value = int(result.out.rstrip())
        return current_value == expected_value

    @override
    def check_missing_system_requirements(self) -> list[str]:
        """Checks the system requirements for K8s.

        If a sysctl cannot be read, the charm will be blocked
        as this indicates a configuration issue.

        Returns:
            list[str]: List of missing requirement error messages.
        """
        missing_requirements = []

        # define system requirements: property_name, required_value, comparison_op, config_method
        requirements = [
            ("vm.max_map_count", 262144, "<", "node level: sysctl -w"),
            ("vm.swappiness", 0, ">", "node level: sysctl -w"),
            (
                "net.ipv4.tcp_retries2",
                5,
                ">",
                "pod securityContext.sysctls (requires pod restart)",
            ),
        ]

        for property_name, required_value, comparison_op, config_method in requirements:
            if error_message := self._check_kernel_property_requirement(
                property_name, required_value, comparison_op, config_method
            ):
                missing_requirements.append(error_message)

        return missing_requirements

    def _check_kernel_property_requirement(
        self, property_name: str, required_value: int, comparison_op: str, config_method: str
    ) -> str | None:
        """Check if a kernel property meets the required value.

        Args:
            property_name: Kernel property name (e.g., "vm.max_map_count").
            required_value: Required value for the property.
            comparison_op: Comparison operator ("<" or ">") to check
             if current value does not meet the requirement.
            config_method: Description of how to configure this property in K8s.

        Returns:
            str or None: Error message if requirement is not met, None otherwise.
        """
        current_value = self._get_kernel_property_value(property_name)

        if current_value is None:
            return self._build_unreadable_property_error(property_name, config_method)

        if self._property_violates_requirement(current_value, required_value, comparison_op):
            return self._build_property_value_error(
                property_name, current_value, required_value, comparison_op, config_method
            )

        return None

    def _property_violates_requirement(
        self, current_value: int, required_value: int, comparison_op: str
    ) -> bool:
        """Check if current property value violates the requirement.

        Args:
            current_value: Current property value.
            required_value: Required property value.
            comparison_op: Comparison operator ("<" or ">").

        Returns:
            bool: True if requirement is violated, False otherwise.
        """
        if comparison_op == "<":
            return current_value < required_value
        elif comparison_op == ">":
            return current_value > required_value
        return False

    def _build_unreadable_property_error(self, property_name: str, config_method: str) -> str:
        """Build error message for unreadable kernel property.

        Args:
            property_name: kernel property name.
            config_method: description of how to configure this property.

        Returns:
            str: error message.
        """
        error_message = (
            "Cannot read %s from container. "
            "This may indicate missing permissions or node-level configuration issue. "
            "For K8s deployments, configure via %s."
        ) % (property_name, config_method)
        logger.warning(error_message)
        return error_message

    def _build_property_value_error(
        self,
        property_name: str,
        current_value: int,
        required_value: int,
        comparison_op: str,
        config_method: str,
    ) -> str:
        """Build error message for property value that violates requirement.

        Args:
            property_name: Kernel property name.
            current_value: Current property value.
            required_value: Required property value.
            comparison_op: Comparison operator ("<" or ">").
            config_method: Description of how to configure this property.

        Returns:
            str: error message.
        """
        if comparison_op == "<":
            comparison_text = "below"
        else:
            comparison_text = "above"

        if "sysctl -w" in config_method:
            fix_instruction = "sysctl -w %s=%s" % (property_name, required_value)
        else:
            fix_instruction = "%s=%s" % (property_name, required_value)

        error_message = (
            "%s=%s is %s recommended %s. " "For K8s deployments, configure via %s: %s."
        ) % (
            property_name,
            current_value,
            comparison_text,
            required_value,
            config_method,
            fix_instruction,
        )
        logger.warning(error_message)
        return error_message

    @override
    def _get_kernel_property_value(self, property_name: str) -> int | None:
        """Get the value of a kernel parameter.

        Try 3 methods in order to get the value of a kernel parameter:
        1. sysctl -n (most reliable)
        2. sysctl without -n (parse output)
        3. Read directly from /proc/sys/ (fallback)

        Args:
            property_name: Kernel property name (e.g., "vm.max_map_count").

        Returns:
            int | None: Kernel property value, or None if cannot be read.
        """
        # try sysctl -n first, most reliable method
        if (property_value := self._read_kernel_property_via_sysctl_n(property_name)) is not None:
            return property_value

        # fallback: try sysctl without -n flag
        if (property_value := self._read_kernel_property_via_sysctl(property_name)) is not None:
            return property_value

        # final fallback: read directly from /proc/sys/
        return self._read_kernel_property_via_procfs(property_name)

    def _read_kernel_property_via_sysctl_n(self, property_name: str) -> int | None:
        """Read kernel property using 'sysctl -n' command.

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
        """Read kernel property using 'sysctl' command and parse output.

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
            command: Command to run, can contain arguments
            args: Additional command line arguments
            stdin: String input to be passed on the standard input
            use_errors_replace: Ignored in K8s (kept for interface compatibility)

        Returns:
            SimpleNamespace with cmd, out, err, returncode attributes

        Raises:
            OpenSearchCmdError: If command execution fails or container is not ready
        """
        command_with_args = self._build_command_with_args(command, args)
        masked_command = mask_sensitive_information(command_with_args)
        logger.debug("Executing command in container: %s", masked_command)

        try:
            if not self.container.can_connect():
                raise OpenSearchCmdError(cmd=command, out="", err="Container not connected")

            cmd_list = self._build_command_list(command_with_args)
            logger.debug("Executing command list: %s", cmd_list)

            process = self.container.exec(
                cmd_list,
                stdin=stdin.encode("utf-8") if stdin else None,
                encoding="utf-8",
                combine_stderr=True,
            )

            stdout, stderr = self._wait_for_process_output(process, masked_command, command)
            logger.debug(
                "%s:\nstdout: %s\nstderr: %s\nreturncode: 0", masked_command, stdout, stderr
            )

            # note: err is typically empty because combine_stderr=True merges stderr into stdout
            return SimpleNamespace(cmd=command, out=stdout, err=stderr, returncode=0)

        except (PebbleConnectionError, PebbleError, ModelError, OSError, ValueError) as e:
            logger.warning(
                "Error executing command %s: %s: %s", masked_command, type(e).__name__, e
            )
            raise OpenSearchCmdError(cmd=command, out="", err=str(e)) from e

    def _build_command_with_args(self, command: str, args: str | None) -> str:
        """Build command string with optional arguments.

        Args:
            command: command to run
            args: Additional command line arguments

        Returns:
            str: Command with arguments concatenated
        """
        if args is not None:
            return "%s %s" % (command, args)
        return command

    def _build_command_list(self, command_with_args: str) -> list[str]:
        """Build command list for container.exec().

        Detects shell metacharacters and wraps command in shell if needed.
        Otherwise splits command into list of arguments.

        Args:
            command_with_args: Full command string with arguments

        Returns:
            list[str]: Command list suitable for container.exec()
        """
        if self._needs_shell(command_with_args):
            # command contains shell metacharacters, must run via shell
            return ["sh", "-c", command_with_args]
        elif " " in command_with_args:
            # simple command with arguments, split it properly
            return command_with_args.split()
        else:
            return [command_with_args]

    def _needs_shell(self, command: str) -> bool:
        """Check if command requires shell interpretation.

        Shell metacharacters include: |, >, <, &&, ||, ;, $(), ${}, ``, 2>, >>, <<, &, etc.

        Args:
            command: Command string to check

        Returns:
            bool: True if command contains shell metacharacters
        """
        shell_metachars = ["|", ">", "<", "&&", "||", ";", "$(", "${", "`", "2>", ">>", "<<", "&"]
        return any(char in command for char in shell_metachars)

    def _wait_for_process_output(
        self, process, masked_command: str, original_command: str
    ) -> tuple[str, str]:
        """Wait for process to complete and return output.

        Args:
            process: Process object from container.exec()
            masked_command: Command string with sensitive info masked for logging
            original_command: Original command string for error messages

        Returns:
            tuple[str, str]: (stdout, stderr) - stderr is
                typically empty due to combine_stderr=True

        Raises:
            OpenSearchCmdError: If process fails or returns non-zero exit code
        """
        try:
            stdout, stderr = process.wait_output()
            return stdout, stderr
        except Exception as e:
            # wait_output() raises on non-zero exit or other errors
            # some errors are expected and handled by callers, e.g., "does not exist" for keytool
            # log those as debug instead of warning to reduce noise
            error_string = str(e).lower()
            if "does not exist" in error_string or "keystore file does not exist" in error_string:
                logger.debug("wait_output() failed for %s (expected): %s", masked_command, e)
            else:
                logger.warning("wait_output() failed for %s: %s", masked_command, e)
            raise OpenSearchCmdError(cmd=original_command, out="", err=str(e)) from e

    @override
    def stop(self) -> None:
        """Stop the OpenSearch service.

        Raises:
            OpenSearchStopError: If container is not ready or service stop fails.
        """
        try:
            if not self.container.can_connect():
                raise OpenSearchStopError("Container is not ready")

            self.container.stop(self.SERVICE_NAME)
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

    def _ensure_parent_dir(self, path: PathProtocol) -> None:
        """Ensure parent directory exists for a file path inside the container.

        Args:
            path: PathProtocol object whose parent directory should be created

        Raises:
            ContainerNotReadyError: If container is not ready
        """
        if not self.container.can_connect():
            raise ContainerNotReadyError("Container not ready to create directory")

        parent = str(path.parent)
        # containerPath.parent is also a ContainerPath, gives "/etc/opensearch" etc.
        try:
            self.container.make_dir(
                parent, make_parents=True, permissions=DIR_PERMISSIONS_READONLY
            )
        except (PebbleError, FileExistsError):
            # directory might already exist, which is fine
            pass

    @override
    def write_text(self, content: str, path: pathops.PathProtocol) -> None:  # type: ignore[override]
        """K8s-safe write: ensure parent dir exists and handle pebble readiness.

        Overrides BaseWorkload.write_text() to ensure parent directories exist
        before writing, which is critical for K8s where directories may not exist
        yet or may disappear during container restarts.

        Args:
            content: Content to write to the file
            path: PathProtocol object representing the file path

        Raises:
            ContainerNotReadyError: If container is not ready
            OpenSearchFileOperationError: For other file operation errors
        """
        try:
            if not self.container.can_connect():
                raise ContainerNotReadyError("Container not ready for write_text")

            # ensure parent directory exists before writing
            self._ensure_parent_dir(path)

            # use ContainerPath API to write the file
            path.write_text(content)
        except PebbleConnectionError as e:
            # raise ContainerNotReadyError so hooks can defer cleanly
            raise ContainerNotReadyError("Container not ready for write_text: %s" % e) from e
        except (PebbleError, ModelError, OSError, ValueError) as e:
            raise OpenSearchFileOperationError(e) from e

    @override
    def read_text(self, path: pathops.PathProtocol) -> str:  # type: ignore[override]
        """K8s-safe read with proper pebble error handling.

        Overrides BaseWorkload.read_text() to handle PebbleConnectionError
        gracefully, allowing event handlers to defer when container is not ready.

        Args:
            path: PathProtocol object representing the file path

        Returns:
            str: content read from the file

        Raises:
            ContainerNotReadyError: if container is not ready
            OpenSearchFileOperationError: for other file operation errors
        """
        try:
            if not self.container.can_connect():
                raise ContainerNotReadyError("Container not ready for read_text")

            return path.read_text()
        except PebbleConnectionError as e:
            # raise ContainerNotReadyError so hooks can defer cleanly
            raise ContainerNotReadyError("Container not ready for read_text: %s" % e) from e
        except (PebbleError, ModelError, OSError, ValueError) as e:
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
