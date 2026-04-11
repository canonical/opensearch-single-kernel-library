#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base interface for common workload operations."""

import logging
import socket
from abc import ABC, abstractmethod
from contextlib import contextmanager
from types import SimpleNamespace
from typing import List, Optional

from charmlibs import pathops
from charmlibs.pathops import PathProtocol
from ops import ModelError
from ops.pebble import Error as PebbleError

from opensearch_single_kernel.common.constants import (
    BASE_SNAP_DIR,
    SNAP,
    SNAP_COMMON,
    SNAP_DATA,
    OpenSearchPaths,
)
from opensearch_single_kernel.common.exceptions import OpenSearchFileOperationError

logger = logging.getLogger(__name__)


class Paths:
    """This class represents the group of Paths that need to be exposed.

    Args:
            home: Home path of Opensearch, equivalent to the env variable ${OPENSEARCH_HOME}
            conf: Path to the config folder of opensearch
            data: Path to the data folder of opensearch
            logs: Path to the logs folder of opensearch
            jdk: Path of the jdk that comes bundled with the opensearch distro
            tmp: JNA temporary directory
            bin: Path to the bin/ folder
    """

    def __init__(self, root: PathProtocol):
        super().__init__()
        self.root = root

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
    def opensearch_config(self) -> PathProtocol:
        """Return path to the opensearch.yml config file."""
        return self.conf / "opensearch.yml"

    @property
    def opensearch_keystore(self) -> PathProtocol:
        """Return path to the opensearch keystore."""
        return self.conf / "opensearch.keystore"

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

    @property
    def plugins(self) -> PathProtocol:
        """Returns Plugins Path"""
        return self.home / "plugins"

    @property
    def certs(self) -> PathProtocol:
        """Returns Certificates Path"""
        return self.conf / "certificates"

    @property
    def certs_relative(self) -> str:
        """Returns Certificates relative Path"""
        return "certificates"

    @property
    def certs_chain(self) -> PathProtocol:
        """Returns path to the certificates chain file."""
        return self.certs / "chain.pem"

    @property
    def seed_hosts(self) -> PathProtocol:
        """Returns path to the Opensearch seed hosts config file."""
        return self.conf / "unicast_hosts.txt"


# --- Base Workload
class BaseWorkload(ABC):
    """Base interface for common workload operations."""

    @property
    @abstractmethod
    def root(self) -> PathProtocol:
        """Return the root path."""
        pass

    @abstractmethod
    def install(self) -> None:
        """Install the workload."""
        pass

    def prepare_container(self) -> None:
        """Prepare the workload runtime environment.

        K8s workloads should override this to perform container preparation that requires Pebble
        connectivity (e.g. permissions, and Pebble layer configuration).
        """
        return None

    @property
    @abstractmethod
    def paths(self) -> Paths:
        """Return the Workload's paths"""
        pass

    @property
    @abstractmethod
    def workload_present(self) -> bool:
        """Flag to check if workload is present and ready."""
        pass

    @property
    @abstractmethod
    def can_connect(self) -> bool:
        """Flag to check if workload is present and Pebble API is connectable."""
        pass

    def write_text(self, content: str, path: pathops.PathProtocol) -> None:
        """Write content to a file on disk.

        Args:
            content (str): The content to be written.
            path (str): The file path where the content should be written.
        """
        try:
            path.write_text(content)
        except (
            FileNotFoundError,
            LookupError,
            NotADirectoryError,
            PermissionError,
            pathops.PebbleConnectionError,
            ValueError,
        ) as e:
            raise OpenSearchFileOperationError(e)

    def read_text(self, path: pathops.PathProtocol) -> str:
        """Read content from a file on disk.

        Args:
            path (str): The file path to read from.

        Returns:
            str: The content read from the file.
        """
        try:
            return path.read_text()
        except (
            FileNotFoundError,
            UnicodeError,
            PermissionError,
            PebbleError,
            ModelError,
            pathops.PebbleConnectionError,
        ) as e:
            raise OpenSearchFileOperationError(e)

    def mkdir(
        self,
        path: pathops.PathProtocol,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        """Create a directory on disk.

        Args:
            path (str): The directory path to create.
            mode (int): The mode/permissions to use for the new directory.
            parents (bool): Whether to create parent directories if they do not exist.
            exist_ok (bool): Whether to ignore the error if the directory already exists.
        """
        try:
            path.mkdir(mode=mode, parents=parents, exist_ok=exist_ok)
        except (
            PebbleError,
            ModelError,
            FileExistsError,
            FileNotFoundError,
            LookupError,
            NotADirectoryError,
            PermissionError,
            pathops.PebbleConnectionError,
            ValueError,
        ) as e:
            raise OpenSearchFileOperationError(e)

    def exists(self, path: pathops.PathProtocol) -> bool:
        """Check if a file or directory exists on disk.

        Args:
            path (str): The file or directory path to check.

        Returns:
            bool: True if the file or directory exists, False otherwise.
        """
        try:
            return path.exists()
        except (PermissionError, pathops.PebbleConnectionError) as e:
            raise OpenSearchFileOperationError(e)

    def unlink(self, path: pathops.PathProtocol, missing_ok: bool = False) -> None:
        """Remove a file from disk.

        Args:
            path (str): The file path to remove.
            missing_ok (bool): Whether to ignore the error if the file does not exist.
        """
        try:
            path.unlink(missing_ok=missing_ok)
        except (
            FileNotFoundError,
            IsADirectoryError,
            PermissionError,
            pathops.PebbleConnectionError,
        ) as e:
            raise OpenSearchFileOperationError(e)

    @contextmanager
    def temp_file(
        self,
        mode: str = "w+b",
        data: str | None = None,
        encoding=None,
        dir: PathProtocol | None = None,
        delete=True,
        *,
        errors=None,
        suffix=None,
    ):
        """Context manager for creating temporary files."""
        pass

    @abstractmethod
    def is_service_started(self, paused: Optional[bool] = False) -> bool:
        """Check if the snap service and JVM process are running.

        Set paused=True if the process was intentionally paused.
        """
        pass

    @abstractmethod
    def get_publish_host(self) -> Optional[str]:
        """Return the host to use for OpenSearch `http.publish_host`."""
        pass

    @property
    @abstractmethod
    def keytool_cmd(self) -> str:
        """Return the keytool command appropriate for this workload substrate."""
        pass

    @abstractmethod
    def start_service_only(self):
        """Start the actual service only (snap / pebble)."""
        pass

    def is_reachable(self, host: str, port: int) -> bool:
        """Attempting a socket connection to a host/port."""
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except OSError as e:
            logger.debug("Cannot connect to the OpenSearch server...")
            logger.debug("Connection to %s:%d fails with: %s", host, port, e)
            return False

    @abstractmethod
    def run_script(self, script_name: str, args: str = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME."""
        pass

    @abstractmethod
    def run_cmd(
        self,
        command: str,
        args: str = None,
        use_errors_replace: bool = False,
        stdin: str = None,
    ) -> SimpleNamespace:
        """Run Command in CLI"""
        pass

    @abstractmethod
    def meminfo(self) -> dict[str, float]:
        """Read the /proc/meminfo file and return the values."""
        pass

    def _parse_meminfo_output(self, output: str) -> dict[str, float]:
        """Parse meminfo output into a dictionary."""
        try:
            meminfo_lines = output.split("\n")
            meminfo = [line.split() for line in meminfo_lines if line.strip()]
            return {line[0][:-1]: float(line[1]) for line in meminfo if len(line) >= 2}
        except (ValueError, IndexError, AttributeError) as parse_error:
            logger.warning("Failed to parse meminfo output: %s", parse_error)
            return {}

    @abstractmethod
    def is_failed(self) -> bool:
        """Check if snap service failed."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop the opensearch service."""
        pass

    @abstractmethod
    def start_service(self):
        """Start the opensearch service."""
        pass

    @abstractmethod
    def _apply_system_requirement(self, system_requirement: str, value: int) -> bool:
        """Apply a system requirement."""
        pass

    @abstractmethod
    def _get_kernel_property_value(self, prop: str) -> int | None:
        """Get the value of a kernel parameter."""
        pass

    def check_missing_system_requirements(self) -> List[str]:
        """Checks the system requirements.

        Raises:
            OpenSearchCmdError: If the kernel property value cannot be read
                or if applying a system requirement fails.
        """
        missing_requirements = []

        prop, val = "vm.max_map_count", 262144
        if self._get_kernel_property_value(prop) < val and not self._apply_system_requirement(
            prop, val
        ):
            missing_requirements.append(f"{prop} should be at least {val}")

        prop, val = "vm.swappiness", 0
        if self._get_kernel_property_value(prop) > val and not self._apply_system_requirement(
            prop, 0
        ):
            missing_requirements.append(f"{prop} should be at most {val}")

        prop, val = "net.ipv4.tcp_retries2", 5
        if self._get_kernel_property_value(prop) > val and not self._apply_system_requirement(
            prop, val
        ):
            missing_requirements.append(f"{prop} should be at most {val}")

        if missing_requirements:
            logger.error("Missing system requirements: %s", missing_requirements)
        return missing_requirements
