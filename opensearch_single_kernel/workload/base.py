#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base interface for common workload operations."""

import logging
import socket
from abc import ABC, abstractmethod
from collections.abc import Generator
from contextlib import contextmanager
from platform import machine
from types import SimpleNamespace
from typing import List, Optional

from charmlibs import pathops
from charmlibs.pathops import PathProtocol
from ops import ModelError
from ops.pebble import Error as PebbleError

from opensearch_single_kernel.common.constants import (
    BASE_SNAP_DIR,
    DIR_PERMISSIONS_READONLY,
    SNAP,
    SNAP_COMMON,
    SNAP_DATA,
    OpenSearchPaths,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchFileOperationError,
)

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

    def __init__(self, root: PathProtocol, charm_root: PathProtocol):
        super().__init__()
        self.root = root
        self.charm_root = charm_root

    @property
    def base_snap_dir(self) -> PathProtocol:
        """Get path to the Base snap directory."""
        return self.root / BASE_SNAP_DIR

    @property
    def snap_data(self) -> PathProtocol:
        """Get path to the snap data directory."""
        return self.base_snap_dir / SNAP_DATA

    @property
    def snap_common(self) -> PathProtocol:
        """Get path to the snap common directory."""
        return self.base_snap_dir / SNAP_COMMON

    @property
    def snap(self) -> PathProtocol:
        """Get path to the snap directory."""
        return self.root / SNAP

    @property
    def home(self) -> PathProtocol:
        """Get path to the home snap directory."""
        return self.snap_data / OpenSearchPaths.HOME.val

    @property
    def conf(self) -> PathProtocol:
        """Get path to the conf snap directory."""
        return self.snap_data / OpenSearchPaths.CONF.val

    @property
    def opensearch_config(self) -> PathProtocol:
        """Get path to the opensearch.yml config file."""
        return self.conf / "opensearch.yml"

    @property
    def opensearch_keystore(self) -> PathProtocol:
        """Get path to the opensearch keystore."""
        return self.conf / "opensearch.keystore"

    @property
    def opensearch_keystore_binary(self) -> str:
        """Name of the opensearch-keystore binary."""
        return "opensearch.keystore"

    @property
    def data(self) -> PathProtocol:
        """Get path to the data snap directory."""
        return self.snap_common / OpenSearchPaths.DATA.val

    @property
    def logs(self) -> PathProtocol:
        """Get path to the logs snap directory."""
        return self.snap_common / OpenSearchPaths.LOGS.val

    @property
    def jdk(self) -> PathProtocol:
        """Get path to the jdk directory."""
        if machine() == "aarch64":
            return self.snap / "usr/lib/jvm/java-21-openjdk-arm64"
        else:
            return self.snap / "usr/lib/jvm/java-21-openjdk-amd64"

    @property
    def tmp(self) -> PathProtocol:
        """Get path to the tmp directory."""
        return self.snap_common / OpenSearchPaths.TMP.val

    @property
    def bin(self) -> PathProtocol:
        """Get path to the bin directory."""
        return self.snap / OpenSearchPaths.BIN.val

    @property
    def plugins(self) -> PathProtocol:
        """Get Plugins Path"""
        return self.home / "plugins"

    @property
    def certs(self) -> PathProtocol:
        """Get Certificates Path"""
        return self.conf / "certificates"

    @property
    def certs_relative(self) -> str:
        """Get Certificates relative Path"""
        return "certificates"

    @property
    def certs_chain(self) -> PathProtocol:
        """Get path to the certificates chain file."""
        return self.certs / "chain.pem"

    @property
    def seed_hosts(self) -> PathProtocol:
        """Get path to the Opensearch seed hosts config file."""
        return self.conf / "unicast_hosts.txt"

    @property
    def charm_version(self) -> PathProtocol:
        """Get path to charm version file."""
        return self.charm_root / "charm_version"

    @property
    def workload_version(self) -> PathProtocol:
        """Get path to workload version file."""
        return self.charm_root / "workload_version"

    @property
    def compatibility_matrix(self) -> PathProtocol:
        """Get path to compatibility matrix file."""
        return self.data / "compatibility_matrix.json"

    @property
    def grafana_dashboard(self) -> PathProtocol:
        """Get path to grafana dashboard file."""
        return self.charm_root / "src/grafana_dashboards/opensearch.json"


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

    def write_text(
        self, content: str, path: pathops.PathProtocol, mode: int | None = None
    ) -> None:
        """Write content to a file on disk.

        Args:
            content (str): The content to be written.
            path (str): The file path where the content should be written.
            mode (int, optional): The mode/permissions to use when writing the file.

        Raises:
            OpenSearchFileOperationError: If there is an error during the file write operation.
        """
        try:
            path.write_text(content, mode=mode)
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
        mode: int = DIR_PERMISSIONS_READONLY,
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

        Raises:
            OpenSearchFileOperationError: If there is an error accessing the file system.
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
    @abstractmethod
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
        """Context manager for creating temporary files."""
        raise NotImplementedError

    @abstractmethod
    def is_service_started(self, paused: Optional[bool] = False) -> bool:
        """Check if the snap service and JVM process are running.

        Set paused=True if the process was intentionally paused.
        """
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
    def run_script(self, script_name: str, args: str = None, stdin: str | None = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME."""
        pass

    @abstractmethod
    def run_cmd(
        self,
        command: str,
        args: str | None = None,
        use_errors_replace: bool = False,
        stdin: str | None = None,
    ) -> SimpleNamespace:
        """Run Command in CLI"""
        pass

    @abstractmethod
    def memtotal(self) -> float:
        """Return the total memory of the system in kbytes."""
        raise NotImplementedError

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

    def _get_kernel_property_value(self, prop: str) -> int:
        """Get the value of a kernel parameter.

        Args:
            prop: Kernel property name (e.g., "vm.max_map_count").

        Returns:
            int: Kernel property value.

        Raises:
            OpenSearchCmdError: If the kernel property value cannot be read.
        """
        try:
            return int(self.run_cmd("sysctl", args=f"-n {prop}").out.rstrip())
        except OpenSearchCmdError as e:
            error_message = e.err or e.out or str(e)
            logger.warning("sysctl -n %s failed: %s", prop, error_message)
            # Propagate error
            raise e

    @abstractmethod
    def check_missing_system_requirements(self) -> List[str]:
        """Checks the system requirements.

        Raises:
            OpenSearchCmdError: If the kernel property value cannot be read
                or if applying a system requirement fails.
        """
        raise NotImplementedError

    @abstractmethod
    def chain_path(self) -> str:
        """Get the certificate chain to use for requests"""
        raise NotImplementedError

    @abstractmethod
    def get_workload_version(self) -> str:
        """Get the workload version."""
        raise NotImplementedError

    @property
    def version(self) -> str:
        """Returns the version number of this opensearch instance."""
        # Will have a format similar to:
        # Version: 2.14.0, Build: tar/.../2024-05-27T21:17:37.476666822Z, JVM: 21.0.2
        result = self.get_workload_version()
        logger.debug("version call output: %s", result)
        return result.split(", ")[0].split(": ")[1]

    def get_host_public_ip(self) -> str | None:
        """Get the public IP address of the host."""
        return None
