#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base interface for common workload operations."""
import socket
from abc import ABC, abstractmethod
from types import SimpleNamespace
from typing import List, Optional

from pydantic import BaseModel

from opensearch_single_kernel.utils.logging import WithLogging


class Paths(BaseModel):
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

    home: str
    conf: str
    data: str
    logs: str
    jdk: str
    tmp: str
    bin: str

    @property
    def plugins(self):
        """Returns Plugins Path"""
        return f"{self.home}/plugins"

    @property
    def certs(self):
        """Returns Certificates Path"""
        return f"{self.conf}/certificates"  # must be under config

    @property
    def certs_relative(self):
        """Returns Certificates relative Path"""
        return "certificates"

    @property
    def seed_hosts(self):
        """Returns Seed hosts"""
        return f"{self.conf}/unicast_hosts.txt"


# --- Base Workload
class BaseWorkload(ABC, WithLogging):
    """Base interface for common workload operations."""

    @abstractmethod
    def install(self) -> None:
        """Install the workload."""
        pass

    @property
    @abstractmethod
    def paths(self) -> Paths:
        """Return the Workload's paths"""
        pass

    @abstractmethod
    def is_service_started(self, paused: Optional[bool] = False) -> bool:
        """Check if the snap service and JVM process are running.

        Set paused=True if the process was intentionally paused.
        """
        pass

    @abstractmethod
    def get_host_public_ip(self) -> Optional[str]:
        """Fetches the Public IP address of the current unit."""
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
            self.logger.debug(f"Connection to {host}:{port} fails with: {e}")
            return False

    @abstractmethod
    def run_script(self, script_name: str, args: str = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME."""
        pass

    @abstractmethod
    def run_cmd(
        self, command: str, args: str = None, use_errors_replace: bool = False, stdin: str = None
    ) -> SimpleNamespace:
        """Run Command in CLI"""
        pass

    @abstractmethod
    def meminfo(self) -> dict[str, float]:
        """Read the /proc/meminfo file and return the values."""
        pass

    @abstractmethod
    def is_failed(self) -> bool:
        """Check if snap service failed."""
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
    def _get_kernel_property_value(self, prop: str) -> int:
        """Get the value of a kernel parameter."""
        pass

    def check_missing_system_requirements(self) -> List[str]:
        """Checks the system requirements."""
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
            self.logger.error("Missing system requirements: %s", missing_requirements)
        return missing_requirements
