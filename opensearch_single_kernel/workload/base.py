#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base interface for workload operations across different substrates."""
import socket
from abc import ABC, abstractmethod
from typing import Optional

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
            bin: optional, Path to the bin/ folder
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


class BaseWorkload(ABC, WithLogging):
    """Base interface for common workload operations."""

    @abstractmethod
    def install(self) -> None:
        """Install the workload."""
        pass

    @abstractmethod
    @property
    def paths(self) -> Paths:
        """Return the Workload's paths"""
        pass

    @abstractmethod
    def is_service_started(self, paused: Optional[bool] = False) -> bool:
        """Check if the snap service and JVM process are running.

        Set paused=True if the process was intentionally paused.
        """
        pass

    @property
    def is_reachable(self, host: str, port: int) -> bool:
        """Attempting a socket connection to a host/port."""
        s = socket.socket()
        s.settimeout(5)
        try:
            s.connect((host, port))
            return True
        except Exception as e:
            self.logger.debug(f"Connection to {host}:{port} fails with: {e}")
            return False
        finally:
            s.close()
