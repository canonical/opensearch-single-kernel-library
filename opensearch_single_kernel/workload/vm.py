#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Machine VM Workload."""

import logging
import os
import subprocess
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from functools import cached_property
from pathlib import Path
from types import SimpleNamespace

from charmlibs import pathops
from charmlibs.pathops import LocalPath, PathProtocol
from overrides import override
from tenacity import Retrying, retry, stop_after_attempt, wait_exponential, wait_fixed

from opensearch_single_kernel.common.constants import OPENSEARCH_SNAP_REVISION
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchInstallError,
    OpenSearchMissingError,
    OpenSearchStartError,
    OpenSearchStopError,
)
from opensearch_single_kernel.lib.charms.operator_libs_linux.v1.systemd import (
    service_failed,
    service_running,
)
from opensearch_single_kernel.lib.charms.operator_libs_linux.v2 import snap
from opensearch_single_kernel.lib.charms.operator_libs_linux.v2.snap import SnapError
from opensearch_single_kernel.utils.helpers import mask_sensitive_information
from opensearch_single_kernel.workload.base import BaseWorkload, Paths

logger = logging.getLogger(__name__)


class VMWorkload(BaseWorkload):
    """OpenSearch Machine VM Workload."""

    SERVICE_NAME = "daemon"

    def __init__(self, charm_root: Path):
        super().__init__()
        self.charm_root = charm_root

    @cached_property
    def opensearch_snap(self) -> snap.Snap:
        """Return the opensearch snap."""
        for attempt in Retrying(stop=stop_after_attempt(12), wait=wait_fixed(10), reraise=True):
            with attempt:
                opensearch_snap = snap.SnapCache()["opensearch"]
        logger.debug(
            f"Snap opensearch fetched after {attempt.retry_state.attempt_number - 1} attempts"
        )
        return opensearch_snap

    @property
    @override
    def workload_present(self) -> bool:
        """Check if the snap is installed."""
        try:
            return self.opensearch_snap.present
        except SnapError:
            return False

    @property
    @override
    def can_connect(self) -> bool:
        """Check if the snap is installed and we can connect to the snapd API."""
        try:
            return bool(self.opensearch_snap.services[self.SERVICE_NAME])
        except KeyError:
            return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    @override
    def install(self) -> None:
        """Install the workload."""
        try:
            cache = snap.SnapCache()
            opensearch_snap = cache["opensearch"]
            # Make sure that we have the exact revision
            opensearch_snap.ensure(snap.SnapState.Latest, revision=OPENSEARCH_SNAP_REVISION)
            opensearch_snap.connect("process-control")
            self.opensearch_snap = opensearch_snap
            if not opensearch_snap.held:
                # hold the snap in charm determined revision
                opensearch_snap.hold()
        except snap.SnapError as e:
            logger.error("Failed to install/upgrade opensearch. \n%s", e)
            raise OpenSearchInstallError()

    @contextmanager
    def temp_file(
        self,
        mode="w+b",
        data: str | None = None,
        encoding: str | None = None,
        dir: PathProtocol | None = None,
        delete: bool = True,
        chown: str | None = None,
        *,
        errors: str | None = None,
        suffix: str | None = None,
    ) -> Generator[PathProtocol, None, None]:
        """Create a temporary file and return the file, clean it once context is closed."""
        f = tempfile.NamedTemporaryFile(
            mode=mode,
            encoding=encoding,
            dir=dir.as_posix() if dir else None,
            delete=False,
            errors=errors,
            suffix=suffix,
        )
        if chown is not None:
            command = f"sudo chown {chown} {f.name}"
            self.run_cmd(command)
        file_path: PathProtocol = self.root / f.name
        try:
            if data:
                self.write_text(data, file_path)
            yield file_path
        finally:
            if not f.closed:
                f.close()
            if delete:
                try:
                    file_path.unlink()
                except OSError as e:
                    raise e

    @override
    def run_script(self, script_name: str, args: str = None, stdin: str | None = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME.

        Args:
            script_name (str): The name of script file to execute.
            args (str): Arguments passed to the script.
            stdin (str): String input to be passed on the standard input of the subprocess.
        """
        script_path = f"{self.paths.home}/{script_name}"
        if not os.access(script_path, os.X_OK):
            self.run_cmd(f"chmod a+x {script_path}")

        self.run_cmd(f"snap run --shell opensearch.daemon -- {script_path}", args)

    @property
    @override
    def keytool_cmd(self) -> str:
        """Return VM keytool command via snap wrapper."""
        return "opensearch.keytool"

    @override
    def get_host_public_ip(self) -> str | None:
        """Return unit public address from Juju."""
        cmd = "unit-get public-address"
        try:
            output = self.run_cmd(cmd)
        except OpenSearchCmdError:
            return None
        if output.returncode != 0:
            return None

        return output.out.strip()

    @override
    def is_service_started(self, paused: bool | None = False) -> bool:
        """Check if the snap service and JVM process are running.

        Set paused=True if the process was intentionally paused.
        """
        if not self.opensearch_snap.present:
            return False

        if not service_running("snap.opensearch.daemon.service"):
            return False

        # Now, we must dig deeper into the actual status of systemd and the JVM process.
        # First, we want to make sure the process is not stopped, dead or zombie.
        try:
            pid = self.run_cmd("lsof", args="-ti:9200").out.rstrip()
            if not pid or not os.path.exists(f"/proc/{pid}/stat"):
                return False
            with open(f"/proc/{pid}/stat") as f:
                stat = f.read()
        except (subprocess.CalledProcessError, OpenSearchCmdError):
            return False

        # From: https://github.com/torvalds/linux/blob/ \
        #     8d8d276ba2fb5f9ac4984f5c10ae60858090babc/fs/proc/array.c#L126-L140
        # Possible states to consider:
        # "R (running)",		/* 0x00 */
        # "S (sleeping)",		/* 0x01 */
        # "D (disk sleep)",	/* 0x02 */
        # "T (stopped)",		/* 0x04 */
        # "t (tracing stop)",	/* 0x08 */
        # "X (dead)",		/* 0x10 */
        # "Z (zombie)",		/* 0x20 */
        # "P (parked)",		/* 0x40 */
        # "I (idle)",		/* 0x80 */
        # "Parked" state is ignored as it applies to threads.
        if stat[2] == "T" and paused:
            return True

        # We do not check reachability of the service
        return stat[2] not in ["Z", "T", "X"]

    @override
    def start_service_only(self):
        """Start the actual service only (snap / pebble)."""
        if not self.opensearch_snap.present:
            raise OpenSearchMissingError()

        try:
            self.opensearch_snap.start([self.SERVICE_NAME])
        except snap.SnapError as e:
            logger.error("Failed to start the opensearch.%s service. \n%s", self.SERVICE_NAME, e)
            raise OpenSearchStartError()

    @override
    def is_failed(self) -> bool:
        """Check if snap service failed."""
        if not self.opensearch_snap.present:
            raise OpenSearchMissingError()

        return service_failed("snap.opensearch.daemon.service")

    @override
    def start_service(self):
        """Start the snap exposed "daemon" service."""
        if not self.opensearch_snap.present:
            raise OpenSearchMissingError()

        if self.opensearch_snap.services[self.SERVICE_NAME]["active"]:
            logger.info("The opensearch.%s service is already started.", self.SERVICE_NAME)
            return

        try:
            self.opensearch_snap.start([self.SERVICE_NAME])
        except snap.SnapError as e:
            logger.error("Failed to start the opensearch.%s service. \n%s", self.SERVICE_NAME, e)
            raise OpenSearchStartError()

    def _apply_system_requirement(self, system_requirement: str, value: int) -> bool:
        """Apply a system requirement.

        Args:
            system_requirement (str): Kernel parameter to update.
            value (int): Value of the kernel parameter.

        Returns:
            applied (bool): Whether the kernel value is applied successfully.
        """
        try:
            self.run_cmd(f"sysctl -w {system_requirement}={value}")
            return int(self.run_cmd(f"sysctl -n {system_requirement}").out.rstrip()) == value
        except OpenSearchCmdError:
            return False

    @override
    def check_missing_system_requirements(self) -> list[str]:
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

    @override
    def run_cmd(
        self,
        command: str,
        args: str | None = None,
        use_errors_replace: bool = False,
        stdin: str | None = None,
    ) -> SimpleNamespace:
        """Run command.

        Args:
            command: can contain arguments
            args: command line arguments
            stdin: string input to be passed on the standard input of the subprocess
            use_errors_replace: replace errors with empty string

        Returns the stdout
        """
        command_with_args = command
        if args is not None:
            command_with_args = f"{command} {args}"

        # only log the command and no arguments to avoid logging sensitive information
        command = mask_sensitive_information(command_with_args)
        logger.debug("Executing command: %s", command)

        run_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
            encoding="utf-8",
            timeout=25,
            env=os.environ,
        )

        # OpenSSL's "pkcs12 -in" output may contain non-UTF-8 bytes in Bag Attributes
        # (e.g., friendlyName: debian:netlock_arany_=class_gold=_fQtanúsítvány.pem). When Python
        # decodes stdout/stderr as UTF-8, this can raise UnicodeDecodeError.
        #
        # We enable errors="replace" only when explicitly requested (e.g., in list_cas or
        # certificate-issuer parsing), because those commands only need ASCII PEM blocks
        # and not the exact attribute encoding. All other commands (keytool, chmod, x509)
        # should fail if their output is not valid UTF-8.
        if use_errors_replace:
            run_kwargs["errors"] = "replace"
        if stdin:
            run_kwargs["input"] = stdin
        try:
            output = subprocess.run(command_with_args, **run_kwargs)
            if output.returncode != 0:
                logger.debug(
                    "%s:\n Stderr: %s\n Stdout: %s", command, output.stderr, output.stdout
                )
                raise OpenSearchCmdError(cmd=command, out=output.stdout, err=output.stderr)
            return SimpleNamespace(
                cmd=command, out=output.stdout, err=output.stderr, returncode=output.returncode
            )
        except (TimeoutError, subprocess.TimeoutExpired):
            raise OpenSearchCmdError(cmd=command)

    @override
    def stop(self) -> None:
        """Stop the opensearch service."""
        if not self.opensearch_snap.present:
            raise OpenSearchMissingError()

        try:
            self.opensearch_snap.stop([self.SERVICE_NAME])
        except SnapError as e:
            logger.error("Failed to stop the opensearch.%s service. \n%s", self.SERVICE_NAME, e)
            raise OpenSearchStopError()

    @property
    @override
    def paths(self) -> Paths:
        """Return Workload's paths"""
        return Paths(self.root, LocalPath(self.charm_root))

    @property
    @override
    def root(self) -> PathProtocol:
        """Return the root path."""
        return pathops.LocalPath("/")

    @override
    def chain_path(self) -> str:
        """Return the local path to chain.pem."""
        return self.paths.certs_chain.as_posix()

    @override
    def get_workload_version(self) -> str:
        """Return the workload version."""
        return self.run_cmd("opensearch.opensearch-bin", args="--version 2>/dev/null").out.strip()

    @override
    def memtotal(self) -> float:
        """Read the /proc/meminfo file and return the values in kB.

        Returns:
            float: The total memory of the system in bytes.

        Raises:
            OpenSearchCmdError: If there is an error reading the memory information.
        """
        try:
            output = self.run_cmd("cat /proc/meminfo").out
            lines = [line.split() for line in output.split("\n") if line.strip()]
            meminfo = {line[0][:-1]: float(line[1]) for line in lines if len(line) >= 2}
            return meminfo["MemTotal"]
        except (OpenSearchCmdError, OSError, ValueError, IndexError, AttributeError) as e:
            logger.warning("Failed to read meminfo: %s", e)
            raise OpenSearchCmdError(cmd="cat /proc/meminfo", err=str(e))
