#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Machine VM Workload."""
import os
import subprocess
from typing import Optional

from overrides import override
from tenacity import Retrying, retry, stop_after_attempt, wait_exponential, wait_fixed

from opensearch_single_kernel.common.constants import OPENSEARCH_SNAP_REVISION, VM_PATHS
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchInstallError,
    OpenSearchMissingError,
    OpenSearchStartError,
)
from opensearch_single_kernel.lib.charms.operator_libs_linux.v1.systemd import (
    service_failed,
)
from opensearch_single_kernel.lib.charms.operator_libs_linux.v2 import snap
from opensearch_single_kernel.utils.helpers import mask_sensitive_information
from opensearch_single_kernel.workload.base import BaseWorkload, Paths


class VMWorkload(BaseWorkload):
    """OpenSearch Machine VM Workload."""

    SERVICE_NAME = "daemon"

    def __init__(self):
        super().__init__()
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(wait=5)):
            with attempt:
                cache = snap.SnapCache()
                self.opensearch_snap = cache["opensearch"]

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
            self.opensearch_snap = cache["opensearch"]
            # Make sure that we have the exact revision
            self.opensearch_snap.ensure(snap.SnapState.Latest, revision=OPENSEARCH_SNAP_REVISION)
            self.opensearch_snap.connect("process-control")
            if not self.opensearch_snap.held:
                # hold the snap in charm determined revision
                self.opensearch_snap.hold()
        except snap.SnapError as e:
            self.logger.error(f"Failed to install/upgrade opensearch. \n{e}")
            raise OpenSearchInstallError()

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(0.5), reraise=True)
    @override
    def _run_cmd(self, command: str, args: str = None, stdin: str = None) -> str:
        """Run command.

        Arg:
            command: can contain arguments
            args: command line arguments
            stdin: string input to be passed on the standard input of the subprocess

        Returns the stdout
        """
        command_with_args = command
        if args is not None:
            command_with_args = f"{command} {args}"

        # only log the command and no arguments to avoid logging sensitive information
        command = mask_sensitive_information(command_with_args)
        self.logger.debug(f"Executing command: {command}")

        try:
            output = subprocess.run(
                command_with_args,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                env=os.environ,
            )

            self.logger.debug(f"{command}:\n{output.stdout}")

            if output.returncode != 0:
                self.logger.debug(
                    f"{command}:\n Stderr: {output.stderr}\n Stdout: {output.stdout}"
                )
                raise OpenSearchCmdError(output.stderr)
        except (TimeoutError, subprocess.TimeoutExpired) as e:
            raise OpenSearchCmdError(e)
        return output.stdout.strip()

    @override
    def run_script(self, script_name: str, args: str = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME."""
        script_path = f"{self.paths.home}/{script_name}"
        if not os.access(script_path, os.X_OK):
            self._run_cmd(f"chmod a+x {script_path}")

        self._run_cmd(f"snap run --shell opensearch.daemon -- {script_path}", args)

    @property
    @override
    def paths(self):
        """Return Workload's paths"""
        return Paths(**VM_PATHS)

    @override
    def is_service_started(self, paused: Optional[bool] = False) -> bool:
        """Check if the snap service and JVM process are running.

        Set paused=True if the process was intentionally paused.
        """
        return False

    @override
    def start_service_only(self):
        """Start the actual service only (snap / pebble)."""
        pass

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
            self.logger.info(f"The opensearch.{self.SERVICE_NAME} service is already started.")
            return

        try:
            self.opensearch_snap.start([self.SERVICE_NAME])
        except snap.SnapError as e:
            self.logger.error(f"Failed to start the opensearch.{self.SERVICE_NAME} service. \n{e}")
            raise OpenSearchStartError()

    @override
    def meminfo(self) -> dict[str, float]:
        """Read the /proc/meminfo file and return the values.

        According to the kernel source code, the values are always in kB:
            https://github.com/torvalds/linux/blob/
                2a130b7e1fcdd83633c4aa70998c314d7c38b476/fs/proc/meminfo.c#L31
        """
        with open("/proc/meminfo") as f:
            meminfo = f.read().split("\n")
            meminfo = [line.split() for line in meminfo if line.strip()]

        return {line[0][:-1]: float(line[1]) for line in meminfo}
