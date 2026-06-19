# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""PebbleObserver: spawns and manages the periodic pebble observer subprocess."""

import logging
import os
import signal
import subprocess
import sys
from pathlib import Path
from sys import version_info
from typing import TYPE_CHECKING

from ops.framework import Object

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)

LOG_FILE_PATH = "/tmp/pebble_observer.log"


class PebbleObserver(Object):
    """Manages a background subprocess that periodically dispatches pebble_can_connect."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "pebble-observer")
        self._charm = charm

    def start(self) -> None:
        """Start observer if not running; restart if previous process is dead."""
        if (existing_pid := self._charm.state.server.pebble_observer_pid) is not None:
            try:
                os.kill(existing_pid, 0)
                return  # process is alive
            except OSError:
                pass  # process is dead — fall through and spawn a new one

        new_env = os.environ.copy()
        new_env.pop("JUJU_CONTEXT_ID", None)

        # Add venv site-packages to PYTHONPATH (same pattern as PostgreSQL operator)
        for loc in new_env.get("PYTHONPATH", "").split(":"):
            path = Path(loc)
            venv_path = (
                path
                / ".."
                / "venv"
                / "lib"
                / f"python{version_info.major}.{version_info.minor}"
                / "site-packages"
            )
            if path.stem == "lib":
                new_env["PYTHONPATH"] = f"{venv_path.resolve()}:{new_env['PYTHONPATH']}"
                break

        process = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "opensearch_single_kernel.pebble_observer",
                self._charm.unit.name,
                str(self._charm.charm_dir),
            ],
            stdout=open(LOG_FILE_PATH, "a"),  # noqa: SIM115
            stderr=subprocess.STDOUT,
            env=new_env,
        )

        self._charm.state.server.pebble_observer_pid = str(process.pid)
        logger.info("Started pebble observer with PID %d", process.pid)

    def stop(self) -> None:
        """SIGTERM the observer subprocess and clear stored PID."""
        if (pid := self._charm.state.server.pebble_observer_pid) is None:
            return

        try:
            os.kill(pid, signal.SIGTERM)
            logger.info("Stopped pebble observer PID %d", pid)
        except OSError:
            pass

        del self._charm.state.server.pebble_observer_pid
