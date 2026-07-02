#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Pebble observer subprocess: dispatches pebble_can_connect periodically."""

import subprocess
import sys
from time import sleep

from ops import pebble

from opensearch_single_kernel.common.constants import CONTAINER_NAME

INTERVAL_SECONDS = 30
JUJU_EXEC = "juju-exec"


def dispatch(unit: str, charm_dir: str) -> None:
    """Dispatch pebble_can_connect on the given unit via juju-exec."""
    cmd = f"JUJU_DISPATCH_PATH=hooks/pebble_can_connect {charm_dir}/dispatch"
    subprocess.run([JUJU_EXEC, "-u", unit, cmd])  # noqa: S603


def main() -> None:
    """Main loop: sleep then dispatch on repeat."""
    unit, charm_dir = sys.argv[1:]
    while True:
        sleep(INTERVAL_SECONDS)
        client = pebble.Client(f"/charm/containers/{CONTAINER_NAME}/pebble.socket")
        try:
            # check if Pebble is responsive same as unit.get_container("opensearch").can_connect()
            client.get_system_info()
            dispatch(unit, charm_dir)
            return  # exit after successful dispatch
        except (pebble.ConnectionError, FileNotFoundError, pebble.APIError):
            # If we can't connect to Pebble, or the socket isn't found, or we get an API error,
            # log and retry after the sleep interval
            print(
                "Pebble not responsive, will retry dispatching pebble_can_connect after sleep interval."
            )
            continue


if __name__ == "__main__":
    main()
