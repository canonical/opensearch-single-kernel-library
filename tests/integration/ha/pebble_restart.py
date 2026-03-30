# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Pebble restart-delay tweaks for K8s HA tests.

Uses kubectl to copy a layer file into the workload
container and run `pebble add --combine` + `pebble replan`.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from pytest_operator.plugin import OpsTest

from opensearch_single_kernel.common.constants import CONTAINER_NAME

_PEBBLE = "/charm/bin/pebble"
_SERVICE = "opensearch"


def _kubectl_base() -> list[str]:
    if shutil.which("microk8s"):
        return ["microk8s", "kubectl"]
    return ["kubectl"]


def modify_pebble_restart_delay(
    ops_test: OpsTest,
    unit_name: str,
    pebble_plan_path: str | Path,
    *,
    ensure_replan: bool = True,
) -> None:
    """Merge a Pebble layer on the workload container and replan."""
    namespace = ops_test.model.info.name
    pod = unit_name.replace("/", "-")
    container = CONTAINER_NAME
    remote = f"/tmp/pebble_layer_{pod}.yml"
    local = Path(pebble_plan_path).resolve()

    kubectl = _kubectl_base()
    subprocess.run(
        [*kubectl, "cp", str(local), f"{namespace}/{pod}:{remote}", "-c", container],
        check=True,
    )
    add_cmd = [
        *kubectl,
        "exec",
        "-n",
        namespace,
        pod,
        "-c",
        container,
        "--",
        _PEBBLE,
        "add",
        "--combine",
        _SERVICE,
        remote,
    ]
    subprocess.run(add_cmd, check=True)
    replan_cmd = [
        *kubectl,
        "exec",
        "-n",
        namespace,
        pod,
        "-c",
        container,
        "--",
        _PEBBLE,
        "replan",
    ]
    proc = subprocess.run(replan_cmd, capture_output=True, text=True)
    if ensure_replan and proc.returncode != 0:
        raise RuntimeError(f"pebble replan failed for {unit_name}: {proc.stderr or proc.stdout}")
