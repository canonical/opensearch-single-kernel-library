#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Chaos Mesh helpers for k8s HA network tests."""

from __future__ import annotations

import logging
import os
import string
import subprocess
import tempfile
from pathlib import Path

from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

HA_DIR = Path(__file__).resolve().parent
CHAOS_NETWORK_LOSS_YML = HA_DIR / "manifests" / "chaos_network_loss.yml"
DEPLOY_SCRIPT = HA_DIR / "scripts" / "deploy_chaos_mesh.sh"
DESTROY_SCRIPT = HA_DIR / "scripts" / "destroy_chaos_mesh.sh"

NETWORK_CHAOS_NAME = "network-loss-primary"


def _kubectl_env() -> dict[str, str]:
    env = os.environ.copy()
    env["KUBECONFIG"] = os.path.expanduser("~/.kube/config")
    return env


def deploy_chaos_mesh(namespace: str) -> None:
    """Deploy Chaos Mesh into the Juju model namespace (MicroK8s)."""
    subprocess.check_output(
        ["bash", str(DEPLOY_SCRIPT), namespace],
        env=_kubectl_env(),
    )


def destroy_chaos_mesh(namespace: str) -> None:
    """Remove Chaos Mesh from the cluster."""
    subprocess.check_output(
        ["bash", str(DESTROY_SCRIPT), namespace],
        env=_kubectl_env(),
    )


def cut_network_from_unit_k8s(ops_test: OpsTest, juju_unit_name: str) -> None:
    """Isolate a unit's pod from the cluster using Chaos Mesh NetworkChaos."""
    namespace = ops_test.model.info.name
    pod = juju_unit_name.replace("/", "-")
    logger.info("Applying network loss on ns=%s pod=%s", namespace, pod)

    with CHAOS_NETWORK_LOSS_YML.open() as chaos_network_loss_file:
        template = string.Template(chaos_network_loss_file.read())
        manifest = template.substitute(namespace=namespace, pod=pod)

    with tempfile.NamedTemporaryFile(
        mode="wb",
        suffix=".yml",
        delete=False,
    ) as temp_file:
        temp_file.write(manifest.encode())
        temp_path = temp_file.name

    try:
        subprocess.check_output(
            ["microk8s", "kubectl", "apply", "-f", temp_path],
            stderr=subprocess.STDOUT,
            env=_kubectl_env(),
        )
    except subprocess.CalledProcessError as err:
        logger.error(
            "Failed to apply network isolation: [%s] output=%r",
            err.returncode,
            getattr(err, "output", None),
        )
        raise
    finally:
        Path(temp_path).unlink(missing_ok=True)


def restore_network_for_unit_k8s(ops_test: OpsTest) -> None:
    """Remove the NetworkChaos object so the pod can communicate again."""
    namespace = ops_test.model.info.name
    subprocess.check_output(
        [
            "microk8s",
            "kubectl",
            "-n",
            namespace,
            "delete",
            "networkchaos",
            NETWORK_CHAOS_NAME,
            "--ignore-not-found",
        ],
        stderr=subprocess.STDOUT,
        env=_kubectl_env(),
    )
