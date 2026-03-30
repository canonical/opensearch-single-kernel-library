# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


"""General helpers for unit and integration tests."""

from typing import Literal, TypeAlias

Substrate: TypeAlias = Literal["vm", "k8s"]


def patch_workload_meminfo(mocker, substrate: Substrate, return_value: dict[str, float]):
    """Patch meminfo on the concrete workload class.

    VM charm returns a new :class:`VMWorkload` on every ``charm.workload`` access, so
    instance-level patches do not reach managers. Patch the class method instead.
    """
    if substrate == "vm":
        return mocker.patch(
            "opensearch_single_kernel.workload.vm.VMWorkload.meminfo",
            return_value=return_value,
        )
    return mocker.patch(
        "opensearch_single_kernel.workload.k8s.K8sWorkload.meminfo",
        return_value=return_value,
    )


def patch_workload_check_missing_system_requirements(
    mocker, substrate: Substrate, return_value: list[str]
):
    """Patch sysctl-style checks on the workload implementation used for ``substrate``."""
    if substrate == "vm":
        return mocker.patch(
            "opensearch_single_kernel.workload.base.BaseWorkload.check_missing_system_requirements",
            return_value=return_value,
        )
    return mocker.patch(
        "opensearch_single_kernel.workload.k8s.K8sWorkload.check_missing_system_requirements",
        return_value=return_value,
    )
