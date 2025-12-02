#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Machine VM Workload."""

from overrides import override
from tenacity import retry, stop_after_attempt, wait_exponential

from opensearch_single_kernel.common.exceptions import OpenSearchInstallError
from opensearch_single_kernel.common.literals import OPENSEARCH_SNAP_REVISION
from opensearch_single_kernel.lib.charms.operator_libs_linux.v2 import snap
from opensearch_single_kernel.workload.base import BaseWorkload


class VMWorkload(BaseWorkload):
    """OpenSearch Machine VM Workload."""

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
