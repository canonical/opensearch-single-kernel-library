#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""A set of utility functions for managing peer clusters."""

from opensearch_single_kernel.core.models.peer_cluster import (
    PeerClusterApp,
    PeerClusterOrchestrators,
)


def update_cluster_fleet(
    fleet_dict: dict[str, dict[str, PeerClusterApp]], app: PeerClusterApp, key: str | None = None
) -> None:
    """Update fleet dictionary with the app, or remove the entry if no planned units."""
    if not key:
        key = app.app.id

    if app.planned_units == 0:
        fleet_dict.pop(key, None)
        return

    fleet_dict.update({key: app})


def is_failover_promoted(orchestrators: PeerClusterOrchestrators) -> bool:
    """Checks if failover orchestrator was promoted to the main orchestrator"""
    return (
        orchestrators.failover_app is not None
        and orchestrators.main_app is not None
        and orchestrators.failover_app.id == orchestrators.main_app.id
    )
