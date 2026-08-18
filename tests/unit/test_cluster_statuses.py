# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for ClusterManager status reassert (DPE #75)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from opensearch_single_kernel.common.constants import (
    CLUSTER_MANAGER_VOTING_ROLES_PROVIDED_INVALID,
    DeploymentType,
    StartMode,
    State,
)
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.core.models import DeploymentState, PeerClusterConfig
from opensearch_single_kernel.managers.cluster import ClusterManager
from opensearch_single_kernel.utils.status import format_status


def _manager(
    *,
    roles_config="cluster_manager,data",
    deployment_desc=None,
    is_peer_consumer=False,
):
    state = MagicMock()
    state.statuses.get.return_value = SimpleNamespace(root=[])
    state.config = {
        "cluster_name": "test",
        "init_hold": False,
        "roles": roles_config,
    }
    state.application.deployment_desc = deployment_desc
    state.is_peer_cluster_consumer.return_value = is_peer_consumer
    state.oauth_relation = None
    state.jwt_relation = None
    workload = MagicMock()
    return ClusterManager(state, workload), state


def _deployment_desc(
    *,
    roles=None,
    state_value=State.ACTIVE,
    state_message="",
    typ=DeploymentType.MAIN_ORCHESTRATOR,
    start=StartMode.WITH_PROVIDED_ROLES,
):
    return SimpleNamespace(
        typ=typ,
        start=start,
        config=PeerClusterConfig(
            cluster_name="test",
            init_hold=False,
            roles=roles if roles is not None else ["cluster_manager", "data"],
        ),
        state=DeploymentState(value=state_value, message=state_message),
        pending_directives=[],
    )


def test_invalid_cm_and_voting_only_always_reasserted_from_config():
    """#75: invalid roles in juju config must stay blocked after SHOW_STATUS clears."""
    mgr, _ = _manager(
        roles_config="cluster_manager, voting_only",
        deployment_desc=_deployment_desc(
            roles=["cluster_manager", "data"],  # last good applied roles
            state_value=State.ACTIVE,  # SHOW_STATUS already applied/cleared path
            state_message="",
        ),
    )

    statuses = mgr.get_statuses("app", recompute=True)

    assert PeerClusterStatuses.INVALID_CM_AND_VOTING_ONLY_ROLES.value in statuses


def test_blocked_deployment_message_reasserted_without_pending_directives():
    """Blocked deployment state messages must not depend on SHOW_STATUS directive."""
    message = CLUSTER_MANAGER_VOTING_ROLES_PROVIDED_INVALID
    mgr, _ = _manager(
        roles_config="cluster_manager,data",
        deployment_desc=_deployment_desc(
            state_value=State.BLOCKED_CANNOT_APPLY_NEW_ROLES,
            state_message=message,
        ),
    )

    statuses = mgr.get_statuses("app", recompute=True)

    expected = format_status(
        GeneralStatuses.BLOCKING_DIRECTIVE.value,
        params={"directive": message},
    )
    assert expected in statuses


def test_cm_removal_forbidden_from_user_config():
    mgr, _ = _manager(
        roles_config="data",
        deployment_desc=_deployment_desc(roles=["cluster_manager", "data"]),
    )

    statuses = mgr.get_statuses("app")

    assert PeerClusterStatuses.CM_ROLE_REMOVAL_FORBIDDEN.value in statuses


def test_valid_roles_idle():
    mgr, _ = _manager(
        roles_config="cluster_manager,data",
        deployment_desc=_deployment_desc(
            roles=["cluster_manager", "data"],
            state_value=State.ACTIVE,
        ),
    )
    # security index path may add no-data-node if not data+... mark security inited
    mgr.state.application.security_index_initialised = True

    statuses = mgr.get_statuses("app")

    assert statuses == [GeneralStatuses.ACTIVE_IDLE.value]
