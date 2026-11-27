# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_peer_clusters library."""

from unittest.mock import MagicMock, PropertyMock

import pytest

from opensearch_single_kernel.common.constants import (
    DeploymentType,
    Directive,
    StartMode,
    State,
)
from opensearch_single_kernel.common.exceptions import OpenSearchProvidedRolesException
from opensearch_single_kernel.common.statuses import GeneralStatuses
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    Node,
    PeerClusterConfig,
)
from tests.unit.helpers import deployment_descriptions


class PatchedUnit:
    def __init__(self, name: str):
        self.name = name


user_configs = {
    "default": PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
    "name": PeerClusterConfig(
        cluster_name="logs", init_hold=False, roles=[], profile="production"
    ),
    "init_hold": PeerClusterConfig(
        cluster_name="", init_hold=True, roles=[], profile="production"
    ),
    "roles_ok": PeerClusterConfig(
        cluster_name="",
        init_hold=False,
        roles=["cluster_manager", "data"],
        profile="production",
    ),
    "roles_ko": PeerClusterConfig(
        cluster_name="", init_hold=False, roles=["data"], profile="production"
    ),
    "roles_temp": PeerClusterConfig(
        cluster_name="", init_hold=True, roles=["data.hot"], profile="production"
    ),
}

p_units = [
    PatchedUnit(name="opensearch/0"),
    PatchedUnit(name="opensearch/1"),
    PatchedUnit(name="opensearch/2"),
    PatchedUnit(name="opensearch/3"),
    PatchedUnit(name="opensearch/4"),
]


@pytest.mark.parametrize("peer_relation_present", [True, False])
def test_stop_workload_clears_started_with_or_without_peer_relation(
    harness, mocker, peer_relation_present
):
    """Stopping still finishes if the peer relation is gone during storage removal."""
    charm = harness.charm
    charm.state.server.started = "2026-11-13T11:00:00Z"
    if not peer_relation_present:
        with harness.hooks_disabled():
            harness.remove_relation(charm.state.peer_relation.id)

    stop = mocker.patch.object(charm.cluster_manager.workload, "stop")
    mocker.patch.object(charm.cluster_manager, "is_started", return_value=False)

    charm.cluster_manager.stop_workload()

    stop.assert_called_once_with()
    if peer_relation_present:
        assert charm.state.server.started == ""
    else:
        assert charm.state.peer_relation is None


def test_can_start(harness, mocker):
    """Test the can_start logic."""
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        return_value=None,
        new_callable=PropertyMock,
    )
    assert not harness.charm.state.application.deployment_desc

    # with different directives
    for directives, expected in [
        ([], True),
        ([Directive.SHOW_STATUS], True),
        ([Directive.SHOW_STATUS, Directive.WAIT_FOR_PEER_CLUSTER_RELATION], False),
        ([Directive.INHERIT_CLUSTER_NAME], False),
    ]:
        deployment_desc = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="logs",
                init_hold=False,
                roles=["cluster_manager", "data"],
                profile="production",
            ),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=directives,
            app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            state=DeploymentState(value=State.ACTIVE),
            profile="production",
        )
        mocker.patch(
            "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
            return_value=deployment_desc,
            new_callable=PropertyMock,
        )
        can_start = harness.charm.cluster_manager.no_blocking_directives()

        assert can_start == expected, (
            f"Failed for directives {directives}: expected {expected} but got {can_start}"
        )


@pytest.mark.parametrize(
    "security_initialised,started,live_roles,ignore_lock",
    [
        (False, False, [], True),
        (True, True, [], True),
        (True, False, [], False),
        (True, True, ["cluster_manager"], True),
        (True, True, ["data"], False),
        (False, False, ["data"], False),
    ],
)
def test_first_data_node_bootstrap_requires_no_running_data_nodes(
    harness, mocker, patch_deployment_desc, security_initialised, started, live_roles, ignore_lock
):
    """Allow bootstrap and recovery with all data nodes down, but use a live cluster's lock."""
    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
    deployment = charm.state.application.deployment_desc
    deployment.typ = DeploymentType.OTHER
    deployment.start = StartMode.WITH_PROVIDED_ROLES
    deployment.config.roles = ["data"]
    charm.state.application.is_security_index_initialised = security_initialised
    if started:
        charm.state.server.started = "2026-11-13T11:00:00Z"
    mocker.patch.object(charm.workload, "is_service_started", return_value=False)
    mocker.patch.object(charm.cluster_manager, "get_cluster_first_data_node", return_value=None)
    nodes = []
    if live_roles:
        nodes.append(
            Node(
                name="other-0",
                roles=live_roles,
                ip="10.0.0.2",
                app=deployment.app,
                unit_number=1,
            )
        )

    assert bool(charm.cluster_manager.should_ignore_lock(deployment, nodes)) == ignore_lock


def test_pre_validate_roles_change(harness, mocker):
    """Test the pre_validation of roles change."""
    mocker.patch(
        "ops.model.Model.get_relation",
        return_value=MagicMock(units=set(p_units)),
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
        return_value=DeploymentDescription(
            config=user_configs["roles_ok"],
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[],
            app=App(model_uuid=harness.charm.model.uuid, name="logs"),
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            state=DeploymentState(value=State.ACTIVE),
        ),
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.alt_hosts",
        new_callable=PropertyMock,
        return_value=[],
    )
    try:
        mocker.patch(
            "opensearch_single_kernel.managers.cluster.ClusterManager._nodes",
            new_callable=PropertyMock,
            return_value=[
                Node(
                    name=node.name.replace("/", "-")
                    + f".{harness.charm.state.application.deployment_desc.app.short_id}",
                    roles=["data"],
                    ip="1.1.1.1",
                    app=harness.charm.state.application.deployment_desc.app,
                    unit_number=int(node.name.split("/")[-1]),
                )
                for node in p_units
            ]
            + [
                Node(
                    name=f"node-5.{harness.charm.state.application.deployment_desc.app.short_id}",
                    roles=["data"],
                    ip="2.2.2.2",
                    app=harness.charm.state.application.deployment_desc.app,
                    unit_number=5,
                )
            ],
        )
        harness.charm.cluster_manager._pre_validate_roles_change(
            new_roles=["data", "ml"], prev_roles=["data", "ml"]
        )

        harness.charm.cluster_manager._pre_validate_roles_change(
            new_roles=[], prev_roles=["data", "ml"]
        )

    except OpenSearchProvidedRolesException:
        pytest.fail("_pre_validate_roles_change() failed unexpectedly.")

    with pytest.raises(OpenSearchProvidedRolesException):
        harness.charm.cluster_manager._pre_validate_roles_change(
            new_roles=["cluster_manager", "voting_only"], prev_roles=[]
        )
    with pytest.raises(OpenSearchProvidedRolesException):
        harness.charm.cluster_manager._pre_validate_roles_change(
            new_roles=["data"], prev_roles=["cluster_manager", "data"]
        )
    with pytest.raises(OpenSearchProvidedRolesException):
        harness.charm.cluster_manager._pre_validate_roles_change(
            new_roles=["ml"], prev_roles=["ml", "data"]
        )
    with pytest.raises(OpenSearchProvidedRolesException):
        # no other data nodes in cluster fleet
        mocker.patch(
            "opensearch_single_kernel.managers.cluster.ClusterManager._nodes",
            new_callable=PropertyMock,
            return_value=[
                Node(
                    name=node.name.replace("/", "-")
                    + f".{harness.charm.state.application.deployment_desc.app.short_id}",
                    roles=["data"],
                    ip="1.1.1.1",
                    app=harness.charm.state.application.deployment_desc.app,
                    unit_number=int(node.name.split("/")[-1]),
                )
                for node in p_units
            ],
        )
        harness.charm.cluster_manager._pre_validate_roles_change(
            new_roles=["ml"], prev_roles=["data", "ml"]
        )


@pytest.mark.parametrize("new_roles", [["foo"], ["data.warm"]], ids=["foo", "data.warm"])
def test_existing_cluster_setup_rejected_roles(harness, new_roles):
    """Test that a roles change dropping cluster_manager keeps the previous deployment."""
    prev_deployment_desc = deployment_descriptions["ok"]

    deployment_desc = harness.charm.cluster_manager._existing_cluster_setup(
        PeerClusterConfig(cluster_name="", init_hold=False, roles=new_roles),
        prev_deployment_desc,
    )

    assert deployment_desc.state.value == State.BLOCKED_CANNOT_APPLY_NEW_ROLES
    assert deployment_desc.config == prev_deployment_desc.config
    assert deployment_desc.start == prev_deployment_desc.start
    assert deployment_desc.typ == prev_deployment_desc.typ
    assert deployment_desc.promotion_time == prev_deployment_desc.promotion_time


def test_existing_cluster_setup_applies_new_roles(harness):
    """Test that a valid roles change is applied."""
    prev_deployment_desc = deployment_descriptions["ok"]

    deployment_desc = harness.charm.cluster_manager._existing_cluster_setup(
        user_configs["roles_ok"], prev_deployment_desc
    )

    assert deployment_desc.state.value == State.ACTIVE
    assert deployment_desc.config.roles == ["cluster_manager", "data"]
    assert deployment_desc.start == StartMode.WITH_PROVIDED_ROLES
    assert deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
    assert deployment_desc.promotion_time == prev_deployment_desc.promotion_time


def test_no_cluster_manager_left_ignores_current_unit(harness, mocker, patch_deployment_desc):
    cluster_manager = harness.charm.cluster_manager
    state = harness.charm.state
    current = Node(
        name=state.unit_name,
        roles=["cluster_manager", "data"],
        ip=state.node_host,
        app=state.application.deployment_desc.app,
        unit_number=0,
    )
    other_app = MagicMock()
    other_app.app.id = "other-model/data"
    mocker.patch.object(type(cluster_manager), "_nodes", return_value=[current])
    mocker.patch.object(type(cluster_manager), "alt_hosts", new_callable=PropertyMock)
    mocker.patch(
        "opensearch_single_kernel.common.client.OpenSearchClient.is_node_up", return_value=True
    )
    mocker.patch.object(
        type(state.application),
        "apps_in_fleet",
        new_callable=PropertyMock,
        return_value=[other_app],
    )

    assert cluster_manager.no_cluster_manager_left


def test_bootstrap_contributors_use_node_host(harness, patch_deployment_desc):
    cm_names, cm_ips = [], []

    harness.charm.cluster_manager.configure_bootstrap_contributors(
        ["cluster_manager"], cm_names, cm_ips
    )

    assert cm_ips == [harness.charm.state.node_host]


@pytest.mark.parametrize("security_initialized", [False, True])
@pytest.mark.parametrize("tls_configured", [False, True])
@pytest.mark.parametrize("started", [False, True])
def test_startup_status_respects_local_tls_without_hiding_unavailable_nodes(
    harness, mocker, patch_deployment_desc, security_initialized, tls_configured, started
):
    charm = harness.charm
    mocker.patch.object(
        type(charm.state.application),
        "is_security_index_initialised",
        new_callable=PropertyMock,
        return_value=security_initialized,
    )
    mocker.patch.object(
        type(charm.state.server),
        "tls_configured",
        new_callable=PropertyMock,
        return_value=tls_configured,
    )
    charm.state.server.started = "2026-11-13T00:00:00" if started else ""
    charm.state.server.start_pending = not started
    mocker.patch.object(charm.workload, "is_service_started", return_value=False)

    statuses = charm.cluster_manager.get_statuses("unit")
    messages = [status.message for status in statuses]

    assert (GeneralStatuses.WAITING_TO_START.value.message in messages) == (
        not started and tls_configured
    )
    assert (GeneralStatuses.SERVICE_UNAVAILABLE.value.message in messages) == started


def test_tls_ready_does_not_imply_startup_was_requested(harness, mocker):
    from tests.unit.helpers import deployment_descriptions

    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.charm.state.application.deployment_desc = deployment_descriptions[
            "cm-only"
        ].model_copy(deep=True)
    charm = harness.charm
    mocker.patch.object(
        type(charm.state.server), "tls_configured", new_callable=PropertyMock, return_value=True
    )

    statuses = charm.cluster_manager.get_statuses("unit", recompute=True)

    assert GeneralStatuses.WAITING_TO_START.value.message not in [s.message for s in statuses]
