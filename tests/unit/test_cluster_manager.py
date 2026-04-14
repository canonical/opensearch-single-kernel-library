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
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    Node,
    PeerClusterConfig,
)


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


def test_can_start(harness, mocker):
    """Test the can_start logic."""
    mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        return_value=None,
        new_callable=PropertyMock,
    )
    assert not harness.charm.cluster_manager.check_if_can_start()

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

        can_start = harness.charm.cluster_manager.check_if_can_start()
        assert (
            can_start == expected
        ), f"Failed for directives {directives}: expected {expected} but got {can_start}"


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
