# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Profile and application statuses reflect the current fleet and application removal."""

import pytest

from opensearch_single_kernel.common.constants import STATUS_PEERS_RELATION
from opensearch_single_kernel.common.statuses import GeneralStatuses, ProfileStatuses
from opensearch_single_kernel.core.models import App, PeerClusterApp
from opensearch_single_kernel.core.models import TestingProfile as Profile
from opensearch_single_kernel.utils.helpers import deployment_type
from tests.unit.helpers import deployment_descriptions


@pytest.mark.parametrize("scope", ["unit", "app"])
def test_application_removal_does_not_request_more_profile_resources(
    harness, mocker, patch_deployment_desc, scope
):
    harness.set_planned_units(0)
    requirements = mocker.patch.object(
        harness.charm.profiles_manager,
        "get_missing_requirements",
        return_value=["At least 1 data nodes are required."],
    )

    assert harness.charm.profiles_manager.get_statuses(scope) == [
        GeneralStatuses.ACTIVE_IDLE.value
    ]
    requirements.assert_not_called()


def test_profile_checks_resume_when_application_scales_up(harness, mocker, patch_deployment_desc):
    manager = harness.charm.profiles_manager
    mocker.patch.object(manager, "get_missing_requirements", return_value=["Missing data node"])
    harness.set_planned_units(0)
    assert manager.get_statuses("unit") == [GeneralStatuses.ACTIVE_IDLE.value]

    harness.set_planned_units(1)

    assert any(
        s.short_message == ProfileStatuses.MISSING_PROFILE_REQUIREMENTS.value.short_message
        for s in manager.get_statuses("unit")
    )


def test_application_removal_reports_stopping(harness, patch_deployment_desc):
    harness.set_planned_units(0)

    assert harness.charm.cluster_manager.get_statuses("app") == [
        GeneralStatuses.SERVICE_IS_STOPPING.value.model_copy(update={"running": None})
    ]


@pytest.mark.parametrize("deployment", ["data-only", "ok"])
def test_profile_includes_local_app_before_provider_broadcasts_it(harness, deployment):
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.set_planned_units(1)
        charm = harness.charm
        description = deployment_descriptions[deployment].model_copy(deep=True)
        charm.state.application.deployment_desc = description
        main = App(model_uuid="model-uuid", name="main")
        fleet = {
            main.id: PeerClusterApp(
                app=main, planned_units=1, units=["main/0"], roles=["cluster_manager"]
            )
        }
        charm.state.application.cluster_fleet_apps = fleet

    assert charm.profiles_manager.check_cluster_topology(Profile()) == []
    assert charm.state.application.cluster_fleet_apps == fleet


def test_profile_uses_current_local_scale_instead_of_stale_fleet_entry(harness):
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.set_planned_units(1)
        charm = harness.charm
        charm.state.application.deployment_desc = deployment_descriptions["data-only"].model_copy(
            deep=True
        )
        main = App(model_uuid="model-uuid", name="main")
        current = charm.state.current_peer_cluster_app
        fleet = {
            main.id: PeerClusterApp(
                app=main, planned_units=1, units=["main/0"], roles=["cluster_manager"]
            ),
            current.app.id: current.model_copy(update={"planned_units": 0}),
        }
        charm.state.application.cluster_fleet_apps = fleet

    assert charm.profiles_manager.check_cluster_topology(Profile()) == []
    assert charm.state.application.cluster_fleet_apps == fleet


def test_removal_status_clears_when_application_scales_up(harness, patch_deployment_desc):
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.add_relation(STATUS_PEERS_RELATION, harness.charm.app.name)
    manager = harness.charm.cluster_manager
    harness.set_planned_units(0)
    harness.charm.status_handler._recompute_statuses_for_scope("app", manager)

    harness.set_planned_units(1)

    assert GeneralStatuses.SERVICE_IS_STOPPING.value.message not in [
        s.message for s in manager.get_statuses("app")
    ]


@pytest.mark.parametrize(
    "case",
    [
        "waiting",
        "provider-no-units",
        "no-provider",
        "bootstrapped",
        "local-fleet",
        "remote-fleet",
        "known-cm-fleet",
        "valid-fleet",
    ],
)
@pytest.mark.parametrize("deployment", ["data-only", "failover"])
def test_initial_provider_fleet_gap_only_affects_topology_status(
    harness, mocker, case, deployment
):
    from opensearch_single_kernel.common.constants import PEER_CLUSTER_RELATION

    charm = harness.charm
    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.set_planned_units(1)
        description = deployment_descriptions["data-only"].model_copy(deep=True)
        if deployment == "failover":
            description.config.roles = ["cluster_manager"]
            description.config.init_hold = True
            description.typ = deployment_type(description.config, description.start)
        charm.state.application.deployment_desc = description
        charm.state.application.bootstrapped = case == "bootstrapped"
        current = charm.state.current_peer_cluster_app
        fleet = {current.app.id: current}
        main = App(model_uuid="model-uuid", name="main")
        provider_app = PeerClusterApp(
            app=main, planned_units=0, units=[], roles=["cluster_manager"]
        )
        if case in ("known-cm-fleet", "valid-fleet"):
            provider_app.planned_units = 1
            provider_app.units = ["main/0"]
        if case == "valid-fleet":
            provider_app.roles = ["cluster_manager", "data"]
        if case in ("local-fleet", "known-cm-fleet", "valid-fleet"):
            fleet[main.id] = provider_app
        charm.state.application.cluster_fleet_apps = fleet
        if case != "no-provider":
            relation_id = harness.add_relation(PEER_CLUSTER_RELATION, "main")
            if case != "provider-no-units":
                harness.add_relation_unit(relation_id, "main/0")
            if case == "remote-fleet":
                import json

                harness.update_relation_data(
                    relation_id,
                    "main",
                    {"cluster_fleet_apps": json.dumps({main.id: provider_app.to_dict()})},
                )
    manager = charm.profiles_manager
    mocker.patch.object(type(charm.workload), "check_missing_system_requirements", return_value=[])
    mocker.patch.object(manager, "check_memory_requirements", return_value=[])

    requirements_met = case == "valid-fleet" or (
        case == "known-cm-fleet" and deployment == "data-only"
    )
    assert manager.check_profile_requirements() == requirements_met
    statuses = manager.get_statuses("unit")
    assert any(status.status == "blocked" for status in statuses) == (
        not requirements_met and case not in ("waiting", "provider-no-units", "remote-fleet")
    )

    manager.check_memory_requirements.return_value = ["Insufficient memory"]
    assert any("Insufficient memory" in status.message for status in manager.get_statuses("unit"))
    assert not manager.check_profile_requirements()
