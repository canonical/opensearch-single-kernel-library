# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for profile requirement checks and profile changes on config-changed."""

import pytest

from opensearch_single_kernel.common.constants import PerformanceType
from opensearch_single_kernel.core.models import ProductionProfile, TestingProfile

_8GB_IN_KB = 8 * 1024 * 1024


@pytest.fixture
def production_topology_met(harness, mocker):
    """Control whether the production topology requirements are met; testing ones always are."""
    met = {"value": False}

    def check_cluster_topology(profile):
        if profile.type == PerformanceType.PRODUCTION and not met["value"]:
            return ["At least 3 cluster manager nodes and 3 data nodes are required."]
        return []

    mocker.patch.object(
        harness.charm.profiles_manager,
        "check_cluster_topology",
        side_effect=check_cluster_topology,
    )
    workload = harness.charm.profiles_manager.workload
    mocker.patch.object(workload, "memtotal", return_value=_8GB_IN_KB)
    mocker.patch.object(workload, "check_missing_system_requirements", return_value=[])
    return met


@pytest.fixture
def update_jvm_heap_size(harness, mocker):
    mocker.patch.object(harness.charm.config_manager.workload, "memtotal", return_value=_8GB_IN_KB)
    return mocker.patch.object(harness.charm.config_manager, "_update_jvm_heap_size")


@pytest.fixture
def restart_opensearch(harness, mocker):
    mocker.patch.object(
        harness.charm.cluster_manager.workload, "is_service_started", return_value=True
    )
    return mocker.patch(
        "opensearch_single_kernel.events.opensearch.OpenSearchEventsHandler._on_restart_opensearch"
    )


def test_check_profile_requirements_uses_given_profile(harness, production_topology_met):
    """The requirements of the given profile are checked, not those of the stored one."""
    with harness.hooks_disabled():
        harness.update_config({"profile": "testing"})
    harness.charm.state.server.profile = ProductionProfile()

    assert not harness.charm.profiles_manager.check_profile_requirements()
    assert harness.charm.profiles_manager.check_profile_requirements(TestingProfile())


def test_profile_change_applied_when_stored_profile_requirements_unmet(
    harness, production_topology_met, update_jvm_heap_size, restart_opensearch
):
    """Switching production -> testing is applied even though production is unmet (DPE-11188)."""
    harness.charm.state.server.profile = ProductionProfile()

    harness.update_config({"profile": "testing"})

    assert harness.charm.state.server.profile == TestingProfile()
    update_jvm_heap_size.assert_called_once()
    restart_opensearch.assert_called_once()


def test_profile_change_deferred_until_requirements_met(
    harness, production_topology_met, update_jvm_heap_size, restart_opensearch
):
    """Switching testing -> production defers without any change, then applies on retry."""
    harness.charm.state.server.profile = TestingProfile()

    harness.update_config({"profile": "production"})

    assert harness.charm.state.server.profile == TestingProfile()
    update_jvm_heap_size.assert_not_called()
    restart_opensearch.assert_not_called()

    production_topology_met["value"] = True
    harness.framework.reemit()

    assert harness.charm.state.server.profile == ProductionProfile()
    update_jvm_heap_size.assert_called_once()
    restart_opensearch.assert_called_once()


def test_first_profile_applied_once_requirements_met(
    harness, production_topology_met, update_jvm_heap_size, restart_opensearch
):
    """With no stored profile, the heap is set once the configured profile's requirements are met."""
    assert harness.charm.state.server.profile is None

    harness.update_config({"profile": "production"})

    assert harness.charm.state.server.profile is None
    update_jvm_heap_size.assert_not_called()

    production_topology_met["value"] = True
    harness.framework.reemit()

    assert harness.charm.state.server.profile == ProductionProfile()
    update_jvm_heap_size.assert_called_once()
