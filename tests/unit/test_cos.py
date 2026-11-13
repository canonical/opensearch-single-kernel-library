# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the metrics scrape job."""

import json
from unittest.mock import PropertyMock

import pytest

from opensearch_single_kernel.common.constants import COS_PORT, PEER_RELATION


@pytest.fixture
def scrape_job(harness, patch_deployment_desc, mocker):
    """Return the scrape function."""
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.cos_password",
        new_callable=PropertyMock,
        return_value="cos-password",
    )
    mocker.patch(
        "opensearch_single_kernel.core.peer_relation.OpenSearchApplication.admin_secrets",
        new_callable=PropertyMock,
        return_value={"ca-cert": "ca"},
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.get_prometheus_labels",
        return_value={"roles": "cluster_manager,data"},
    )
    return harness.charm.cos_events.scrape_config


def test_scrape_job_targets(harness, mocker, scrape_job, substrate):
    """Test the K8s job lists every unit and the VM job only this unit."""
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.peer_unit_hosts",
        new_callable=PropertyMock,
        return_value={"host-2", "host-0", "host-1"},
    )

    if substrate == "vm":
        # every unit sends its own job
        expected = [f"{harness.charm.state.host_ip}:{COS_PORT}"]
    else:
        # only the leader sends a job, so it should list every unit
        expected = [f"host-0:{COS_PORT}", f"host-1:{COS_PORT}", f"host-2:{COS_PORT}"]

    [job] = scrape_job()
    assert job["static_configs"][0]["targets"] == expected


def test_scrape_job_verifies_tls_with_ca(scrape_job):
    [job] = scrape_job()

    assert job["scheme"] == "https"
    assert job["tls_config"] == {"ca": "ca"}


@pytest.mark.skip_if_substrate("vm")
def test_scrape_job_drops_departed_unit(harness, mocker, scrape_job):
    """Test the leader removes a departed unit from the K8s job."""
    mocker.patch("socket.getfqdn", side_effect=lambda name="": name)
    app = harness.charm.app.name

    with harness.hooks_disabled():
        harness.set_leader(True)
        peer = harness.model.get_relation(PEER_RELATION)
        harness.add_relation_unit(peer.id, f"{app}/1")
        metrics = harness.add_relation("metrics-endpoint", "prometheus")
        harness.charm.cos_events.metrics_endpoint.set_scrape_job_spec()

    def targets():
        [job] = json.loads(harness.get_relation_data(metrics, app)["scrape_jobs"])
        return job["static_configs"][0]["targets"]

    assert targets() == [
        f"{app}-0.{app}-endpoints:{COS_PORT}",
        f"{app}-1.{app}-endpoints:{COS_PORT}",
    ]

    harness.remove_relation_unit(peer.id, f"{app}/1")

    assert targets() == [f"{app}-0.{app}-endpoints:{COS_PORT}"]
