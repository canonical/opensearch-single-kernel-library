# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the metrics scrape job."""

from unittest.mock import PropertyMock

import pytest

from opensearch_single_kernel.common.constants import COS_PORT


@pytest.fixture
def scrape_job(harness, patch_deployment_desc, substrate, mocker):
    """Return given subtrate's scrape function."""
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
        "opensearch_single_kernel.managers.tls.TlsManager.all_tls_resources_stored",
        return_value=True,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.get_prometheus_labels",
        return_value={"roles": "cluster_manager,data"},
    )
    cos_events = harness.charm.cos_events
    return cos_events.scrape_vm_config if substrate == "vm" else cos_events.scrape_k8s_config


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
