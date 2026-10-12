# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Compatibility tests for relation payloads from older charm revisions."""

import json

import pytest
from pydantic import ValidationError

from opensearch_single_kernel.common.constants import CertType, Scope
from opensearch_single_kernel.core.models import PeerClusterRelData, PeerClusterRelErrorData


def test_legacy_wrong_orchestrator_error_produces_blocked_status():
    """The stable operator's message must map to a status instead of None."""
    error = PeerClusterRelErrorData.from_dict(
        {
            "cluster_name": "upgrades",
            "should_sever_relation": True,
            "should_wait": False,
            "blocked_message": "Related to non 'main/failover'-orchestrator cluster.",
            "deployment_desc": None,
        }
    )

    status = error.get_status()

    assert status is not None
    assert status.status == "blocked"
    assert status.message == "Related to non 'main/failover'-orchestrator cluster."


@pytest.fixture
def legacy_peer_cluster_data():
    """A legacy provider payload, before optional cloud credentials were added."""
    return {
        "cluster_name": "upgrades",
        "cm_nodes": [],
        "deployment_desc": None,
        "credentials": {
            "admin_username": "admin",
            "admin_password": "admin-password",
            "admin_password_hash": "admin-hash",
            "kibana_password": "kibana-password",
            "kibana_password_hash": "kibana-hash",
            "admin_tls": {
                "ca-cert": "test-ca",
                "cert": "test-cert",
                "key": "test-key",
                "chain": "test-chain",
                "keystore-password": "keystore-password",
                "truststore-password": "truststore-password",
            },
        },
    }


@pytest.mark.parametrize("peek_secrets", [False, True])
@pytest.mark.parametrize("representation", ["inline", "secret"])
def test_peer_cluster_tls_survives_mixed_version_decode(
    harness, mocker, legacy_peer_cluster_data, peek_secrets, representation
):
    """Both wire formats retain the credentials needed to import and compare TLS."""
    payload = legacy_peer_cluster_data
    tls = payload["credentials"]["admin_tls"].copy()
    if representation == "secret":
        with harness.hooks_disabled():
            harness.add_relation("peer-cluster", "main")
        secret_id = harness.add_model_secret("main", tls)
        harness.grant_secret(secret_id, harness.charm.app)
        # Match the secret URI form published by the supported Juju deployments.
        payload["credentials"]["admin_tls"] = secret_id.replace("secret:", "secret://", 1)

    data = PeerClusterRelData.peer_cluster_rel_data_from_str(
        harness.charm.state.secrets, json.dumps(payload), peek_secrets=peek_secrets
    )

    assert data.credentials.admin_tls == tls
    # The same decoded credentials must survive persistence and later reads.
    assert PeerClusterRelData.from_str(data.to_str()).credentials.admin_tls == tls
    harness.charm.state.secrets.put_object(
        Scope.UNIT, CertType.UNIT_TRANSPORT.val, {"ca-cert": "test-ca"}
    )
    mocker.patch.object(harness.charm.tls_manager, "all_tls_resources_stored", return_value=True)
    assert harness.charm.tls_manager.peer_cluster_error_from_tls(data) is None


@pytest.mark.parametrize("peek_secrets", [False, True])
@pytest.mark.parametrize("representation", ["missing", "null", "empty"])
def test_peer_cluster_optional_credentials_remain_absent(
    harness, legacy_peer_cluster_data, peek_secrets, representation
):
    """Older payloads can omit optional credentials without failing validation."""
    credentials = legacy_peer_cluster_data["credentials"]
    if representation == "missing":
        del credentials["admin_tls"]
    else:
        credentials["admin_tls"] = None if representation == "null" else ""

    data = PeerClusterRelData.peer_cluster_rel_data_from_str(
        harness.charm.state.secrets,
        json.dumps(legacy_peer_cluster_data),
        peek_secrets=peek_secrets,
    )

    assert data.credentials.admin_tls is None
    assert data.credentials.monitor_password is None
    assert data.credentials.s3 is None
    assert data.credentials.azure is None
    assert data.credentials.gcs is None


@pytest.mark.parametrize("admin_tls", [123, ["test-ca"], {"ca-cert": ["test-ca"]}])
def test_peer_cluster_invalid_tls_is_not_silently_discarded(
    harness, legacy_peer_cluster_data, admin_tls
):
    """Invalid populated credentials must fail validation rather than appear absent."""
    legacy_peer_cluster_data["credentials"]["admin_tls"] = admin_tls

    with pytest.raises(ValidationError):
        PeerClusterRelData.peer_cluster_rel_data_from_str(
            harness.charm.state.secrets, json.dumps(legacy_peer_cluster_data)
        )
