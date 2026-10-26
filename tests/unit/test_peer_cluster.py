# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the peer-cluster relation."""

from unittest.mock import MagicMock, PropertyMock

import pytest

from opensearch_single_kernel.core.peer_cluster_relation import PeerCluster


def test_peer_cluster_data_when_relation_is_gone():
    relation = MagicMock(data={})
    peer_cluster = PeerCluster(relation, MagicMock(), MagicMock(), MagicMock())

    assert peer_cluster.data() is None


@pytest.mark.parametrize("main_data", [MagicMock(), None], ids=["main", "non-main"])
def test_backup_credentials_updated_from_main(harness, mocker, main_data):
    charm = harness.charm
    mocker.patch.object(charm.peer_cluster_manager, "update_admin_secrets_from_relation")
    mocker.patch.object(charm.tls_manager, "store_new_tls_resources")
    mocker.patch.object(charm.internal_users_manager, "put_internal_user")
    mocker.patch.object(
        type(charm.state), "ca_rotation_complete_in_cluster", new_callable=PropertyMock
    ).return_value = False
    mocker.patch.object(charm.state, "get_rel_data_from_main_orchestrator", return_value=main_data)
    update_credentials = mocker.patch.object(
        charm.snapshots_manager, "update_backup_credentials_from_peer_relation"
    )

    charm.peer_cluster_events._set_security_conf(MagicMock())

    if main_data:
        update_credentials.assert_called_once_with(main_data)
    else:
        update_credentials.assert_not_called()
