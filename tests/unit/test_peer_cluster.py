# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the peer-cluster relation."""

from unittest.mock import MagicMock

from opensearch_single_kernel.core.peer_cluster_relation import PeerCluster


def test_peer_cluster_data_when_relation_is_gone():
    relation = MagicMock(data={})
    peer_cluster = PeerCluster(relation, MagicMock(), MagicMock(), MagicMock())

    assert peer_cluster.data() is None
