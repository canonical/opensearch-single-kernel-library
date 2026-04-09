#!/usr/bin/env python3

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base classes for charm relations."""

import logging
from contextlib import contextmanager

from ops.model import Application, Relation, Unit

from opensearch_single_kernel.core.models import (
    OpenSearchAppPeerModel,
    OpenSearchServerPeerModel,
    PeerClusterAppModel,
    PeerClusterServerModel,
)
from opensearch_single_kernel.lib.charms.data_platform_libs.v1.data_interfaces import (
    OpsOtherPeerUnitRepositoryInterface,
    OpsPeerRepositoryInterface,
    OpsPeerUnitRepositoryInterface,
    OpsRelationRepositoryInterface,
)

logger = logging.getLogger(__name__)


class RelationState:
    """Relation state object."""

    def __init__(
        self,
        relation: Relation | None,
        repository: (
            OpsPeerRepositoryInterface[OpenSearchAppPeerModel]
            | OpsPeerUnitRepositoryInterface[OpenSearchServerPeerModel]
            | OpsOtherPeerUnitRepositoryInterface[OpenSearchServerPeerModel]
            | OpsRelationRepositoryInterface[PeerClusterAppModel]
            | OpsRelationRepositoryInterface[PeerClusterServerModel]
        ),
        component: Unit | Application | None,
    ):
        self.relation = relation
        self.repository = repository
        self.component = component

    def __bool__(self) -> bool:
        """Boolean evaluation based on the existence of the relation in the repository."""
        try:
            return bool(self.repository and self.relation)
        except AttributeError:
            return False

    @contextmanager
    def update(self):
        """Context manager for batch-updating the model."""
        if not self.relation:
            raise ValueError("Cannot update state: relation is missing.")

        if hasattr(self, "model") and self.model:
            m = self.model
            yield m
            if hasattr(self, "write"):
                self.write(m)
            else:
                self.repository.write_model(self.relation.id, m)
        else:
            m = self.repository.build_model(self.relation.id)
            yield m
            self.repository.write_model(self.relation.id, m)
