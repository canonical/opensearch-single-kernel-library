#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Object representing the global state of OpenSearch Charm."""

from typing import TYPE_CHECKING


from opensearch_single_kernel.utils.logging import WithLogging
from ops import Object

if TYPE_CHECKING:
    from base_charm import OpenSearchBaseCharm


class GlobalState(Object, WithLogging):
    """Properties and relations of the charm."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "charm_state")
        self.charm = charm
        self.config = charm.config
