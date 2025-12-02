#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Charm literals."""

from enum import Enum


class Substrates(str, Enum):
    """Possible substrates."""

    K8S = "k8s"
    VM = "vm"


# Opensearch Snap revision
OPENSEARCH_SNAP_REVISION = 79  # Keep in sync with `workload_version` file
