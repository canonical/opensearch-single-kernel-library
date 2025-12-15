#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""

from ops.main import main

from opensearch_single_kernel.base_charm import OpenSearchBaseCharm


class OpenSearchOperatorCharm(OpenSearchBaseCharm):
    """This class represents the machine charm for OpenSearch."""

    def __init__(self, *args):
        super().__init__(*args)


if __name__ == "__main__":
    main(OpenSearchOperatorCharm)
