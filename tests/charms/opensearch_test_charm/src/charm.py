#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""

from ops.main import main

from opensearch_single_kernel.vm_charm import OpenSearchVMCharm

if __name__ == "__main__":
    main(OpenSearchVMCharm)
