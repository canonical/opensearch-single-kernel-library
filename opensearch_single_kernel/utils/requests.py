#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for requests."""
import ssl

from requests.adapters import HTTPAdapter


class SSLStringAdapter(HTTPAdapter):
    """Custom Transport Adapter that loads SSL certificates directly from a string."""

    def __init__(self, cert_string, **kwargs):
        """Initialize the adapter with the certificate string."""
        self.cert_string = cert_string
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        """Initialize the pool manager with a custom SSL context."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        try:
            context.load_verify_locations(cadata=self.cert_string)
        except Exception as e:
            print(f"Error loading certificate string: {e}")
            raise
        # Pass the context into the pool manager
        pool_kwargs["ssl_context"] = context
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
