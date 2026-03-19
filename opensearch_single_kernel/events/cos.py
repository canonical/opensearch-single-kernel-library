#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for COS configuration & events."""

import logging
from typing import TYPE_CHECKING, Any

from ops import Object

from opensearch_single_kernel.common.constants import (
    COS_PORT,
    COS_RELATION,
    COS_USER,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    CertType,
    Scope,
)
from opensearch_single_kernel.lib.charms.grafana_agent.v0.cos_agent import (
    COSAgentProvider,
)
from opensearch_single_kernel.utils.secrets import password_key

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class CosEventsHandler(Object):
    """Class implementing OpenSearch COS configuration & event handling."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, key="cos_events")
        self.charm = charm

        self.cos_integration = COSAgentProvider(
            self.charm,
            relation_name=COS_RELATION,
            scrape_configs=self.scrape_config,
            refresh_events=[
                self.charm.on.config_changed,
                self.charm.on.set_password_action,
                self.charm.on.secret_changed,
                self.charm.on[PEER_RELATION].relation_changed,
                self.charm.on[PEER_CLUSTER_RELATION].relation_changed,
            ],
            metrics_rules_dir="./src/alert_rules/prometheus",
            log_slots=["opensearch:logs"],
        )

    def scrape_config(self) -> list[dict[str, Any]]:
        """Generates the scrape config as needed."""
        if (
            not (
                app_secrets := self.charm.state.secrets.get_object(
                    Scope.APP, CertType.APP_ADMIN.val, peek=True
                )
            )
            or not (ca := app_secrets.get("ca-cert"))
            or not (pwd := self.charm.state.secrets.get(Scope.APP, password_key(COS_USER)))
            or not (prometheus_labels := self.charm.cluster_manager.get_prometheus_labels())
        ):
            # Not yet ready, waiting for certain values to be set
            return []
        return [
            {
                "metrics_path": "/_prometheus/metrics",
                "static_configs": [
                    {
                        "targets": [f"{self.charm.state.host_ip}:{COS_PORT}"],
                        "labels": prometheus_labels,
                    }
                ],
                "tls_config": {"ca": ca},
                "scheme": "https" if self.charm.tls_manager.all_tls_resources_stored() else "http",
                "basic_auth": {"username": f"{COS_USER}", "password": f"{pwd}"},
            }
        ]
