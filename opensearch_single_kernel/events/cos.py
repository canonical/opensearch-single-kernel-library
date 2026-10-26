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
    Substrates,
)
from opensearch_single_kernel.lib.charms.grafana_agent.v0.cos_agent import (
    COSAgentProvider,
)
from opensearch_single_kernel.lib.charms.grafana_k8s.v0.grafana_dashboard import (
    GrafanaDashboardProvider,
)
from opensearch_single_kernel.lib.charms.loki_k8s.v1.loki_push_api import (
    LogForwarder,
)
from opensearch_single_kernel.lib.charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointProvider,
)

if TYPE_CHECKING:
    from opensearch_single_kernel.charms.base import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class CosEventsHandler(Object):
    """Class implementing OpenSearch COS configuration & event handling."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, key="cos_events")
        self.charm = charm

        if self.charm.substrate == Substrates.VM:
            # VM
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
            return

        # K8s
        # 1. Metrics (Prometheus)
        self.metrics_endpoint = MetricsEndpointProvider(
            self.charm,
            relation_name="metrics-endpoint",
            refresh_event=[
                self.charm.on.config_changed,
                self.charm.on.set_password_action,
                self.charm.on.secret_changed,
                self.charm.on[PEER_RELATION].relation_changed,
                self.charm.on[PEER_RELATION].relation_departed,
                self.charm.on[PEER_CLUSTER_RELATION].relation_changed,
            ],
            alert_rules_path="./src/alert_rules/prometheus",
            lookaside_jobs_callable=self.scrape_config,
        )

        # 2. Logs (Loki)
        self.log_proxy = LogForwarder(
            self.charm,
            relation_name="logging",
        )

        # 3. Dashboards (Grafana)
        self.grafana_dashboards = GrafanaDashboardProvider(
            self.charm, relation_name="grafana-dashboard"
        )

    def scrape_config(self) -> list[dict[str, Any]]:
        """Generate the scrape config."""
        if (
            # deployment_desc is used to get unit name which is needed for prometheus labels
            not self.charm.state.application.deployment_desc
            or not (ca := self.charm.state.application.admin_secrets.get("ca-cert"))
            or not (pwd := self.charm.state.application.cos_password)
            or not (prometheus_labels := self.charm.cluster_manager.get_prometheus_labels())
        ):
            # Not yet ready, waiting for certain values to be set
            return []

        if self.charm.substrate == Substrates.K8S:
            # only the leader sends a job, so it should list every unit
            hosts = sorted(self.charm.state.peer_unit_hosts)
        else:
            # every unit sends its own job
            hosts = [self.charm.state.host_ip]

        return [
            {
                "metrics_path": "/_prometheus/metrics",
                "static_configs": [
                    {
                        "targets": [f"{host}:{COS_PORT}" for host in hosts],
                        "labels": prometheus_labels,
                    }
                ],
                "tls_config": {"ca": ca},
                "scheme": "https",
                "basic_auth": {"username": f"{COS_USER}", "password": f"{pwd}"},
            }
        ]
