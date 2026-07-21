#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handler for COS configuration & events."""

import logging
from typing import TYPE_CHECKING, Any

from ops import Object, RelationCreatedEvent

from opensearch_single_kernel.common.constants import (
    COS_PORT,
    COS_RELATION,
    COS_USER,
    GRAFANA_K8S_RELATION,
    LOKI_K8S_RELATION,
    PEER_CLUSTER_RELATION,
    PEER_RELATION,
    PROMETHEUS_K8S_RELATION,
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
        self.framework.observe(
            self.charm.on[COS_RELATION].relation_created, self._on_cos_relation_created
        )
        self.framework.observe(
            self.charm.on[PROMETHEUS_K8S_RELATION].relation_created, self._on_cos_relation_created
        )
        self.framework.observe(
            self.charm.on[LOKI_K8S_RELATION].relation_created, self._on_cos_relation_created
        )
        self.framework.observe(
            self.charm.on[GRAFANA_K8S_RELATION].relation_created, self._on_cos_relation_created
        )

        if self.charm.substrate == Substrates.VM:
            # VM
            self.cos_integration = COSAgentProvider(
                self.charm,
                relation_name=COS_RELATION,
                scrape_configs=self.scrape_vm_config(),
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
            jobs=self.scrape_k8s_config(),
            refresh_event=[
                self.charm.on.config_changed,
                self.charm.on.set_password_action,
                self.charm.on.secret_changed,
                self.charm.on[PEER_RELATION].relation_changed,
                self.charm.on[PEER_CLUSTER_RELATION].relation_changed,
            ],
            alert_rules_path="./src/alert_rules/prometheus",
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

    def _on_cos_relation_created(self, event: RelationCreatedEvent) -> None:
        """Handle the `RelationCreatedEvent` event."""
        if self.charm.state.substrate == Substrates.VM and (
            self.charm.state.loki_relation
            or self.charm.state.grafana_relation
            or self.charm.state.prometheus_relation
        ):
            logger.warning(
                "grafana-k8s, loki-k8s, prometheus-k8s relation is not possible for vm, use grafana-agent instead"
            )
            return
        if self.charm.state.substrate == Substrates.K8S and self.charm.state.cos_agent_relation:
            logger.warning(
                "grafana-agent relation is not possible for k8s, use grafana-k8s, loki-k8s, prometheus-k8s instead"
            )

    def scrape_vm_config(self) -> list[dict[str, Any]]:
        """Generate the scrape config for VM platform."""
        if (
            # deployment_desc is used to get unit name which is needed for prometheus labels
            not self.charm.state.application.deployment_desc
            or not (ca := self.charm.state.application.admin_secrets.get("ca-cert"))
            or not (pwd := self.charm.state.application.cos_password)
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
                "scheme": (
                    "https" if self.charm.tls_manager.all_tls_resources_stored() else "http"
                ),
                "basic_auth": {"username": f"{COS_USER}", "password": f"{pwd}"},
            }
        ]

    def scrape_k8s_config(self) -> list[dict[str, Any]]:
        """Generate the scrape config for K8s platform."""
        if (
            # deployment_desc is used to get unit name which is needed for prometheus labels
            not self.charm.state.application.deployment_desc
            or not (pwd := self.charm.state.application.cos_password)
            or not (prometheus_labels := self.charm.cluster_manager.get_prometheus_labels())
        ):
            # Not yet ready, waiting for certain values to be set
            return []

        tls_enabled = self.charm.tls_manager.all_tls_resources_stored()
        config: dict[str, Any] = {
            "metrics_path": "/_prometheus/metrics",
            "static_configs": [
                {
                    "targets": [f"{self.charm.state.host_ip}:{COS_PORT}"],
                    "labels": prometheus_labels,
                }
            ],
            "scheme": "https" if tls_enabled else "http",
            "basic_auth": {"username": f"{COS_USER}", "password": f"{pwd}"},
        }
        if tls_enabled:
            config["tls_config"] = {"insecure_skip_verify": True}
        return [config]
