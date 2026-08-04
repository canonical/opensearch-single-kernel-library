# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import json
import logging

from data_platform_helpers.advanced_statuses import StatusObject
from data_platform_helpers.advanced_statuses.types import Scope as AdvancedStatusesScope
from overrides import override

from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.common.statuses import (
    GeneralStatuses,
    PeerClusterStatuses,
)
from opensearch_single_kernel.core.models.peer_secrets import (
    OpenSearchAppPeerPluginSecretsModel,
)
from opensearch_single_kernel.core.models.plain_base import PluginConfigInfo
from opensearch_single_kernel.core.models.smtp import SmtpConfig
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import diff
from opensearch_single_kernel.utils.status import format_status
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PluginManager(BaseManager):
    """Manager to persist OpenSearch plugin configuration information"""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        """Creates the plugin manager class."""
        super().__init__(state, workload, "plugin_manager")

    def update_plugin_configs(self, configs_from_relation: dict[str, PluginConfigInfo]) -> None:
        """Add or Remove plugin config information transferred from main orchestrator"""
        current_app_plugin_info = self.state.application.plugin_config_info
        add, remove = diff(configs_from_relation.keys(), current_app_plugin_info.keys())

        for label in remove:
            self.remove_plugin_secret(label)

        for label in add:
            plugin = configs_from_relation[label]
            if plugin.secret_name:
                self.put_plugin_config(
                    scope=Scope.APP,
                    label=label,
                    relation_name=plugin.relation_name,
                )

    def remove_plugin_secret_ids(self):
        """Removes secret IDs from the stored plugin confis"""
        plugins = self.state.application.plugin_config_info
        for label, plugin in plugins.items():
            self.put_plugin_config(
                scope=Scope.APP,
                label=label,
                relation_name=plugin.relation_name,
            )

    def put_plugin_config(
        self,
        scope: Scope,
        label: str,
        relation_name: str | None = None,
        cleanup: dict[str, list[str]] | None = None,
    ) -> None:
        """Adds plugin configuration information to peer relation data"""
        state = self.state.application if scope == Scope.APP else self.state.server
        plugins = state.plugin_config_info
        plugin_config = plugins.get(label) or PluginConfigInfo()
        plugin_config.relation_name = relation_name
        plugin_config.secret_name = label
        if cleanup:
            plugin_config.add_cleanup_items(cleanup)
        plugins[label] = plugin_config
        state.plugin_config_info = plugins

    def put_notifications_plugin_smtp_config(
        self,
        config: SmtpConfig,
        credentials: dict[str, str],
        store_secret: bool,
        relation_name: str,
    ) -> None:
        """Add a notifications plugin SMTP config with credentials and secret (if store_secret)."""
        cleanup = {
            "keys": list(credentials.keys()),
            "smtp_account_id": [config.smtp_account_id],
        }
        self.put_plugin_config(scope=Scope.UNIT, label=config.label, cleanup=cleanup)

        if store_secret:
            # leader stores secret for subclusters for per relation
            self.store_plugin_secret(
                content={
                    "keys": credentials,
                    "smtp_account_id": cleanup["smtp_account_id"],
                },
                label=config.label,
                relation_name=relation_name,
            )

    def remove_plugin_config(self, scope: Scope, label: str) -> None:
        """Removes plugin configuration information from peer relation data"""
        state = self.state.application if scope == Scope.APP else self.state.server
        plugins = state.plugin_config_info
        if label in plugins:
            del plugins[label]
        state.plugin_config_info = plugins

    def remove_plugin_secrets(self) -> None:
        """Removes all plugin secrets and their corresponding config info."""
        for label, plugin_config in self.state.application.plugin_config_info.items():
            if plugin_config.secret_name:
                self.remove_plugin_secret(label)

    def store_plugin_secret(
        self,
        *,
        content: dict,
        label: str,
        relation_name: str | None = None,
    ) -> None:
        """Create/update app-scoped plugin secret and store id in peers data.

        Args:
            content: dictionary of the secret payload
            label: label of the secret to store
            relation_name: name of the relation from which the secret content came
        """
        self.add_plugin_secret(label, json.dumps(content))
        self.put_plugin_config(Scope.APP, label=label, relation_name=relation_name)

    def remove_plugin_secret(self, label: str) -> None:
        """Delete app-scoped plugin secret and remove id from peers data.

        Args:
            label: label of the secret to remove
        """
        self.delete_plugin_secret(label)
        self.remove_plugin_config(Scope.APP, label)

    def _load_plugin_secrets(
        self,
    ) -> tuple[OpenSearchAppPeerPluginSecretsModel | None, dict]:
        """Return the plugins sibling secret model and its decoded contents.

        Returns (None, {}) when the sibling model is unavailable.
        """
        plugin_m = self.state.application.build_sibling_model(OpenSearchAppPeerPluginSecretsModel)
        if not plugin_m:
            return None, {}
        return plugin_m, (json.loads(plugin_m.plugin_secrets) if plugin_m.plugin_secrets else {})

    def _plugin_secret_name(self, plugin_name: str) -> str | None:
        """Return the configured secret_name for a plugin, or None if it has none."""
        config = self.state.application.plugin_config_info.get(plugin_name)
        return config.secret_name if config and config.secret_name else None

    def add_plugin_secret(self, plugin_name: str, secret_content: str) -> None:
        """Add or overwrite a plugin's secret in the plugins Juju secret group."""
        if not (secret_name := self._plugin_secret_name(plugin_name)):
            logger.warning(f"No secret_name defined for plugin {plugin_name}")
            return
        plugin_m, secrets = self._load_plugin_secrets()
        if not plugin_m:
            return
        secrets[secret_name] = secret_content
        plugin_m.plugin_secrets = json.dumps(secrets)

    def get_plugin_secret(self, plugin_name: str) -> str | None:
        """Return the stored secret content for a plugin, or None if not set."""
        if not (secret_name := self._plugin_secret_name(plugin_name)):
            return None
        _, secrets = self._load_plugin_secrets()
        return secrets.get(secret_name)

    def delete_plugin_secret(self, plugin_name: str) -> None:
        """Delete a plugin's secret from the plugins Juju secret group."""
        if not (secret_name := self._plugin_secret_name(plugin_name)):
            logger.warning(
                f"Cannot delete secret: no secret_name defined for plugin {plugin_name}"
            )
            return
        plugin_m, secrets = self._load_plugin_secrets()
        if not plugin_m:
            return
        if secrets.pop(secret_name, None) is not None:
            plugin_m.plugin_secrets = json.dumps(secrets)
        else:
            logger.debug(f"Secret for plugin {plugin_name} was not found, nothing to delete.")

    def missing_plugins_relations(self) -> list[str]:
        """Get the cureent missing plugins relations."""
        # Check the plugin_config_info to get configured relations
        plugin_relation_names = [
            s.relation_name
            for s in self.state.application.plugin_config_info.values()
            if s.relation_name
        ]
        return [
            relation_name
            for relation_name in plugin_relation_names
            if not self.state.relation_exists(relation_name)
        ]

    @override
    def get_statuses(
        self, scope: AdvancedStatusesScope, recompute: bool = False
    ) -> list[StatusObject]:
        """Compute the manager's statuses."""
        if not recompute:
            return self.state.statuses.get(scope, self.name).root or [
                GeneralStatuses.ACTIVE_IDLE.value
            ]

        status_list: list[StatusObject] = []

        if scope == "app":
            if self.state.application.missing_relations and (
                missing_relations := self.missing_plugins_relations()
            ):
                status_list.append(
                    format_status(
                        PeerClusterStatuses.PEER_CLUSTER_MISSING_RELATIONS.value,
                        {"relation": missing_relations[0]},
                    )
                )

        return status_list or [GeneralStatuses.ACTIVE_IDLE.value]
