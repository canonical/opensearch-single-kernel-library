# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import json
import logging

from ops import ModelError, SecretNotFoundError

from opensearch_single_kernel.common.constants import Scope
from opensearch_single_kernel.core.models import PluginConfigInfo, SmtpConfig
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.helpers import diff
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PluginManager(BaseManager):
    """Manager to persist OpenSearch plugin configuration information"""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        """Creates the plugin manager class."""
        super().__init__(state, workload)
        self.name = "plugin_manager"

    def update_plugin_configs(self, configs_from_relation) -> None:
        """Add or Remove plugin config information transferred from main orchestrator"""
        current_app_plugin_info = self.state.application.plugin_config_info
        add, remove = diff(configs_from_relation.keys(), current_app_plugin_info.keys())

        for label in remove:
            self.remove_plugin_secret(label)

        for label in add:
            plugin = configs_from_relation[label]
            if plugin.secret_id:
                self.state.secrets.get_tracked_secret(plugin.secret_id, Scope.APP, label)
                self.put_plugin_config(
                    scope=Scope.APP,
                    label=label,
                    secret_id=plugin.secret_id,
                    relation_name=plugin.relation_name,
                )

    def remove_plugin_secret_ids(self):
        """Removes secret IDs from the stored plugin confis"""
        plugins = self.state.application.plugin_config_info
        for label, plugin in plugins.items():
            self.put_plugin_config(
                scope=Scope.APP,
                label=label,
                secret_id=None,
                relation_name=plugin.relation_name,
            )

    def put_plugin_config(
        self,
        scope: Scope,
        label: str,
        secret_id: str | None = None,
        relation_name: str | None = None,
        cleanup: dict[str, list[str]] | None = None,
    ) -> None:
        """Adds plugin configuration information to peer relation data"""
        state = self.state.application if scope == Scope.APP else self.state.server
        plugins = state.plugin_config_info
        plugin_config = plugins.get(label) or PluginConfigInfo()
        plugin_config.relation_name = relation_name
        plugin_config.secret_id = secret_id
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
            if plugin_config.secret_id:
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
        self.state.secrets.put(Scope.APP, label, json.dumps(content))
        secret_id = self.state.secrets.get_secret_id(Scope.APP, label)
        if not secret_id:
            logger.error("Could not create secret with label: %s", label)
        self.put_plugin_config(
            Scope.APP, label=label, secret_id=secret_id, relation_name=relation_name
        )

    def remove_plugin_secret(self, label: str) -> None:
        """Delete app-scoped plugin secret and remove id from peers data.

        Args:
            label: label of the secret to remove
        """
        try:
            self.state.secrets.delete(Scope.APP, label)
        except SecretNotFoundError:
            logger.error("Can't find secret '%s'", label)
        except ModelError as e:
            logger.error("Cannot delete secret %s: %s", label, e)
        self.remove_plugin_config(Scope.APP, label)

    def missing_plugins_relations(self) -> list[str]:
        """Get the cureent plugins missing relations."""
        # Check the plugin_config_info to get configured relations
        plugin_relation_names = [
            s.relation_name
            for s in self.state.application.plugin_config_info.values()
            if s.relation_name
        ]
        return [
            relation_name
            for relation_name in plugin_relation_names
            if self.state.relation_exists(relation_name)
        ]
