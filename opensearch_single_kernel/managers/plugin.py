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
from opensearch_single_kernel.core.models import PluginConfigInfo
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.workload.base import BaseWorkload

logger = logging.getLogger(__name__)


class PluginManager(BaseManager):
    """Manager to persist OpenSearch plugin configuration information"""

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        """Creates the plugin manager class."""
        super().__init__(state, workload)
        self.name = "plugin_manager"

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

    def remove_plugin_config(self, scope: Scope, label: str) -> None:
        """Removes plugin configuration information from peer relation data"""
        state = self.state.application if scope == Scope.APP else self.state.server
        plugins = state.plugin_config_info
        if label in plugins:
            del plugins[label]
        state.plugin_config_info = plugins

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
