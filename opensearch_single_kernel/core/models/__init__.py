#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of models used for the operation of the charm.

Split across submodules by relation/concern (base, peer, peer_cluster, lock, upgrades,
jwt, storage, profiles, smtp) but re-exported here so existing `from
opensearch_single_kernel.core.models import ...` call sites keep working unchanged.
"""

from opensearch_single_kernel.core.models.base import (
    App,
    DeploymentDescription,
    DeploymentState,
    Model,
    Node,
    PeerClusterConfig,
    PluginConfigInfo,
)
from opensearch_single_kernel.core.models.jwt import JWTAuthConfiguration
from opensearch_single_kernel.core.models.lock import (
    LockAppStateModel,
    LockServerStateModel,
)
from opensearch_single_kernel.core.models.peer import (
    OpenSearchAppPeerAdminTlsSecretsModel,
    OpenSearchAppPeerModel,
    OpenSearchAppPeerPluginSecretsModel,
    OpenSearchAppPeerUserSecretsModel,
    OpenSearchServerPeerHttpSecretsModel,
    OpenSearchServerPeerModel,
    OpenSearchServerPeerTransportSecretsModel,
)
from opensearch_single_kernel.core.models.peer_cluster import (
    PeerClusterApp,
    PeerClusterAppModel,
    PeerClusterOrchestrators,
    PeerClusterRelErrorData,
    PeerClusterServerModel,
)
from opensearch_single_kernel.core.models.persistent import (
    PersistentModel,
    bind_model,
)
from opensearch_single_kernel.core.models.profiles import (
    ClusterTopologyRequirements,
    OpenSearchProfile,
    ProductionProfile,
    ProfileMemoryRequirements,
    TestingProfile,
)
from opensearch_single_kernel.core.models.smtp import SmtpConfig
from opensearch_single_kernel.core.models.storage import (
    AzureRelData,
    GcsRelData,
    ObjectStorageConfig,
    S3RelData,
)
from opensearch_single_kernel.core.models.upgrades import (
    LifecycleUnitTearingDownAndAppActive,
    UnitUpgradesState,
    UpgradeAppModel,
    UpgradeServerModel,
    UpgradeVersions,
)

__all__ = [
    "App",
    "AzureRelData",
    "ClusterTopologyRequirements",
    "DeploymentDescription",
    "DeploymentState",
    "GcsRelData",
    "JWTAuthConfiguration",
    "LifecycleUnitTearingDownAndAppActive",
    "LockAppStateModel",
    "LockServerStateModel",
    "Model",
    "Node",
    "ObjectStorageConfig",
    "OpenSearchAppPeerAdminTlsSecretsModel",
    "OpenSearchAppPeerModel",
    "OpenSearchAppPeerPluginSecretsModel",
    "OpenSearchAppPeerUserSecretsModel",
    "OpenSearchProfile",
    "OpenSearchServerPeerHttpSecretsModel",
    "OpenSearchServerPeerModel",
    "OpenSearchServerPeerTransportSecretsModel",
    "PeerClusterApp",
    "PeerClusterAppModel",
    "PeerClusterConfig",
    "PeerClusterOrchestrators",
    "PeerClusterRelErrorData",
    "PeerClusterServerModel",
    "PersistentModel",
    "PluginConfigInfo",
    "ProductionProfile",
    "ProfileMemoryRequirements",
    "S3RelData",
    "SmtpConfig",
    "TestingProfile",
    "UnitUpgradesState",
    "UpgradeAppModel",
    "UpgradeServerModel",
    "UpgradeVersions",
    "bind_model",
]
