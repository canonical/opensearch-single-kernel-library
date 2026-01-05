# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
from opensearch_single_kernel.common.constants import (
    DeploymentType,
    Directive,
    StartMode,
    State,
)
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
)

deployment_descriptions = {
    "ok": DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        app=App(model_uuid="model-uuid", name="opensearch"),
        state=DeploymentState(value=State.ACTIVE),
    ),
    "ko": DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="logs", init_hold=True, roles=["ml"], profile="production"
        ),
        start=StartMode.WITH_PROVIDED_ROLES,
        pending_directives=[Directive.WAIT_FOR_PEER_CLUSTER_RELATION],
        typ=DeploymentType.OTHER,
        app=App(model_uuid="model-uuid", name="opensearch"),
        state=DeploymentState(value=State.BLOCKED_CANNOT_START_WITH_ROLES, message="error"),
    ),
    "cm-only": DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="", init_hold=False, roles=["cluster-manager"], profile="production"
        ),
        start=StartMode.WITH_PROVIDED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        app=App(model_uuid="model-uuid", name="opensearch"),
        state=DeploymentState(value=State.ACTIVE),
    ),
    "data-only": DeploymentDescription(
        config=PeerClusterConfig(
            cluster_name="", init_hold=False, roles=["data"], profile="production"
        ),
        start=StartMode.WITH_PROVIDED_ROLES,
        pending_directives=[],
        typ=DeploymentType.OTHER,
        app=App(model_uuid="model-uuid", name="opensearch"),
        state=DeploymentState(value=State.ACTIVE),
    ),
}
