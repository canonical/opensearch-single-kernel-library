# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling k8s resources."""

import logging

from lightkube.core.client import Client
from lightkube.models.authorization_v1 import (
    ResourceAttributes,
    SelfSubjectAccessReviewSpec,
)
from lightkube.resources.apps_v1 import StatefulSet
from lightkube.resources.authorization_v1 import SelfSubjectAccessReview
from lightkube.resources.core_v1 import Pod

from opensearch_single_kernel.common.exceptions import (
    OpenSearchK8sDeployedWithoutTrustError,
)

# default logging from lightkube httpx requests is very noisy
logging.getLogger("lightkube").disabled = True
logging.getLogger("lightkube.core.client").disabled = True
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


class K8sClient:
    """Client for handling k8s resources for OpenSearch charms."""

    def __init__(self, pod_name: str, namespace: str):
        self.pod_name: str = pod_name
        self.app_name: str = "-".join(pod_name.split("-")[:-1])
        self.namespace: str = namespace

    @property
    def client(self) -> Client:
        """The Lightkube client."""
        return Client(  # pyright: ignore[reportArgumentType]
            field_manager=self.pod_name,
            namespace=self.namespace,
        )

    # BEGIN: helpers

    def check_if_deployed_without_trust(self) -> None:
        """Checks if the application was deployed without `juju trust`.

        Raises:
            OpenSearchK8sDeployedWithoutTrustError: If the application was
              deployed without `juju trust`.
        """
        if not (
            self.client.create(
                SelfSubjectAccessReview(
                    spec=SelfSubjectAccessReviewSpec(
                        resourceAttributes=ResourceAttributes(
                            name=self.app_name,
                            namespace=self.namespace,
                            resource="statefulset",
                            verb="patch",
                        )
                    )
                )
            ).status.allowed
        ):
            logger.warning(
                f"Run `juju trust {self.app_name} --scope=cluster`. Needed for in-place refreshes"
            )
            raise OpenSearchK8sDeployedWithoutTrustError(app_name=self.app_name)

    def on_deployed_without_trust(self) -> None:
        """Blocks the application and returns a specific error message."""
        logger.error("Kubernetes application needs `juju trust`")
        raise OpenSearchK8sDeployedWithoutTrustError(app_name=self.app_name)

    def set_partition(self, value: int) -> None:
        """Sets the partition value."""
        self.client.patch(
            res=StatefulSet,
            name=self.app_name,
            obj={"spec": {"updateStrategy": {"rollingUpdate": {"partition": value}}}},
        )

    # END: helpers

    # BEGIN: Private methods
    def get_partition(self) -> int:
        """Gets the stateful set rolling partition."""
        stateful_set = self.client.get(res=StatefulSet, name=self.app_name)
        return stateful_set.spec.updateStrategy.rollingUpdate.partition

    def get_revision(self) -> str:
        """Gets the stateful set revision."""
        stateful_set = self.client.get(res=StatefulSet, name=self.app_name)
        return stateful_set.status.updateRevision

    def list_revisions(self) -> dict[str, str]:
        """Returns a mapping of {unit name: Kubernetes controller revision hash.

        This is used for kubernetes upgrades to get the version of each container.
        """
        pods = self.client.list(res=Pod, labels={"app.kubernetes.io/name": self.app_name})

        def get_unit_name(pod_name: str) -> str:
            app_name, unit_number = pod_name.rsplit("-", maxsplit=1)
            return f"{app_name}/{unit_number}"

        # We can type ignore here
        return {
            get_unit_name(pod.metadata.name): pod.metadata.labels["controller-revision-hash"]  # type: ignore
            for pod in pods
        }
