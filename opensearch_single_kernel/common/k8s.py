# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling k8s resources."""

import logging

from httpx2 import HTTPError
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
    OpenSearchK8sError,
)

# default logging from lightkube httpx requests is very noisy
logging.getLogger("lightkube").setLevel(logging.WARNING)
logging.getLogger("lightkube.core.client").setLevel(logging.WARNING)
logging.getLogger("httpx2").setLevel(logging.WARNING)
logging.getLogger("httpcore2").setLevel(logging.WARNING)

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
            OpenSearchK8sError: If the Kubernetes permission check fails.
        """
        try:
            allowed = self.client.create(
                SelfSubjectAccessReview(
                    spec=SelfSubjectAccessReviewSpec(
                        resourceAttributes=ResourceAttributes(
                            name=self.app_name,
                            namespace=self.namespace,
                            resource="statefulsets",
                            verb="patch",
                        )
                    )
                )
            ).status.allowed
        except HTTPError as e:
            raise OpenSearchK8sError(
                f"Failed to check StatefulSet permissions for {self.namespace}/{self.app_name}: {e}"
            ) from e

        if not allowed:
            logger.warning(
                f"Run `juju trust {self.app_name} --scope=cluster`. Needed for in-place upgrades"
            )
            raise OpenSearchK8sDeployedWithoutTrustError(app_name=self.app_name)

    def set_partition(self, value: int) -> None:
        """Sets the partition value."""
        logger.debug(f"From unit {self.pod_name} setting partition to {value} for {self.app_name}")
        try:
            self.client.patch(
                res=StatefulSet,
                name=self.app_name,
                obj={"spec": {"updateStrategy": {"rollingUpdate": {"partition": value}}}},
            )
        except HTTPError as e:
            raise OpenSearchK8sError(
                f"Failed to set the StatefulSet partition for {self.namespace}/{self.app_name}: {e}"
            ) from e

    # END: helpers

    # BEGIN: Private methods
    def get_partition(self) -> int:
        """Gets the stateful set rolling partition."""
        try:
            stateful_set = self.client.get(res=StatefulSet, name=self.app_name)
        except HTTPError as e:
            raise OpenSearchK8sError(
                f"Failed to read the StatefulSet partition for {self.namespace}/{self.app_name}: {e}"
            ) from e

        return stateful_set.spec.updateStrategy.rollingUpdate.partition

    def get_revision(self) -> str:
        """Gets the stateful set revision."""
        try:
            stateful_set = self.client.get(res=StatefulSet, name=self.app_name)
        except HTTPError as e:
            raise OpenSearchK8sError(
                f"Failed to read the StatefulSet revision for {self.namespace}/{self.app_name}: {e}"
            ) from e

        return stateful_set.status.updateRevision

    def list_revisions(self) -> dict[str, str]:
        """Returns a mapping of {unit name: Kubernetes controller revision hash.

        This is used for kubernetes upgrades to get the version of each container.
        """

        def get_unit_name(pod_name: str) -> str:
            app_name, unit_number = pod_name.rsplit("-", maxsplit=1)
            return f"{app_name}/{unit_number}"

        try:
            pods = self.client.list(res=Pod, labels={"app.kubernetes.io/name": self.app_name})

            # Lightkube sends the request when we loop over the pods
            return {
                get_unit_name(pod.metadata.name): pod.metadata.labels["controller-revision-hash"]  # type: ignore
                for pod in pods
            }
        except HTTPError as e:
            raise OpenSearchK8sError(
                f"Failed to list pod revisions for {self.namespace}/{self.app_name}: {e}"
            ) from e
