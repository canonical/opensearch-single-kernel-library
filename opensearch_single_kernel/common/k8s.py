# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling k8s resources."""

import json
import logging
from functools import cache

from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.resources.apps_v1 import StatefulSet
from lightkube.resources.core_v1 import Pod

from opensearch_single_kernel.common.exceptions import (
    OpenSearchK8sDeployedWithoutTrustError,
)

# default logging from lightkube httpx requests is very noisy
logging.getLogger("lightkube").disabled = True
logging.getLogger("lightkube.core.client").disabled = True
logging.getLogger("httpx").disabled = True
logging.getLogger("httpcore").disabled = True

logger = logging.getLogger(__name__)


class K8sClient:
    """Client for handling k8s resources for OpenSearch charms."""

    def __init__(self, pod_name: str, namespace: str):
        self.pod_name: str = pod_name
        self.app_name: str = "-".join(pod_name.split("-")[:-1])
        self.namespace: str = namespace

    def __eq__(self, other: object) -> bool:
        """__eq__ dunder.

        Allows to get cache hit on calls on the same method from different instances of K8sClient
        as `self` is passed to methods.
        """
        return isinstance(other, K8sClient) and self.__dict__ == other.__dict__

    def __hash__(self) -> int:
        """__hash__ dunder.

        For dict like caching.
        """
        return hash(json.dumps(self.__dict__, sort_keys=True))

    @property
    def client(self) -> Client:
        """The Lightkube client."""
        return Client(  # pyright: ignore[reportArgumentType]
            field_manager=self.pod_name,
            namespace=self.namespace,
        )

    # BEGIN: getters

    def get_partition(self) -> int:
        """Gets the stateful set rolling partition."""
        return self._get_partition()

    def get_revision(self) -> str:
        """Gets the stateful set revision."""
        return self._get_revision()

    def list_revisions(self) -> dict[str, str]:
        """Returns a mapping of {unit name: Kubernetes controller revision hash.

        This is used for kubernetes upgrades to get the version of each container.
        """
        return self._list_revisions()

    # END: getters

    # BEGIN: helpers

    def on_deployed_without_trust(self) -> None:
        """Blocks the application and returns a specific error message."""
        logger.error("Kubernetes application needs `juju trust`")
        raise OpenSearchK8sDeployedWithoutTrustError(app_name=self.app_name)

    def set_partition(self, value: int) -> None:
        """Sets the partition value."""
        try:
            self.client.patch(
                res=StatefulSet,
                name=self.app_name,
                obj={"spec": {"updateStrategy": {"rollingUpdate": {"partition": value}}}},
            )
            self._get_partition.cache_clear()  # Clean the cache.
        except ApiError as e:
            if e.status.code == 403:
                self.on_deployed_without_trust()
                return
            raise

    # END: helpers

    # BEGIN: Private methods
    @cache
    def _get_partition(self, *_) -> int:
        partition = self.client.get(res=StatefulSet, name=self.app_name)
        if (
            not partition.spec
            or not partition.spec.updateStrategy
            or not partition.spec.updateStrategy.rollingUpdate
            or partition.spec.updateStrategy.rollingUpdate.partition
            is None  # partition == 0 is valid so we check for None explicitly.
        ):
            raise Exception("Incomplete stateful set.")
        return partition.spec.updateStrategy.rollingUpdate.partition

    def _get_revision(self, *_) -> str:
        stateful_set = self.client.get(res=StatefulSet, name=self.app_name)
        if not stateful_set.status or not stateful_set.status.updateRevision:
            raise Exception("Incomplete stateful set")
        return stateful_set.status.updateRevision

    def _list_revisions(self, *_) -> dict[str, str]:
        pods = self.client.list(res=Pod, labels={"app.kubernetes.io/name": self.app_name})

        def get_unit_name(pod_name: str) -> str:
            *app_name, unit_number = pod_name.split("-")
            return f'{"-".join(app_name)}/{unit_number}'

        # We can type ignore here
        return {
            get_unit_name(pod.metadata.name): pod.metadata.labels["controller-revision-hash"]  # type: ignore
            for pod in pods
        }
