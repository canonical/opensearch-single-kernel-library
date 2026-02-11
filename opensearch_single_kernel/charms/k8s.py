#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Kubernetes Charm."""

import logging
import time
from typing import Any

from lightkube import Client
from lightkube.core.exceptions import ApiError
from lightkube.resources.apps_v1 import StatefulSet
from lightkube.types import PatchType
from ops.model import ModelError

from opensearch_single_kernel.charms.base import OpenSearchBaseCharm
from opensearch_single_kernel.common.constants import (
    CONTAINER_NAME,
    FS_GROUP_CHANGE_POLICY,
    INIT_CONTAINER_IMAGE,
    INIT_CONTAINER_NAME,
    INIT_CONTAINER_ROOT_GID,
    INIT_CONTAINER_ROOT_UID,
    K8S_CERTIFICATES_MOUNT_PATH,
    K8S_DATA_MOUNT_PATH,
    K8S_LOGS_MOUNT_PATH,
    OPENSEARCH_RUN_AS_GROUP,
    OPENSEARCH_RUN_AS_USER,
    POD_RESTART_ANNOTATION_KEY,
    SYSCTL_TCP_RETRIES2_NAME,
    SYSCTL_TCP_RETRIES2_VALUE,
    Substrates,
)
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.utils.helpers import (
    convert_to_int,
    has_duplicate_env,
    remove_duplicates,
)
from opensearch_single_kernel.utils.status import Status
from opensearch_single_kernel.workload.base import BaseWorkload
from opensearch_single_kernel.workload.k8s import K8sWorkload

logger = logging.getLogger(__name__)


class OpenSearchK8sCharm(OpenSearchBaseCharm):
    """OpenSearch Kubernetes Charm"""

    def __init__(self, *args):
        """Initialize the OpenSearch Kubernetes Charm.

        This calls the __init__ of the class that comes after OpenSearchBaseCharm in the MRO,
        which is ops.CharmBase. This skips OpenSearchBaseCharm.__init__().
        We need self.unit initialized first (from ops.CharmBase.__init__())
        Then, we need to create the workload with the container before initializing managers.
        This ensures the container is available before creating
        the workload and initializing manager.

        Args:
            *args: variable length argument list passed to ops.CharmBase.__init__().

        """
        super(OpenSearchBaseCharm, self).__init__(*args)

        self.status = Status(self)
        self.state = ClusterState(self, self.substrate)

        # Get container may return None if not ready yet
        try:
            container = self.unit.get_container(CONTAINER_NAME)
        except ModelError:
            container = None

        # Workload can be created even if container is None
        # it will check readiness when needed
        if container is None:

            def get_container():
                try:
                    return self.unit.get_container(CONTAINER_NAME)
                except ModelError:
                    return None

            self._workload = K8sWorkload(container_getter=get_container)
        else:
            self._workload = K8sWorkload(container_getter=lambda: container)

        # Now, we can initialize managers
        # The managers will check workload.workload_present when they need to use it
        self._initialize_managers()

    @property
    def workload(self) -> BaseWorkload:
        """Access current workload instance.

        Returns the workload object.

        Returns:
            BaseWorkload: The K8sWorkload instance for this charm
        """
        return self._workload

    @property
    def substrate(self) -> Substrates:
        """Access current substrate type.

        Returns:
            Substrates: always Substrates.K8S for this charm
        """
        return Substrates.K8S

    def _configure_pod_sysctls(self) -> None:
        """Configure pod sysctls and security context using lightkube.

        Patches the StatefulSet to add:
        - Pod-level sysctls: net.ipv4.tcp_retries2=5
        - Pod securityContext: fsGroup=584792, fsGroupChangePolicy=OnRootMismatch
        - Container securityContext for opensearch container:
         runAsNonRoot=true, runAsUser=584792, runAsGroup=584792

        Important: We do not set pod-level runAsNonRoot/runAsUser/runAsGroup because:
        - The charm container (Juju agent/Pebble) needs to run as root
        - Only the opensearch container should run as non-root (UID 584792)
        - Pod-level runAsNonRoot conflicts with container-level runAsUser=0

        This should be called from event handlers (install, config-changed, start)
        to ensure the pod spec is configured correctly. The StatefulSet may not exist during
        initial deployment so we will retry on next event but actually it will run once and reapply
        if there are external changes.

        Changes to securityContext.sysctls require a pod restart to take effect.
        The StatefulSet controller will automatically roll pods when the template changes.
        """
        try:
            if not self._validate_sysctl_prerequisites():
                return

            client = Client()
            namespace = self.model.name
            statefulset_name = self.app.name

            if (statefulset := self._get_statefulset(client, statefulset_name, namespace)) is None:
                return

            # repair duplicate env vars if needed
            statefulset = self._repair_duplicate_env_vars(
                client, statefulset, statefulset_name, namespace
            )

            template_spec = statefulset.spec.template.spec  # type: ignore[union-attr]
            containers = template_spec.containers or []

            # Extract pod securityContext and find opensearch container
            pod_spec = self._extract_pod_security_context(template_spec)
            if (
                opensearch_container_idx := self._find_opensearch_container_index(containers)
            ) is None:
                return

            # check current configuration state
            config_state = self._check_configuration_state(
                pod_spec, containers[opensearch_container_idx], template_spec.initContainers or []
            )

            if config_state["is_fully_configured"]:
                logger.debug(
                    "Pod sysctls, securityContext, and initContainer already configured correctly; skipping patch."
                )
                return

            # build JSON patch operations
            json_operations = self._build_pod_security_context_patches(pod_spec, config_state)
            json_operations.extend(
                self._build_container_security_context_patches(
                    containers[opensearch_container_idx], opensearch_container_idx, config_state
                )
            )
            json_operations.extend(self._build_sysctl_patches(pod_spec, config_state))
            json_operations.extend(
                self._build_init_container_patches(
                    containers[opensearch_container_idx],
                    template_spec.initContainers or [],
                    config_state,
                )
            )

            if not json_operations:
                logger.debug(
                    "Pod sysctls, securityContext, and initContainer already configured correctly; nothing to patch."
                )
                return

            # apply json patches
            client.patch(
                res=StatefulSet,
                name=statefulset_name,
                namespace=namespace,
                obj=json_operations,
                patch_type=PatchType.JSON,
            )
            logger.info(
                "Configured pod sysctls, securityContext, and initContainer via JSON patch. Pod restart required for changes to take effect."
            )

            # trigger pod restart via annotation update for changes to take effect
            self._trigger_pod_restart_via_annotation(client, statefulset_name, namespace)

        except ApiError as e:
            logger.warning(
                "Failed to patch StatefulSet for sysctls: %s. "
                "Pod sysctls may not be configured. Ensure kubelet allows unsafe sysctls.",
                e,
            )
        except Exception as e:
            logger.warning(
                "Unexpected error while configuring pod sysctls: %s. "
                "Pod sysctls may not be configured.",
                e,
            )

    def _validate_sysctl_prerequisites(self) -> bool:
        """Validate that prerequisites for sysctl configuration are met.

        Checks that app name and model name are available, which are required
        to identify the StatefulSet to patch.

        Returns:
            bool: True if all prerequisites are met, False otherwise.
        """
        if not self.app.name:
            logger.warning(
                "Cannot configure pod sysctls: app name is not available yet. "
                "This is normal during initial deployment."
            )
            return False

        if not self.model.name:
            logger.warning(
                "Cannot configure pod sysctls: model name is not available yet. "
                "This is normal during initial deployment."
            )
            return False

        return True

    def _get_statefulset(
        self, client: Client, statefulset_name: str, namespace: str
    ) -> StatefulSet | None:
        """Get the StatefulSet, returning None if it doesn't exist yet.

        Args:
            client: The lightkube Client instance.
            statefulset_name: name of the StatefulSet to retrieve.
            namespace: Kubernetes namespace.

        Returns:
            StatefulSet or None: The StatefulSet object if found,
            None if it doesn't exist (404 error).

        Raises:
            ApiError: If API call fails with an error other than 404.
        """
        try:
            return client.get(res=StatefulSet, name=statefulset_name, namespace=namespace)
        except ApiError as e:
            if e.status.code == 404:
                logger.debug(
                    "StatefulSet %s does not exist yet. "
                    "Will retry on next event. This is normal during initial deployment.",
                    statefulset_name,
                )
                return None
            raise

    def _repair_duplicate_env_vars(
        self, client: Client, statefulset: StatefulSet, statefulset_name: str, namespace: str
    ) -> StatefulSet:
        """Repair duplicate environment variables in containers if needed.

        Scans all containers in the StatefulSet template and removes duplicate
        environment variable entries using JSON Patch operations.

        Args:
            client: The lightkube Client instance.
            statefulset: The StatefulSet object to check and repair.
            statefulset_name: Name of the StatefulSet.
            namespace: Kubernetes namespace.

        Returns:
            StatefulSet: The StatefulSet object.

        Raises:
            ApiError: If StatefulSet patch or refetch fails.
        """
        template_spec = statefulset.spec.template.spec  # type: ignore[union-attr]
        containers = template_spec.containers or []

        json_operations_env_repair = []
        for container_idx, container in enumerate(containers):
            container_dict = container.to_dict() if hasattr(container, "to_dict") else container
            if not isinstance(container_dict, dict):
                continue

            if (env := container_dict.get("env")) and has_duplicate_env(env):
                container_name = container_dict.get("name", f"idx-{container_idx}")
                logger.warning(
                    "Duplicate env detected in container %s; repairing.", container_name
                )
                unique_env_vars = remove_duplicates(env)
                # ensure all items are dicts for JSON patch
                env_dicts = []
                for env_item in unique_env_vars:
                    if isinstance(env_item, dict):
                        env_dicts.append(env_item)
                    elif hasattr(env_item, "to_dict"):
                        env_dicts.append(env_item.to_dict())
                    elif hasattr(env_item, "__dict__"):
                        env_dicts.append(dict(env_item))
                    else:
                        # fallback: try to convert
                        env_dicts.append(
                            {
                                "name": getattr(env_item, "name", ""),
                                "value": getattr(env_item, "value", ""),
                            }
                        )
                json_operations_env_repair.append(
                    {
                        "operation": "replace",
                        "path": f"/spec/template/spec/containers/{container_idx}/env",
                        "value": env_dicts,
                    }
                )

        if json_operations_env_repair:
            logger.warning("StatefulSet has duplicate env entries; repairing with JSON patch.")
            client.patch(
                res=StatefulSet,
                name=statefulset_name,
                namespace=namespace,
                obj=json_operations_env_repair,
                patch_type=PatchType.JSON,
            )
            # refetch after repair so later logic uses clean object
            return client.get(res=StatefulSet, name=statefulset_name, namespace=namespace)

        return statefulset

    def _extract_pod_security_context(self, template_spec) -> dict:
        """Extract pod securityContext as a dictionary.

        Args:
            template_spec: The pod template spec object from
             StatefulSet.spec.template.spec.

        Returns:
            dict: dictionary representation of the pod securityContext,
                or empty dict if not present.
        """
        if security_context := getattr(template_spec, "securityContext", None):
            if hasattr(security_context, "to_dict"):
                return security_context.to_dict()
            elif isinstance(security_context, dict):
                return security_context.copy()
        return {}

    def _find_opensearch_container_index(self, containers: list) -> int | None:
        """Find the index of the opensearch container in the containers list.

        Args:
            containers: list of container objects from the pod template spec.

        Returns:
            int or None: index of the opensearch container if found, None otherwise.
        """
        for container_idx, container in enumerate(containers):
            container_dict = container.to_dict() if hasattr(container, "to_dict") else container
            if isinstance(container_dict, dict) and container_dict.get("name") == CONTAINER_NAME:
                return container_idx
        logger.warning(
            "Opensearch container %s not found in StatefulSet; cannot configure container securityContext.",
            CONTAINER_NAME,
        )
        return None

    def _check_configuration_state(
        self, pod_spec: dict, opensearch_container: Any, existing_init_containers: list
    ) -> dict:
        """Check the current configuration state and return a state dictionary.

        Verifies whether sysctls, pod securityContext, container securityContext,
        and initContainer are already configured correctly.

        Args:
            pod_spec: dict representation of pod securityContext.
            opensearch_container: the opensearch container object from the pod template.
            existing_init_containers: list of existing initContainer objects.

        Returns:
            dict: dictionary with keys:
                - sysctl_configured (bool): Whether sysctls are configured correctly.
                - pod_security_context_configured (bool): Whether pod
                    securityContext is configured.
                - container_security_context_configured (bool): Whether container
                        securityContext is configured.
                - init_container_exists (bool): Whether fix-permissions initContainer exists.
                - is_fully_configured (bool): Whether all configurations are complete.
        """
        # check sysctl configuration
        existing_sysctls = pod_spec.get("sysctls") or []
        desired_sysctl_name = SYSCTL_TCP_RETRIES2_NAME
        desired_sysctl_value = SYSCTL_TCP_RETRIES2_VALUE

        sysctl_configured = False
        for sysctl_entry in existing_sysctls:
            if isinstance(sysctl_entry, dict) and sysctl_entry.get("name") == desired_sysctl_name:
                if str(sysctl_entry.get("value", "")) == desired_sysctl_value:
                    sysctl_configured = True
                break

        # check pod-level securityContext
        desired_fs_group = OPENSEARCH_RUN_AS_USER
        # change ownership only if it's root-owned, otherwise leave it.
        desired_fs_group_change_policy = FS_GROUP_CHANGE_POLICY

        pod_security_context_configured = (
            convert_to_int(pod_spec.get("fsGroup")) == desired_fs_group
            and pod_spec.get("fsGroupChangePolicy") == desired_fs_group_change_policy
        )

        # check container-level securityContext for opensearch container
        opensearch_container_dict = (
            opensearch_container.to_dict()
            if hasattr(opensearch_container, "to_dict")
            else opensearch_container
        )
        opensearch_sc = (
            opensearch_container_dict.get("securityContext") or {}
            if isinstance(opensearch_container_dict, dict)
            else {}
        )

        container_security_context_configured = (
            opensearch_sc.get("runAsNonRoot") is True
            and convert_to_int(opensearch_sc.get("runAsUser")) == OPENSEARCH_RUN_AS_USER
            and convert_to_int(opensearch_sc.get("runAsGroup")) == OPENSEARCH_RUN_AS_GROUP
        )

        # check if initContainer exists
        init_container_exists = False
        for init_container in existing_init_containers:
            init_container_dict = (
                init_container.to_dict() if hasattr(init_container, "to_dict") else init_container
            )
            if (
                isinstance(init_container_dict, dict)
                and init_container_dict.get("name") == INIT_CONTAINER_NAME
            ):
                init_container_exists = True
                break
            elif hasattr(init_container, "name") and init_container.name == INIT_CONTAINER_NAME:
                init_container_exists = True
                break

        return {
            "sysctl_configured": sysctl_configured,
            "pod_security_context_configured": pod_security_context_configured,
            "container_security_context_configured": container_security_context_configured,
            "init_container_exists": init_container_exists,
            "is_fully_configured": (
                sysctl_configured
                and pod_security_context_configured
                and container_security_context_configured
                and init_container_exists
            ),
        }

    def _build_pod_security_context_patches(
        self, pod_spec: dict, config_state: dict
    ) -> list[dict]:
        """Build JSON patch operations for pod-level securityContext.

        Creates JSON Patch operations to configure fsGroup and fsGroupChangePolicy,
        and removes pod-level runAsNonRoot/runAsUser/runAsGroup if present.

        Args:
            pod_spec: dict representation of pod securityContext.
            config_state: dict containing configuration state checks.

        Returns:
            list[dict]: list of JSON Patch operation dictionaries. empty list if no changes needed.
        """
        json_operations = []

        # ensure pod securityContext exists
        if not pod_spec:
            json_operations.append(
                {
                    "operation": "add",
                    "path": "/spec/template/spec/securityContext",
                    "value": {},
                }
            )
            pod_spec = {}

        # add/update pod-level fsGroup and fsGroupChangePolicy
        if not config_state["pod_security_context_configured"]:
            desired_fs_group = OPENSEARCH_RUN_AS_USER

            if (fs_group := pod_spec.get("fsGroup")) is None or convert_to_int(
                fs_group
            ) != desired_fs_group:
                json_operations.append(
                    {
                        "operation": "replace" if "fsGroup" in pod_spec else "add",
                        "path": "/spec/template/spec/securityContext/fsGroup",
                        "value": desired_fs_group,
                    }
                )
            if pod_spec.get("fsGroupChangePolicy") != FS_GROUP_CHANGE_POLICY:
                json_operations.append(
                    {
                        "operation": "replace" if "fsGroupChangePolicy" in pod_spec else "add",
                        "path": "/spec/template/spec/securityContext/fsGroupChangePolicy",
                        "value": FS_GROUP_CHANGE_POLICY,
                    }
                )

        # remove pod-level runAsNonRoot, runAsUser, runAsGroup if they exist
        # these should NOT be set at pod level because charm container runs as root
        for field in ["runAsNonRoot", "runAsUser", "runAsGroup"]:
            if field in pod_spec:
                json_operations.append(
                    {
                        "operation": "remove",
                        "path": f"/spec/template/spec/securityContext/{field}",
                    }
                )

        return json_operations

    def _build_container_security_context_patches(
        self, opensearch_container: Any, container_idx: int, config_state: dict
    ) -> list[dict]:
        """Build JSON patch operations for container-level securityContext.

        Creates JSON Patch operations to configure runAsNonRoot, runAsUser,
        runAsGroup, and allowPrivilegeEscalation for the opensearch container.

        Args:
            opensearch_container: the opensearch container object.
            container_idx: index of the opensearch container in the containers list.
            config_state: dictionary containing configuration state checks.

        Returns:
            list[dict]: list of JSON Patch operation dictionaries. empty list if no changes needed.
        """
        json_operations = []

        if not config_state["container_security_context_configured"]:
            opensearch_container_dict = (
                opensearch_container.to_dict()
                if hasattr(opensearch_container, "to_dict")
                else opensearch_container
            )
            opensearch_sc = (
                opensearch_container_dict.get("securityContext") or {}
                if isinstance(opensearch_container_dict, dict)
                else {}
            )

            # ensure container securityContext exists
            if not opensearch_sc:
                json_operations.append(
                    {
                        "operation": "add",
                        "path": f"/spec/template/spec/containers/{container_idx}/securityContext",
                        "value": {},
                    }
                )

            # set runAsNonRoot, runAsUser, runAsGroup for opensearch container
            security_context_fields = [
                ("runAsNonRoot", True),
                ("runAsUser", OPENSEARCH_RUN_AS_USER),
                ("runAsGroup", OPENSEARCH_RUN_AS_GROUP),
                ("allowPrivilegeEscalation", False),
            ]

            for field_name, field_value in security_context_fields:
                json_operations.append(
                    {
                        "operation": "replace" if field_name in opensearch_sc else "add",
                        "path": f"/spec/template/spec/containers/{container_idx}/securityContext/{field_name}",
                        "value": field_value,
                    }
                )

        return json_operations

    def _build_sysctl_patches(self, pod_spec: dict, config_state: dict) -> list[dict]:
        """Build JSON patch operations for sysctls.

        Creates JSON Patch operation to configure net.ipv4.tcp_retries2=5,
        merging with any existing sysctls.

        Args:
            pod_spec: dictionary representation of pod securityContext.
            config_state: dictionary containing configuration state checks.

        Returns:
            list[dict]: list containing one JSON Patch operation dictionary,
             or empty list if no changes needed.
        """
        json_operations = []

        if not config_state["sysctl_configured"]:
            existing_sysctls = pod_spec.get("sysctls") or []
            desired_sysctl_name = SYSCTL_TCP_RETRIES2_NAME
            desired_sysctl_value = SYSCTL_TCP_RETRIES2_VALUE

            # merge sysctls
            sysctl_map = {}
            for sysctl_entry in existing_sysctls:
                if isinstance(sysctl_entry, dict) and (sysctl_name := sysctl_entry.get("name")):
                    sysctl_map[sysctl_name] = sysctl_entry.get("value", "")

            sysctl_map[desired_sysctl_name] = desired_sysctl_value
            merged_sysctls = [
                {"name": sysctl_name, "value": str(sysctl_value)}
                for sysctl_name, sysctl_value in sysctl_map.items()
            ]

            # add or replace sysctls
            json_operations.append(
                {
                    "operation": "replace" if "sysctls" in pod_spec else "add",
                    "path": "/spec/template/spec/securityContext/sysctls",
                    "value": merged_sysctls,
                }
            )

        return json_operations

    def _build_init_container_patches(
        self, opensearch_container: Any, existing_init_containers: list, config_state: dict
    ) -> list[dict]:
        """Build JSON patch operations for initContainer.

        Creates JSON Patch operation to add the fix-permissions initContainer
        if it doesn't already exist. The initContainer fixes volume mount permissions
        before the main opensearch container starts.

        Args:
            opensearch_container: the opensearch container object.
            existing_init_containers: list of existing initContainer objects.
            config_state: dictionary containing configuration state checks.

        Returns:
            list[dict]: list containing one JSON Patch operation dictionary,
             or empty list if no changes needed.
        """
        json_operations = []

        if not config_state["init_container_exists"]:
            # Get volume mounts from opensearch container
            opensearch_container_dict = (
                opensearch_container.to_dict()
                if hasattr(opensearch_container, "to_dict")
                else opensearch_container
            )
            opensearch_volume_mounts = (
                opensearch_container_dict.get("volumeMounts") or []
                if isinstance(opensearch_container_dict, dict)
                else []
            )

            # filter volume mounts to only include storage volumes that need permission fixes
            storage_volume_mounts = []
            for volume_mount in opensearch_volume_mounts:
                volume_mount_dict = (
                    volume_mount.to_dict() if hasattr(volume_mount, "to_dict") else volume_mount
                )
                if isinstance(volume_mount_dict, dict):
                    if (mount_path := volume_mount_dict.get("mountPath", "")) in [
                        K8S_DATA_MOUNT_PATH,
                        K8S_LOGS_MOUNT_PATH,
                        K8S_CERTIFICATES_MOUNT_PATH,
                    ]:
                        storage_volume_mounts.append(
                            {
                                "name": volume_mount_dict.get("name", ""),
                                "mountPath": mount_path,
                            }
                        )

            # build initContainer definition
            init_container = self._create_fix_permissions_init_container(storage_volume_mounts)

            # convert existing initContainers to list of dicts
            existing_init_containers_list = []
            for init_container in existing_init_containers:
                init_container_dict = (
                    init_container.to_dict()
                    if hasattr(init_container, "to_dict")
                    else init_container
                )
                if isinstance(init_container_dict, dict):
                    existing_init_containers_list.append(init_container_dict)
                elif hasattr(init_container, "__dict__"):
                    existing_init_containers_list.append(dict(init_container))
                else:
                    logger.warning(
                        "Could not convert initContainer to dict, skipping: %s", init_container
                    )
                    continue

            # Add our initContainer at the beginning
            existing_init_containers_list.insert(0, init_container)

            json_operations.append(
                {
                    "operation": "replace" if existing_init_containers else "add",
                    "path": "/spec/template/spec/initContainers",
                    "value": existing_init_containers_list,
                }
            )

            logger.info(
                "Added initContainer 'fix-permissions' to fix volume mount permissions (runs as root before main container)"
            )

        return json_operations

    def _create_fix_permissions_init_container(self, volume_mounts: list[dict]) -> dict:
        """Create the fix-permissions initContainer definition.

        Creates an initContainer specification that runs as root to fix permissions
        on mounted volumes before the main opensearch container starts.
        These are external PersistentVolumeClaims mounted at runtime
        separate from the image filesystem.

        Args:
            volume_mounts: list of volume mount dictionaries to include in the initContainer.

        Returns:
            dict: complete initContainer specification dictionary.
        """
        return {
            "name": INIT_CONTAINER_NAME,
            "image": INIT_CONTAINER_IMAGE,
            "command": [
                "bash",
                "-lc",
                (
                    "set -eux\n"
                    "# Fix permissions for opensearch-logs volume\n"
                    "mkdir -p /var/log/opensearch/logs\n"
                    "chown -R 584792:584792 /var/log/opensearch || true\n"
                    "chmod -R u+rwX,g+rwX,o+rwX /var/log/opensearch || true\n"
                    "chmod 2777 /var/log/opensearch /var/log/opensearch/logs || true\n"
                    "# Fix permissions for opensearch-data volume\n"
                    "if [ -d /var/lib/opensearch ]; then\n"
                    "  mkdir -p /var/lib/opensearch/data\n"
                    "  chown -R 584792:584792 /var/lib/opensearch\n"
                    "  chmod -R u+rwX,g+rwX /var/lib/opensearch\n"
                    "  chmod 2770 /var/lib/opensearch /var/lib/opensearch/data || true\n"
                    "fi\n"
                    "# Fix permissions for certificates volume\n"
                    "if [ -d /etc/opensearch ]; then\n"
                    "  mkdir -p /etc/opensearch/certificates\n"
                    "  chown -R 584792:584792 /etc/opensearch/certificates\n"
                    "  chmod -R u+rwX,g+rX /etc/opensearch/certificates\n"
                    "  chmod 2750 /etc/opensearch/certificates || true\n"
                    "fi\n"
                ),
            ],
            "securityContext": {
                "runAsUser": INIT_CONTAINER_ROOT_UID,
                "runAsGroup": INIT_CONTAINER_ROOT_GID,
            },
            "volumeMounts": volume_mounts,
        }

    def _trigger_pod_restart_via_annotation(
        self, client: Client, statefulset_name: str, namespace: str
    ) -> None:
        """Trigger pod restart by updating a template annotation.

        Updates the StatefulSet template annotation with a timestamp to force
        a pod rollout. This ensures pods restart and pick up sysctl changes.

        Args:
            client: the lightkube Client instance.
            statefulset_name: name of the StatefulSet to update.
            namespace: Kubernetes namespace where the StatefulSet exists.
        """
        try:
            # Get current StatefulSet to check if annotations exist
            statefulset = client.get(StatefulSet, name=statefulset_name, namespace=namespace)
            template_metadata = (
                statefulset.spec.template.metadata
                if hasattr(statefulset.spec.template, "metadata")
                else None
            )
            existing_annotations = {}
            if (
                template_metadata
                and hasattr(template_metadata, "annotations")
                and (anns := template_metadata.annotations)
            ):
                if isinstance(anns, dict):
                    existing_annotations = anns
                elif hasattr(anns, "to_dict"):
                    existing_annotations = anns.to_dict()

            # update or add restart timestamp annotation
            restart_timestamp = str(time.time())
            if existing_annotations:
                restart_annotation_operations = [
                    {
                        "operation": (
                            "replace"
                            if POD_RESTART_ANNOTATION_KEY in existing_annotations
                            else "add"
                        ),
                        "path": "/spec/template/metadata/annotations/%s"
                        % POD_RESTART_ANNOTATION_KEY,
                        "value": restart_timestamp,
                    }
                ]
            else:
                restart_annotation_operations = [
                    {
                        "operation": "add",
                        "path": "/spec/template/metadata/annotations",
                        "value": {POD_RESTART_ANNOTATION_KEY: restart_timestamp},
                    }
                ]

            client.patch(
                res=StatefulSet,
                name=statefulset_name,
                namespace=namespace,
                obj=restart_annotation_operations,
                patch_type=PatchType.JSON,
            )
            logger.info(
                "Updated StatefulSet annotation (%s=%s) "
                "to trigger pod rollout for sysctl changes",
                POD_RESTART_ANNOTATION_KEY,
                restart_timestamp,
            )
        except Exception as e:
            logger.warning(
                "Could not trigger pod restart via annotation update: %s. "
                "Pods may need manual restart to pick up sysctl changes. "
                "StatefulSet controller should auto-rollout on template changes.",
                e,
            )
