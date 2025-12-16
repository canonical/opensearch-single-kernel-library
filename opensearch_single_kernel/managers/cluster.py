#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Cluster manager."""
import datetime
import time
from typing import List, Optional

from tenacity import (
    Retrying,
    stop_after_attempt,
    wait_exponential,
)

from opensearch_single_kernel.common.constants import (
    CertType,
    Directive,
    Scope,
    StartMode,
)
from opensearch_single_kernel.common.exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
    OpenSearchNotFullyReadyError,
    OpenSearchStartTimeoutError,
)
from opensearch_single_kernel.core.models import DeploymentDescription, Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.base import BaseManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
from opensearch_single_kernel.utils.topology import ClusterTopology
from opensearch_single_kernel.workload.base import BaseWorkload


class ClusterManager(BaseManager):
    """OpenSearch Cluster Manager.

    This manager is responsible for the different operations regarding configuring and
    managing opensearch cluster.
    """

    CONFIG_YML = "opensearch.yml"

    def __init__(self, state: ClusterState, workload: BaseWorkload):
        super().__init__(state, workload)
        self.name = "cluster_manager"
        self.yaml_setter = YamlConfigSetter(self.workload.paths.conf)

    def start(self, wait_until_http_200: bool = True):
        """Start the opensearch service."""

        def _is_connected():
            return self.is_node_up() if wait_until_http_200 else self.is_started()

        if self.is_started():
            return

        # start the opensearch service
        self.workload.start_service()

        start = datetime.now()
        while not (connected := _is_connected()) and (datetime.now() - start).seconds < 180:
            time.sleep(3)
        if not connected:
            self.logger.debug(f"waited {datetime.now() - start} opensearch did not start")
            raise OpenSearchStartTimeoutError()

    def is_started(self) -> bool:
        """Check if OpenSearch is started."""
        reachable = self.workload.is_reachable(self.state.host_ip, self.state.port)
        if not reachable:
            self.logger.debug("Cannot connect to the OpenSearch server...")

        return reachable

    def set_client_auth(self):
        """Configure TLS and basic http for clients."""
        # The security plugin will accept TLS client certs if certs but doesn't require them
        # TODO this may be set to REQUIRED if we want to ensure certs provided by the client app
        self.yaml_setter.put(
            self.CONFIG_YML, "plugins.security.ssl.http.clientauth_mode", "OPTIONAL"
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/basic_internal_auth_domain/http_enabled",
            True,
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/clientcert_auth_domain/http_enabled",
            True,
        )

        self.yaml_setter.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/clientcert_auth_domain/transport_enabled",
            True,
        )

        self.yaml_setter.append(
            self.JVM_OPTIONS,
            "-Djdk.tls.client.protocols=TLSv1.2",
        )

    def cleanup_bootstrap_conf(self):
        """Clean up bootstrap state and remove initial_cluster_manager_nodes from config"""
        if self.state.unit.is_app_leader:
            self.state.application.update({"bootstrapped", True})
        self.state.unit.relation_data.pop("bootstrap_contributor")
        self.yaml_setter.delete(self.CONFIG_YML, "cluster.initial_cluster_manager_nodes")

    def is_opensearch_started(self) -> bool:
        """Returns whether OpenSearch has started."""
        reachable = self.workload.is_reachable(self.state.host, self.state.port)
        if not reachable:
            self.logger.debug("Cannot connect to the OpenSearch server...")

        return reachable

    @property
    def roles(self) -> List[str]:
        """Get the list of the roles assigned to this node."""
        try:
            return self.opensearch_client.roles(self.state.unit.unit_name, self.state.alt_hosts)
        except OpenSearchHttpError:
            return self.yaml_setter.load("opensearch.yml")["node.roles"]

    def should_initialise_security_index(self) -> bool:
        """Returns whether the unit should initialise the security index."""
        return (
            self.state.opensearch_unit.is_app_leader
            and not self.state.opensearch_application.security_index_initialised
            and (
                "data" in self.state.application.deployment_desc.config.roles
                or self.state.application.deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            )
        )

    def initialise_security_index(self):
        """Initialise security Index.

        This function is called after opensearch has started.

        Run the security_admin script, it creates and initializes the opendistro_security index.

        IMPORTANT: must only run once per cluster, otherwise the index gets overrode
        """
        admin_secrets = self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        try:
            args = [
                f"-cd {self.workload.paths.conf}/opensearch-security/",
                f"-cn {self.state.application.deployment_desc.config.cluster_name}",
                f"-h {self.state.unit_ip}",
                f"-ts {self.workload.paths.certs}/ca.p12",
                f"-tspass {self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)['truststore-password']}",
                "-tsalias ca",
                "-tst PKCS12",
                f"-ks {self.workload.paths.certs}/{CertType.APP_ADMIN}.p12",
                f"-kspass {self.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)['keystore-password']}",
                f"-ksalias {CertType.APP_ADMIN}",
                "-kst PKCS12",
            ]

            admin_key_pwd = admin_secrets.get("key-password", None)
            if admin_key_pwd is not None:
                args.append(f"-keypass {admin_key_pwd}")

            self.workload.run_script(
                "plugins/opensearch-security/tools/securityadmin.sh", " ".join(args)
            )
            self._put_security_index_initialised()

        except OpenSearchCmdError as e:
            self.logger.debug(f"Error when initializing the security index: {e.out}")
            raise e

    def _put_security_index_initialised(self):
        """Set the security index initialized flag."""
        # TODO: Add peer cluster updates here we need to update relations
        self.state.opensearch_application.update({"security_index_initialised": "True"})

    def wait_for_opensearch_up(self):
        """Wait for opensearch to be fully ready."""
        # it sometimes takes a few seconds before the node is fully "up" otherwise a 503 error
        # may be thrown when calling a node - we want to ensure this node is perfectly ready
        # before marking it as ready
        for attempt in Retrying(
            stop=stop_after_attempt(5),
            wait=wait_exponential(multiplier=2, min=2, max=10),
            reraise=True,
        ):
            with attempt:
                if not self.is_node_up():
                    raise OpenSearchNotFullyReadyError("Node started but not fully ready yet.")

    def can_start(self, deployment_desc: Optional[DeploymentDescription] = None) -> bool:
        """Return whether the service of a node can start."""
        if not (deployment_desc := deployment_desc or self.deployment_desc()):
            return False

        blocking_directives = [
            Directive.WAIT_FOR_PEER_CLUSTER_RELATION,
            Directive.RECONFIGURE,
            Directive.VALIDATE_CLUSTER_NAME,
            Directive.INHERIT_CLUSTER_NAME,
        ]
        self.logger.debug("Directives: %s", deployment_desc.pending_directives)
        for directive in deployment_desc.pending_directives:
            if directive in blocking_directives:
                self.logger.debug("blocking directive %s", directive)
                return False

        return True

    def get_nodes(self, use_localhost: bool) -> List[Node]:
        """Fetch the list of nodes of the cluster, depending on the requester."""
        if self.state.planned_units == 0 and not self.state.application.deployment_desc:
            # This app is going away and the -broken event already happened
            return []

        # This means it's the first unit on the cluster.
        if self.state.application.deployment_desc.start == StartMode.WITH_PROVIDED_ROLES:
            computed_roles = self.state.application.deployment_desc.config.roles
        else:
            computed_roles = ClusterTopology.generated_roles()

        if (
            self.state.server.is_app_leader
            and "data" in computed_roles
            and not self.state.application.security_index_initialised
        ):
            return []
        return ClusterTopology.nodes(self.opensearch_client, use_localhost, self.alt_hosts)

    def compute_and_broadcast_updated_topology(self, current_nodes: List[Node]) -> bool:
        """Compute cluster topology and broadcast node configs (roles for now) to change if any.

        Returns whether a nodes_config object has been updated or not.
        """
        if not current_nodes:
            return False

        current_reported_nodes = {
            name: Node.from_dict(node)
            for name, node in (self.state.application.nodes_config or {}).items()
        }

        if (
            deployment_desc := self.state.application.deployment_desc
        ).start == StartMode.WITH_GENERATED_ROLES:
            updated_nodes = ClusterTopology.recompute_nodes_conf(
                logger=self.logger, app_id=deployment_desc.app.id, nodes=current_nodes
            )
        else:
            updated_nodes = {}
            for node in current_nodes:
                roles = node.roles
                temperature = node.temperature

                # only change the roles of the nodes of the current cluster
                if node.app.id == deployment_desc.app.id:
                    roles = deployment_desc.config.roles
                    temperature = deployment_desc.config.data_temperature

                updated_nodes[node.name] = Node(
                    name=node.name,
                    roles=roles,
                    ip=node.ip,
                    app=node.app,
                    unit_number=self.unit_id,
                    temperature=temperature,
                )

        if current_reported_nodes == updated_nodes:
            return False

        self.state.application.put_object("nodes_config", updated_nodes)
        return True

    def reconfigure_unit(self) -> bool:
        """Reconfigure unit based on the nodes_config.

        Returns if a restart is needed or not.
        """
        if not (nodes_config := self.state.application.get_object("nodes_config")):
            return False

        nodes_config = {name: Node.from_dict(node) for name, node in nodes_config.items()}

        # update (append) CM IPs
        self.add_seed_hosts(
            [node.ip for node in list(nodes_config.values()) if node.is_cm_eligible()]
        )

        if not (new_node_conf := nodes_config.get(self.state.unit_name)):
            # the conf could not be computed / broadcast, because this node is
            # "starting" and is not online "yet" - either barely being configured (i.e. TLS)
            # or waiting to start.
            return False

        current_conf = self.yaml_setter.load(self.CONFIG_YML)
        stored_roles = current_conf["node.roles"] or ["coordinating"]
        new_conf_roles = new_node_conf.roles or ["coordinating"]
        if (
            sorted(stored_roles) == sorted(new_conf_roles)
            and current_conf.get("node.attr.temp") == new_node_conf.temperature
        ):
            # no conf change (roles for now)
            return False
        return True

    def add_seed_hosts(self, cm_ips: List[str]):
        """Add CM nodes ips / host names to the seed host list of this unit."""
        cm_ips_set = set(cm_ips)

        # only update the file if there is data to update
        # TODO: This should be handled at the workload level since on K8s it will be different
        if cm_ips_set:
            with open(self.workload.paths.seed_hosts, "w+") as f:
                lines = "\n".join([entry for entry in cm_ips_set if entry.strip()])
                f.write(f"{lines}\n")

    def clean_up_started_state(self) -> None:
        """Remove the 'started' key from the unit state."""
        self.state.opensearch_unit.relation_data.pop("started")

    def is_node_up(self):
        """Check whether opensearch is up"""
        return self.opensearch_client.is_node_up()
