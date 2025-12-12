#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Cluster manager."""
from typing import List, Optional

from tenacity import (
    Retrying,
    stop_after_attempt,
    wait_exponential,
)

from opensearch_single_kernel.common.base import BaseManager
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
)
from opensearch_single_kernel.core.models import DeploymentDescription, Node
from opensearch_single_kernel.core.state import ClusterState
from opensearch_single_kernel.managers.topology import TopologyManager
from opensearch_single_kernel.utils.config import YamlConfigSetter
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
            # TODO: Update this once we include peer CM relation
            # and (
            #    "data" in self.opensearch_peer_cm.deployment_desc().config.roles
            #    or self.opensearch_peer_cm.deployment_desc().start
            #    == StartMode.WITH_GENERATED_ROLES
            # )
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
                # TODO: Consider deployment description from peer cm
                #  f"-cn {self.opensearch_peer_cm.deployment_desc().config.cluster_name}",
                f"-h {self.unit_ip}",
                f"-ts {self.opensearch.paths.certs}/ca.p12",
                f"-tspass {self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)['truststore-password']}",
                "-tsalias ca",
                "-tst PKCS12",
                f"-ks {self.opensearch.paths.certs}/{CertType.APP_ADMIN}.p12",
                f"-kspass {self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)['keystore-password']}",
                f"-ksalias {CertType.APP_ADMIN}",
                "-kst PKCS12",
            ]

            admin_key_pwd = admin_secrets.get("key-password", None)
            if admin_key_pwd is not None:
                args.append(f"-keypass {admin_key_pwd}")

            self.opensearch.run_script(
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

    def _apply_peer_cm_directives_and_check_if_can_start(self) -> bool:
        """Apply the directives computed by the opensearch peer cluster manager."""
        if not (deployment_desc := self.state.application.deployment_desc()):
            # the deployment description hasn't finished being computed by the leader
            return False

        # check possibility to start
        self.logger.debug("Checking if cluster can start with deploy desc: %s", deployment_desc)
        if self.can_start(deployment_desc):
            try:
                self.get_nodes(False)
            except OpenSearchHttpError:
                return False
            return True

        # TODO: Need to find a solution for this
        # if self.unit.is_leader():
        # self.opensearch_peer_cm.apply_status_if_needed(
        # deployment_desc, show_status_only_once=False
        # )

        return False

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
            computed_roles = TopologyManager.generated_roles()

        if (
            self.state.opensearch_unit.is_app_leader
            and "data" in computed_roles
            and not self.state.opensearch_application.security_index_initialised
        ):
            return []
        return TopologyManager.nodes(self.opensearch_client, use_localhost, self.state.alt_hosts)

    def clean_up_started_state(self) -> None:
        """Remove the 'started' key from the unit state."""
        self.state.opensearch_unit.relation_data.pop("started")

    def is_node_up(self):
        """Check whether opensearch is up"""
        return self.opensearch_client.is_node_up()
