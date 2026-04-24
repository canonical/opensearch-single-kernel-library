# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for opensearch tls manager."""
import itertools
import re
import uuid
from unittest import mock
from unittest.mock import MagicMock, PropertyMock, call

import pytest
import responses
from ops import MaintenanceStatus

from opensearch_single_kernel.common.constants import (
    CA_ALIAS,
    CertType,
    DeploymentType,
    Scope,
    StartMode,
    State,
)
from opensearch_single_kernel.common.statuses import TlsStatuses
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
)
from tests.unit.helpers import (
    create_utf8_encoded_private_key,
    deployment_descriptions,
    mock_response_health_green,
    mock_response_lock_not_requested,
    mock_response_nodes,
    mock_response_put_http_cert,
    mock_response_put_transport_cert,
    mock_response_root,
)


def _workload_class_name(substrate: str) -> str:
    """Return workload class name for the given substrate.

    Keep class naming consistent with implementation:
    - VM: VMWorkload
    - K8s: K8sWorkload
    """
    return "VMWorkload" if substrate == "vm" else "K8sWorkload"


def single_space(input: str) -> str:
    """Replace multiple spaces with one."""
    return " ".join(input.split())


def test_get_sans(harness, mocker, substrate):
    """Test the SANs returned depending on the cert type."""
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    deployment_desc.return_value = deployment_descriptions["ok"]

    assert harness.charm.tls_manager._get_sans(CertType.APP_ADMIN) == {"sans_oid": ["1.2.3.4.5.5"]}

    if substrate == "vm":
        get_publish_host = mocker.patch(
            "opensearch_single_kernel.workload.vm.VMWorkload.get_publish_host"
        )
    else:
        mocker.patch(
            "opensearch_single_kernel.core.state.ClusterState.fqdn",
            return_value="opensearch-0.opensearch-endpoints.namespace.svc.cluster.local",
            new_callable=PropertyMock,
        )
    getfqdn = mocker.patch("socket.getfqdn")
    gethostname = mocker.patch("socket.gethostname")
    gethostbyaddr = mocker.patch("socket.gethostbyaddr")

    gethostbyaddr.return_value = (
        harness.charm.state.unit_name,
        ["alias"],
        ["address1", "address2"],
    )
    gethostname.return_value = "nebula"
    getfqdn.return_value = "nebula"
    # For VM: returns IP address
    # For K8s: returns DNS name
    if substrate == "vm":
        get_publish_host.return_value = "192.168.1.100"

    base_ips = ["1.1.1.1", "address1", "address2"]
    base_dns_entries = [harness.charm.state.unit_name, "nebula", "alias"]
    unit_http_sans = harness.charm.tls_manager._get_sans(CertType.UNIT_HTTP)

    # expected results differ by substrate
    if substrate == "vm":
        expected_sans = {
            "sans_oid": ["1.2.3.4.5.5"],
            "sans_ip": sorted(base_ips + ["192.168.1.100"]),
            "sans_dns": sorted(base_dns_entries),
        }
    else:  # k8s
        expected_sans = {
            "sans_oid": ["1.2.3.4.5.5"],
            "sans_ip": [],
            "sans_dns": sorted(
                [harness.charm.state.unit_name, "nebula"]
                + ["opensearch-0.opensearch-endpoints.namespace.svc.cluster.local"]
            ),
        }

    assert dict((key, sorted(val)) for key, val in unit_http_sans.items()) == expected_sans

    unit_transport_sans = harness.charm.tls_manager._get_sans(CertType.UNIT_TRANSPORT)
    expected_transport_sans = (
        {
            "sans_oid": ["1.2.3.4.5.5"],
            "sans_ip": sorted(base_ips),
            "sans_dns": sorted(base_dns_entries),
        }
        if substrate == "vm"
        else {
            "sans_oid": ["1.2.3.4.5.5"],
            "sans_ip": [],
            "sans_dns": sorted(
                [
                    harness.charm.state.unit_name,
                    "nebula",
                    "opensearch-0.opensearch-endpoints.namespace.svc.cluster.local",
                ]
            ),
        }
    )
    assert (
        dict((key, sorted(val)) for key, val in unit_transport_sans.items())
        == expected_transport_sans
    )


def test_get_certificate_subject_uses_short_unit_identity_on_k8s(harness, mocker, substrate):
    """K8s CSR common name should stay within X.509 limits."""
    if substrate == "vm":
        pytest.skip("K8s-only certificate subject behavior")

    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.unit_name",
        new_callable=PropertyMock,
        return_value="opensearch-k8s-0.a03",
    )
    mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.fqdn",
        new_callable=PropertyMock,
        return_value="opensearch-k8s-0.opensearch-k8s-endpoints.ktest1.svc.cluster.local",
    )

    assert harness.charm.tls_manager._get_certificate_subject(CertType.UNIT_TRANSPORT) == (
        "opensearch-k8s-0"
    )
    assert len(harness.charm.tls_manager._get_certificate_subject(CertType.UNIT_HTTP)) <= 64


def test_find_secret(harness):
    """Test the secrets lookup depending on the event data."""
    event_data_cert = "cert_abcd12345"
    event_data_csr = "csr_abcd12345"

    assert harness.charm.tls_manager.find_secret(event_data_cert, "cert") is None
    assert harness.charm.tls_manager.find_secret(event_data_csr, "csr") is None

    harness.charm.state.secrets.put_object(
        Scope.UNIT, CertType.UNIT_TRANSPORT.val, {"cert": event_data_cert}
    )
    harness.charm.state.secrets.put_object(
        Scope.APP, CertType.APP_ADMIN.val, {"csr": event_data_csr}
    )

    scope, certtype, secret = harness.charm.tls_manager.find_secret(event_data_cert, "cert")
    assert scope == Scope.UNIT
    assert certtype == CertType.UNIT_TRANSPORT
    assert secret["cert"] == event_data_cert

    scope, certtype, secret = harness.charm.tls_manager.find_secret(event_data_csr, "csr")
    assert scope == Scope.APP
    assert certtype == CertType.APP_ADMIN
    assert secret["csr"] == event_data_csr


def test_on_relation_created_admin(harness, mocker):
    """Test on certificate relation created event."""
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    create_certificate_signing_request = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.create_certificate_signing_request"
    )
    mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    event_mock = MagicMock()

    harness.set_leader(is_leader=True)
    harness.charm.tls_events._on_tls_relation_created(event_mock)

    assert create_certificate_signing_request.mock_calls == [
        mock.call(Scope.APP, CertType.APP_ADMIN),
        mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT),
        mock.call(Scope.UNIT, CertType.UNIT_HTTP),
    ]


def test_on_relation_created_only_main_orchestrator_requests_application_cert(harness, mocker):
    """Test on certificate relation created event."""
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=DeploymentType.OTHER,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )
    # Truststore password is required
    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {"truststore-password": "abc"},
    )

    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    create_certificate_signing_request = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.create_certificate_signing_request"
    )
    mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    event_mock = MagicMock()

    harness.set_leader(is_leader=True)
    harness.charm.tls_events._on_tls_relation_created(event_mock)

    assert create_certificate_signing_request.mock_calls == [
        mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT),
        mock.call(Scope.UNIT, CertType.UNIT_HTTP),
    ]


def test_on_relation_created_non_admin(harness, mocker):
    """Test on certificate relation created event."""
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    create_certificate_signing_request = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.create_certificate_signing_request"
    )
    mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    event_mock = MagicMock()

    truststore_password = "12345"
    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {"truststore-password": truststore_password},
    )

    harness.set_leader(is_leader=False)
    harness.charm.tls_events._on_tls_relation_created(event_mock)
    assert create_certificate_signing_request.mock_calls == [
        mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT),
        mock.call(Scope.UNIT, CertType.UNIT_HTTP),
    ]


def test_on_set_tls_private_key(harness, mocker, substrate):
    """Test _on_set_tls private key event."""
    event_mock = MagicMock(params={"category": "app-admin"})
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    if substrate == "vm":
        mocker.patch("opensearch_single_kernel.workload.vm.VMWorkload.get_publish_host")
    else:
        mocker.patch(
            "opensearch_single_kernel.core.state.ClusterState.fqdn",
            return_value="opensearch-0.opensearch-endpoints.namespace.svc.cluster.local",
            new_callable=PropertyMock,
        )
    request_certificate_creation = mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )

    harness.set_leader(is_leader=False)
    deployment_desc.return_value = deployment_descriptions["ko"]
    harness.charm.tls_events._on_set_private_key(event_mock)
    request_certificate_creation.assert_not_called()

    harness.set_leader(is_leader=True)
    deployment_desc.return_value = deployment_descriptions["ok"]
    harness.charm.tls_events._on_set_private_key(event_mock)
    request_certificate_creation.assert_called_once()

    event_mock = MagicMock(params={"category": "unit-transport"})
    harness.set_leader(is_leader=False)
    harness.charm.tls_events._on_set_private_key(event_mock)
    request_certificate_creation.assert_called()


def test_on_certificate_available(harness, mocker):
    """Test _on_certificate_available event."""
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    deployment_desc.return_value = deployment_descriptions["ok"]
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.create_certificate_signing_request"
    )
    mocker.patch("opensearch_single_kernel.managers.tls.TlsManager.create_store_pwd_if_not_exists")
    mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    mocker.patch("opensearch_single_kernel.managers.tls.TlsManager.store_new_ca")
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca", return_value="ca_12345"
    )
    on_tls_conf_set = mocker.patch(
        "opensearch_single_kernel.events.tls.TLSEventsHandler.on_tls_conf_set"
    )
    csr = "csr_12345"
    cert = "cert_12345"
    chain = ["chain_12345"]
    ca = "ca_12345"
    keystore_password = "keystore_12345"
    secret_key = CertType.UNIT_TRANSPORT.val

    harness.set_leader(is_leader=True)
    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {"truststore-password": "truststore_12345"},
    )
    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        secret_key,
        {"csr": csr, "keystore-password": keystore_password},
    )

    event_mock = MagicMock(certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca)
    harness.charm.tls_events._on_certificate_available(event_mock)

    assert harness.charm.state.server.transport_secrets == {
        "csr": csr,
        "chain": chain[0],
        "cert": cert,
        "ca-cert": ca,
        "keystore-password": keystore_password,
    }
    on_tls_conf_set.assert_called()


def test_on_certificate_expiring(harness, mocker, substrate):
    """Test _on_certificate_available event."""
    request_certificate_creation = mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    if substrate == "vm":
        mocker.patch("opensearch_single_kernel.workload.vm.VMWorkload.get_publish_host")
    else:
        mocker.patch(
            "opensearch_single_kernel.core.state.ClusterState.fqdn",
            return_value="opensearch-0.opensearch-endpoints.namespace.svc.cluster.local",
            new_callable=PropertyMock,
        )
    csr = "csr_12345"
    cert = "cert_12345"
    key = create_utf8_encoded_private_key()
    secret_key = CertType.UNIT_TRANSPORT.val

    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        secret_key,
        {"csr": csr, "cert": cert, "key": key},
    )

    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    event_mock = MagicMock(certificate=cert)
    harness.charm.tls_events._on_certificate_expiring(event_mock)

    request_certificate_creation.assert_called_once()


def test_on_certificate_invalidated(harness, mocker, substrate):
    """Test _on_certificate_invalidated event."""
    request_certificate_creation = mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    if substrate == "vm":
        mocker.patch("opensearch_single_kernel.workload.vm.VMWorkload.get_publish_host")
    else:
        mocker.patch(
            "opensearch_single_kernel.core.state.ClusterState.fqdn",
            return_value="opensearch-0.opensearch-endpoints.namespace.svc.cluster.local",
            new_callable=PropertyMock,
        )
    csr = "csr_12345"
    cert = "cert_12345"
    key = create_utf8_encoded_private_key()
    secret_key = CertType.UNIT_TRANSPORT.val

    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        secret_key,
        {"csr": csr, "cert": cert, "key": key},
    )

    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=DeploymentType.MAIN_ORCHESTRATOR,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    event_mock = MagicMock(certificate=cert)
    harness.charm.tls_events._on_certificate_invalidated(event_mock)

    request_certificate_creation.assert_called_once()


# Testing store_new_ca() function
def test_truststore_password_secret(harness, mocker, substrate):
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    mocker.patch("opensearch_single_kernel.utils.certificates.store_ca_chain")
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    deployment_desc.return_value = deployment_descriptions["ok"]
    create_store_pwd_if_not_exists = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.create_store_pwd_if_not_exists"
    )

    harness.set_leader(is_leader=False)
    harness.charm.tls_manager.store_new_ca(CertType.UNIT_HTTP, False)

    create_store_pwd_if_not_exists.assert_not_called()

    harness.set_leader(is_leader=True)
    harness.charm.tls_manager.store_new_ca(CertType.UNIT_HTTP, True)

    create_store_pwd_if_not_exists.assert_called_once()


@pytest.mark.parametrize(
    ("deployment_type"),
    (
        (DeploymentType.MAIN_ORCHESTRATOR),
        (DeploymentType.OTHER),
        (DeploymentType.FAILOVER_ORCHESTRATOR),
    ),
)
def test_on_certificate_available_leader_app_cert_full_workflow(
    deployment_type, harness, mocker, substrate, mock_fs_interactions
):
    """New certificate received.

    The charm leader unit should save the new certificate both to
    Juju secrets and to the keystore.

    Applies to:
        - all deployments
        - leader ONLY
    """
    csr = "csr"
    key = "key"
    ca = "ca"

    new_cert = "new_cert"
    new_chain = ["new_chain"]

    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": csr,
            "key": key,
            "ca-cert": ca,
            "cert": "old_cert",
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
        },
    )
    # Purposefully not adding unit certificates, to also trigger corner-case checks
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    read_stored_ca = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca"
    )
    workload_class = _workload_class_name(substrate)
    run_cmd = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd"
    )
    tempfile = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.temp_file"
    )
    event_mock = MagicMock(
        certificate_signing_request=csr, chain=new_chain, certificate=new_cert, ca=ca
    )

    # There was no change of the CA (certificate), the event matches the one on disk
    read_stored_ca.return_value = ca

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    harness.set_leader(is_leader=True)

    original_status_app = harness.model.app.status
    original_status_unit = harness.model.unit.status
    harness.charm.restart_opensearch_event = MagicMock()

    harness.charm.tls_events._on_certificate_available(event_mock)

    # The new cert is saved to the keystore
    # NOTE on the leader node, the operation is redundant i.e. executed TWICE
    # This is because the function that applies on normal units to save app certificate
    # is executed on top of the mechanism that recognizes that the leader
    # received a new app cert
    assert run_cmd.call_count == 6

    certs_dir = str(harness.charm.workload.paths.certs)
    conf_dir = str(harness.charm.workload.paths.conf)
    assert re.search(
        "openssl pkcs12 -export .*-out " rf"{certs_dir}/app-admin\.p12 .*-name app-admin",
        run_cmd.call_args_list[0].args[0],
    )
    expected_mode = "640"
    assert re.search(
        rf"(sudo )?chmod {expected_mode} {certs_dir}/app-admin\.p12",
        run_cmd.call_args_list[1].args[0],
    )
    if substrate == "vm":
        assert any(
            f"sudo chown snap_daemon:root {certs_dir}/app-admin.p12" in call.args[0]
            for call in run_cmd.call_args_list
        )
    assert conf_dir in str(tempfile.call_args_list[0][1]["dir"])

    assert harness.model.app.status == original_status_app
    assert harness.model.unit.status == original_status_unit

    # The new certificate is now replacing the old one in Peer Relation secrets
    assert harness.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
        "csr": csr,
        "key": key,
        "ca-cert": ca,
        "cert": new_cert,
        "chain": new_chain[0],
        "truststore-password": "truststore_12345",
        "keystore-password": "keystore_12345",
    }


# NOTE: Syntax: parametrized has to be the outermost decorator
@pytest.mark.parametrize(
    ("deployment_type", "leader", "cert_type"),
    itertools.product(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ],
        [True, False],
        [CertType.UNIT_HTTP.val, CertType.UNIT_TRANSPORT.val],
    ),
)
def test_on_certificate_available_any_node_unit_cert_full_workflow(
    deployment_type, leader, cert_type, harness, mocker, substrate, mock_fs_interactions
):
    """New *unit* certificate received.

    At this point the charm leader unit should save the new certificate both to
    Juju secrets and to the keystore.

    Applies to:
        - all deployments
        - all units
    """
    csr = "csr"
    key = "key"
    ca = "ca"
    keystore_password = "keystore_12345"

    new_cert = "new_cert"
    new_chain = ["new_chain"]

    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": csr,
            "key": key,
            "ca-cert": ca,
            "cert": "old_cert",
            "keystore-password": keystore_password,
            "truststore-password": "truststore_12345",
        },
    )
    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        CertType.UNIT_TRANSPORT,
        {
            "csr": f"{CertType.UNIT_TRANSPORT.val}-csr",
            "truststore-password": "truststore_12345",
            "keystore-password": keystore_password,
            "key": key,
            "ca-cert": ca,
            "cert": "old_cert",
        },
    )

    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        CertType.UNIT_HTTP,
        {
            "csr": f"{CertType.UNIT_HTTP.val}-csr",
            "truststore-password": "truststore_12345",
            "keystore-password": keystore_password,
            "key": key,
            "ca-cert": ca,
            "cert": "old_cert",
        },
    )

    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch("opensearch_single_kernel.managers.config.ConfigManager.update_opensearch_config")
    read_stored_ca = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca"
    )
    workload_class = _workload_class_name(substrate)
    run_cmd = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd"
    )
    tempfile = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.temp_file"
    )
    event_mock = MagicMock(
        certificate_signing_request=f"{cert_type}-csr",
        chain=new_chain,
        certificate=new_cert,
        ca=ca,
    )

    # There was no change of the CA (certificate), the event matches the one on disk
    read_stored_ca.return_value = ca

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    harness.set_leader(is_leader=leader)

    original_status_unit = harness.model.unit.status
    harness.charm.restart_opensearch_event = MagicMock()

    harness.charm.tls_events._on_certificate_available(event_mock)

    # The new cert is saved to the keystore
    if harness.charm.unit.is_leader():
        assert run_cmd.call_count == 3
    else:
        assert run_cmd.call_count == 6

    certs_dir = str(harness.charm.workload.paths.certs)
    conf_dir = str(harness.charm.workload.paths.conf)
    assert re.search(
        "openssl pkcs12 -export .*-out " rf"{certs_dir}/{cert_type}\.p12 .*-name {cert_type}",
        run_cmd.call_args_list[0].args[0],
    )
    expected_mode = "640"
    assert re.search(
        rf"(sudo )?chmod {expected_mode} {certs_dir}/{cert_type}\.p12",
        run_cmd.call_args_list[1].args[0],
    )
    if substrate == "vm":
        assert any(
            f"sudo chown snap_daemon:root {certs_dir}/{cert_type}.p12" in call.args[0]
            for call in run_cmd.call_args_list
        )
    assert conf_dir in str(tempfile.call_args_list[0][1]["dir"])

    assert harness.model.unit.status == original_status_unit

    # The new certificate is now replacing the old one in Peer Relation secrets
    assert harness.charm.state.secrets.get_object(Scope.UNIT, cert_type) == {
        "csr": f"{cert_type}-csr",
        "key": key,
        "ca-cert": ca,
        "cert": new_cert,
        "chain": new_chain[0],
        "keystore-password": keystore_password,
        "truststore-password": "truststore_12345",
    }

    ##########################################################################
    # Tests below verify to the CA rotation cycle
    ##########################################################################


# NOTE: Syntax: parametrized has to be the outermost decorator
@pytest.mark.parametrize(
    ("deployment_type"),
    [
        (DeploymentType.MAIN_ORCHESTRATOR),
        (DeploymentType.OTHER),
        (DeploymentType.FAILOVER_ORCHESTRATOR),
    ],
)
def test_on_certificate_available_ca_rotation_first_stage_any_cluster_leader(
    deployment_type, harness, mocker, mock_fs_interactions, substrate
):
    """Test CA rotation 1st stage.

    At this point the charm already is receiving a new CA cert from the
    'self-signed-certificates' charm.
    Note: there is no preceding action on any of the involved parties to trigger that.
    The new CA cert may be received due to a CA change, CA cert expiration, etc.
    The 'self-signed-certificates' operator sends no signal/notification but simply adds
    the new CA certificate to a 'certificate-available' event.

    On this event, the Opensearch charm should:
        - save the new CA cert to truststore ALONGSIDE the old one that receives a new alias
        - set the 'tls_ca_renewing' flag in the peer databag
        - trigger a service restart
        - set the charm state to 'maintenance', indicating CA certificate rotation

    NOTE: The 'certificate-available' event also contains a new cert and chain. These are
    kind of "useless", as will need to request new ones matching the new CA cert.
    Not to modify existing workflows, they are saved to the secret but NOT to the disk.
    (The inconsistency is temporary, while the charm is in a maintenance mode anyway.)

    Applies to
        - any deployment types
        - leader ONLY
        - normal units are passive, see test later
    """
    old_csr = "old_csr"

    new_cert = "new_cert"
    new_chain = ["new_chain"]
    new_ca = "new_ca"

    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch("opensearch_single_kernel.managers.config.ConfigManager.update_opensearch_config")
    read_stored_ca = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca"
    )
    update_request_ca_bundle = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.update_request_ca_bundle"
    )
    split_ca_chain = mocker.patch("opensearch_single_kernel.utils.certificates.split_ca_chain")
    workload_class = _workload_class_name(substrate)
    run_cmd = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd"
    )
    tempfile = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.temp_file"
    )
    add_status = mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.add_status_if_not_present"
    )

    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": old_csr,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "old_ca_cert",
            "cert": "old_cert",
        },
    )

    # NOTE: The event is issued with the old csr, i.e. the identifier of
    # the ongoing transaction. A new csr will be generated and saved in the second step
    event_mock = MagicMock(
        certificate_signing_request=old_csr, chain=new_chain, certificate=new_cert, ca=new_ca
    )

    # The CA stored in the keystore is still the old one
    read_stored_ca.return_value = "old_ca"

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    harness.charm.restart_opensearch_event = MagicMock()

    harness.set_leader(is_leader=True)

    split_ca_chain.return_value = ["new_ca"]
    harness.charm.tls_events._on_certificate_available(event_mock)
    update_request_ca_bundle.assert_called_once()

    # Old CA cert is saved with corresponding alias, new CA cert added to keystore
    # extra commands are expected due to post-write permission/ownership normalization.
    assert run_cmd.call_count == (6 if substrate == "vm" else 5)
    assert any(
        re.search(r"keytool -changealias -alias ca-0 -destalias old-ca-0", call.args[0])
        for call in run_cmd.call_args_list
    )
    assert any(
        re.search(r"keytool -importcert.* *-alias ca-0", call.args[0])
        for call in run_cmd.call_args_list
    )
    assert any(
        f"chmod +r {str(harness.charm.workload.paths.certs)}/{CA_ALIAS}.p12" in call.args[0]
        for call in run_cmd.call_args_list
    )
    expected_mode = "640"
    assert any(
        f"chmod {expected_mode} {str(harness.charm.workload.paths.certs)}/{CA_ALIAS}.p12"
        in call.args[0]
        for call in run_cmd.call_args_list
    )
    if substrate == "vm":
        assert any(
            f"sudo chown snap_daemon:root {str(harness.charm.workload.paths.certs)}/{CA_ALIAS}.p12"
            in call.args[0]
            for call in run_cmd.call_args_list
        )
    else:
        assert not any(
            f"chown snap_daemon:root {str(harness.charm.workload.paths.certs)}/{CA_ALIAS}.p12"
            in call.args[0]
            for call in run_cmd.call_args_list
        )
        assert any(
            f"chown 584792:0 {str(harness.charm.workload.paths.certs)}/{CA_ALIAS}.p12"
            in call.args[0]
            for call in run_cmd.call_args_list
        )
    assert str(harness.charm.workload.paths.conf) in str(tempfile.call_args_list[0][1]["dir"])
    # NOTE: The new cert and chain are NOT saved into the keystore (disk)

    # Set flag, set status, restart
    assert harness.charm.state.server.tls_ca_renewing
    add_status.assert_has_calls(
        [
            call(
                TlsStatuses.TLS_CA_ROTATION.value,
                "unit",
                harness.charm.tls_manager.name,
            )
        ]
    )
    harness.charm.restart_opensearch_event.emit.assert_called_once()

    # The new certificate is now replacing the old one in Peer Relation secrets
    # NOTE: INCONSISTENCY: The new cert and chain ARE saved into the secret
    assert harness.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
        "csr": old_csr,
        "cert": new_cert,
        "chain": new_chain[0],
        "truststore-password": "truststore_12345",
        "keystore-password": "keystore_12345",
        "ca-cert": new_ca,
    }


@pytest.mark.parametrize(
    ("deployment_type"),
    [
        (DeploymentType.MAIN_ORCHESTRATOR),
        (DeploymentType.OTHER),
        (DeploymentType.FAILOVER_ORCHESTRATOR),
    ],
)
def test_on_certificate_available_ca_rotation_first_stage_any_cluster_non_leader(
    # NOTE: Syntax: parametrized parameter comes first
    deployment_type,
    mocker,
    harness,
    substrate,
    mock_fs_interactions,
):
    """'certificate-available' with an app cert and/or a CA cert.

    ONLY the leader takes action.
    """
    csr = "old_csr"
    cert = "new_cert"
    chain = ["new_chain"]
    ca = "new_ca"

    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": csr,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "old_ca_cert",
            "cert": "old_cert",
        },
    )

    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch("opensearch_single_kernel.managers.config.ConfigManager.update_opensearch_config")
    read_stored_ca = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca"
    )

    workload_class = _workload_class_name(substrate)
    run_cmd = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd"
    )
    mocker.patch(f"opensearch_single_kernel.workload.{substrate}.{workload_class}.temp_file")
    event_mock = MagicMock(certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca)

    read_stored_ca.return_value = "stored_ca"

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    harness.set_leader(is_leader=False)
    original_status = harness.model.unit.status
    harness.charm.restart_opensearch_event = MagicMock()

    harness.charm.tls_events._on_certificate_available(event_mock)

    # No action taken, no change on status or certificates
    assert run_cmd.call_count == 0
    assert harness.model.unit.status == original_status
    harness.charm.restart_opensearch_event.emit.assert_not_called()
    assert harness.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
        "csr": csr,
        "keystore-password": "keystore_12345",
        "truststore-password": "truststore_12345",
        "ca-cert": "old_ca_cert",
        "cert": "old_cert",
    }


# Mocks on functions we want to investigate
# NOTE: Syntax: parametrized has to be the outermost decorator
@pytest.mark.parametrize(
    ("deployment_type"),
    [
        (DeploymentType.MAIN_ORCHESTRATOR),
        (DeploymentType.OTHER),
        (DeploymentType.FAILOVER_ORCHESTRATOR),
    ],
)
@responses.activate
def test_on_certificate_available_ca_rotation_second_stage_any_cluster_leader(
    deployment_type, harness, mocker, substrate, mock_fs_interactions
):
    """Test CA rotation 2nd stage.

    At this point the charm already has the new CA cert stored locally
    (with the old CA cert also being kept around) and a service restart
    was supposed to take place.

    After the restart
        - old certificates have to be invalidated
        - unit certificates have to be renewed using the new CA cert
        - to signify the above being completed, the 'tls_ca_renewed' flag is set in the databag.

    Applies to
        - any deployment types
        - LEADER ONLY
    """
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    generate_csr = mocker.patch("opensearch_single_kernel.managers.tls.generate_csr")
    request_certificate_renewal = mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_renewal"
    )
    workload_class = _workload_class_name(substrate)
    mocker.patch(f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd")
    request_certificate_revocation = mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_revocation"
    )
    request_certificate_creation = mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    mocker.patch("opensearch_single_kernel.managers.cluster.ClusterManager.wait_for_opensearch_up")
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.wait_opensearch_part_of_cluster"
    )
    mocker.patch("opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca")
    mocker.patch(
        "opensearch_single_kernel.managers.exclusions.NodesExclusionsManager.delete_current"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.exclusions.NodesExclusionsManager.delete_current"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.create_cos_user"
    )
    mocker.patch("socket.socket.connect")
    add_status = mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.add_status_if_not_present"
    )

    generate_csr.return_value = uuid.uuid4().hex.encode()
    # Units had their certificates already
    old_csr = "old_csr"
    old_key = create_utf8_encoded_private_key()
    old_subject = "old_subject"
    keystore_password = "keystore_12345"

    new_ca = "new_ca"

    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": old_csr,
            "keystore-password": keystore_password,
            "truststore-password": "truststore_12345",
            "ca-cert": new_ca,
            "key": old_key,
            "subject": old_subject,
        },
    )
    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        CertType.UNIT_TRANSPORT.val,
        {
            "keystore-password": keystore_password,
            "csr": "csr-transport",
            "key": "key-transport",
        },
    )
    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        CertType.UNIT_HTTP.val,
        {"keystore-password": keystore_password, "csr": "csr-http", "key": "key-http"},
    )

    # Leader ONLY
    with harness.hooks_disabled():
        harness.set_leader(is_leader=True)
        harness.charm.state.application.security_index_initialised = True

        # We passed the 1st stage of the certificate renewalV
        harness.charm.state.server.tls_ca_renewing = True

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )
    # TODO: Re enable mock over upgrade
    # upgrade_mock = MagicMock(app_status=ActiveStatus())
    # upgrade_mock.get_unit_juju_status.return_value = ActiveStatus()
    # upgrade.return_value = upgrade_mock

    # OpenSearch reports its logical node identity, which now matches the formatted unit name.
    mock_response_root(harness.charm.state.unit_name, harness.charm.state.host_ip)
    mock_response_nodes(harness.charm.state.unit_name, harness.charm.state.host_ip)
    mock_response_lock_not_requested("1.1.1.1")
    mock_response_health_green("1.1.1.1")
    event = MagicMock(after_upgrade=False)

    harness.charm.opensearch_events._post_start_init(event)

    # 'tls_ca_renewed' flag is set, new unit certificates were requested
    assert harness.charm.state.server.tls_ca_renewed
    new_app_admin_secret = harness.charm.state.secrets.get_object(
        Scope.APP, CertType.APP_ADMIN.val
    )

    assert new_app_admin_secret["csr"] != old_csr
    assert new_app_admin_secret["ca-cert"] == new_ca
    assert new_app_admin_secret["key"] == old_key
    assert new_app_admin_secret["subject"] != old_subject
    # 1 for admin cert, 2 for unit certs
    assert generate_csr.call_count == 3

    # new unit certs
    assert request_certificate_revocation.call_count == 2
    request_certificate_revocation.assert_has_calls([call(b"csr-http"), call(b"csr-transport")])

    assert request_certificate_renewal.call_count == 2
    request_certificate_renewal.assert_has_calls(
        [
            call(
                old_certificate_signing_request=b"csr-http",
                new_certificate_signing_request=generate_csr(),
            ),
            call(
                old_certificate_signing_request=b"csr-transport",
                new_certificate_signing_request=generate_csr(),
            ),
        ]
    )

    # new admin cert
    assert request_certificate_creation.call_count == 1
    # we store the decoded csr in the secret but pass it as bytes to the function
    assert (
        request_certificate_creation.call_args.kwargs["certificate_signing_request"].decode()
        == new_app_admin_secret["csr"]
    )

    add_status.assert_not_called()


# Mocks on functions we want to investigate
# NOTE: Syntax: parametrized has to be the outermost decorator
@pytest.mark.parametrize(
    ("deployment_type"),
    [
        (DeploymentType.MAIN_ORCHESTRATOR),
        (DeploymentType.OTHER),
        (DeploymentType.FAILOVER_ORCHESTRATOR),
    ],
)
@responses.activate
def test_on_certificate_available_ca_rotation_second_stage_any_cluster_non_leader(
    deployment_type, harness, mocker, substrate, mock_fs_interactions
):
    """Test CA rotation 2nd stage.

    At this point the charm already has the new CA cert stored locally
    (with the old CA cert also being kept around) and a service restart
    was supposed to take place.

    After the restart, unit certificates have to be renewed,
    and the 'tls_ca_renewed' flag has to be set in the databag.

    Applies to
        - any deployment types
        - any units
    """
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    generate_csr = mocker.patch("opensearch_single_kernel.managers.tls.generate_csr")
    request_certificate_renewal = mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_renewal"
    )
    workload_class = _workload_class_name(substrate)
    mocker.patch(f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd")
    mocker.patch("opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca")
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    request_certificate_revocation = mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_revocation"
    )
    mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    mocker.patch("opensearch_single_kernel.managers.cluster.ClusterManager.wait_for_opensearch_up")
    mocker.patch(
        "opensearch_single_kernel.managers.cluster.ClusterManager.wait_opensearch_part_of_cluster"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.exclusions.NodesExclusionsManager.delete_current"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.exclusions.NodesExclusionsManager.delete_current"
    )
    mocker.patch("socket.socket.connect")
    add_status = mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.add_status_if_not_present"
    )

    generate_csr.return_value = uuid.uuid4().hex.encode()
    # Units had their certificates already
    csr = "old_csr"
    ca = "new_ca"
    keystore_password = "keystore_12345"

    csr_http_old = "csr-http-old"
    csr_transport_old = "csr-transport-old"

    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": csr,
            "truststore-password": "truststore_12345",
            "keystore-password": keystore_password,
            "ca-cert": ca,
        },
    )
    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        CertType.UNIT_TRANSPORT.val,
        {
            "keystore-password": keystore_password,
            "csr": csr_transport_old,
            "key": "key-transport",
        },
    )
    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        CertType.UNIT_HTTP.val,
        {"keystore-password": keystore_password, "csr": csr_http_old, "key": "key-http"},
    )

    # Emphasizing: NON-leader
    harness.set_leader(is_leader=False)
    with harness.hooks_disabled():
        harness.charm.state.application.security_index_initialised = True

        # We passed the 1st stage of the certificate renewalV
        harness.charm.state.server.tls_ca_renewing = True

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )
    # TODO: Re enable mock over upgrade
    # upgrade_mock = MagicMock(app_status=ActiveStatus())
    # upgrade_mock.get_unit_juju_status.return_value = ActiveStatus()
    # upgrade.return_value = upgrade_mock

    # OpenSearch reports its logical node identity, which now matches the formatted unit name.
    mock_response_root(harness.charm.state.unit_name, harness.charm.state.host_ip)
    mock_response_nodes(harness.charm.state.unit_name, harness.charm.state.host_ip)
    mock_response_lock_not_requested("1.1.1.1")
    mock_response_health_green("1.1.1.1")
    event = MagicMock(after_upgrade=False)

    harness.charm.opensearch_events._post_start_init(event)

    # 'tls_ca_renewed' flag is set, new unit certificates were requested
    assert harness.charm.state.server.tls_ca_renewed
    # Note that the old flag is left intact
    assert harness.charm.state.server.tls_ca_renewing

    assert request_certificate_revocation.call_count == 2
    request_certificate_revocation.assert_has_calls(
        [call(csr_http_old.encode()), call(csr_transport_old.encode())]
    )

    assert request_certificate_renewal.call_count == 2
    request_certificate_renewal.assert_has_calls(
        [
            call(
                old_certificate_signing_request=csr_http_old.encode(),
                new_certificate_signing_request=generate_csr(),
            ),
            call(
                old_certificate_signing_request=csr_transport_old.encode(),
                new_certificate_signing_request=generate_csr(),
            ),
        ]
    )

    assert (
        harness.charm.state.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val)["csr"]
        != csr_http_old
    )
    assert (
        harness.charm.state.secrets.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val)["csr"]
        != csr_transport_old
    )

    add_status.assert_not_called()


@pytest.mark.parametrize(
    ("deployment_type"),
    [
        (DeploymentType.MAIN_ORCHESTRATOR),
        (DeploymentType.OTHER),
        (DeploymentType.FAILOVER_ORCHESTRATOR),
    ],
)
def test_on_certificate_available_ca_rotation_third_stage_leader_cert_app(
    deployment_type, harness, mocker, substrate, mock_fs_interactions
):
    """Test CA rotation 3rd stage -- *app* certificate.

    At this point, the new CA has been already saved to the keystore.
    The charm receives the new app certificate. The leader unit has to save it.

    Applies to:

    """
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )

    read_stored_ca = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca"
    )
    workload_class = _workload_class_name(substrate)
    tempfile = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.temp_file"
    )
    run_cmd = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd"
    )
    cert = "new_cert"
    chain = ["new_chain"]
    csr = "old_csr"
    ca = "new_ca"
    key = "key"
    keystore_password = "keystore_12345"

    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": csr,
            "truststore-password": "truststore_12345",
            "keystore-password": keystore_password,
            "ca-cert": ca,
            "key": key,
        },
    )

    event_mock = MagicMock(certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca)

    # The new CA cert has been saved to the keystore earlier
    def mock_stored_ca(alias: str | None = None):
        if alias == "old-ca":
            return "old_ca_cert"
        return ca

    read_stored_ca.side_effect = mock_stored_ca

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    harness.charm.restart_opensearch_event = MagicMock()
    harness.model.unit.status = MaintenanceStatus()
    original_status = harness.model.unit.status

    with harness.hooks_disabled():
        harness.set_leader(is_leader=True)
        harness.charm.state.application.is_security_index_initialised = True

        # We passed the 1st stage of the certificate renewalV
        harness.charm.state.server.tls_ca_renewing = True
        harness.charm.state.server.tls_ca_renewed = True

    harness.charm.tls_events._on_certificate_available(event_mock)

    # NOTE: Currently store_new_tls_resources() is invoked twice for 'app-admin' cert!
    assert run_cmd.call_count == 6

    # Exporting new certs
    assert re.search(
        "openssl pkcs12 -export .* -out "
        rf"{str(harness.charm.workload.paths.certs)}/app-admin\.p12 -name app-admin",
        run_cmd.call_args_list[0].args[0],
    )
    expected_mode = "640"
    assert re.search(
        rf"(sudo )?chmod {expected_mode} {str(harness.charm.workload.paths.certs)}/app-admin\.p12",
        run_cmd.call_args_list[1].args[0],
    )
    if substrate == "vm":
        assert any(
            "sudo chown snap_daemon:root "
            f"{str(harness.charm.workload.paths.certs)}/app-admin.p12" in call.args[0]
            for call in run_cmd.call_args_list
        )
    assert str(harness.charm.workload.paths.conf) in str(tempfile.call_args_list[0][1]["dir"])
    assert harness.charm.state.server.tls_ca_renewed
    # Note that the old flag is left intact
    assert harness.charm.state.server.tls_ca_renewing

    assert harness.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
        "csr": csr,
        "cert": cert,
        "chain": chain[0],
        "truststore-password": "truststore_12345",
        "keystore-password": "keystore_12345",
        "key": key,
        "ca-cert": ca,
    }

    assert harness.model.unit.status.message == ""
    assert harness.model.unit.status == original_status


# Mocks to investigate/compare/alter
# NOTE: Syntax: parametrized has to be the outermost decorator
@pytest.mark.parametrize(
    ("deployment_type, leader, cert_type"),
    list(
        itertools.product(
            [
                (DeploymentType.MAIN_ORCHESTRATOR),
                (DeploymentType.OTHER),
                (DeploymentType.FAILOVER_ORCHESTRATOR),
            ],
            [True, False],
            [CertType.UNIT_HTTP.val, CertType.UNIT_TRANSPORT.val],
        )
    ),
)
@responses.activate
def test_on_certificate_available_ca_rotation_third_stage_any_unit_cert_unit(
    deployment_type, leader, cert_type, harness, substrate, mocker, mock_fs_interactions
):
    """Test CA rotation 3rd stage -- *unit* certificate.

    At this point, the new CA has been already saved to the keystore.
    The charm receives a new unit certificate in the 'certificate-available' event.
    The unit has to
        1. save the new certificate
        2. if it was the last one to be updated: remove CA renewal flags
        3. if it was the last one updated: remove CA from keystore

    Applies to:
        - all deployments
        - all units
    """
    cert = "new_cert"
    chain = ["new_chain"]
    ca = "new_ca"
    key = "key"
    keystore_password = "keystore_12345"

    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    exists = mocker.patch("charmlibs.pathops.LocalPath.exists")
    mocker.patch("socket.socket.connect")

    mocker.patch("opensearch_single_kernel.managers.config.ConfigManager.update_opensearch_config")
    read_stored_ca = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca"
    )
    reload_tls_certificates = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.reload_tls_certificates"
    )
    remove_ca_from_request_bundle = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager._remove_ca_from_request_bundle"
    )
    mocker.patch("opensearch_single_kernel.managers.tls.TlsManager.update_request_ca_bundle")
    workload_class = _workload_class_name(substrate)
    tempfile = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.temp_file"
    )
    run_cmd = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd"
    )
    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": "new_csr",
            "keystore-password": keystore_password,
            "truststore-password": "truststore_12345",
            "ca-cert": ca,
            "cert": "cert",
            "key": "new_key",
            "subject": "new_subject",
            "chain": chain,
        },
    )

    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        CertType.UNIT_TRANSPORT,
        {
            "csr": f"{CertType.UNIT_TRANSPORT.val}-csr-new",
            "truststore-password": "truststore_12345",
            "keystore-password": keystore_password,
            "key": key,
            "ca-cert": ca,
            "cert": "old_cert",
        },
    )

    harness.charm.state.secrets.put_object(
        Scope.UNIT,
        CertType.UNIT_HTTP,
        {
            "csr": f"{CertType.UNIT_HTTP.val}-csr-new",
            "truststore-password": "truststore_12345",
            "keystore-password": keystore_password,
            "key": key,
            "ca-cert": ca,
            "cert": "old_cert",
        },
    )

    # The event is addressing the transaction identified by the new csr
    # for the corresponding cert type defined by the test parameter
    event_mock = MagicMock(
        certificate_signing_request=f"{cert_type}-csr-new",
        chain=chain,
        certificate=cert,
        ca=ca,
    )

    # The new CA cert has been saved to the keystore earlier
    read_stored_ca.return_value = ca

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    harness.charm.restart_opensearch_event = MagicMock()
    harness.model.unit.status = MaintenanceStatus()

    with harness.hooks_disabled():
        harness.set_leader(True)
        harness.charm.state.application.is_security_index_initialised = True
        harness.charm.state.application.is_admin_user_initialized = True
        harness.set_leader(leader)

        # We passed the 1st stage of the certificate renewalV
        harness.charm.state.server.tls_ca_renewing = True
        harness.charm.state.server.tls_ca_renewed = True

    reload_tls_certificates.side_effect = None
    mock_response_put_transport_cert("1.1.1.1")
    mock_response_put_http_cert("1.1.1.1")
    original_status = harness.model.unit.status

    exists.return_value = True

    harness.charm.tls_events._on_certificate_available(event_mock)

    remove_ca_from_request_bundle.assert_called_once()

    # Saving new cert, cleaning up CA renewal flag, removing old CA from keystore
    # Note: the high number of operations come from the fact that on each certificate received
    # the 'issuer' is checked on each certificate that is saved on the disk.
    if harness.charm.unit.is_leader():
        assert run_cmd.call_count == (18 if substrate == "vm" else 10)
    else:
        assert run_cmd.call_count == (21 if substrate == "vm" else 13)

    certs_dir = str(harness.charm.workload.paths.certs)
    conf_dir = str(harness.charm.workload.paths.conf)
    assert re.search(
        "openssl pkcs12 -export .* -out " rf"{certs_dir}/{cert_type}\.p12 -name {cert_type}",
        run_cmd.call_args_list[0].args[0],
    )
    expected_mode = "640"
    assert (
        f"chmod {expected_mode} {certs_dir}/{cert_type}.p12" in run_cmd.call_args_list[1].args[0]
    )
    if substrate == "vm":
        assert any(
            f"sudo chown snap_daemon:root {certs_dir}/{cert_type}.p12" in call.args[0]
            for call in run_cmd.call_args_list
        )

    assert any(
        (
            "-delete" in call.args[0]
            and "-keystore" in call.args[0]
            and "-alias old-ca-0" in call.args[0]
        )
        for call in run_cmd.call_args_list
    )
    assert not any("-alias old-ca " in call.args[0] for call in run_cmd.call_args_list)
    assert conf_dir in str(tempfile.call_args_list[0][1]["dir"])

    assert not harness.charm.state.server.tls_ca_renewing
    assert not harness.charm.state.server.tls_ca_renewed

    assert harness.model.unit.status.message == ""
    assert harness.model.unit.status == original_status


# Additional potential phases of the workflow


# Mock to investigate/compare/alter
@pytest.mark.parametrize(
    ("deployment_type", "leader"),
    list(
        itertools.product(
            [
                (DeploymentType.MAIN_ORCHESTRATOR),
                (DeploymentType.OTHER),
                (DeploymentType.FAILOVER_ORCHESTRATOR),
            ],
            [True, False],
        )
    ),
)
def test_on_certificate_available_rotation_ongoing_on_this_unit(
    deployment_type, leader, harness, substrate, mocker, mock_fs_interactions
):
    """Additional 'certificate-available' event while processing CA rotation.

    This run represents a 'certificate-available' right before the leader
    sets the TLS renewal flags in the peer relation.

    In this case, the leader must execute the update logic for itself.

    Remaining units will just wait until the first flags are set, hence
    will not have `run_cmd` calls.

    Applies to:
        - any deployment
        - any unit
    """
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.state.OpenSearchApplication.deployment_desc",
        new_callable=PropertyMock,
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.purge_initial_default_users"
    )
    mocker.patch(
        "opensearch_single_kernel.managers.internal_users.InternalUsersManager.put_or_update_internal_user_leader"
    )
    split_ca_chain = mocker.patch("opensearch_single_kernel.utils.certificates.split_ca_chain")

    mocker.patch("opensearch_single_kernel.managers.config.ConfigManager.update_opensearch_config")
    read_stored_ca = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.read_stored_ca"
    )
    mocker.patch("opensearch_single_kernel.managers.tls.TlsManager.update_request_ca_bundle")
    workload_class = _workload_class_name(substrate)
    mocker.patch(f"opensearch_single_kernel.workload.{substrate}.{workload_class}.temp_file")
    run_cmd = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{workload_class}.run_cmd"
    )
    add_status = mocker.patch(
        "opensearch_single_kernel.core.state.ClusterState.add_status_if_not_present"
    )
    csr = "old_csr"
    cert = "new_cert"
    chain = ["new_chain"]
    ca = "new_ca"

    harness.charm.state.secrets.put_object(
        Scope.APP,
        CertType.APP_ADMIN.val,
        {
            "csr": csr,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "old_ca_cert",
            "cert": "old_cert",
        },
    )

    read_stored_ca.return_value = "stored_ca"

    # Applies to ANY deployment type
    deployment_desc.return_value = DeploymentDescription(
        config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[], profile="production"),
        start=StartMode.WITH_GENERATED_ROLES,
        pending_directives=[],
        typ=deployment_type,
        app=App(model_uuid=harness.charm.model.uuid, name=harness.charm.app.name),
        state=DeploymentState(value=State.ACTIVE),
    )

    harness.charm.on.certificate_available = MagicMock(
        certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
    )

    harness.set_leader(is_leader=leader)

    # This unit is within the process of certificate renewal
    with harness.hooks_disabled():
        harness.charm.state.server.tls_ca_renewing = True

    split_ca_chain.return_value = ["new_ca"]
    harness.charm.tls_events._on_certificate_available(harness.charm.on.certificate_available)

    if leader:
        assert run_cmd.call_count == 3
        add_status.assert_has_calls(
            [
                call(
                    TlsStatuses.TLS_CA_ROTATION.value,
                    "unit",
                    harness.charm.tls_manager.name,
                )
            ]
        )
        assert harness.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": csr,
            "chain": "new_chain",
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "new_ca",
            "cert": "new_cert",
        }
    else:
        # We have scope == Scope.APP, so we will skip the entire logic
        assert run_cmd.call_count == 0
        add_status.assert_not_called()
        assert harness.charm.state.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": csr,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "old_ca_cert",
            "cert": "old_cert",
        }


# Mock to investigate/compare/alter

# TODO: Add final test of on_certificate_available and rotation ongoing on other unit
# After we implement scale up scale down.
