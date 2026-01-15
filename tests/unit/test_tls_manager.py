# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for opensearch tls manager."""
from unittest import mock
from unittest.mock import MagicMock, PropertyMock

from opensearch_single_kernel.common.constants import (
    CertType,
    DeploymentType,
    Scope,
    StartMode,
    State,
)
from opensearch_single_kernel.core.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    PeerClusterConfig,
)
from tests.unit.helpers import create_utf8_encoded_private_key, deployment_descriptions


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

    get_host_public_ip = mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{substrate.upper()}Workload.get_host_public_ip"
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
    get_host_public_ip.return_value = "XX.XXX.XX.XXX"

    base_ips = ["1.1.1.1", "address1", "address2"]
    base_dns_entries = [harness.charm.state.unit_name, "nebula", "alias"]
    unit_http_sans = harness.charm.tls_manager._get_sans(CertType.UNIT_HTTP)
    assert dict((key, sorted(val)) for key, val in unit_http_sans.items()) == {
        "sans_oid": ["1.2.3.4.5.5"],
        "sans_ip": sorted(base_ips + ["XX.XXX.XX.XXX"]),
        "sans_dns": sorted(base_dns_entries),
    }

    unit_transport_sans = harness.charm.tls_manager._get_sans(CertType.UNIT_TRANSPORT)
    assert dict((key, sorted(val)) for key, val in unit_transport_sans.items()) == {
        "sans_oid": ["1.2.3.4.5.5"],
        "sans_ip": sorted(base_ips),
        "sans_dns": sorted(base_dns_entries),
    }


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
        "opensearch_single_kernel.managers.users.UsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch("opensearch_single_kernel.managers.users.UsersManager.purge_initial_users")
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
        "opensearch_single_kernel.managers.users.UsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch("opensearch_single_kernel.managers.users.UsersManager.purge_initial_users")
    create_certificate_signing_request = mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.create_certificate_signing_request"
    )
    mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    event_mock = MagicMock()

    harness.set_leader(is_leader=True)
    harness.charm.tls_events._on_tls_relation_created(event_mock)

    create_certificate_signing_request.mock_calls == [
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
        "opensearch_single_kernel.managers.users.UsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch("opensearch_single_kernel.managers.users.UsersManager.purge_initial_users")
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
    create_certificate_signing_request == [
        mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT),
        mock.call(Scope.UNIT, CertType.UNIT_HTTP),
    ]


def test_on_set_tls_private_key(harness, mocker, substrate):
    """Test _on_set_tls private key event."""
    event_mock = MagicMock(params={"category": "app-admin"})
    mocker.patch(
        "opensearch_single_kernel.managers.users.UsersManager.put_or_update_internal_user_leader"
    )
    mocker.patch("opensearch_single_kernel.managers.users.UsersManager.purge_initial_users")
    mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{substrate.upper()}Workload.get_host_public_ip"
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
    mocker.patch(
        "opensearch_single_kernel.managers.tls.TlsManager.create_certificate_signing_request"
    )
    mocker.patch("opensearch_single_kernel.managers.tls.TlsManager.create_store_pwd_if_not_exists")
    mocker.patch(
        "opensearch_single_kernel.lib.charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    mocker.patch("opensearch_single_kernel.events.tls.TLSEventsHandler.store_new_ca")
    mocker.patch(
        "opensearch_single_kernel.managers.users.UsersManager.put_or_update_internal_user_leader"
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
        Scope.UNIT,
        secret_key,
        {"csr": csr, "keystore-password": keystore_password},
    )

    event_mock = MagicMock(certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca)
    harness.charm.tls_events._on_certificate_available(event_mock)

    harness.charm.state.secrets.get_object(Scope.UNIT, secret_key) == {
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
    mocker.patch(
        f"opensearch_single_kernel.workload.{substrate}.{substrate.upper()}Workload.get_host_public_ip"
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
