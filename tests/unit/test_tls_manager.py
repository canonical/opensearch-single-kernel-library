# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for opensearch tls manager."""
from unittest.mock import PropertyMock

from opensearch_single_kernel.common.constants import CertType
from tests.unit.helpers import deployment_descriptions


def single_space(input: str) -> str:
    """Replace multiple spaces with one."""
    return " ".join(input.split())


def test_get_sans(harness, mocker, substrate):
    """Test the SANs returned depending on the cert type."""
    deployment_desc = mocker.patch(
        "opensearch_single_kernel.core.models.OpenSearchApplication.deployment_desc",
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

    print(f"Unit name in test {harness.charm.unit_name}")
    gethostbyaddr.return_value = (
        harness.charm.state.server.unit_name,
        ["alias"],
        ["address1", "address2"],
    )
    gethostname.return_value = "nebula"
    getfqdn.return_value = "nebula"
    get_host_public_ip.return_value = "XX.XXX.XX.XXX"

    base_ips = ["1.1.1.1", "address1", "address2"]
    base_dns_entries = [harness.charm.state.server.unit_name, "nebula", "alias"]
    print(f"The test is expecting this {base_dns_entries}")
    unit_http_sans = harness.charm.tls_manager._get_sans(CertType.UNIT_HTTP)
    print(f"And is having this {unit_http_sans}")
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
