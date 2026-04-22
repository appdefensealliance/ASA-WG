"""Tests for Azure Networking checks."""

from unittest.mock import MagicMock

from ada_cloud_audit.checks.azure.networking import (
    check_rdp_restricted,
    check_ssh_restricted,
    check_udp_restricted,
    check_https_restricted,
    check_subnets_have_nsgs,
    check_app_gateway_tls,
    check_app_gateway_http2,
)
from ada_cloud_audit.models import Verdict


def test_rdp_restricted_pass_no_nsgs(azure_session, mock_azure_modules):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client
    mock_client.network_security_groups.list_all.return_value = []

    result = check_rdp_restricted(azure_session)
    assert result.spec_id == "4.3.1"
    assert result.verdict == Verdict.PASS


def test_rdp_restricted_pass_no_internet_rule(azure_session, mock_azure_modules, mock_nsg):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    nsg = mock_nsg(rules=[{
        "name": "allow-internal-rdp",
        "direction": "Inbound",
        "access": "Allow",
        "source": "10.0.0.0/8",
        "dest_port": "3389",
    }])
    mock_client.network_security_groups.list_all.return_value = [nsg]

    result = check_rdp_restricted(azure_session)
    assert result.verdict == Verdict.PASS


def test_rdp_restricted_fail(azure_session, mock_azure_modules, mock_nsg):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    nsg = mock_nsg(rules=[{
        "name": "allow-rdp-internet",
        "direction": "Inbound",
        "access": "Allow",
        "source": "*",
        "dest_port": "3389",
    }])
    mock_client.network_security_groups.list_all.return_value = [nsg]

    result = check_rdp_restricted(azure_session)
    assert result.verdict == Verdict.FAIL


def test_ssh_restricted_fail(azure_session, mock_azure_modules, mock_nsg):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    nsg = mock_nsg(rules=[{
        "name": "allow-ssh-all",
        "direction": "Inbound",
        "access": "Allow",
        "source": "Internet",
        "dest_port": "22",
    }])
    mock_client.network_security_groups.list_all.return_value = [nsg]

    result = check_ssh_restricted(azure_session)
    assert result.spec_id == "4.3.2"
    assert result.verdict == Verdict.FAIL


def test_ssh_restricted_pass_deny_rule(azure_session, mock_azure_modules, mock_nsg):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    nsg = mock_nsg(rules=[{
        "name": "deny-ssh",
        "direction": "Inbound",
        "access": "Deny",
        "source": "*",
        "dest_port": "22",
    }])
    mock_client.network_security_groups.list_all.return_value = [nsg]

    result = check_ssh_restricted(azure_session)
    assert result.verdict == Verdict.PASS


def test_subnets_have_nsgs_pass(azure_session, mock_azure_modules):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    subnet = MagicMock()
    subnet.name = "default"
    subnet.network_security_group = MagicMock()  # Has NSG

    vnet = MagicMock()
    vnet.name = "test-vnet"
    vnet.subnets = [subnet]

    mock_client.virtual_networks.list_all.return_value = [vnet]

    result = check_subnets_have_nsgs(azure_session)
    assert result.spec_id == "4.3.11"
    assert result.verdict == Verdict.PASS


def test_subnets_have_nsgs_fail(azure_session, mock_azure_modules):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    subnet = MagicMock()
    subnet.name = "default"
    subnet.network_security_group = None  # No NSG

    vnet = MagicMock()
    vnet.name = "test-vnet"
    vnet.subnets = [subnet]

    mock_client.virtual_networks.list_all.return_value = [vnet]

    result = check_subnets_have_nsgs(azure_session)
    assert result.verdict == Verdict.FAIL


def test_subnets_skip_gateway(azure_session, mock_azure_modules):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    subnet = MagicMock()
    subnet.name = "GatewaySubnet"
    subnet.network_security_group = None

    vnet = MagicMock()
    vnet.name = "test-vnet"
    vnet.subnets = [subnet]

    mock_client.virtual_networks.list_all.return_value = [vnet]

    result = check_subnets_have_nsgs(azure_session)
    assert result.verdict == Verdict.PASS  # GatewaySubnet skipped


def test_app_gateway_tls_pass(azure_session, mock_azure_modules):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    gw = MagicMock()
    gw.name = "test-agw"
    gw.ssl_policy = MagicMock()
    gw.ssl_policy.min_protocol_version = "TLSv1_2"
    mock_client.application_gateways.list_all.return_value = [gw]

    result = check_app_gateway_tls(azure_session)
    assert result.spec_id == "4.3.12"
    assert result.verdict == Verdict.PASS


def test_app_gateway_http2_fail(azure_session, mock_azure_modules):
    mock_network = mock_azure_modules["azure.mgmt.network"]
    mock_client = MagicMock()
    mock_network.NetworkManagementClient.return_value = mock_client

    gw = MagicMock()
    gw.name = "test-agw"
    gw.enable_http2 = False
    mock_client.application_gateways.list_all.return_value = [gw]

    result = check_app_gateway_http2(azure_session)
    assert result.spec_id == "4.3.13"
    assert result.verdict == Verdict.FAIL
