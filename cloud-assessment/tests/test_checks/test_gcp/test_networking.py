"""Tests for GCP Networking checks."""

from unittest.mock import patch, MagicMock

import pytest

from ada_cloud_audit.checks.gcp.networking import (
    check_ssl_policies,
    check_legacy_networks,
    check_dnssec,
    check_dnssec_key_signing,
    check_dnssec_zone_signing,
    check_ssh_firewall,
    check_rdp_firewall,
)
from ada_cloud_audit.models import Verdict


def test_check_ssl_policies_pass_no_proxies(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]

    mock_ssl_client = MagicMock()
    mock_https_client = MagicMock()
    mock_ssl_proxy_client = MagicMock()

    mock_compute.SslPoliciesClient.return_value = mock_ssl_client
    mock_compute.TargetHttpsProxiesClient.return_value = mock_https_client
    mock_compute.TargetSslProxiesClient.return_value = mock_ssl_proxy_client

    mock_ssl_client.list.return_value = []
    mock_https_client.list.return_value = []
    mock_ssl_proxy_client.list.return_value = []

    result = check_ssl_policies(gcp_session)
    assert result.spec_id == "4.1.1"
    assert result.verdict == Verdict.PASS


def test_check_legacy_networks_pass_no_networks(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]
    mock_client = MagicMock()
    mock_compute.NetworksClient.return_value = mock_client
    mock_client.list.return_value = []

    result = check_legacy_networks(gcp_session)
    assert result.spec_id == "4.2.1"
    assert result.verdict == Verdict.PASS


def test_check_legacy_networks_pass_vpc(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]
    mock_client = MagicMock()
    mock_compute.NetworksClient.return_value = mock_client

    mock_network = MagicMock()
    mock_network.name = "default"
    mock_network.subnetworks = ["subnet-1"]
    mock_network.auto_create_subnetworks = True
    mock_network.I_pv4_range = None
    mock_client.list.return_value = [mock_network]

    result = check_legacy_networks(gcp_session)
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.networking._check_dns_zones")
def test_check_dnssec_pass_no_zones(mock_zones, gcp_session):
    mock_zones.return_value = []
    result = check_dnssec(gcp_session)
    assert result.spec_id == "4.2.2"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.networking._check_dns_zones")
def test_check_dnssec_pass(mock_zones, gcp_session):
    mock_zone = MagicMock()
    mock_zone.name = "example-zone"
    mock_zone.dnssec_config = {"state": "on"}
    mock_zones.return_value = [mock_zone]

    result = check_dnssec(gcp_session)
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.networking._check_dns_zones")
def test_check_dnssec_fail(mock_zones, gcp_session):
    mock_zone = MagicMock()
    mock_zone.name = "example-zone"
    mock_zone.dnssec_config = {"state": "off"}
    mock_zones.return_value = [mock_zone]

    result = check_dnssec(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.networking._check_dns_zones")
def test_check_dnssec_key_signing_pass(mock_zones, gcp_session):
    mock_zone = MagicMock()
    mock_zone.name = "example-zone"
    mock_zone.dnssec_config = {
        "state": "on",
        "defaultKeySpecs": [
            {"keyType": "keySigning", "algorithm": "ECDSAP256SHA256"}
        ],
    }
    mock_zones.return_value = [mock_zone]

    result = check_dnssec_key_signing(gcp_session)
    assert result.spec_id == "4.2.3"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.networking._check_dns_zones")
def test_check_dnssec_key_signing_fail(mock_zones, gcp_session):
    mock_zone = MagicMock()
    mock_zone.name = "example-zone"
    mock_zone.dnssec_config = {
        "state": "on",
        "defaultKeySpecs": [
            {"keyType": "keySigning", "algorithm": "RSASHA1"}
        ],
    }
    mock_zones.return_value = [mock_zone]

    result = check_dnssec_key_signing(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.networking._check_dns_zones")
def test_check_dnssec_zone_signing_pass(mock_zones, gcp_session):
    mock_zone = MagicMock()
    mock_zone.name = "example-zone"
    mock_zone.dnssec_config = {
        "state": "on",
        "defaultKeySpecs": [
            {"keyType": "zoneSigning", "algorithm": "ECDSAP256SHA256"}
        ],
    }
    mock_zones.return_value = [mock_zone]

    result = check_dnssec_zone_signing(gcp_session)
    assert result.spec_id == "4.2.4"
    assert result.verdict == Verdict.PASS


def test_check_ssh_firewall_pass(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]
    mock_client = MagicMock()
    mock_compute.FirewallsClient.return_value = mock_client

    mock_fw = MagicMock()
    mock_fw.name = "allow-internal-ssh"
    mock_fw.direction = "INGRESS"
    mock_allowed = MagicMock()
    mock_allowed.I_p_protocol = "tcp"
    mock_allowed.ports = ["22"]
    mock_fw.allowed = [mock_allowed]
    mock_fw.source_ranges = ["10.0.0.0/8"]
    mock_client.list.return_value = [mock_fw]

    result = check_ssh_firewall(gcp_session)
    assert result.spec_id == "4.3.3"
    assert result.verdict == Verdict.PASS


def test_check_ssh_firewall_fail(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]
    mock_client = MagicMock()
    mock_compute.FirewallsClient.return_value = mock_client

    mock_fw = MagicMock()
    mock_fw.name = "allow-all-ssh"
    mock_fw.direction = "INGRESS"
    mock_allowed = MagicMock()
    mock_allowed.I_p_protocol = "tcp"
    mock_allowed.ports = ["22"]
    mock_fw.allowed = [mock_allowed]
    mock_fw.source_ranges = ["0.0.0.0/0"]
    mock_client.list.return_value = [mock_fw]

    result = check_ssh_firewall(gcp_session)
    assert result.verdict == Verdict.FAIL


def test_check_rdp_firewall_pass(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]
    mock_client = MagicMock()
    mock_compute.FirewallsClient.return_value = mock_client
    mock_client.list.return_value = []

    result = check_rdp_firewall(gcp_session)
    assert result.spec_id == "4.3.4"
    assert result.verdict == Verdict.PASS


def test_check_rdp_firewall_fail(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]
    mock_client = MagicMock()
    mock_compute.FirewallsClient.return_value = mock_client

    mock_fw = MagicMock()
    mock_fw.name = "allow-rdp"
    mock_fw.direction = "INGRESS"
    mock_allowed = MagicMock()
    mock_allowed.I_p_protocol = "tcp"
    mock_allowed.ports = ["3389"]
    mock_fw.allowed = [mock_allowed]
    mock_fw.source_ranges = ["0.0.0.0/0"]
    mock_client.list.return_value = [mock_fw]

    result = check_rdp_firewall(gcp_session)
    assert result.verdict == Verdict.FAIL
