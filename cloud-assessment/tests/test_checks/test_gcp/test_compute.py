"""Tests for GCP Compute checks."""

from unittest.mock import patch, MagicMock

import pytest

from ada_cloud_audit.checks.gcp.compute import (
    check_cloud_functions_runtimes,
    check_block_project_ssh_keys,
    check_ip_forwarding,
    check_default_service_account,
    check_default_sa_full_access,
    check_serial_port,
    check_oslogin,
)
from ada_cloud_audit.models import Verdict


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_block_project_ssh_keys_pass_no_instances(mock_list, gcp_session):
    mock_list.return_value = []
    result = check_block_project_ssh_keys(gcp_session)
    assert result.spec_id == "1.3.4"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_block_project_ssh_keys_pass(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", metadata_items={"block-project-ssh-keys": "true"}),
    ]
    result = check_block_project_ssh_keys(gcp_session)
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_block_project_ssh_keys_fail(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", metadata_items={}),
    ]
    result = check_block_project_ssh_keys(gcp_session)
    assert result.verdict == Verdict.FAIL
    assert "vm-1" in result.evidence


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_ip_forwarding_pass(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", can_ip_forward=False),
    ]
    result = check_ip_forwarding(gcp_session)
    assert result.spec_id == "1.5.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_ip_forwarding_fail(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", can_ip_forward=True),
    ]
    result = check_ip_forwarding(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_default_service_account_pass(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", service_accounts=[
            {"email": "custom-sa@test-project-123.iam.gserviceaccount.com", "scopes": []}
        ]),
    ]
    result = check_default_service_account(gcp_session)
    assert result.spec_id == "1.6.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_default_service_account_fail(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", service_accounts=[
            {"email": "123456789-compute@developer.gserviceaccount.com", "scopes": []}
        ]),
    ]
    result = check_default_service_account(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_default_sa_full_access_pass(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", service_accounts=[
            {"email": "123456789-compute@developer.gserviceaccount.com",
             "scopes": ["https://www.googleapis.com/auth/devstorage.read_only"]}
        ]),
    ]
    result = check_default_sa_full_access(gcp_session)
    assert result.spec_id == "1.6.2"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_default_sa_full_access_fail(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", service_accounts=[
            {"email": "123456789-compute@developer.gserviceaccount.com",
             "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}
        ]),
    ]
    result = check_default_sa_full_access(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_serial_port_pass(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", metadata_items={}),
    ]
    result = check_serial_port(gcp_session)
    assert result.spec_id == "1.7.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.compute.list_all_instances")
def test_check_serial_port_fail(mock_list, gcp_session, mock_vm_instance):
    mock_list.return_value = [
        mock_vm_instance("vm-1", metadata_items={"serial-port-enable": "true"}),
    ]
    result = check_serial_port(gcp_session)
    assert result.verdict == Verdict.FAIL


def test_check_oslogin_pass(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]
    mock_client = MagicMock()
    mock_compute.ProjectsClient.return_value = mock_client

    mock_project = MagicMock()
    oslogin_item = MagicMock()
    oslogin_item.key = "enable-oslogin"
    oslogin_item.value = "TRUE"
    mock_project.common_instance_metadata.items = [oslogin_item]
    mock_client.get.return_value = mock_project

    result = check_oslogin(gcp_session)
    assert result.spec_id == "1.8.2"
    assert result.verdict == Verdict.PASS


def test_check_oslogin_fail(gcp_session, mock_google_modules):
    mock_compute = mock_google_modules["google.cloud.compute_v1"]
    mock_client = MagicMock()
    mock_compute.ProjectsClient.return_value = mock_client

    mock_project = MagicMock()
    mock_project.common_instance_metadata.items = []
    mock_client.get.return_value = mock_project

    result = check_oslogin(gcp_session)
    assert result.verdict == Verdict.FAIL


def test_check_cloud_functions_runtimes_pass_no_functions(gcp_session, mock_google_modules):
    mock_functions = mock_google_modules["google.cloud.functions_v2"]
    mock_client = MagicMock()
    mock_functions.FunctionServiceClient.return_value = mock_client
    mock_client.list_functions.return_value = []

    result = check_cloud_functions_runtimes(gcp_session)
    assert result.spec_id == "1.2.6"
    assert result.verdict == Verdict.PASS


def test_check_cloud_functions_runtimes_fail(gcp_session, mock_google_modules):
    mock_functions = mock_google_modules["google.cloud.functions_v2"]
    mock_client = MagicMock()
    mock_functions.FunctionServiceClient.return_value = mock_client

    mock_func = MagicMock()
    mock_func.name = "projects/test/locations/us-central1/functions/old-func"
    mock_func.build_config.runtime = "python37"
    mock_client.list_functions.return_value = [mock_func]

    result = check_cloud_functions_runtimes(gcp_session)
    assert result.verdict == Verdict.FAIL
    assert "python37" in result.evidence
