"""Tests for Azure Storage checks."""

from unittest.mock import MagicMock

from ada_cloud_audit.checks.azure.storage import (
    check_blob_soft_delete,
    check_file_share_soft_delete,
    check_container_soft_delete,
    check_default_network_deny,
    check_public_network_access_disabled,
    check_secure_transfer,
    check_min_tls_version,
    check_blob_public_access_disabled,
    check_key_rotation_reminders,
    check_access_keys_regenerated,
    check_storage_key_access_disabled,
    check_sas_expiry,
)
from ada_cloud_audit.models import Verdict


def test_secure_transfer_pass(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(https_only=True)]

    result = check_secure_transfer(azure_session)
    assert result.spec_id == "5.3.1"
    assert result.verdict == Verdict.PASS


def test_secure_transfer_fail(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(https_only=False)]

    result = check_secure_transfer(azure_session)
    assert result.spec_id == "5.3.1"
    assert result.verdict == Verdict.FAIL


def test_secure_transfer_no_accounts(azure_session, mock_azure_modules):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = []

    result = check_secure_transfer(azure_session)
    assert result.verdict == Verdict.PASS


def test_min_tls_pass(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(min_tls="TLS1_2")]

    result = check_min_tls_version(azure_session)
    assert result.spec_id == "5.3.2"
    assert result.verdict == Verdict.PASS


def test_min_tls_fail(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(min_tls="TLS1_0")]

    result = check_min_tls_version(azure_session)
    assert result.verdict == Verdict.FAIL


def test_default_network_deny_pass(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(default_action="Deny")]

    result = check_default_network_deny(azure_session)
    assert result.spec_id == "5.2.1"
    assert result.verdict == Verdict.PASS


def test_default_network_deny_fail(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(default_action="Allow")]

    result = check_default_network_deny(azure_session)
    assert result.verdict == Verdict.FAIL


def test_blob_public_access_pass(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(allow_blob_public=False)]

    result = check_blob_public_access_disabled(azure_session)
    assert result.spec_id == "5.5.2"
    assert result.verdict == Verdict.PASS


def test_blob_public_access_fail(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(allow_blob_public=True)]

    result = check_blob_public_access_disabled(azure_session)
    assert result.verdict == Verdict.FAIL


def test_storage_key_access_pass(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(allow_shared_key=False)]

    result = check_storage_key_access_disabled(azure_session)
    assert result.spec_id == "5.7.2"
    assert result.verdict == Verdict.PASS


def test_storage_key_access_fail(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(allow_shared_key=True)]

    result = check_storage_key_access_disabled(azure_session)
    assert result.verdict == Verdict.FAIL


def test_public_network_access_pass(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(public_network_access="Disabled")]

    result = check_public_network_access_disabled(azure_session)
    assert result.spec_id == "5.2.2"
    assert result.verdict == Verdict.PASS


def test_public_network_access_fail(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account(public_network_access="Enabled")]

    result = check_public_network_access_disabled(azure_session)
    assert result.verdict == Verdict.FAIL


def test_sas_expiry_inconclusive(azure_session, mock_azure_modules):
    result = check_sas_expiry(azure_session)
    assert result.spec_id == "5.8.1"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_access_keys_regenerated_inconclusive(azure_session, mock_azure_modules):
    result = check_access_keys_regenerated(azure_session)
    assert result.spec_id == "5.7.1"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_blob_soft_delete_pass(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account()]

    delete_policy = MagicMock()
    delete_policy.enabled = True
    props = MagicMock()
    props.delete_retention_policy = delete_policy
    mock_client.blob_services.get_service_properties.return_value = props

    result = check_blob_soft_delete(azure_session)
    assert result.spec_id == "5.1.1"
    assert result.verdict == Verdict.PASS


def test_blob_soft_delete_fail(azure_session, mock_azure_modules, mock_storage_account):
    mock_storage = mock_azure_modules["azure.mgmt.storage"]
    mock_client = MagicMock()
    mock_storage.StorageManagementClient.return_value = mock_client
    mock_client.storage_accounts.list.return_value = [mock_storage_account()]

    delete_policy = MagicMock()
    delete_policy.enabled = False
    props = MagicMock()
    props.delete_retention_policy = delete_policy
    mock_client.blob_services.get_service_properties.return_value = props

    result = check_blob_soft_delete(azure_session)
    assert result.verdict == Verdict.FAIL
