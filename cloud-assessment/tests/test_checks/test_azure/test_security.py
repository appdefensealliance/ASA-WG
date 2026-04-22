"""Tests for Azure Security checks (Key Vault + Defender)."""

from unittest.mock import MagicMock

from ada_cloud_audit.checks.azure.security import (
    check_key_vault_recoverable,
    check_key_vault_public_access,
    check_notify_severity_high,
    check_owner_role_notifications,
    check_additional_email,
    check_cert_validity,
    check_notify_attack_paths,
    check_security_benchmark_policies,
)
from ada_cloud_audit.models import Verdict


def _mock_vault(name="test-vault", soft_delete=True, purge_protection=True,
                default_action="Deny"):
    vault = MagicMock()
    vault.name = name
    vault.properties.enable_soft_delete = soft_delete
    vault.properties.enable_purge_protection = purge_protection
    vault.properties.vault_uri = f"https://{name}.vault.azure.net/"
    net_acls = MagicMock()
    net_acls.default_action = default_action
    vault.properties.network_acls = net_acls
    return vault


def test_key_vault_recoverable_pass(azure_session, mock_azure_modules):
    mock_kv = mock_azure_modules["azure.mgmt.keyvault"]
    mock_client = MagicMock()
    mock_kv.KeyVaultManagementClient.return_value = mock_client
    mock_client.vaults.list.return_value = [_mock_vault()]

    result = check_key_vault_recoverable(azure_session)
    assert result.spec_id == "2.1.1"
    assert result.verdict == Verdict.PASS


def test_key_vault_recoverable_fail_no_purge(azure_session, mock_azure_modules):
    mock_kv = mock_azure_modules["azure.mgmt.keyvault"]
    mock_client = MagicMock()
    mock_kv.KeyVaultManagementClient.return_value = mock_client
    mock_client.vaults.list.return_value = [_mock_vault(purge_protection=False)]

    result = check_key_vault_recoverable(azure_session)
    assert result.verdict == Verdict.FAIL
    assert "purge protection" in result.evidence


def test_key_vault_recoverable_no_vaults(azure_session, mock_azure_modules):
    mock_kv = mock_azure_modules["azure.mgmt.keyvault"]
    mock_client = MagicMock()
    mock_kv.KeyVaultManagementClient.return_value = mock_client
    mock_client.vaults.list.return_value = []

    result = check_key_vault_recoverable(azure_session)
    assert result.verdict == Verdict.PASS


def test_key_vault_public_access_pass(azure_session, mock_azure_modules):
    mock_kv = mock_azure_modules["azure.mgmt.keyvault"]
    mock_client = MagicMock()
    mock_kv.KeyVaultManagementClient.return_value = mock_client
    mock_client.vaults.list.return_value = [_mock_vault(default_action="Deny")]

    result = check_key_vault_public_access(azure_session)
    assert result.spec_id == "2.1.2"
    assert result.verdict == Verdict.PASS


def test_key_vault_public_access_fail(azure_session, mock_azure_modules):
    mock_kv = mock_azure_modules["azure.mgmt.keyvault"]
    mock_client = MagicMock()
    mock_kv.KeyVaultManagementClient.return_value = mock_client
    mock_client.vaults.list.return_value = [_mock_vault(default_action="Allow")]

    result = check_key_vault_public_access(azure_session)
    assert result.verdict == Verdict.FAIL


def test_cert_validity_inconclusive(azure_session, mock_azure_modules):
    result = check_cert_validity(azure_session)
    assert result.spec_id == "2.5.5"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_notify_attack_paths_inconclusive(azure_session, mock_azure_modules):
    result = check_notify_attack_paths(azure_session)
    assert result.spec_id == "3.2.2"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_security_benchmark_policies_inconclusive(azure_session, mock_azure_modules):
    result = check_security_benchmark_policies(azure_session)
    assert result.spec_id == "3.6.1"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_additional_email_pass(azure_session, mock_azure_modules):
    mock_sec = mock_azure_modules["azure.mgmt.security"]
    mock_client = MagicMock()
    mock_sec.SecurityCenter.return_value = mock_client

    contact = MagicMock()
    contact.emails = "security@example.com"
    mock_client.security_contacts.list.return_value = [contact]

    result = check_additional_email(azure_session)
    assert result.spec_id == "3.3.2"
    assert result.verdict == Verdict.PASS


def test_additional_email_fail(azure_session, mock_azure_modules):
    mock_sec = mock_azure_modules["azure.mgmt.security"]
    mock_client = MagicMock()
    mock_sec.SecurityCenter.return_value = mock_client

    contact = MagicMock()
    contact.emails = ""
    mock_client.security_contacts.list.return_value = [contact]

    result = check_additional_email(azure_session)
    assert result.verdict == Verdict.FAIL
