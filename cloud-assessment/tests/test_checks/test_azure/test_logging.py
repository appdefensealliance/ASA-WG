"""Tests for Azure Logging checks."""

from unittest.mock import MagicMock

from ada_cloud_audit.checks.azure.logging import (
    check_audit_log_retention,
    check_resource_logging,
    check_key_vault_logging,
    check_alert_create_policy,
    check_alert_delete_policy,
    check_alert_create_nsg,
    check_diagnostic_setting_exists,
    check_diagnostic_categories,
    check_alert_service_health,
)
from ada_cloud_audit.models import Verdict


def _mock_activity_alert(operation_name, enabled=True):
    alert = MagicMock()
    alert.enabled = enabled
    cond = MagicMock()
    field_cond = MagicMock()
    field_cond.field = "operationName"
    field_cond.equals = operation_name
    cond.all_of = [field_cond]
    alert.condition = cond
    return alert


def test_audit_log_retention_inconclusive(azure_session, mock_azure_modules):
    result = check_audit_log_retention(azure_session)
    assert result.spec_id == "3.10.7"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_resource_logging_inconclusive(azure_session, mock_azure_modules):
    result = check_resource_logging(azure_session)
    assert result.spec_id == "3.11.3"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_diagnostic_categories_inconclusive(azure_session, mock_azure_modules):
    result = check_diagnostic_categories(azure_session)
    assert result.spec_id == "3.11.16"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_alert_create_policy_pass(azure_session, mock_azure_modules):
    mock_monitor = mock_azure_modules["azure.mgmt.monitor"]
    mock_client = MagicMock()
    mock_monitor.MonitorManagementClient.return_value = mock_client

    alert = _mock_activity_alert("Microsoft.Authorization/policyAssignments/write")
    mock_client.activity_log_alerts.list_by_subscription_id.return_value = [alert]

    result = check_alert_create_policy(azure_session)
    assert result.spec_id == "3.11.5"
    assert result.verdict == Verdict.PASS


def test_alert_create_policy_fail(azure_session, mock_azure_modules):
    mock_monitor = mock_azure_modules["azure.mgmt.monitor"]
    mock_client = MagicMock()
    mock_monitor.MonitorManagementClient.return_value = mock_client
    mock_client.activity_log_alerts.list_by_subscription_id.return_value = []

    result = check_alert_create_policy(azure_session)
    assert result.verdict == Verdict.FAIL


def test_alert_delete_policy_pass(azure_session, mock_azure_modules):
    mock_monitor = mock_azure_modules["azure.mgmt.monitor"]
    mock_client = MagicMock()
    mock_monitor.MonitorManagementClient.return_value = mock_client

    alert = _mock_activity_alert("Microsoft.Authorization/policyAssignments/delete")
    mock_client.activity_log_alerts.list_by_subscription_id.return_value = [alert]

    result = check_alert_delete_policy(azure_session)
    assert result.spec_id == "3.11.6"
    assert result.verdict == Verdict.PASS


def test_alert_create_nsg_fail(azure_session, mock_azure_modules):
    mock_monitor = mock_azure_modules["azure.mgmt.monitor"]
    mock_client = MagicMock()
    mock_monitor.MonitorManagementClient.return_value = mock_client

    # Alert exists but for wrong operation
    alert = _mock_activity_alert("Microsoft.Authorization/policyAssignments/write")
    mock_client.activity_log_alerts.list_by_subscription_id.return_value = [alert]

    result = check_alert_create_nsg(azure_session)
    assert result.spec_id == "3.11.7"
    assert result.verdict == Verdict.FAIL


def test_diagnostic_setting_pass(azure_session, mock_azure_modules):
    mock_monitor = mock_azure_modules["azure.mgmt.monitor"]
    mock_client = MagicMock()
    mock_monitor.MonitorManagementClient.return_value = mock_client

    setting = MagicMock()
    setting.name = "activity-log-export"
    mock_client.diagnostic_settings.list.return_value = [setting]

    result = check_diagnostic_setting_exists(azure_session)
    assert result.spec_id == "3.11.15"
    assert result.verdict == Verdict.PASS


def test_diagnostic_setting_fail(azure_session, mock_azure_modules):
    mock_monitor = mock_azure_modules["azure.mgmt.monitor"]
    mock_client = MagicMock()
    mock_monitor.MonitorManagementClient.return_value = mock_client
    mock_client.diagnostic_settings.list.return_value = []

    result = check_diagnostic_setting_exists(azure_session)
    assert result.verdict == Verdict.FAIL


def test_key_vault_logging_no_vaults(azure_session, mock_azure_modules):
    mock_kv = mock_azure_modules["azure.mgmt.keyvault"]
    mock_monitor = mock_azure_modules["azure.mgmt.monitor"]
    mock_kv_client = MagicMock()
    mock_mon_client = MagicMock()
    mock_kv.KeyVaultManagementClient.return_value = mock_kv_client
    mock_monitor.MonitorManagementClient.return_value = mock_mon_client
    mock_kv_client.vaults.list.return_value = []

    result = check_key_vault_logging(azure_session)
    assert result.spec_id == "3.11.4"
    assert result.verdict == Verdict.PASS
