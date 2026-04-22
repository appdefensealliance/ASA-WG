"""Tests for Azure Database checks."""

from unittest.mock import MagicMock

from ada_cloud_audit.checks.azure.database import (
    check_sql_auditing,
    check_sql_encryption,
    check_sql_firewall,
    check_sql_ad_admin,
    check_pg_ssl,
    check_pg_log_checkpoints,
    check_mysql_ssl,
)
from ada_cloud_audit.models import Verdict


def _mock_sql_server(name="test-sql"):
    server = MagicMock()
    server.name = name
    server.id = f"/subscriptions/00000000/resourceGroups/test-rg/providers/Microsoft.Sql/servers/{name}"
    return server


def test_sql_auditing_pass(azure_session, mock_azure_modules):
    mock_sql = mock_azure_modules["azure.mgmt.sql"]
    mock_client = MagicMock()
    mock_sql.SqlManagementClient.return_value = mock_client

    server = _mock_sql_server()
    mock_client.servers.list.return_value = [server]

    policy = MagicMock()
    policy.state = "Enabled"
    mock_client.server_blob_auditing_policies.get.return_value = policy

    result = check_sql_auditing(azure_session)
    assert result.spec_id == "6.15.1"
    assert result.verdict == Verdict.PASS


def test_sql_auditing_fail(azure_session, mock_azure_modules):
    mock_sql = mock_azure_modules["azure.mgmt.sql"]
    mock_client = MagicMock()
    mock_sql.SqlManagementClient.return_value = mock_client

    server = _mock_sql_server()
    mock_client.servers.list.return_value = [server]

    policy = MagicMock()
    policy.state = "Disabled"
    mock_client.server_blob_auditing_policies.get.return_value = policy

    result = check_sql_auditing(azure_session)
    assert result.verdict == Verdict.FAIL


def test_sql_auditing_no_servers(azure_session, mock_azure_modules):
    mock_sql = mock_azure_modules["azure.mgmt.sql"]
    mock_client = MagicMock()
    mock_sql.SqlManagementClient.return_value = mock_client
    mock_client.servers.list.return_value = []

    result = check_sql_auditing(azure_session)
    assert result.verdict == Verdict.PASS


def test_sql_firewall_pass(azure_session, mock_azure_modules):
    mock_sql = mock_azure_modules["azure.mgmt.sql"]
    mock_client = MagicMock()
    mock_sql.SqlManagementClient.return_value = mock_client

    server = _mock_sql_server()
    mock_client.servers.list.return_value = [server]

    rule = MagicMock()
    rule.name = "allow-office"
    rule.start_ip_address = "10.0.0.1"
    rule.end_ip_address = "10.0.0.255"
    mock_client.firewall_rules.list_by_server.return_value = [rule]

    result = check_sql_firewall(azure_session)
    assert result.spec_id == "6.5.2"
    assert result.verdict == Verdict.PASS


def test_sql_firewall_fail(azure_session, mock_azure_modules):
    mock_sql = mock_azure_modules["azure.mgmt.sql"]
    mock_client = MagicMock()
    mock_sql.SqlManagementClient.return_value = mock_client

    server = _mock_sql_server()
    mock_client.servers.list.return_value = [server]

    rule = MagicMock()
    rule.name = "AllowAllAzureIps"
    rule.start_ip_address = "0.0.0.0"
    rule.end_ip_address = "0.0.0.0"
    mock_client.firewall_rules.list_by_server.return_value = [rule]

    result = check_sql_firewall(azure_session)
    assert result.verdict == Verdict.FAIL


def test_sql_ad_admin_pass(azure_session, mock_azure_modules):
    mock_sql = mock_azure_modules["azure.mgmt.sql"]
    mock_client = MagicMock()
    mock_sql.SqlManagementClient.return_value = mock_client

    server = _mock_sql_server()
    mock_client.servers.list.return_value = [server]

    admin = MagicMock()
    mock_client.server_azure_ad_administrators.list_by_server.return_value = [admin]

    result = check_sql_ad_admin(azure_session)
    assert result.spec_id == "6.11.1"
    assert result.verdict == Verdict.PASS


def test_sql_ad_admin_fail(azure_session, mock_azure_modules):
    mock_sql = mock_azure_modules["azure.mgmt.sql"]
    mock_client = MagicMock()
    mock_sql.SqlManagementClient.return_value = mock_client

    server = _mock_sql_server()
    mock_client.servers.list.return_value = [server]
    mock_client.server_azure_ad_administrators.list_by_server.return_value = []

    result = check_sql_ad_admin(azure_session)
    assert result.verdict == Verdict.FAIL


def test_pg_ssl_no_servers(azure_session, mock_azure_modules):
    mock_pg = mock_azure_modules["azure.mgmt.rdbms.postgresql_flexibleservers"]
    mock_client = MagicMock()
    mock_pg.PostgreSQLManagementClient.return_value = mock_client
    mock_client.servers.list.return_value = []

    result = check_pg_ssl(azure_session)
    assert result.spec_id == "6.3.1"
    assert result.verdict == Verdict.PASS


def test_mysql_ssl_no_servers(azure_session, mock_azure_modules):
    mock_mysql = mock_azure_modules["azure.mgmt.rdbms.mysql_flexibleservers"]
    mock_client = MagicMock()
    mock_mysql.MySQLManagementClient.return_value = mock_client
    mock_client.servers.list.return_value = []

    result = check_mysql_ssl(azure_session)
    assert result.spec_id == "6.3.2"
    assert result.verdict == Verdict.PASS
