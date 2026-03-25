"""Tests for GCP Database checks."""

from unittest.mock import patch, MagicMock

import pytest

from ada_cloud_audit.checks.gcp.database import (
    check_local_infile,
    check_skip_show_database,
    check_external_scripts,
    check_cross_db_ownership,
    check_contained_db_auth,
    check_user_options,
    check_trace_flag_3625,
    check_remote_access,
    check_log_connections,
    check_log_disconnections,
    check_log_min_messages,
    check_log_min_error_statement,
    check_log_min_duration_statement,
    check_pgaudit,
    check_ssl_required,
    check_no_public_ip_whitelist,
    check_private_ip,
    check_mysql_admin_access,
)
from ada_cloud_audit.models import Verdict


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_local_infile_pass_no_instances(mock_list, gcp_session):
    mock_list.return_value = []
    result = check_local_infile(gcp_session)
    assert result.spec_id == "6.1.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_local_infile_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "mysql-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"databaseFlags": [{"name": "local_infile", "value": "off"}]},
    }]
    result = check_local_infile(gcp_session)
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_local_infile_fail(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "mysql-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"databaseFlags": [{"name": "local_infile", "value": "on"}]},
    }]
    result = check_local_infile(gcp_session)
    assert result.verdict == Verdict.FAIL
    assert "mysql-1" in result.evidence


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_local_infile_fail_flag_absent(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "mysql-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"databaseFlags": []},
    }]
    result = check_local_infile(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_skip_show_database_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "mysql-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"databaseFlags": [{"name": "skip_show_database", "value": "on"}]},
    }]
    result = check_skip_show_database(gcp_session)
    assert result.spec_id == "6.5.4"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_external_scripts_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "sqlserver-1",
        "databaseVersion": "SQLSERVER_2019_STANDARD",
        "settings": {"databaseFlags": [{"name": "external scripts enabled", "value": "off"}]},
    }]
    result = check_external_scripts(gcp_session)
    assert result.spec_id == "6.2.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_cross_db_ownership_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "sqlserver-1",
        "databaseVersion": "SQLSERVER_2019_STANDARD",
        "settings": {"databaseFlags": [{"name": "cross db ownership chaining", "value": "off"}]},
    }]
    result = check_cross_db_ownership(gcp_session)
    assert result.spec_id == "6.5.5"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_contained_db_auth_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "sqlserver-1",
        "databaseVersion": "SQLSERVER_2019_STANDARD",
        "settings": {"databaseFlags": [{"name": "contained database authentication", "value": "off"}]},
    }]
    result = check_contained_db_auth(gcp_session)
    assert result.spec_id == "6.5.6"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_user_options_pass_not_set(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "sqlserver-1",
        "databaseVersion": "SQLSERVER_2019_STANDARD",
        "settings": {"databaseFlags": []},
    }]
    result = check_user_options(gcp_session)
    assert result.spec_id == "6.6.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_user_options_fail_set(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "sqlserver-1",
        "databaseVersion": "SQLSERVER_2019_STANDARD",
        "settings": {"databaseFlags": [{"name": "user options", "value": "536"}]},
    }]
    result = check_user_options(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_trace_flag_3625_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "sqlserver-1",
        "databaseVersion": "SQLSERVER_2019_STANDARD",
        "settings": {"databaseFlags": [{"name": "3625", "value": "on"}]},
    }]
    result = check_trace_flag_3625(gcp_session)
    assert result.spec_id == "6.6.2"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_remote_access_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "sqlserver-1",
        "databaseVersion": "SQLSERVER_2019_STANDARD",
        "settings": {"databaseFlags": [{"name": "remote access", "value": "off"}]},
    }]
    result = check_remote_access(gcp_session)
    assert result.spec_id == "6.10.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_log_connections_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": [{"name": "log_connections", "value": "on"}]},
    }]
    result = check_log_connections(gcp_session)
    assert result.spec_id == "6.15.2"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_log_disconnections_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": [{"name": "log_disconnections", "value": "on"}]},
    }]
    result = check_log_disconnections(gcp_session)
    assert result.spec_id == "6.15.3"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_log_min_messages_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": [{"name": "log_min_messages", "value": "warning"}]},
    }]
    result = check_log_min_messages(gcp_session)
    assert result.spec_id == "6.15.4"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_log_min_messages_fail_low_level(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": [{"name": "log_min_messages", "value": "notice"}]},
    }]
    result = check_log_min_messages(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_log_min_error_statement_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": [{"name": "log_min_error_statement", "value": "error"}]},
    }]
    result = check_log_min_error_statement(gcp_session)
    assert result.spec_id == "6.15.5"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_log_min_duration_statement_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": [{"name": "log_min_duration_statement", "value": "-1"}]},
    }]
    result = check_log_min_duration_statement(gcp_session)
    assert result.spec_id == "6.15.6"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_log_min_duration_statement_fail(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": [{"name": "log_min_duration_statement", "value": "1000"}]},
    }]
    result = check_log_min_duration_statement(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_pgaudit_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": [{"name": "cloudsql.enable_pgaudit", "value": "on"}]},
    }]
    result = check_pgaudit(gcp_session)
    assert result.spec_id == "6.15.7"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_ssl_required_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "db-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"ipConfiguration": {"requireSsl": True}},
    }]
    result = check_ssl_required(gcp_session)
    assert result.spec_id == "6.3.4"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_ssl_required_fail(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "db-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"ipConfiguration": {"requireSsl": False}},
    }]
    result = check_ssl_required(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_no_public_ip_whitelist_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "db-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"ipConfiguration": {"authorizedNetworks": [
            {"value": "10.0.0.0/8"}
        ]}},
    }]
    result = check_no_public_ip_whitelist(gcp_session)
    assert result.spec_id == "6.5.3"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_no_public_ip_whitelist_fail(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "db-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"ipConfiguration": {"authorizedNetworks": [
            {"value": "0.0.0.0/0"}
        ]}},
    }]
    result = check_no_public_ip_whitelist(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_private_ip_pass(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "db-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"ipConfiguration": {"privateNetwork": "projects/test/networks/default"}},
        "ipAddresses": [{"type": "PRIVATE", "ipAddress": "10.0.0.1"}],
    }]
    result = check_private_ip(gcp_session)
    assert result.spec_id == "6.8.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_check_private_ip_fail(mock_list, gcp_session):
    mock_list.return_value = [{
        "name": "db-1",
        "databaseVersion": "MYSQL_8_0",
        "settings": {"ipConfiguration": {}},
        "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.1.2.3"}],
    }]
    result = check_private_ip(gcp_session)
    assert result.verdict == Verdict.FAIL


def test_check_mysql_admin_access_inconclusive(gcp_session):
    result = check_mysql_admin_access(gcp_session)
    assert result.spec_id == "6.9.1"
    assert result.verdict == Verdict.INCONCLUSIVE


@patch("ada_cloud_audit.checks.gcp.database.list_sql_instances")
def test_filter_ignores_wrong_db_type(mock_list, gcp_session):
    """MySQL flag checks should not check PostgreSQL instances."""
    mock_list.return_value = [{
        "name": "pg-1",
        "databaseVersion": "POSTGRES_14",
        "settings": {"databaseFlags": []},
    }]
    result = check_local_infile(gcp_session)
    # No MySQL instances, so should pass
    assert result.verdict == Verdict.PASS
