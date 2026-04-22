"""Azure Database checks for ADA Cloud assessment.

Covers 11 requirements (maps to CIS Azure Database Services Benchmark v2.0.0):
- 6.3.1: PostgreSQL enforce SSL
- 6.3.2: MySQL enforce SSL
- 6.3.3: MySQL TLS 1.2
- 6.4.2: SQL Database encryption
- 6.5.2: SQL no 0.0.0.0/0 ingress
- 6.11.1: Azure AD admin for SQL
- 6.13.1: PostgreSQL log_checkpoints
- 6.13.2: PostgreSQL log_connections
- 6.13.3: PostgreSQL log_disconnections
- 6.14.1: PostgreSQL log_retention_days
- 6.15.1: SQL auditing on
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict


# --- PostgreSQL checks ---

def _check_pg_config(session: AzureSession, spec_id: str, title: str,
                     param_name: str, expected: str,
                     compare_fn=None) -> RequirementResult:
    """Common helper for PostgreSQL flexible server configuration checks."""
    try:
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient

        client = PostgreSQLManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No PostgreSQL Flexible Servers found")

        non_compliant = []
        for server in servers:
            rg = server.id.split("/")[4]
            try:
                config = client.configurations.get(rg, server.name, param_name)
                value = getattr(config, "value", "")
                if compare_fn:
                    if not compare_fn(value):
                        non_compliant.append(f"{server.name} ({param_name}={value})")
                elif value.lower() != expected.lower():
                    non_compliant.append(f"{server.name} ({param_name}={value})")
            except Exception:
                non_compliant.append(f"{server.name} (unable to read {param_name})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             f"Non-compliant servers:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(servers)} PostgreSQL servers are compliant")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_pg_ssl(session: AzureSession) -> RequirementResult:
    """ADA 6.3.1: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL."""
    return _check_pg_config(session, "6.3.1",
        "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server",
        "require_secure_transport", "on")


def check_pg_log_checkpoints(session: AzureSession) -> RequirementResult:
    """ADA 6.13.1: Ensure 'log_checkpoints' is set to 'ON' for PostgreSQL."""
    return _check_pg_config(session, "6.13.1",
        "Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server",
        "log_checkpoints", "on")


def check_pg_log_connections(session: AzureSession) -> RequirementResult:
    """ADA 6.13.2: Ensure 'log_connections' is set to 'ON' for PostgreSQL."""
    return _check_pg_config(session, "6.13.2",
        "Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server",
        "log_connections", "on")


def check_pg_log_disconnections(session: AzureSession) -> RequirementResult:
    """ADA 6.13.3: Ensure 'log_disconnections' is set to 'ON' for PostgreSQL."""
    return _check_pg_config(session, "6.13.3",
        "Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server",
        "log_disconnections", "on")


def check_pg_log_retention(session: AzureSession) -> RequirementResult:
    """ADA 6.14.1: Ensure 'log_retention_days' is greater than 3 days for PostgreSQL."""
    return _check_pg_config(session, "6.14.1",
        "Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server",
        "logfiles.retention_days", "3",
        compare_fn=lambda v: int(v) > 3 if v.isdigit() else False)


# --- MySQL checks ---

def check_mysql_ssl(session: AzureSession) -> RequirementResult:
    """ADA 6.3.2: Ensure 'Enforce SSL connection' is set to 'Enabled' for MySQL."""
    try:
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

        client = MySQLManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result("6.3.2",
                "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server",
                "Azure", Verdict.PASS, "No MySQL Flexible Servers found")

        non_compliant = []
        for server in servers:
            rg = server.id.split("/")[4]
            try:
                config = client.configurations.get(rg, server.name, "require_secure_transport")
                if getattr(config, "value", "").lower() != "on":
                    non_compliant.append(server.name)
            except Exception:
                non_compliant.append(f"{server.name} (unable to check)")

        if non_compliant:
            return make_result("6.3.2",
                "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server",
                "Azure", Verdict.FAIL,
                "MySQL servers without SSL enforced:\n" + "\n".join(non_compliant))
        return make_result("6.3.2",
            "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server",
            "Azure", Verdict.PASS, f"All {len(servers)} MySQL servers enforce SSL")
    except Exception as e:
        return make_result("6.3.2",
            "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_mysql_tls(session: AzureSession) -> RequirementResult:
    """ADA 6.3.3: Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL."""
    try:
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

        client = MySQLManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result("6.3.3",
                "Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server",
                "Azure", Verdict.PASS, "No MySQL Flexible Servers found")

        non_compliant = []
        for server in servers:
            rg = server.id.split("/")[4]
            try:
                config = client.configurations.get(rg, server.name, "tls_version")
                value = getattr(config, "value", "")
                if "TLSv1.2" not in value:
                    non_compliant.append(f"{server.name} (tls_version={value})")
            except Exception:
                non_compliant.append(f"{server.name} (unable to check)")

        if non_compliant:
            return make_result("6.3.3",
                "Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server",
                "Azure", Verdict.FAIL,
                "MySQL servers without TLS 1.2:\n" + "\n".join(non_compliant))
        return make_result("6.3.3",
            "Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server",
            "Azure", Verdict.PASS, f"All {len(servers)} MySQL servers use TLS 1.2")
    except Exception as e:
        return make_result("6.3.3",
            "Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# --- SQL Database checks ---

def check_sql_auditing(session: AzureSession) -> RequirementResult:
    """ADA 6.15.1: Ensure that 'Auditing' is set to 'On'."""
    try:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result("6.15.1",
                "Ensure that 'Auditing' is set to 'On'",
                "Azure", Verdict.PASS, "No SQL Servers found")

        non_compliant = []
        for server in servers:
            rg = server.id.split("/")[4]
            try:
                policy = client.server_blob_auditing_policies.get(rg, server.name)
                if getattr(policy, "state", "") != "Enabled":
                    non_compliant.append(server.name)
            except Exception:
                non_compliant.append(f"{server.name} (unable to check)")

        if non_compliant:
            return make_result("6.15.1",
                "Ensure that 'Auditing' is set to 'On'",
                "Azure", Verdict.FAIL,
                "SQL Servers without auditing:\n" + "\n".join(non_compliant))
        return make_result("6.15.1",
            "Ensure that 'Auditing' is set to 'On'",
            "Azure", Verdict.PASS,
            f"All {len(servers)} SQL Servers have auditing enabled")
    except Exception as e:
        return make_result("6.15.1",
            "Ensure that 'Auditing' is set to 'On'",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_sql_encryption(session: AzureSession) -> RequirementResult:
    """ADA 6.4.2: Ensure that 'Data encryption' is set to 'On' on a SQL Database."""
    try:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result("6.4.2",
                "Ensure that 'Data encryption' is set to 'On' on a SQL Database",
                "Azure", Verdict.PASS, "No SQL Servers found")

        non_compliant = []
        for server in servers:
            rg = server.id.split("/")[4]
            dbs = list(client.databases.list_by_server(rg, server.name))
            for db in dbs:
                if db.name == "master":
                    continue
                try:
                    tde = client.transparent_data_encryptions.get(rg, server.name, db.name, "current")
                    if getattr(tde, "state", "") != "Enabled":
                        non_compliant.append(f"{server.name}/{db.name}")
                except Exception:
                    non_compliant.append(f"{server.name}/{db.name} (unable to check)")

        if non_compliant:
            return make_result("6.4.2",
                "Ensure that 'Data encryption' is set to 'On' on a SQL Database",
                "Azure", Verdict.FAIL,
                "Databases without encryption:\n" + "\n".join(non_compliant))
        return make_result("6.4.2",
            "Ensure that 'Data encryption' is set to 'On' on a SQL Database",
            "Azure", Verdict.PASS, "All SQL Databases have data encryption enabled")
    except Exception as e:
        return make_result("6.4.2",
            "Ensure that 'Data encryption' is set to 'On' on a SQL Database",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_sql_firewall(session: AzureSession) -> RequirementResult:
    """ADA 6.5.2: Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0."""
    try:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result("6.5.2",
                "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
                "Azure", Verdict.PASS, "No SQL Servers found")

        non_compliant = []
        for server in servers:
            rg = server.id.split("/")[4]
            rules = list(client.firewall_rules.list_by_server(rg, server.name))
            for rule in rules:
                start_ip = getattr(rule, "start_ip_address", "")
                end_ip = getattr(rule, "end_ip_address", "")
                if start_ip == "0.0.0.0" and end_ip in ("0.0.0.0", "255.255.255.255"):
                    non_compliant.append(
                        f"{server.name}: rule '{rule.name}' allows {start_ip}-{end_ip}")

        if non_compliant:
            return make_result("6.5.2",
                "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
                "Azure", Verdict.FAIL,
                "SQL Servers with overly permissive firewall rules:\n" + "\n".join(non_compliant))
        return make_result("6.5.2",
            "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
            "Azure", Verdict.PASS,
            f"All {len(servers)} SQL Servers have properly restricted firewall rules")
    except Exception as e:
        return make_result("6.5.2",
            "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_sql_ad_admin(session: AzureSession) -> RequirementResult:
    """ADA 6.11.1: Ensure Azure Active Directory Admin is configured for SQL Servers."""
    try:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result("6.11.1",
                "Ensure that Azure Active Directory Admin is Configured for SQL Servers",
                "Azure", Verdict.PASS, "No SQL Servers found")

        non_compliant = []
        for server in servers:
            rg = server.id.split("/")[4]
            admins = list(client.server_azure_ad_administrators.list_by_server(rg, server.name))
            if not admins:
                non_compliant.append(server.name)

        if non_compliant:
            return make_result("6.11.1",
                "Ensure that Azure Active Directory Admin is Configured for SQL Servers",
                "Azure", Verdict.FAIL,
                "SQL Servers without Entra ID admin:\n" + "\n".join(non_compliant))
        return make_result("6.11.1",
            "Ensure that Azure Active Directory Admin is Configured for SQL Servers",
            "Azure", Verdict.PASS,
            f"All {len(servers)} SQL Servers have Entra ID admin configured")
    except Exception as e:
        return make_result("6.11.1",
            "Ensure that Azure Active Directory Admin is Configured for SQL Servers",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")
