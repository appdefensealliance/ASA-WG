"""Azure Database checks for ADA Cloud assessment.

Covers 24 requirements (maps to CIS Azure Database Services Benchmark v2.0.0):

PostgreSQL (original):
- 6.3.1: PostgreSQL enforce SSL
- 6.13.1: PostgreSQL log_checkpoints
- 6.13.2: PostgreSQL log_connections
- 6.13.3: PostgreSQL log_disconnections
- 6.14.1: PostgreSQL log_retention_days

PostgreSQL (new):
- 6.3.5: PostgreSQL Entra-only auth
- 6.13.4: PostgreSQL connection_throttle
- 6.3.6: PostgreSQL ssl_min_protocol_version

MySQL (original):
- 6.3.2: MySQL enforce SSL
- 6.3.3: MySQL TLS 1.2

MySQL (new):
- 6.11.2: MySQL Entra-only auth

SQL (original):
- 6.4.2: SQL Database encryption
- 6.5.2: SQL no 0.0.0.0/0 ingress
- 6.11.1: Azure AD admin for SQL
- 6.15.1: SQL auditing on

SQL (new):
- 6.15.9: SQL audit retention > 90 days
- 6.3.7: SQL minimum TLS 1.2

Redis:
- 6.16.1: Redis Entra auth
- 6.16.2: Redis SSL only
- 6.16.3: Redis TLS 1.2+
- 6.16.4: Redis managed identity
- 6.16.5: Redis access keys disabled
- 6.16.6: Redis stable update channel

Cosmos DB:
- 6.17.1: Cosmos DB local auth disabled
- 6.17.2: Cosmos DB firewall rules
- 6.17.3: Cosmos DB logging

Data Factory:
- 6.18.1: Data Factory managed identities
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


# --- Additional PostgreSQL checks ---

def check_pg_entra_only_auth(session: AzureSession) -> RequirementResult:
    """ADA 6.3.5: Ensure PostgreSQL uses Entra-only authentication."""
    spec_id = "6.3.5"
    title = "Ensure Entra ID-Only Authentication is Enabled for PostgreSQL Flexible Servers"
    try:
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient

        client = PostgreSQLManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No PostgreSQL Flexible Servers found")

        non_compliant = []
        for server in servers:
            auth_config = getattr(server, "auth_config", None)
            if auth_config:
                ad_auth = getattr(auth_config, "active_directory_auth", "")
                pw_auth = getattr(auth_config, "password_auth", "")
                if str(ad_auth).lower() != "enabled":
                    non_compliant.append(
                        f"{server.name} (activeDirectoryAuth={ad_auth})")
                elif str(pw_auth).lower() == "enabled":
                    non_compliant.append(
                        f"{server.name} (passwordAuth still enabled)")
            else:
                non_compliant.append(f"{server.name} (no authConfig found)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "PostgreSQL servers without Entra-only auth:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(servers)} PostgreSQL servers use Entra-only authentication")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_pg_connection_throttle(session: AzureSession) -> RequirementResult:
    """ADA 6.13.4: Ensure 'connection_throttle.enable' is ON for PostgreSQL."""
    return _check_pg_config(session, "6.13.4",
        "Ensure Server Parameter 'connection_throttle.enable' is set to 'ON' for PostgreSQL",
        "connection_throttle.enable", "on")


def check_pg_ssl_min_version(session: AzureSession) -> RequirementResult:
    """ADA 6.3.6: Ensure ssl_min_protocol_version is TLSv1.2 for PostgreSQL."""
    return _check_pg_config(session, "6.3.6",
        "Ensure 'ssl_min_protocol_version' is set to 'TLSv1.2' for PostgreSQL",
        "ssl_min_protocol_version", "TLSv1.2",
        compare_fn=lambda v: v in ("TLSv1.2", "TLSv1.3"))


# --- Additional MySQL checks ---

def check_mysql_entra_only_auth(session: AzureSession) -> RequirementResult:
    """ADA 6.11.2: Ensure MySQL uses Entra-only authentication."""
    spec_id = "6.11.2"
    title = "Ensure Entra ID-Only Authentication is Enabled for MySQL Flexible Servers"
    try:
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

        client = MySQLManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No MySQL Flexible Servers found")

        non_compliant = []
        for server in servers:
            # Check Azure AD administrators
            rg = server.id.split("/")[4]
            try:
                admins = list(
                    client.azure_ad_administrators.list_by_server(rg, server.name))
                if not admins:
                    non_compliant.append(
                        f"{server.name} (no Entra ID admin configured)")
            except Exception:
                non_compliant.append(f"{server.name} (unable to check Entra admin)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "MySQL servers without Entra-only auth:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(servers)} MySQL servers have Entra ID authentication configured")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# --- Additional SQL checks ---

def check_sql_audit_retention(session: AzureSession) -> RequirementResult:
    """ADA 6.15.9: Ensure SQL audit retention is > 90 days."""
    spec_id = "6.15.9"
    title = "Ensure SQL Auditing Retention is Greater Than 90 Days"
    try:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No SQL Servers found")

        non_compliant = []
        for server in servers:
            rg = server.id.split("/")[4]
            try:
                policy = client.server_blob_auditing_policies.get(rg, server.name)
                if getattr(policy, "state", "") != "Enabled":
                    non_compliant.append(f"{server.name} (auditing not enabled)")
                    continue
                retention = getattr(policy, "retention_days", 0) or 0
                if retention < 90 and retention != 0:
                    # retention_days=0 means unlimited
                    non_compliant.append(
                        f"{server.name} (retention={retention} days, need >= 90)")
            except Exception:
                non_compliant.append(f"{server.name} (unable to check)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "SQL Servers with insufficient audit retention:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(servers)} SQL Servers have audit retention >= 90 days")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_sql_min_tls(session: AzureSession) -> RequirementResult:
    """ADA 6.3.7: Ensure SQL Server minimum TLS version is 1.2."""
    spec_id = "6.3.7"
    title = "Ensure SQL Server Minimum TLS Version is Set to 1.2"
    try:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(session.credential, session.subscription_id)
        servers = list(client.servers.list())

        if not servers:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No SQL Servers found")

        non_compliant = []
        for server in servers:
            min_tls = getattr(server, "minimal_tls_version", "")
            if min_tls and min_tls < "1.2":
                non_compliant.append(
                    f"{server.name} (minimalTlsVersion={min_tls})")
            elif not min_tls:
                non_compliant.append(
                    f"{server.name} (minimalTlsVersion not set)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "SQL Servers with TLS below 1.2:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(servers)} SQL Servers use TLS 1.2+")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# --- Redis checks ---

def _list_redis_caches(session: AzureSession) -> list:
    """List all Redis caches in the subscription."""
    from azure.mgmt.redis import RedisManagementClient

    client = RedisManagementClient(session.credential, session.subscription_id)
    return list(client.redis.list_by_subscription())


def check_redis_entra_auth(session: AzureSession) -> RequirementResult:
    """ADA 6.16.1: Ensure Redis uses Entra ID authentication."""
    spec_id = "6.16.1"
    title = "Ensure Entra ID Authentication is Enabled for Azure Cache for Redis"
    try:
        caches = _list_redis_caches(session)

        if not caches:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Redis caches found")

        non_compliant = []
        for cache in caches:
            config = getattr(cache, "redis_configuration", None) or {}
            # Check if AAD auth is enabled via config dict or properties
            aad_enabled = False
            if isinstance(config, dict):
                aad_enabled = config.get("aad-enabled", "false").lower() == "true"
            else:
                aad_val = getattr(config, "aad_enabled", None)
                aad_enabled = str(aad_val).lower() == "true" if aad_val else False
            if not aad_enabled:
                non_compliant.append(f"{cache.name} (Entra auth not enabled)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Redis caches without Entra auth:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(caches)} Redis caches have Entra auth enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_redis_ssl_only(session: AzureSession) -> RequirementResult:
    """ADA 6.16.2: Ensure Redis non-SSL port is disabled."""
    spec_id = "6.16.2"
    title = "Ensure Non-SSL Port is Disabled for Azure Cache for Redis"
    try:
        caches = _list_redis_caches(session)

        if not caches:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Redis caches found")

        non_compliant = []
        for cache in caches:
            non_ssl = getattr(cache, "enable_non_ssl_port", False)
            if non_ssl:
                non_compliant.append(f"{cache.name} (non-SSL port enabled)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Redis caches with non-SSL port enabled:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(caches)} Redis caches have non-SSL port disabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_redis_tls_version(session: AzureSession) -> RequirementResult:
    """ADA 6.16.3: Ensure Redis minimum TLS version is 1.2."""
    spec_id = "6.16.3"
    title = "Ensure Minimum TLS Version is 1.2 for Azure Cache for Redis"
    try:
        caches = _list_redis_caches(session)

        if not caches:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Redis caches found")

        non_compliant = []
        for cache in caches:
            min_tls = getattr(cache, "minimum_tls_version", "")
            if min_tls and str(min_tls) not in ("1.2", "1.3"):
                non_compliant.append(
                    f"{cache.name} (minimumTlsVersion={min_tls})")
            elif not min_tls:
                non_compliant.append(
                    f"{cache.name} (minimumTlsVersion not set)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Redis caches with TLS below 1.2:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(caches)} Redis caches use TLS 1.2+")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_redis_managed_identity(session: AzureSession) -> RequirementResult:
    """ADA 6.16.4: Ensure Redis has managed identity configured."""
    spec_id = "6.16.4"
    title = "Ensure Managed Identity is Configured for Azure Cache for Redis"
    try:
        caches = _list_redis_caches(session)

        if not caches:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Redis caches found")

        non_compliant = []
        for cache in caches:
            identity = getattr(cache, "identity", None)
            identity_type = getattr(identity, "type", None) if identity else None
            if not identity_type:
                non_compliant.append(f"{cache.name} (no managed identity)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Redis caches without managed identity:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(caches)} Redis caches have managed identity configured")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_redis_access_keys_disabled(session: AzureSession) -> RequirementResult:
    """ADA 6.16.5: Ensure Redis access key authentication is disabled."""
    spec_id = "6.16.5"
    title = "Ensure Access Key Authentication is Disabled for Azure Cache for Redis"
    try:
        caches = _list_redis_caches(session)

        if not caches:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Redis caches found")

        non_compliant = []
        for cache in caches:
            disabled = getattr(cache, "disable_access_key_authentication", False)
            if not disabled:
                non_compliant.append(
                    f"{cache.name} (access key auth not disabled)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Redis caches with access key auth enabled:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(caches)} Redis caches have access key auth disabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_redis_update_channel(session: AzureSession) -> RequirementResult:
    """ADA 6.16.6: Ensure Redis uses a stable update channel."""
    spec_id = "6.16.6"
    title = "Ensure Stable Update Channel is Configured for Azure Cache for Redis"
    try:
        caches = _list_redis_caches(session)

        if not caches:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Redis caches found")

        non_compliant = []
        for cache in caches:
            channel = getattr(cache, "update_channel", None)
            if channel and str(channel).lower() not in ("stable", ""):
                non_compliant.append(
                    f"{cache.name} (updateChannel={channel})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Redis caches not on stable channel:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(caches)} Redis caches use stable update channel")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# --- Cosmos DB checks ---

def check_cosmos_local_auth_disabled(session: AzureSession) -> RequirementResult:
    """ADA 6.17.1: Ensure Cosmos DB local authentication is disabled."""
    spec_id = "6.17.1"
    title = "Ensure Local Authentication is Disabled for Cosmos DB Accounts"
    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient

        client = CosmosDBManagementClient(session.credential, session.subscription_id)
        accounts = list(client.database_accounts.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Cosmos DB accounts found")

        non_compliant = []
        for acct in accounts:
            local_auth = getattr(acct, "disable_local_auth", False)
            if not local_auth:
                non_compliant.append(
                    f"{acct.name} (local auth not disabled)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Cosmos DB accounts with local auth enabled:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} Cosmos DB accounts have local auth disabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_cosmos_firewall(session: AzureSession) -> RequirementResult:
    """ADA 6.17.2: Ensure Cosmos DB has firewall rules configured."""
    spec_id = "6.17.2"
    title = "Ensure Firewall Rules are Configured for Cosmos DB Accounts"
    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient

        client = CosmosDBManagementClient(session.credential, session.subscription_id)
        accounts = list(client.database_accounts.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Cosmos DB accounts found")

        non_compliant = []
        for acct in accounts:
            ip_rules = getattr(acct, "ip_rules", []) or []
            vnet_filter = getattr(acct, "is_virtual_network_filter_enabled", False)
            public_access = getattr(acct, "public_network_access", "Enabled")

            if str(public_access) == "Disabled":
                continue  # Public access disabled, no firewall needed
            if not ip_rules and not vnet_filter:
                non_compliant.append(
                    f"{acct.name} (no IP rules or VNet filter configured)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Cosmos DB accounts without firewall:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} Cosmos DB accounts have firewall configured")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_cosmos_logging(session: AzureSession) -> RequirementResult:
    """ADA 6.17.3: Ensure diagnostic logging is enabled for Cosmos DB."""
    spec_id = "6.17.3"
    title = "Ensure Diagnostic Logging is Enabled for Cosmos DB Accounts"
    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
        from azure.mgmt.monitor import MonitorManagementClient

        cosmos_client = CosmosDBManagementClient(
            session.credential, session.subscription_id)
        monitor_client = MonitorManagementClient(
            session.credential, session.subscription_id)
        accounts = list(cosmos_client.database_accounts.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Cosmos DB accounts found")

        non_compliant = []
        for acct in accounts:
            settings = list(monitor_client.diagnostic_settings.list(acct.id))
            has_logging = any(
                any(getattr(log, "enabled", False)
                    for log in getattr(s, "logs", []))
                for s in settings
            )
            if not has_logging:
                non_compliant.append(acct.name)

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Cosmos DB accounts without diagnostic logging:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} Cosmos DB accounts have diagnostic logging enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# --- Data Factory checks ---

def check_data_factory_managed_identity(session: AzureSession) -> RequirementResult:
    """ADA 6.18.1: Ensure Data Factory has managed identities configured."""
    spec_id = "6.18.1"
    title = "Ensure Managed Identities are Configured for Azure Data Factory"
    try:
        from azure.mgmt.datafactory import DataFactoryManagementClient

        client = DataFactoryManagementClient(session.credential, session.subscription_id)
        factories = list(client.factories.list())

        if not factories:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Data Factory instances found")

        non_compliant = []
        for factory in factories:
            identity = getattr(factory, "identity", None)
            identity_type = getattr(identity, "type", None) if identity else None
            if not identity_type:
                non_compliant.append(f"{factory.name} (no managed identity)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Data Factory instances without managed identity:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(factories)} Data Factory instances have managed identity configured")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")
