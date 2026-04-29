"""GCP Database checks for ADA Cloud assessment.

Covers 20 requirements for Cloud SQL instances:
- 6.1.1, 6.2.1, 6.5.4-6.5.6, 6.6.1-6.6.3, 6.10.1: Database flag checks
- 6.15.2-6.15.7: PostgreSQL logging flags
- 6.3.4: SSL required for all connections
- 6.5.3: No 0.0.0.0/0 in authorized networks
- 6.8.1: Instance IP assignment set to private
- 6.9.1: MySQL anonymous admin login (INCONCLUSIVE)
- 6.12.2: Cloud SQL configured with automated backups
"""

from __future__ import annotations

from typing import Any, Callable

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.gcp.base import GCPSession, list_sql_instances
from ada_cloud_audit.models import RequirementResult, Verdict


def _get_flag_value(instance: dict, flag_name: str) -> str | None:
    """Extract a database flag value from a Cloud SQL instance."""
    flags = instance.get("settings", {}).get("databaseFlags", [])
    for flag in flags:
        if flag.get("name") == flag_name:
            return flag.get("value")
    return None


def _make_flag_check(
    spec_id: str,
    title: str,
    flag_name: str,
    expected: str,
    db_type_filter: str,
    absent_fails: bool = True,
    check_not_equal: bool = False,
) -> Callable[[GCPSession], RequirementResult]:
    """Factory that generates a check function for a Cloud SQL database flag.

    Args:
        spec_id: ADA requirement ID
        title: Human-readable requirement title
        flag_name: Cloud SQL database flag name
        expected: Expected flag value
        db_type_filter: Database version prefix to filter (e.g. "MYSQL", "POSTGRES", "SQLSERVER")
        absent_fails: If True, flag not being set is a failure
        check_not_equal: If True, check that the value does NOT equal expected (for "not configured" checks)
    """

    def check(session: GCPSession) -> RequirementResult:
        try:
            instances = list_sql_instances(session)
        except Exception as e:
            return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                             f"Error listing Cloud SQL instances: {e}")

        filtered = [i for i in instances
                    if db_type_filter in i.get("databaseVersion", "").upper()]

        if not filtered:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             f"No {db_type_filter} Cloud SQL instances found",
                             {"instances_checked": 0})

        non_compliant = []
        compliant = []
        for inst in filtered:
            name = inst.get("name", "unknown")
            value = _get_flag_value(inst, flag_name)

            if value is None:
                if absent_fails:
                    non_compliant.append(f"{name} (flag '{flag_name}' not set)")
                else:
                    compliant.append(name)
            elif check_not_equal:
                if value == expected:
                    non_compliant.append(f"{name} (flag '{flag_name}' = '{value}')")
                else:
                    compliant.append(name)
            else:
                if value.lower() == expected.lower():
                    compliant.append(name)
                else:
                    non_compliant.append(
                        f"{name} (flag '{flag_name}' = '{value}', expected '{expected}')"
                    )

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Non-compliant instances:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {len(compliant)} {db_type_filter} instances compliant",
                         {"compliant": compliant})

    check.__doc__ = f"ADA {spec_id}: {title}"
    return check


# MySQL flag checks
check_local_infile = _make_flag_check(
    "6.1.1",
    "Ensure 'local_infile' database flag for Cloud SQL MySQL instance is set to 'off'",
    "local_infile", "off", "MYSQL",
)

check_skip_show_database = _make_flag_check(
    "6.5.4",
    "Ensure 'skip_show_database' database flag for Cloud SQL MySQL instance is set to 'on'",
    "skip_show_database", "on", "MYSQL",
)

# SQL Server flag checks
check_external_scripts = _make_flag_check(
    "6.2.1",
    "Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'",
    "external scripts enabled", "off", "SQLSERVER",
)

check_cross_db_ownership = _make_flag_check(
    "6.5.5",
    "Ensure 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'",
    "cross db ownership chaining", "off", "SQLSERVER",
)

check_contained_db_auth = _make_flag_check(
    "6.5.6",
    "Ensure 'contained database authentication' database flag for Cloud SQL SQL Server instance is set to 'off'",
    "contained database authentication", "off", "SQLSERVER",
)

check_user_options = _make_flag_check(
    "6.6.1",
    "Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured",
    "user options", "", "SQLSERVER",
    absent_fails=False,
    check_not_equal=False,
)

check_trace_flag_3625 = _make_flag_check(
    "6.6.2",
    "Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'on'",
    "3625", "on", "SQLSERVER",
)

check_remote_access = _make_flag_check(
    "6.10.1",
    "Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'",
    "remote access", "off", "SQLSERVER",
)

# PostgreSQL flag checks
check_log_connections = _make_flag_check(
    "6.15.2",
    "Ensure 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'",
    "log_connections", "on", "POSTGRES",
)

check_log_disconnections = _make_flag_check(
    "6.15.3",
    "Ensure 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'",
    "log_disconnections", "on", "POSTGRES",
)

check_pgaudit = _make_flag_check(
    "6.15.7",
    "Ensure 'cloudsql.enable_pgaudit' database flag for Cloud SQL PostgreSQL instance is set to 'on'",
    "cloudsql.enable_pgaudit", "on", "POSTGRES",
)


def check_log_min_messages(session: GCPSession) -> RequirementResult:
    """ADA 6.15.4: Ensure 'log_min_messages' database flag for Cloud SQL PostgreSQL is set to at least WARNING."""
    VALID_LEVELS = {"warning", "error", "log", "fatal", "panic"}
    spec_id = "6.15.4"
    title = "Ensure 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately"

    try:
        instances = list_sql_instances(session)
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error listing Cloud SQL instances: {e}")

    filtered = [i for i in instances if "POSTGRES" in i.get("databaseVersion", "").upper()]
    if not filtered:
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No PostgreSQL Cloud SQL instances found")

    non_compliant = []
    compliant = []
    for inst in filtered:
        name = inst.get("name", "unknown")
        value = _get_flag_value(inst, "log_min_messages")
        if value is None:
            non_compliant.append(f"{name} (flag 'log_min_messages' not set)")
        elif value.lower() in VALID_LEVELS:
            compliant.append(name)
        else:
            non_compliant.append(f"{name} (log_min_messages = '{value}', expected >= WARNING)")

    if non_compliant:
        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "Non-compliant instances:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, "GCP", Verdict.PASS,
                     f"All {len(compliant)} PostgreSQL instances have log_min_messages >= WARNING",
                     {"compliant": compliant})


def check_log_min_error_statement(session: GCPSession) -> RequirementResult:
    """ADA 6.15.5: Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL is set to at least ERROR."""
    VALID_LEVELS = {"error", "log", "fatal", "panic"}
    spec_id = "6.15.5"
    title = "Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately"

    try:
        instances = list_sql_instances(session)
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error listing Cloud SQL instances: {e}")

    filtered = [i for i in instances if "POSTGRES" in i.get("databaseVersion", "").upper()]
    if not filtered:
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No PostgreSQL Cloud SQL instances found")

    non_compliant = []
    compliant = []
    for inst in filtered:
        name = inst.get("name", "unknown")
        value = _get_flag_value(inst, "log_min_error_statement")
        if value is None:
            non_compliant.append(f"{name} (flag 'log_min_error_statement' not set)")
        elif value.lower() in VALID_LEVELS:
            compliant.append(name)
        else:
            non_compliant.append(
                f"{name} (log_min_error_statement = '{value}', expected >= ERROR)"
            )

    if non_compliant:
        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "Non-compliant instances:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, "GCP", Verdict.PASS,
                     f"All {len(compliant)} PostgreSQL instances have log_min_error_statement >= ERROR",
                     {"compliant": compliant})


def check_log_min_duration_statement(session: GCPSession) -> RequirementResult:
    """ADA 6.15.6: Ensure 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL is set to '-1'."""
    spec_id = "6.15.6"
    title = "Ensure 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1'"

    try:
        instances = list_sql_instances(session)
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error listing Cloud SQL instances: {e}")

    filtered = [i for i in instances if "POSTGRES" in i.get("databaseVersion", "").upper()]
    if not filtered:
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No PostgreSQL Cloud SQL instances found")

    non_compliant = []
    compliant = []
    for inst in filtered:
        name = inst.get("name", "unknown")
        value = _get_flag_value(inst, "log_min_duration_statement")
        if value is None:
            non_compliant.append(f"{name} (flag 'log_min_duration_statement' not set)")
        elif value == "-1":
            compliant.append(name)
        else:
            non_compliant.append(
                f"{name} (log_min_duration_statement = '{value}', expected '-1')"
            )

    if non_compliant:
        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "Non-compliant instances:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, "GCP", Verdict.PASS,
                     f"All {len(compliant)} PostgreSQL instances have log_min_duration_statement = -1",
                     {"compliant": compliant})


def check_ssl_required(session: GCPSession) -> RequirementResult:
    """ADA 6.3.4: Ensure Cloud SQL database instances require all incoming connections to use SSL."""
    spec_id = "6.3.4"
    title = "Ensure Cloud SQL database instances require all incoming connections to use SSL"

    try:
        instances = list_sql_instances(session)
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error listing Cloud SQL instances: {e}")

    if not instances:
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No Cloud SQL instances found")

    non_compliant = []
    compliant = []
    for inst in instances:
        name = inst.get("name", "unknown")
        require_ssl = inst.get("settings", {}).get("ipConfiguration", {}).get("requireSsl", False)
        if require_ssl:
            compliant.append(name)
        else:
            non_compliant.append(f"{name} (requireSsl not enabled)")

    if non_compliant:
        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "Instances not requiring SSL:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, "GCP", Verdict.PASS,
                     f"All {len(compliant)} Cloud SQL instances require SSL",
                     {"compliant": compliant})


def check_no_public_ip_whitelist(session: GCPSession) -> RequirementResult:
    """ADA 6.5.3: Ensure Cloud SQL database instances do not whitelist 0.0.0.0/0."""
    spec_id = "6.5.3"
    title = "Ensure Cloud SQL database instances do not implicitly whitelist all public IP addresses"

    try:
        instances = list_sql_instances(session)
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error listing Cloud SQL instances: {e}")

    if not instances:
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No Cloud SQL instances found")

    non_compliant = []
    compliant = []
    for inst in instances:
        name = inst.get("name", "unknown")
        authorized = inst.get("settings", {}).get("ipConfiguration", {}).get("authorizedNetworks", [])
        open_cidrs = [n.get("value", "") for n in authorized if n.get("value") == "0.0.0.0/0"]
        if open_cidrs:
            non_compliant.append(f"{name} (authorized network includes 0.0.0.0/0)")
        else:
            compliant.append(name)

    if non_compliant:
        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "Instances with 0.0.0.0/0 in authorized networks:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, "GCP", Verdict.PASS,
                     f"No Cloud SQL instances whitelist 0.0.0.0/0",
                     {"compliant": compliant})


def check_private_ip(session: GCPSession) -> RequirementResult:
    """ADA 6.8.1: Ensure Instance IP assignment is set to private."""
    spec_id = "6.8.1"
    title = "Ensure Instance IP assignment is set to private"

    try:
        instances = list_sql_instances(session)
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error listing Cloud SQL instances: {e}")

    if not instances:
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No Cloud SQL instances found")

    non_compliant = []
    compliant = []
    for inst in instances:
        name = inst.get("name", "unknown")
        ip_config = inst.get("settings", {}).get("ipConfiguration", {})
        has_public = any(
            addr.get("type") == "PRIMARY"
            for addr in inst.get("ipAddresses", [])
        )
        private_enabled = ip_config.get("privateNetwork") is not None

        if has_public and not private_enabled:
            non_compliant.append(f"{name} (has public IP, no private network)")
        elif has_public:
            non_compliant.append(f"{name} (has public IP assigned)")
        else:
            compliant.append(name)

    if non_compliant:
        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "Instances with public IP:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, "GCP", Verdict.PASS,
                     f"All {len(compliant)} Cloud SQL instances use private IP only",
                     {"compliant": compliant})


def check_mysql_admin_access(session: GCPSession) -> RequirementResult:
    """ADA 6.9.1: Ensure MySQL database does not allow anonymous admin login (INCONCLUSIVE)."""
    return make_result(
        "6.9.1",
        "Ensure Cloud SQL MySQL instance does not allow anyone to connect with administrative privileges",
        "GCP",
        Verdict.INCONCLUSIVE,
        "This check requires a network-level MySQL connection to verify anonymous admin access. "
        "Manual verification required: connect to the MySQL instance and run "
        "'SELECT user, host FROM mysql.user WHERE user = \"\"' to check for anonymous accounts.",
    )


# Special handling for user_options: flag should NOT be configured
def _check_user_options(session: GCPSession) -> RequirementResult:
    """ADA 6.6.1: Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured."""
    spec_id = "6.6.1"
    title = "Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured"

    try:
        instances = list_sql_instances(session)
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error listing Cloud SQL instances: {e}")

    filtered = [i for i in instances if "SQLSERVER" in i.get("databaseVersion", "").upper()]
    if not filtered:
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No SQL Server Cloud SQL instances found")

    non_compliant = []
    compliant = []
    for inst in filtered:
        name = inst.get("name", "unknown")
        value = _get_flag_value(inst, "user options")
        if value is not None:
            non_compliant.append(f"{name} (user options = '{value}', should not be configured)")
        else:
            compliant.append(name)

    if non_compliant:
        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "Non-compliant instances:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, "GCP", Verdict.PASS,
                     f"All {len(compliant)} SQL Server instances do not have 'user options' configured",
                     {"compliant": compliant})


# Override the factory-generated user_options check with the proper one
check_user_options = _check_user_options


check_user_connections = _make_flag_check(
    "6.6.3",
    "Ensure 'user Connections' Database Flag for Cloud SQL SQL Server Instance Is Set to a Non-limiting Value",
    "user connections", "0", "SQLSERVER",
    absent_fails=False,  # Default (not set) is acceptable
)


def check_automated_backups(session: GCPSession) -> RequirementResult:
    """ADA 6.12.2: Ensure Cloud SQL instances are configured with automated backups."""
    spec_id = "6.12.2"
    title = "Ensure That Cloud SQL Database Instances Are Configured With Automated Backups"

    try:
        instances = list_sql_instances(session)
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error listing Cloud SQL instances: {e}")

    if not instances:
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No Cloud SQL instances found")

    non_compliant = []
    compliant = []
    for inst in instances:
        name = inst.get("name", "unknown")
        backup_cfg = inst.get("settings", {}).get("backupConfiguration", {})
        if backup_cfg.get("enabled", False):
            compliant.append(name)
        else:
            non_compliant.append(f"{name} (automated backups not enabled)")

    if non_compliant:
        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "Instances without automated backups:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, "GCP", Verdict.PASS,
                     f"All {len(compliant)} Cloud SQL instances have automated backups enabled",
                     {"compliant": compliant})
