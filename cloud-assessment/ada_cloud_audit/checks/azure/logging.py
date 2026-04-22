"""Azure Logging and Monitoring checks for ADA Cloud assessment.

Covers 16 requirements:
- 3.10.7: Audit logs retained 90 days (custom)
- 3.11.3: Azure Monitor Resource Logging enabled
- 3.11.4: Key Vault logging enabled
- 3.11.5-3.11.14: Activity Log Alerts (10 checks)
- 3.11.15: Diagnostic Setting for Subscription Activity Logs
- 3.11.16: Diagnostic Setting captures appropriate categories
- 3.11.17: Activity Log Alert for Service Health
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict


def _check_activity_log_alert(session: AzureSession, spec_id: str, title: str,
                               operation_name: str) -> RequirementResult:
    """Common helper for Activity Log Alert checks."""
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        client = MonitorManagementClient(session.credential, session.subscription_id)
        alerts = list(client.activity_log_alerts.list_by_subscription_id())

        for alert in alerts:
            if not getattr(alert, "enabled", True):
                continue
            condition = getattr(alert, "condition", None)
            if not condition:
                continue
            all_of = getattr(condition, "all_of", [])
            for cond in all_of:
                field = getattr(cond, "field", "")
                equals = getattr(cond, "equals", "")
                if field == "operationName" and equals == operation_name:
                    return make_result(spec_id, title, "Azure", Verdict.PASS,
                                     f"Activity Log Alert configured for {operation_name}")

        return make_result(spec_id, title, "Azure", Verdict.FAIL,
                         f"No Activity Log Alert found for {operation_name}")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                         f"Error checking activity log alerts: {e}")


def check_audit_log_retention(session: AzureSession) -> RequirementResult:
    """ADA 3.10.7: Ensure audit logs are retained for a minimum of 90 days."""
    return make_result("3.10.7",
        "Ensure That Audit Logs are retained for a Minimum of 90 Days",
        "Azure", Verdict.INCONCLUSIVE,
        "Log retention configuration varies by destination (Log Analytics, Storage Account, Event Hub). "
        "Manual verification required: check retention settings for each diagnostic setting destination.")


def check_resource_logging(session: AzureSession) -> RequirementResult:
    """ADA 3.11.3: Ensure Azure Monitor Resource Logging is enabled for all services."""
    return make_result("3.11.3",
        "Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it",
        "Azure", Verdict.INCONCLUSIVE,
        "Resource-level diagnostic settings must be checked per-resource. "
        "Manual verification required: audit diagnostic settings across all resource types.")


def check_key_vault_logging(session: AzureSession) -> RequirementResult:
    """ADA 3.11.4: Ensure logging for Azure Key Vault is enabled."""
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        from azure.mgmt.keyvault import KeyVaultManagementClient

        kv_client = KeyVaultManagementClient(session.credential, session.subscription_id)
        monitor_client = MonitorManagementClient(session.credential, session.subscription_id)

        vaults = list(kv_client.vaults.list())
        if not vaults:
            return make_result("3.11.4",
                "Ensure that logging for Azure Key Vault is 'Enabled'",
                "Azure", Verdict.PASS, "No Key Vaults found")

        non_compliant = []
        for vault in vaults:
            settings = list(monitor_client.diagnostic_settings.list(vault.id))
            has_logging = any(
                any(getattr(log, "enabled", False) for log in getattr(s, "logs", []))
                for s in settings
            )
            if not has_logging:
                non_compliant.append(vault.name)

        if non_compliant:
            return make_result("3.11.4",
                "Ensure that logging for Azure Key Vault is 'Enabled'",
                "Azure", Verdict.FAIL,
                "Key Vaults without logging:\n" + "\n".join(non_compliant))
        return make_result("3.11.4",
            "Ensure that logging for Azure Key Vault is 'Enabled'",
            "Azure", Verdict.PASS,
            f"All {len(vaults)} Key Vaults have logging enabled")
    except Exception as e:
        return make_result("3.11.4",
            "Ensure that logging for Azure Key Vault is 'Enabled'",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# Activity Log Alert checks (3.11.5 - 3.11.14)
_ACTIVITY_ALERT_CHECKS = {
    "3.11.5": ("Ensure that Activity Log Alert exists for Create Policy Assignment",
               "Microsoft.Authorization/policyAssignments/write"),
    "3.11.6": ("Ensure that Activity Log Alert exists for Delete Policy Assignment",
               "Microsoft.Authorization/policyAssignments/delete"),
    "3.11.7": ("Ensure that Activity Log Alert exists for Create or Update Network Security Group",
               "Microsoft.Network/networkSecurityGroups/write"),
    "3.11.8": ("Ensure that Activity Log Alert exists for Delete Network Security Group",
               "Microsoft.Network/networkSecurityGroups/delete"),
    "3.11.9": ("Ensure that Activity Log Alert exists for Create or Update Security Solution",
               "Microsoft.Security/securitySolutions/write"),
    "3.11.10": ("Ensure that Activity Log Alert exists for Delete Security Solution",
                "Microsoft.Security/securitySolutions/delete"),
    "3.11.11": ("Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule",
                "Microsoft.Sql/servers/firewallRules/write"),
    "3.11.12": ("Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule",
                "Microsoft.Sql/servers/firewallRules/delete"),
    "3.11.13": ("Ensure that Activity Log Alert exists for Create or Update Public IP Address rule",
                "Microsoft.Network/publicIPAddresses/write"),
    "3.11.14": ("Ensure that Activity Log Alert exists for Delete Public IP Address rule",
                "Microsoft.Network/publicIPAddresses/delete"),
}


def _make_alert_check(spec_id: str, title: str, operation_name: str):
    def check_fn(session: AzureSession) -> RequirementResult:
        return _check_activity_log_alert(session, spec_id, title, operation_name)
    check_fn.__doc__ = f"ADA {spec_id}: {title}"
    return check_fn


# Generate alert check functions
check_alert_create_policy = _make_alert_check("3.11.5", *_ACTIVITY_ALERT_CHECKS["3.11.5"])
check_alert_delete_policy = _make_alert_check("3.11.6", *_ACTIVITY_ALERT_CHECKS["3.11.6"])
check_alert_create_nsg = _make_alert_check("3.11.7", *_ACTIVITY_ALERT_CHECKS["3.11.7"])
check_alert_delete_nsg = _make_alert_check("3.11.8", *_ACTIVITY_ALERT_CHECKS["3.11.8"])
check_alert_create_security = _make_alert_check("3.11.9", *_ACTIVITY_ALERT_CHECKS["3.11.9"])
check_alert_delete_security = _make_alert_check("3.11.10", *_ACTIVITY_ALERT_CHECKS["3.11.10"])
check_alert_create_sql_fw = _make_alert_check("3.11.11", *_ACTIVITY_ALERT_CHECKS["3.11.11"])
check_alert_delete_sql_fw = _make_alert_check("3.11.12", *_ACTIVITY_ALERT_CHECKS["3.11.12"])
check_alert_create_public_ip = _make_alert_check("3.11.13", *_ACTIVITY_ALERT_CHECKS["3.11.13"])
check_alert_delete_public_ip = _make_alert_check("3.11.14", *_ACTIVITY_ALERT_CHECKS["3.11.14"])


# New v5 logging checks

def check_diagnostic_setting_exists(session: AzureSession) -> RequirementResult:
    """ADA 3.11.15: Ensure Diagnostic Setting exists for Subscription Activity Logs."""
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        client = MonitorManagementClient(session.credential, session.subscription_id)
        sub_resource_id = f"/subscriptions/{session.subscription_id}"
        settings = list(client.diagnostic_settings.list(sub_resource_id))

        if settings:
            names = [s.name for s in settings]
            return make_result("3.11.15",
                "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs",
                "Azure", Verdict.PASS,
                f"Diagnostic setting(s) found: {', '.join(names)}")
        return make_result("3.11.15",
            "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs",
            "Azure", Verdict.FAIL,
            "No diagnostic settings configured for subscription activity logs")
    except Exception as e:
        return make_result("3.11.15",
            "Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_diagnostic_categories(session: AzureSession) -> RequirementResult:
    """ADA 3.11.16: Ensure Diagnostic Setting captures appropriate categories."""
    return make_result("3.11.16",
        "Ensure Diagnostic Setting captures appropriate categories",
        "Azure", Verdict.INCONCLUSIVE,
        "Diagnostic setting category verification requires checking each setting's log categories. "
        "Manual verification required: ensure Administrative, Security, Alert, and Policy categories are captured.")


def check_alert_service_health(session: AzureSession) -> RequirementResult:
    """ADA 3.11.17: Ensure Activity Log Alert exists for Service Health."""
    return _check_activity_log_alert(session, "3.11.17",
        "Ensure that an Activity Log Alert exists for Service Health",
        "Microsoft.Resourcehealth/healthevent/Activated/action")
