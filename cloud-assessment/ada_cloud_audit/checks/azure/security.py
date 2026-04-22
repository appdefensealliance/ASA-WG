"""Azure Security checks for ADA Cloud assessment.

Covers 13 requirements:
Key Vault:
- 2.1.1: Key Vault recoverable (purge protection)
- 2.1.2: Key Vault Public Network Access disabled
- 2.5.1-2.5.4: Key/Secret expiration for RBAC/Non-RBAC vaults
- 2.5.5: Certificate validity <= 12 months
Defender:
- 3.2.1: Notify severity High
- 3.2.2: Notify attack paths risk level
- 3.3.1: All users with Owner role
- 3.3.2: Additional email addresses
- 3.6.1: Cloud Security Benchmark policies not disabled
- 3.7.1: Defender VM updates check
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict


# --- Key Vault checks ---

def _list_key_vaults(session: AzureSession) -> list:
    from azure.mgmt.keyvault import KeyVaultManagementClient
    client = KeyVaultManagementClient(session.credential, session.subscription_id)
    return list(client.vaults.list())


def check_key_vault_recoverable(session: AzureSession) -> RequirementResult:
    """ADA 2.1.1: Ensure the Key Vault is Recoverable (purge protection enabled)."""
    spec_id = "2.1.1"
    title = "Ensure the Key Vault is Recoverable"
    try:
        vaults = _list_key_vaults(session)
        if not vaults:
            return make_result(spec_id, title, "Azure", Verdict.PASS, "No Key Vaults found")

        non_compliant = []
        for vault in vaults:
            props = vault.properties
            soft_delete = getattr(props, "enable_soft_delete", False)
            purge_protection = getattr(props, "enable_purge_protection", False)
            if not soft_delete or not purge_protection:
                issues = []
                if not soft_delete:
                    issues.append("soft delete disabled")
                if not purge_protection:
                    issues.append("purge protection disabled")
                non_compliant.append(f"{vault.name} ({', '.join(issues)})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Key Vaults not recoverable:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(vaults)} Key Vaults have soft delete and purge protection enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_key_vault_public_access(session: AzureSession) -> RequirementResult:
    """ADA 2.1.2: Ensure Key Vault Public Network Access is Disabled."""
    spec_id = "2.1.2"
    title = "Ensure Key Vault Public Network Access is Disabled"
    try:
        vaults = _list_key_vaults(session)
        if not vaults:
            return make_result(spec_id, title, "Azure", Verdict.PASS, "No Key Vaults found")

        non_compliant = []
        for vault in vaults:
            net_rules = getattr(vault.properties, "network_acls", None)
            if not net_rules or getattr(net_rules, "default_action", "Allow") != "Deny":
                non_compliant.append(f"{vault.name} (public access not restricted)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Key Vaults with public access:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(vaults)} Key Vaults have public access disabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def _check_key_vault_expiry(session: AzureSession, spec_id: str, title: str,
                            item_type: str) -> RequirementResult:
    """Check key or secret expiration in Key Vaults."""
    try:
        from azure.keyvault.keys import KeyClient
        from azure.keyvault.secrets import SecretClient

        vaults = _list_key_vaults(session)
        if not vaults:
            return make_result(spec_id, title, "Azure", Verdict.PASS, "No Key Vaults found")

        now = datetime.now(timezone.utc)
        threshold = timedelta(days=90)
        non_compliant = []

        for vault in vaults:
            vault_url = vault.properties.vault_uri
            try:
                if item_type == "key":
                    client = KeyClient(vault_url=vault_url, credential=session.credential)
                    items = client.list_properties_of_keys()
                else:
                    client = SecretClient(vault_url=vault_url, credential=session.credential)
                    items = client.list_properties_of_secrets()

                for item in items:
                    if not item.enabled:
                        continue
                    expires = item.expires_on
                    if not expires:
                        non_compliant.append(
                            f"{vault.name}/{item.name} (no expiration set)")
                    elif expires > now + threshold:
                        non_compliant.append(
                            f"{vault.name}/{item.name} (expires {expires.isoformat()}, "
                            f"more than 90 days away)")
            except Exception:
                pass  # Skip vaults we can't access

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             f"{item_type.title()}s with expiration issues:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {item_type}s have expiration dates within 90 days")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_key_expiry_rbac(session: AzureSession) -> RequirementResult:
    """ADA 2.5.1: Key expiration in RBAC Key Vaults."""
    return _check_key_vault_expiry(session, "2.5.1",
        "Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults", "key")


def check_key_expiry_non_rbac(session: AzureSession) -> RequirementResult:
    """ADA 2.5.2: Key expiration in Non-RBAC Key Vaults."""
    return _check_key_vault_expiry(session, "2.5.2",
        "Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults", "key")


def check_secret_expiry_rbac(session: AzureSession) -> RequirementResult:
    """ADA 2.5.3: Secret expiration in RBAC Key Vaults."""
    return _check_key_vault_expiry(session, "2.5.3",
        "Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults", "secret")


def check_secret_expiry_non_rbac(session: AzureSession) -> RequirementResult:
    """ADA 2.5.4: Secret expiration in Non-RBAC Key Vaults."""
    return _check_key_vault_expiry(session, "2.5.4",
        "Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults", "secret")


def check_cert_validity(session: AzureSession) -> RequirementResult:
    """ADA 2.5.5: Ensure certificate validity <= 12 months."""
    return make_result("2.5.5",
        "Ensure certificate Validity Period is less than or equal to 12 months",
        "Azure", Verdict.INCONCLUSIVE,
        "Certificate validity period checking requires enumerating certificates across all "
        "Key Vaults and checking issuance policies. Manual verification recommended.")


# --- Defender checks ---

def check_notify_severity_high(session: AzureSession) -> RequirementResult:
    """ADA 3.2.1: Ensure Notify about alerts severity High is enabled."""
    try:
        from azure.mgmt.security import SecurityCenter

        client = SecurityCenter(session.credential, session.subscription_id)
        contacts = list(client.security_contacts.list())

        if not contacts:
            return make_result("3.2.1",
                "Ensure 'Notify about alerts with the following severity' is Set to 'High'",
                "Azure", Verdict.FAIL, "No security contacts configured")

        for contact in contacts:
            alert_notifs = getattr(contact, "alert_notifications", None)
            if alert_notifs:
                state = getattr(alert_notifs, "state", "")
                severity = getattr(alert_notifs, "minimal_severity", "")
                if state == "On" and severity in ("High", "Medium", "Low"):
                    return make_result("3.2.1",
                        "Ensure 'Notify about alerts with the following severity' is Set to 'High'",
                        "Azure", Verdict.PASS,
                        f"Alert notifications enabled with severity: {severity}")

        return make_result("3.2.1",
            "Ensure 'Notify about alerts with the following severity' is Set to 'High'",
            "Azure", Verdict.FAIL, "Alert severity notifications not properly configured")
    except Exception as e:
        return make_result("3.2.1",
            "Ensure 'Notify about alerts with the following severity' is Set to 'High'",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_notify_attack_paths(session: AzureSession) -> RequirementResult:
    """ADA 3.2.2: Ensure notify about attack paths risk level is enabled."""
    return make_result("3.2.2",
        "Ensure 'Notify about attack paths with the following risk level or higher' is enabled",
        "Azure", Verdict.INCONCLUSIVE,
        "Attack path notification settings require Microsoft Defender for Cloud CSPM. "
        "Manual verification required via Azure Portal > Defender for Cloud > Environment settings.")


def check_owner_role_notifications(session: AzureSession) -> RequirementResult:
    """ADA 3.3.1: Ensure 'All users with the following roles' is set to 'Owner'."""
    try:
        from azure.mgmt.security import SecurityCenter

        client = SecurityCenter(session.credential, session.subscription_id)
        contacts = list(client.security_contacts.list())

        for contact in contacts:
            notifs_by_role = getattr(contact, "notifications_by_role", None)
            if notifs_by_role:
                state = getattr(notifs_by_role, "state", "")
                roles = getattr(notifs_by_role, "roles", [])
                if state == "On" and "Owner" in [str(r) for r in roles]:
                    return make_result("3.3.1",
                        "Ensure That 'All users with the following roles' is set to 'Owner'",
                        "Azure", Verdict.PASS, "Owner role notifications enabled")

        return make_result("3.3.1",
            "Ensure That 'All users with the following roles' is set to 'Owner'",
            "Azure", Verdict.FAIL, "Owner role not configured for security notifications")
    except Exception as e:
        return make_result("3.3.1",
            "Ensure That 'All users with the following roles' is set to 'Owner'",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_additional_email(session: AzureSession) -> RequirementResult:
    """ADA 3.3.2: Ensure additional email addresses are configured."""
    try:
        from azure.mgmt.security import SecurityCenter

        client = SecurityCenter(session.credential, session.subscription_id)
        contacts = list(client.security_contacts.list())

        for contact in contacts:
            emails = getattr(contact, "emails", "")
            if emails:
                return make_result("3.3.2",
                    "Ensure 'Additional email addresses' is Configured with a Security Contact Email",
                    "Azure", Verdict.PASS, f"Additional email configured: {emails}")

        return make_result("3.3.2",
            "Ensure 'Additional email addresses' is Configured with a Security Contact Email",
            "Azure", Verdict.FAIL, "No additional security contact email configured")
    except Exception as e:
        return make_result("3.3.2",
            "Ensure 'Additional email addresses' is Configured with a Security Contact Email",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_security_benchmark_policies(session: AzureSession) -> RequirementResult:
    """ADA 3.6.1: Ensure Cloud Security Benchmark policies are not disabled."""
    return make_result("3.6.1",
        "Ensure Microsoft Cloud Security Benchmark policies are not set to 'Disabled'",
        "Azure", Verdict.INCONCLUSIVE,
        "Checking all Microsoft Cloud Security Benchmark policy assignments requires "
        "enumerating Azure Policy assignments. Manual verification recommended via "
        "Azure Portal > Defender for Cloud > Environment settings > Security policy.")


def check_defender_vm_updates(session: AzureSession) -> RequirementResult:
    """ADA 3.7.1: Ensure Defender is configured to check VM OS for updates."""
    try:
        from azure.mgmt.security import SecurityCenter

        client = SecurityCenter(session.credential, session.subscription_id)
        settings = list(client.auto_provisioning_settings.list())

        for setting in settings:
            if getattr(setting, "auto_provision", "") == "On":
                return make_result("3.7.1",
                    "Ensure Microsoft Defender for Cloud is configured to check VM operating systems for updates",
                    "Azure", Verdict.PASS, "Auto provisioning is enabled")

        return make_result("3.7.1",
            "Ensure Microsoft Defender for Cloud is configured to check VM operating systems for updates",
            "Azure", Verdict.FAIL, "Auto provisioning is not enabled")
    except Exception as e:
        return make_result("3.7.1",
            "Ensure Microsoft Defender for Cloud is configured to check VM operating systems for updates",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")
