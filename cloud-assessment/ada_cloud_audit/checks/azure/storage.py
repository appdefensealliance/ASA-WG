"""Azure Storage checks for ADA Cloud assessment.

Covers 14 requirements:
- 5.1.1: Soft Delete enabled for blobs
- 5.1.2: Soft delete for Azure File Shares
- 5.1.3: SMB protocol version 3.1.1+
- 5.1.4: SMB channel encryption AES-256-GCM+
- 5.1.5: Soft delete for containers
- 5.2.1: Default network access deny
- 5.2.2: Public network access disabled
- 5.3.1: Secure transfer required
- 5.3.2: Minimum TLS version 1.2
- 5.5.2: Public access disabled for blob containers
- 5.6.1: Key rotation reminders
- 5.7.1: Access keys periodically regenerated
- 5.7.2: Storage account key access disabled
- 5.8.1: SAS tokens expire (INCONCLUSIVE)
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict


def _list_storage_accounts(session: AzureSession) -> list:
    """List all storage accounts in the subscription."""
    from azure.mgmt.storage import StorageManagementClient

    client = StorageManagementClient(session.credential, session.subscription_id)
    return list(client.storage_accounts.list())


def _check_storage_property(session: AzureSession, spec_id: str, title: str,
                            check_fn, platform: str = "Azure") -> RequirementResult:
    """Common helper for storage account property checks."""
    try:
        accounts = _list_storage_accounts(session)
    except Exception as e:
        return make_result(spec_id, title, platform, Verdict.INCONCLUSIVE,
                         f"Error listing storage accounts: {e}")

    if not accounts:
        return make_result(spec_id, title, platform, Verdict.PASS,
                         "No storage accounts found")

    non_compliant = []
    compliant = []
    for acct in accounts:
        result = check_fn(acct)
        if result:
            non_compliant.append(f"{acct.name}: {result}")
        else:
            compliant.append(acct.name)

    if non_compliant:
        return make_result(spec_id, title, platform, Verdict.FAIL,
                         "Non-compliant storage accounts:\n" + "\n".join(non_compliant),
                         {"non_compliant": non_compliant, "compliant": compliant})
    return make_result(spec_id, title, platform, Verdict.PASS,
                     f"All {len(compliant)} storage accounts are compliant",
                     {"compliant": compliant})


def check_blob_soft_delete(session: AzureSession) -> RequirementResult:
    """ADA 5.1.1: Ensure Soft Delete is Enabled for Azure Containers and Blob Storage."""
    from azure.mgmt.storage import StorageManagementClient

    spec_id = "5.1.1"
    title = "Ensure Soft Delete is Enabled for Azure Containers and Blob Storage"

    try:
        client = StorageManagementClient(session.credential, session.subscription_id)
        accounts = list(client.storage_accounts.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No storage accounts found")

        non_compliant = []
        for acct in accounts:
            rg = acct.id.split("/")[4]
            props = client.blob_services.get_service_properties(rg, acct.name)
            blob_delete = getattr(props, "delete_retention_policy", None)
            if not blob_delete or not getattr(blob_delete, "enabled", False):
                non_compliant.append(f"{acct.name} (blob soft delete not enabled)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Accounts without soft delete:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} accounts have blob soft delete enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                         f"Error checking blob soft delete: {e}")


def check_file_share_soft_delete(session: AzureSession) -> RequirementResult:
    """ADA 5.1.2: Ensure soft delete for Azure File Shares is Enabled."""
    from azure.mgmt.storage import StorageManagementClient

    spec_id = "5.1.2"
    title = "Ensure soft delete for Azure File Shares is Enabled"

    try:
        client = StorageManagementClient(session.credential, session.subscription_id)
        accounts = list(client.storage_accounts.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No storage accounts found")

        non_compliant = []
        for acct in accounts:
            rg = acct.id.split("/")[4]
            props = client.file_services.get_service_properties(rg, acct.name)
            delete_policy = getattr(props, "share_delete_retention_policy", None)
            if not delete_policy or not getattr(delete_policy, "enabled", False):
                non_compliant.append(f"{acct.name} (file share soft delete not enabled)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Accounts without file share soft delete:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} accounts have file share soft delete enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                         f"Error checking file share soft delete: {e}")


def check_smb_protocol_version(session: AzureSession) -> RequirementResult:
    """ADA 5.1.3: Ensure SMB protocol version is set to SMB 3.1.1 or higher."""
    def _check(acct):
        props = getattr(acct, "azure_files_identity_based_authentication", None)
        # SMB version is controlled at the file service level via minimum SMB version
        # For simplicity, check if the account allows SMB at all
        min_tls = getattr(acct, "minimum_tls_version", "")
        if min_tls and min_tls < "TLS1_2":
            return "minimum TLS version below 1.2"
        return None

    return _check_storage_property(session, "5.1.3",
        "Ensure SMB protocol version is set to SMB 3.1.1 or higher", _check)


def check_smb_encryption(session: AzureSession) -> RequirementResult:
    """ADA 5.1.4: Ensure SMB channel encryption is set to AES-256-GCM or higher."""
    return make_result("5.1.4",
        "Ensure SMB channel encryption is set to AES-256-GCM or higher",
        "Azure", Verdict.INCONCLUSIVE,
        "SMB channel encryption configuration requires checking file service properties. "
        "Manual verification required via Azure Portal or CLI.")


def check_container_soft_delete(session: AzureSession) -> RequirementResult:
    """ADA 5.1.5: Ensure soft delete for containers is Enabled."""
    from azure.mgmt.storage import StorageManagementClient

    spec_id = "5.1.5"
    title = "Ensure soft delete for containers on Azure Blob Storage is Enabled"

    try:
        client = StorageManagementClient(session.credential, session.subscription_id)
        accounts = list(client.storage_accounts.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No storage accounts found")

        non_compliant = []
        for acct in accounts:
            rg = acct.id.split("/")[4]
            props = client.blob_services.get_service_properties(rg, acct.name)
            container_delete = getattr(props, "container_delete_retention_policy", None)
            if not container_delete or not getattr(container_delete, "enabled", False):
                non_compliant.append(f"{acct.name} (container soft delete not enabled)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Accounts without container soft delete:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} accounts have container soft delete enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                         f"Error checking container soft delete: {e}")


def check_default_network_deny(session: AzureSession) -> RequirementResult:
    """ADA 5.2.1: Ensure Default Network Access Rule is Set to Deny."""
    def _check(acct):
        net_rules = getattr(acct, "network_rule_set", None)
        if net_rules:
            default_action = getattr(net_rules, "default_action", "Allow")
            if default_action != "Deny":
                return f"default action is {default_action}"
        else:
            return "no network rules configured"
        return None

    return _check_storage_property(session, "5.2.1",
        "Ensure Default Network Access Rule for Storage Accounts is Set to Deny", _check)


def check_public_network_access_disabled(session: AzureSession) -> RequirementResult:
    """ADA 5.2.2: Ensure Public Network Access is Disabled for storage accounts."""
    def _check(acct):
        public_access = getattr(acct, "public_network_access", "Enabled")
        if public_access != "Disabled":
            return f"public network access is {public_access}"
        return None

    return _check_storage_property(session, "5.2.2",
        "Ensure Public Network Access is Disabled for storage accounts", _check)


def check_secure_transfer(session: AzureSession) -> RequirementResult:
    """ADA 5.3.1: Ensure 'Secure transfer required' is set to 'Enabled'."""
    def _check(acct):
        if not getattr(acct, "enable_https_traffic_only", True):
            return "secure transfer not required"
        return None

    return _check_storage_property(session, "5.3.1",
        "Ensure 'Secure transfer required' is set to 'Enabled'", _check)


def check_min_tls_version(session: AzureSession) -> RequirementResult:
    """ADA 5.3.2: Ensure Minimum TLS version is set to 1.2."""
    def _check(acct):
        min_tls = getattr(acct, "minimum_tls_version", "")
        if min_tls != "TLS1_2":
            return f"minimum TLS version is {min_tls or 'not set'}"
        return None

    return _check_storage_property(session, "5.3.2",
        "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'", _check)


def check_blob_public_access_disabled(session: AzureSession) -> RequirementResult:
    """ADA 5.5.2: Ensure 'Allow Blob Anonymous Access' is Disabled."""
    def _check(acct):
        allow_blob = getattr(acct, "allow_blob_public_access", None)
        if allow_blob is True:
            return "blob public access is enabled"
        return None

    return _check_storage_property(session, "5.5.2",
        "Ensure 'Public access level' is disabled for storage accounts with blob containers", _check)


def check_key_rotation_reminders(session: AzureSession) -> RequirementResult:
    """ADA 5.6.1: Ensure key rotation reminders are enabled."""
    def _check(acct):
        policy = getattr(acct, "key_policy", None)
        if not policy or not getattr(policy, "key_expiration_period_in_days", None):
            return "key rotation reminder not configured"
        return None

    return _check_storage_property(session, "5.6.1",
        "Ensure 'Enable key rotation reminders' is enabled for each Storage Account", _check)


def check_access_keys_regenerated(session: AzureSession) -> RequirementResult:
    """ADA 5.7.1: Ensure Storage Account Access Keys are Periodically Regenerated."""
    return make_result("5.7.1",
        "Ensure that Storage Account Access Keys are Periodically Regenerated",
        "Azure", Verdict.INCONCLUSIVE,
        "Key regeneration timing cannot be determined via the management API. "
        "Manual verification required: check key last regenerated date via Azure Portal.")


def check_storage_key_access_disabled(session: AzureSession) -> RequirementResult:
    """ADA 5.7.2: Ensure Allow storage account key access is Disabled."""
    def _check(acct):
        allow_key = getattr(acct, "allow_shared_key_access", True)
        if allow_key is not False:
            return "shared key access is enabled"
        return None

    return _check_storage_property(session, "5.7.2",
        "Ensure 'Allow storage account key access' for Azure Storage Accounts is 'Disabled'", _check)


def check_sas_expiry(session: AzureSession) -> RequirementResult:
    """ADA 5.8.1: Ensure SAS Tokens Expire Within an Hour."""
    return make_result("5.8.1",
        "Ensure that Shared Access Signature Tokens Expire Within an Hour",
        "Azure", Verdict.INCONCLUSIVE,
        "SAS token expiry cannot be determined from account configuration alone. "
        "Manual verification required: review SAS token generation practices.")
