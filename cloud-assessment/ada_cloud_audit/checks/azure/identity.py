"""Azure Identity / Microsoft Entra ID checks for ADA Cloud assessment.

These checks require Microsoft Graph API access which is not yet implemented.
All checks return INCONCLUSIVE with guidance for manual verification.

Covers 21 requirements:
- 2.4.1-2.4.3: Application consent and registration
- 2.7.4: Guest user access restrictions
- 2.8.1: Security Defaults enabled
- 2.9.2: Custom bad password list
- 2.10.2: Guest user review
- 2.11.2-2.11.4: Admin notifications, portal access, custom roles
- 2.13.1: Re-confirm authentication information
- 2.14.1-2.14.8: MFA policies (reset methods, device registration, privileged/non-privileged)
- 2.15.1-2.15.2: MFA for admin groups and Azure Management
- 2.17.1: Notify users on password resets
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict

_NOT_IMPLEMENTED = (
    "This check requires Microsoft Graph API access (Microsoft Entra ID), "
    "which is not yet implemented in the cloud-assessment tool. "
    "Manual verification required via the Microsoft Entra admin center."
)


def _stub(spec_id: str, title: str):
    """Generate a stub check that returns INCONCLUSIVE."""
    def check_fn(session: AzureSession) -> RequirementResult:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, _NOT_IMPLEMENTED)
    check_fn.__doc__ = f"ADA {spec_id}: {title} (not yet automated)"
    return check_fn


check_user_consent = _stub("2.4.1",
    "Ensure 'User consent for applications' is set to 'Do not allow user consent'")

check_gallery_apps = _stub("2.4.2",
    "Ensure that 'Users can add gallery apps to My Apps' is set to 'No'")

check_register_apps = _stub("2.4.3",
    "Ensure That 'Users Can Register Applications' Is Set to 'No'")

check_guest_access_restrictions = _stub("2.7.4",
    "Ensure That 'Guest users access restrictions' is set to restricted")

check_security_defaults = _stub("2.8.1",
    "Ensure Security Defaults is enabled on Microsoft Entra ID")

check_bad_password_list = _stub("2.9.2",
    "Ensure that a Custom Bad Password List is set to 'Enforce'")

check_guest_users_reviewed = _stub("2.10.2",
    "Ensure Guest Users Are Reviewed on a Regular Basis")

check_notify_admin_password_reset = _stub("2.11.2",
    "Ensure 'Notify all admins when other admins reset their password?' is set to 'Yes'")

check_restrict_admin_portal = _stub("2.11.3",
    "Ensure 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'")

check_no_custom_sub_admin_roles = _stub("2.11.4",
    "Ensure That No Custom Subscription Administrator Roles Exist")

check_reconfirm_auth_info = _stub("2.13.1",
    "Ensure 'Number of days before users are asked to re-confirm their authentication information' is set to '90'")

check_reset_methods = _stub("2.14.1",
    "Ensure That 'Number of methods required to reset' is set to '2'")

check_mfa_register_devices = _stub("2.14.2",
    "Ensure 'Require MFA to register or join devices with Microsoft Entra' is set to 'Yes'")

check_mfa_privileged = _stub("2.14.3",
    "Ensure 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users")

check_mfa_remember_disabled = _stub("2.14.4",
    "Ensure 'Allow users to remember MFA on devices they trust' is Disabled")

check_mfa_policy_all_users = _stub("2.14.5",
    "Ensure that A Multi-factor Authentication Policy Exists for All Users")

check_mfa_risky_signins = _stub("2.14.6",
    "Ensure Multi-factor Authentication is Required for Risky Sign-ins")

check_mfa_non_privileged = _stub("2.14.8",
    "Ensure 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users")

check_mfa_admin_groups = _stub("2.15.1",
    "Ensure A Multi-factor Authentication Policy Exists for Administrative Groups")

check_mfa_azure_management = _stub("2.15.2",
    "Ensure Multi-factor Authentication is Required for Azure Management")

check_notify_password_resets = _stub("2.17.1",
    "Ensure 'Notify users on password resets?' is set to 'Yes'")


# --- Non-identity checks that are marked REMOVED in CIS v5 ---
# These return INCONCLUSIVE noting they are no longer in the current CIS benchmark.

_REMOVED = (
    "This check has been removed or reclassified in CIS Azure Foundations "
    "Benchmark v5.0.0 and is not evaluated by the cloud-assessment tool. "
    "See the Specification for details."
)


def _removed_stub(spec_id: str, title: str):
    """Generate a stub for checks removed in CIS v5."""
    def check_fn(session: AzureSession) -> RequirementResult:
        return make_result(spec_id, title, "Azure", Verdict.NOT_APPLICABLE, _REMOVED)
    check_fn.__doc__ = f"ADA {spec_id}: {title} (removed in CIS v5)"
    return check_fn


check_approved_extensions = _removed_stub("1.1.1",
    "Ensure that Only Approved Extensions Are Installed")

check_managed_disks = _removed_stub("1.4.1",
    "Ensure Virtual Machines are utilizing Managed Disks")

check_storage_activity_logs = _removed_stub("3.5.2",
    "Ensure the Storage Container Storing the Activity Logs is not Publicly Accessible")

check_auto_provisioning = _removed_stub("3.8.1",
    "Ensure Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'")

check_pg_allow_azure_services = _removed_stub("6.7.1",
    "Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled")
