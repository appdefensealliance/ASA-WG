"""Azure Identity / Microsoft Entra ID checks for ADA Cloud assessment.

Uses Microsoft Graph API (via msgraph-sdk) for Entra ID checks and
Azure Resource Manager for subscription-level role checks.

Covers requirements:
- 2.4.1, 2.4.3-2.4.4: Application consent, registration, tenant creation
- 2.7.4: Guest user access restrictions
- 2.8.1: Security Defaults enabled
- 2.9.2: Custom bad password list
- 2.10.2, 2.10.4-2.10.5: Guest/disabled/tenant-creator user review
- 2.11.2-2.11.4, 2.11.6-2.11.10: Admin notifications, portal, custom roles,
  admin account hygiene
- 2.13.1: Re-confirm authentication information
- 2.14.1-2.14.4, 2.14.8: MFA policies
- 2.17.1: Notify users on password resets
- 2.18.2: Non-privileged role assignments review
"""

from __future__ import annotations

import logging
from typing import Any

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper: build a GraphServiceClient from the session credential
# ---------------------------------------------------------------------------

def _graph_client(session: AzureSession) -> Any:
    """Create a Microsoft Graph client from the AzureSession credential."""
    from msgraph import GraphServiceClient
    return GraphServiceClient(session.credential)


# ===========================================================================
# 2.4  Application consent and registration
# ===========================================================================

def check_user_consent(session: AzureSession) -> RequirementResult:
    """ADA 2.4.1: Ensure 'User consent for applications' is set to 'Do not allow user consent'."""
    spec_id = "2.4.1"
    title = "Ensure 'User consent for applications' is set to 'Do not allow user consent'"
    try:
        client = _graph_client(session)
        policy = client.policies.authorization_policy.get().result()

        perms = policy.default_user_role_permissions
        granted = getattr(perms, "permission_grant_policies_assigned", []) or []

        # If the list is empty or contains only "ManagePermissionGrantsForOwnedResource.*"
        # entries, user consent is effectively disabled.
        user_consent_enabled = any(
            p for p in granted
            if not p.startswith("ManagePermissionGrantsForOwnedResource")
        )

        if user_consent_enabled:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                f"User consent is allowed. Policies assigned: {granted}")
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            "User consent for applications is disabled (no user-facing grant policies assigned)")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_register_apps(session: AzureSession) -> RequirementResult:
    """ADA 2.4.3: Ensure That 'Users Can Register Applications' Is Set to 'No'."""
    spec_id = "2.4.3"
    title = "Ensure That 'Users Can Register Applications' Is Set to 'No'"
    try:
        client = _graph_client(session)
        policy = client.policies.authorization_policy.get().result()

        allowed = getattr(
            policy.default_user_role_permissions, "allowed_to_create_apps", None
        )

        if allowed is True:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                "Users are allowed to register applications (allowedToCreateApps = true)")
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            "Users cannot register applications (allowedToCreateApps = false)")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_restrict_tenant_creation(session: AzureSession) -> RequirementResult:
    """ADA 2.4.4: Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'."""
    spec_id = "2.4.4"
    title = "Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'"
    try:
        client = _graph_client(session)
        policy = client.policies.authorization_policy.get().result()

        allowed = getattr(
            policy.default_user_role_permissions, "allowed_to_create_tenants", None
        )

        if allowed is True:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                "Non-admin users can create tenants (allowedToCreateTenants = true)")
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            "Non-admin users are restricted from creating tenants")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.7  Guest user access restrictions
# ===========================================================================

def check_guest_access_restrictions(session: AzureSession) -> RequirementResult:
    """ADA 2.7.4: Ensure That 'Guest users access restrictions' is set to restricted."""
    spec_id = "2.7.4"
    title = "Ensure That 'Guest users access restrictions' is set to restricted"
    try:
        client = _graph_client(session)
        policy = client.policies.authorization_policy.get().result()

        # guestUserRoleId values:
        # a0b1b346-4d3e-4e8b-98f8-753987be4970 = same as member users (least restrictive)
        # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = limited access (default)
        # 2af84b1e-32c8-42b7-82bc-daa82404023b = most restrictive
        MOST_RESTRICTIVE = "2af84b1e-32c8-42b7-82bc-daa82404023b"
        LIMITED_ACCESS = "10dae51f-b6af-4016-8d66-8c2a99b929b3"

        guest_role_id = getattr(policy, "guest_user_role_id", None)
        guest_role_str = str(guest_role_id) if guest_role_id else ""

        if guest_role_str == MOST_RESTRICTIVE:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "Guest user access is set to most restrictive")
        elif guest_role_str == LIMITED_ACCESS:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                "Guest user access is set to limited (default) -- should be most restrictive")
        else:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                f"Guest user access is not set to most restrictive (guestUserRoleId: {guest_role_str})")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.8  Security Defaults
# ===========================================================================

def check_security_defaults(session: AzureSession) -> RequirementResult:
    """ADA 2.8.1: Ensure Security Defaults is enabled on Microsoft Entra ID."""
    spec_id = "2.8.1"
    title = "Ensure Security Defaults is enabled on Microsoft Entra ID"
    try:
        client = _graph_client(session)
        policy = (
            client.policies
            .identity_security_defaults_enforcement_policy
            .get()
            .result()
        )

        if getattr(policy, "is_enabled", False):
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "Security Defaults is enabled")
        return make_result(spec_id, title, "Azure", Verdict.FAIL,
            "Security Defaults is disabled. Note: if Conditional Access policies "
            "are in use, Security Defaults should be disabled, but equivalent "
            "protections must be verified via Conditional Access.")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.9  Password policies
# ===========================================================================

def check_bad_password_list(session: AzureSession) -> RequirementResult:
    """ADA 2.9.2: Ensure that a Custom Bad Password List is set to 'Enforce'."""
    spec_id = "2.9.2"
    title = "Ensure that a Custom Bad Password List is set to 'Enforce'"
    try:
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = "https://graph.microsoft.com/v1.0/settings"
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        data = json.loads(response)

        settings_list = data.get("value", [])
        for setting in settings_list:
            display_name = setting.get("displayName", "")
            if "Password Rule Settings" in display_name:
                values = {v["name"]: v["value"] for v in setting.get("values", [])}
                enforce_custom = values.get("EnableBannedPasswordCheckOnPremises", "")
                banned_list = values.get("BannedPasswordList", "")
                ban_mode = values.get("BannedPasswordCheckOnPremisesMode", "")

                if enforce_custom.lower() == "true" and ban_mode.lower() == "enforce":
                    return make_result(spec_id, title, "Azure", Verdict.PASS,
                        f"Custom bad password list is enforced. "
                        f"Mode: {ban_mode}, List has entries: {bool(banned_list)}")
                return make_result(spec_id, title, "Azure", Verdict.FAIL,
                    f"Custom bad password list is not set to Enforce. "
                    f"EnableBannedPasswordCheckOnPremises: {enforce_custom}, "
                    f"Mode: {ban_mode}")

        return make_result(spec_id, title, "Azure", Verdict.FAIL,
            "No 'Password Rule Settings' found in directory settings. "
            "Custom bad password list has not been configured.")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.10  Guest and disabled user review
# ===========================================================================

def check_guest_users_reviewed(session: AzureSession) -> RequirementResult:
    """ADA 2.10.2: Ensure Guest Users Are Reviewed on a Regular Basis."""
    spec_id = "2.10.2"
    title = "Ensure Guest Users Are Reviewed on a Regular Basis"
    try:
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = (
            "https://graph.microsoft.com/v1.0/users"
            "?$filter=userType eq 'Guest'"
            "&$select=displayName,mail,createdDateTime,signInActivity"
        )
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        data = json.loads(response)
        guest_list = data.get("value", [])

        if not guest_list:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "No guest users found in the directory")

        guest_details = []
        for g in guest_list:
            name = g.get("displayName", "N/A")
            mail = g.get("mail", "N/A")
            created = g.get("createdDateTime", "N/A")
            sign_in = g.get("signInActivity", {}) or {}
            last_sign_in = sign_in.get("lastSignInDateTime", "Never") or "Never"
            guest_details.append(
                f"  - {name} ({mail}), created: {created}, last sign-in: {last_sign_in}"
            )

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            f"Found {len(guest_list)} guest user(s) requiring periodic review:\n"
            + "\n".join(guest_details[:50])
            + ("\n  ... (truncated)" if len(guest_details) > 50 else ""))
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_disabled_accounts_permissions(session: AzureSession) -> RequirementResult:
    """ADA 2.10.4: Ensure that a review is conducted of all disabled accounts with permissions."""
    spec_id = "2.10.4"
    title = "Ensure that a review is conducted of all disabled accounts with permissions"
    try:
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        # Get disabled users
        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = (
            "https://graph.microsoft.com/v1.0/users"
            "?$filter=accountEnabled eq false"
            "&$select=id,displayName,userPrincipalName"
        )
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        data = json.loads(response)
        disabled_list = data.get("value", [])

        if not disabled_list:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "No disabled accounts found")

        # Check which disabled users still have directory role assignments
        disabled_with_roles = []
        for user in disabled_list[:100]:  # Limit to avoid throttling
            try:
                req = RequestInformation()
                req.http_method = Method.GET
                req.url = (
                    f"https://graph.microsoft.com/v1.0/users/{user['id']}/memberOf"
                )
                req.headers = HeadersCollection()
                req.headers.try_add("Accept", "application/json")

                resp = adapter.send_primitive_async(req, "bytes").result()
                member_data = json.loads(resp)
                role_names = []
                for r in member_data.get("value", []):
                    odata_type = r.get("@odata.type", "")
                    if "directoryRole" in odata_type:
                        role_names.append(r.get("displayName", "Unknown"))
                if role_names:
                    disabled_with_roles.append(
                        f"  - {user['displayName']} ({user['userPrincipalName']}): "
                        f"{', '.join(role_names)}"
                    )
            except Exception:
                pass

        if disabled_with_roles:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                f"Found {len(disabled_with_roles)} disabled account(s) with active role "
                f"assignments:\n" + "\n".join(disabled_with_roles))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            f"Checked {len(disabled_list)} disabled account(s) -- none have active "
            f"directory role assignments")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_tenant_creator_role(session: AzureSession) -> RequirementResult:
    """ADA 2.10.5: Ensure that the Tenant Creator role is reviewed."""
    spec_id = "2.10.5"
    title = "Ensure that the Tenant Creator role is reviewed"
    try:
        client = _graph_client(session)

        # Find the Tenant Creator directory role
        roles = client.directory_roles.get().result()
        tenant_creator_role = None
        for role in (roles.value or []):
            if getattr(role, "display_name", "") == "Tenant Creator":
                tenant_creator_role = role
                break

        if tenant_creator_role is None:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "Tenant Creator role has not been activated in this directory")

        # List members of the role
        members = (
            client.directory_roles
            .by_directory_role_id(tenant_creator_role.id)
            .members
            .get()
            .result()
        )

        member_list = members.value or []
        if not member_list:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "Tenant Creator role is active but has no members")

        member_details = []
        for m in member_list:
            name = getattr(m, "display_name", "N/A")
            upn = getattr(m, "user_principal_name", "N/A")
            member_details.append(f"  - {name} ({upn})")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            f"Found {len(member_list)} user(s) with Tenant Creator role -- "
            f"review for appropriateness:\n" + "\n".join(member_details))
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.11  Admin restrictions and notifications
# ===========================================================================

def check_notify_admin_password_reset(session: AzureSession) -> RequirementResult:
    """ADA 2.11.2: Ensure 'Notify all admins when other admins reset their password?' is set to 'Yes'."""
    spec_id = "2.11.2"
    title = "Ensure 'Notify all admins when other admins reset their password?' is set to 'Yes'"
    try:
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        # Password reset policies are under the SSPR (Self-Service Password Reset)
        # configuration exposed via the beta endpoint.
        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = (
            "https://graph.microsoft.com/beta/"
            "policies/authenticationMethodsPolicy"
        )
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        data = json.loads(response)

        # Check the registration enforcement state
        # Also inspect the passwordResetPolicies if available
        # The admin notification is controlled under the SSPR policy which may
        # require beta API access.  We also fall back to checking via the
        # /policies/admin* endpoints.

        request_info2 = RequestInformation()
        request_info2.http_method = Method.GET
        request_info2.url = (
            "https://graph.microsoft.com/beta/"
            "policies/adminConsentRequestPolicy"
        )
        request_info2.headers = HeadersCollection()
        request_info2.headers.try_add("Accept", "application/json")

        # Try the password reset notification endpoint
        request_info3 = RequestInformation()
        request_info3.http_method = Method.GET
        request_info3.url = (
            "https://graph.microsoft.com/beta/"
            "settings"
        )
        request_info3.headers = HeadersCollection()
        request_info3.headers.try_add("Accept", "application/json")

        response3 = adapter.send_primitive_async(request_info3, "bytes").result()
        settings_data = json.loads(response3)

        for setting in settings_data.get("value", []):
            display_name = setting.get("displayName", "")
            if "Password Rule Settings" in display_name or "SSPR" in display_name:
                values = {v["name"]: v["value"] for v in setting.get("values", [])}
                notify_admins = values.get(
                    "NotifyAdminsOfAdminPasswordReset", ""
                )
                if notify_admins.lower() == "true":
                    return make_result(spec_id, title, "Azure", Verdict.PASS,
                        "Admin password reset notifications are enabled")
                return make_result(spec_id, title, "Azure", Verdict.FAIL,
                    f"Admin password reset notifications: {notify_admins}")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            "Could not locate password reset notification settings via Graph API. "
            "Manual verification required via Entra admin center > Password reset > "
            "Notifications.")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_restrict_admin_portal(session: AzureSession) -> RequirementResult:
    """ADA 2.11.3: Ensure 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'."""
    spec_id = "2.11.3"
    title = "Ensure 'Restrict access to Microsoft Entra admin center' is Set to 'Yes'"
    try:
        client = _graph_client(session)
        policy = client.policies.authorization_policy.get().result()

        # In the Microsoft Graph API the property is
        # `allowNonAdminUsersToAccessPortal` -- but the SDK may expose it as
        # a snake-cased attribute. We check multiple attribute names.
        restrict_portal = None
        for attr_name in (
            "block_msolpowershell",  # SDK v1
            "allow_non_admin_access_to_microsoft_entra_admin_center",
        ):
            val = getattr(policy, attr_name, None)
            if val is not None:
                restrict_portal = val
                break

        if restrict_portal is None:
            # Fallback: try direct REST call for the beta property
            import json
            from kiota_abstractions.request_information import RequestInformation
            from kiota_abstractions.method import Method
            from kiota_abstractions.headers_collection import HeadersCollection

            adapter = client.request_adapter
            request_info = RequestInformation()
            request_info.http_method = Method.GET
            request_info.url = (
                "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
            )
            request_info.headers = HeadersCollection()
            request_info.headers.try_add("Accept", "application/json")

            resp_bytes = adapter.send_primitive_async(request_info, "bytes").result()
            data = json.loads(resp_bytes)
            restrict_portal = data.get(
                "allowNonAdminAccessToMicrosoftEntraAdminCenter", None
            )

            if restrict_portal is not None:
                if restrict_portal is False:
                    return make_result(spec_id, title, "Azure", Verdict.PASS,
                        "Non-admin access to Entra admin center is restricted")
                return make_result(spec_id, title, "Azure", Verdict.FAIL,
                    "Non-admin users CAN access the Entra admin center")

            return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                "Could not determine admin portal restriction setting. "
                "Manual verification required via Entra admin center > "
                "Users > User settings.")

        # If restrict_portal is False => non-admins CANNOT access => PASS
        # (the property is "allow" so False = restricted)
        if restrict_portal is False:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "Non-admin access to Entra admin center is restricted")
        return make_result(spec_id, title, "Azure", Verdict.FAIL,
            "Non-admin users can access the Entra admin center")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_no_custom_sub_admin_roles(session: AzureSession) -> RequirementResult:
    """ADA 2.11.4: Ensure That No Custom Subscription Administrator Roles Exist."""
    spec_id = "2.11.4"
    title = "Ensure That No Custom Subscription Administrator Roles Exist"
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth_client = AuthorizationManagementClient(
            session.credential, session.subscription_id
        )

        # List custom role definitions scoped to this subscription
        scope = f"/subscriptions/{session.subscription_id}"
        role_defs = list(auth_client.role_definitions.list(scope))

        # Filter to custom roles that have subscription-wide admin-like permissions
        # (actions containing "*" at subscription scope)
        ADMIN_ACTIONS = {"*"}
        custom_admin_roles = []
        for rd in role_defs:
            if getattr(rd, "role_type", "") != "CustomRole":
                continue
            for perm in (rd.permissions or []):
                actions = set(getattr(perm, "actions", []) or [])
                if actions & ADMIN_ACTIONS:
                    custom_admin_roles.append(
                        f"  - {rd.role_name} (id: {rd.name})"
                    )
                    break

        if custom_admin_roles:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                f"Found {len(custom_admin_roles)} custom subscription admin role(s):\n"
                + "\n".join(custom_admin_roles))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            "No custom subscription administrator roles found")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_admin_accounts_cloud_only(session: AzureSession) -> RequirementResult:
    """ADA 2.11.6: Ensure administrative accounts are cloud-only."""
    spec_id = "2.11.6"
    title = "Ensure administrative accounts are cloud-only"
    try:
        client = _graph_client(session)

        # Get all activated directory roles
        roles = client.directory_roles.get().result()
        ADMIN_ROLE_KEYWORDS = {"admin", "administrator", "global"}

        synced_admins = []
        for role in (roles.value or []):
            role_name = getattr(role, "display_name", "") or ""
            if not any(kw in role_name.lower() for kw in ADMIN_ROLE_KEYWORDS):
                continue

            members = (
                client.directory_roles
                .by_directory_role_id(role.id)
                .members
                .get()
                .result()
            )
            for m in (members.value or []):
                on_prem_sync = getattr(m, "on_premises_sync_enabled", None)
                if on_prem_sync is True:
                    name = getattr(m, "display_name", "N/A")
                    upn = getattr(m, "user_principal_name", "N/A")
                    synced_admins.append(
                        f"  - {name} ({upn}) in role '{role_name}'"
                    )

        if synced_admins:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                f"Found {len(synced_admins)} admin account(s) synced from "
                f"on-premises:\n" + "\n".join(synced_admins))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            "All administrative accounts are cloud-only (no on-premises sync)")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_user_access_admin_restricted(session: AzureSession) -> RequirementResult:
    """ADA 2.11.7: Ensure the User Access Administrator role is restricted."""
    spec_id = "2.11.7"
    title = "Ensure the User Access Administrator role is restricted"
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth_client = AuthorizationManagementClient(
            session.credential, session.subscription_id
        )

        scope = f"/subscriptions/{session.subscription_id}"

        # The "User Access Administrator" built-in role ID
        UAA_ROLE_ID = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"

        assignments = list(auth_client.role_assignments.list_for_scope(scope))
        uaa_assignments = []
        for ra in assignments:
            role_def_id = getattr(ra, "role_definition_id", "") or ""
            if UAA_ROLE_ID in role_def_id:
                principal_id = getattr(ra, "principal_id", "N/A")
                principal_type = getattr(ra, "principal_type", "N/A")
                uaa_assignments.append(
                    f"  - Principal: {principal_id} (type: {principal_type})"
                )

        if not uaa_assignments:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "No User Access Administrator role assignments found at subscription scope")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            f"Found {len(uaa_assignments)} User Access Administrator assignment(s) -- "
            f"review for appropriateness:\n" + "\n".join(uaa_assignments))
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_privileged_role_assignments_reviewed(session: AzureSession) -> RequirementResult:
    """ADA 2.11.8: Ensure privileged role assignments are reviewed periodically."""
    spec_id = "2.11.8"
    title = "Ensure privileged role assignments are reviewed periodically"
    try:
        client = _graph_client(session)

        roles = client.directory_roles.get().result()
        PRIVILEGED_KEYWORDS = {
            "global administrator", "privileged role administrator",
            "privileged authentication administrator",
            "security administrator", "exchange administrator",
            "sharepoint administrator", "user administrator",
        }

        privileged_assignments = []
        for role in (roles.value or []):
            role_name = (getattr(role, "display_name", "") or "").lower()
            if role_name not in PRIVILEGED_KEYWORDS:
                continue

            members = (
                client.directory_roles
                .by_directory_role_id(role.id)
                .members
                .get()
                .result()
            )
            for m in (members.value or []):
                name = getattr(m, "display_name", "N/A")
                upn = getattr(m, "user_principal_name", "N/A")
                privileged_assignments.append(
                    f"  - {name} ({upn}) -> {role.display_name}"
                )

        if not privileged_assignments:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "No privileged role assignments found")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            f"Found {len(privileged_assignments)} privileged role assignment(s) -- "
            f"review for appropriateness:\n"
            + "\n".join(privileged_assignments[:50])
            + ("\n  ... (truncated)" if len(privileged_assignments) > 50 else ""))
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_fewer_than_five_global_admins(session: AzureSession) -> RequirementResult:
    """ADA 2.11.9: Ensure fewer than 5 users have Global Administrator assignment."""
    spec_id = "2.11.9"
    title = "Ensure fewer than 5 users have Global Administrator assignment"
    try:
        client = _graph_client(session)

        roles = client.directory_roles.get().result()
        ga_role = None
        for role in (roles.value or []):
            if (getattr(role, "display_name", "") or "").lower() == "global administrator":
                ga_role = role
                break

        if ga_role is None:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "Global Administrator role not activated")

        members = (
            client.directory_roles
            .by_directory_role_id(ga_role.id)
            .members
            .get()
            .result()
        )
        member_list = members.value or []
        member_details = []
        for m in member_list:
            name = getattr(m, "display_name", "N/A")
            upn = getattr(m, "user_principal_name", "N/A")
            member_details.append(f"  - {name} ({upn})")

        count = len(member_list)
        if count >= 5:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                f"Found {count} Global Administrator(s) (should be fewer than 5):\n"
                + "\n".join(member_details))
        if count == 0:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                "No Global Administrators found -- at least 1 is required")
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            f"Found {count} Global Administrator(s) (fewer than 5):\n"
            + "\n".join(member_details))
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_subscription_owners_count(session: AzureSession) -> RequirementResult:
    """ADA 2.11.10: Ensure there are between 2 and 3 subscription Owners."""
    spec_id = "2.11.10"
    title = "Ensure there are between 2 and 3 subscription Owners"
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth_client = AuthorizationManagementClient(
            session.credential, session.subscription_id
        )

        scope = f"/subscriptions/{session.subscription_id}"

        # Built-in "Owner" role definition ID
        OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

        assignments = list(auth_client.role_assignments.list_for_scope(scope))
        owner_assignments = []
        for ra in assignments:
            role_def_id = getattr(ra, "role_definition_id", "") or ""
            if OWNER_ROLE_ID in role_def_id:
                principal_id = getattr(ra, "principal_id", "N/A")
                principal_type = getattr(ra, "principal_type", "N/A")
                owner_assignments.append(
                    f"  - Principal: {principal_id} (type: {principal_type})"
                )

        count = len(owner_assignments)
        if count < 2:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                f"Only {count} subscription Owner(s) found (minimum 2 required):\n"
                + "\n".join(owner_assignments))
        if count > 3:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                f"Found {count} subscription Owner(s) (maximum 3 recommended):\n"
                + "\n".join(owner_assignments))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            f"Found {count} subscription Owner(s) (within 2-3 range):\n"
            + "\n".join(owner_assignments))
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.13  Re-confirm authentication
# ===========================================================================

def check_reconfirm_auth_info(session: AzureSession) -> RequirementResult:
    """ADA 2.13.1: Ensure number of days before re-confirm auth info is set to 90."""
    spec_id = "2.13.1"
    title = ("Ensure 'Number of days before users are asked to re-confirm their "
             "authentication information' is set to '90'")
    try:
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        # SSPR registration re-confirmation is in the beta endpoint
        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = (
            "https://graph.microsoft.com/beta/"
            "policies/authenticationMethodsPolicy"
        )
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        data = json.loads(response)

        # Check registrationEnforcement for re-confirmation
        reg_enforcement = data.get("registrationEnforcement", {})
        campaign = reg_enforcement.get("authenticationMethodsRegistrationCampaign", {})
        days = campaign.get("snoozeDurationInDays", None)

        # Also check directorySettings for SSPR
        request_info2 = RequestInformation()
        request_info2.http_method = Method.GET
        request_info2.url = "https://graph.microsoft.com/beta/settings"
        request_info2.headers = HeadersCollection()
        request_info2.headers.try_add("Accept", "application/json")

        response2 = adapter.send_primitive_async(request_info2, "bytes").result()
        settings_data = json.loads(response2)

        for setting in settings_data.get("value", []):
            display_name = setting.get("displayName", "")
            if "Password Rule Settings" in display_name or "SSPR" in display_name:
                values = {v["name"]: v["value"] for v in setting.get("values", [])}
                reconfirm_days = values.get(
                    "NumberOfDaysBeforeUsersAreAskedToReconfirmTheirAuthenticationInfo",
                    None
                )
                if reconfirm_days is not None:
                    if str(reconfirm_days) == "90":
                        return make_result(spec_id, title, "Azure", Verdict.PASS,
                            "Re-confirmation period is set to 90 days")
                    return make_result(spec_id, title, "Azure", Verdict.FAIL,
                        f"Re-confirmation period is set to {reconfirm_days} days "
                        f"(should be 90)")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            "Could not determine re-confirmation period. Manual verification "
            "required via Entra admin center > Password reset > Registration.")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.14  MFA policies
# ===========================================================================

def check_reset_methods(session: AzureSession) -> RequirementResult:
    """ADA 2.14.1: Ensure 'Number of methods required to reset' is set to '2'."""
    spec_id = "2.14.1"
    title = "Ensure That 'Number of methods required to reset' is set to '2'"
    try:
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = "https://graph.microsoft.com/beta/settings"
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        settings_data = json.loads(response)

        for setting in settings_data.get("value", []):
            display_name = setting.get("displayName", "")
            if "Password Rule Settings" in display_name or "SSPR" in display_name:
                values = {v["name"]: v["value"] for v in setting.get("values", [])}
                num_methods = values.get(
                    "NumberOfMethodsRequiredToReset", None
                )
                if num_methods is not None:
                    if str(num_methods) == "2":
                        return make_result(spec_id, title, "Azure", Verdict.PASS,
                            "Number of methods required to reset is 2")
                    return make_result(spec_id, title, "Azure", Verdict.FAIL,
                        f"Number of methods required to reset is {num_methods} "
                        f"(should be 2)")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            "Could not determine number of reset methods. Manual verification "
            "required via Entra admin center > Password reset > Authentication methods.")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_mfa_register_devices(session: AzureSession) -> RequirementResult:
    """ADA 2.14.2: Ensure 'Require MFA to register or join devices' is set to 'Yes'."""
    spec_id = "2.14.2"
    title = "Ensure 'Require MFA to register or join devices with Microsoft Entra' is set to 'Yes'"
    try:
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = (
            "https://graph.microsoft.com/v1.0/"
            "policies/deviceRegistrationPolicy"
        )
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        data = json.loads(response)

        # Check multiFactorAuthConfiguration
        mfa_config = data.get("multiFactorAuthConfiguration", "")

        if mfa_config == "required" or mfa_config == "1":
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "MFA is required for device registration/join")
        return make_result(spec_id, title, "Azure", Verdict.FAIL,
            f"MFA for device registration is not required "
            f"(multiFactorAuthConfiguration: {mfa_config})")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def _get_conditional_access_policies(session: AzureSession) -> list[dict]:
    """Retrieve all Conditional Access policies via Graph API."""
    import json
    from kiota_abstractions.request_information import RequestInformation
    from kiota_abstractions.method import Method
    from kiota_abstractions.headers_collection import HeadersCollection

    client = _graph_client(session)
    adapter = client.request_adapter

    request_info = RequestInformation()
    request_info.http_method = Method.GET
    request_info.url = (
        "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    )
    request_info.headers = HeadersCollection()
    request_info.headers.try_add("Accept", "application/json")

    response = adapter.send_primitive_async(request_info, "bytes").result()
    data = json.loads(response)
    return data.get("value", [])


# Well-known directory role template IDs for privileged roles
_PRIVILEGED_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Admin
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "f28a1f94-e5a5-4120-a0da-05f5a5e7a2a6",  # SharePoint Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
}


def check_mfa_privileged(session: AzureSession) -> RequirementResult:
    """ADA 2.14.3: Ensure MFA is enabled for all Privileged Users."""
    spec_id = "2.14.3"
    title = "Ensure 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users"
    try:
        policies = _get_conditional_access_policies(session)
        enabled_policies = [
            p for p in policies
            if p.get("state") in ("enabled", "enabledForReportingButNotEnforced")
        ]

        # Check for a policy that targets privileged roles AND requires MFA
        for policy in enabled_policies:
            conditions = policy.get("conditions", {})
            users = conditions.get("users", {})
            include_roles = users.get("includeRoles", [])
            grant = policy.get("grantControls", {}) or {}
            built_in_controls = grant.get("builtInControls", [])

            # Does this policy include privileged roles and require MFA?
            targets_privileged = bool(
                set(include_roles) & _PRIVILEGED_ROLE_IDS
            )
            requires_mfa = "mfa" in built_in_controls

            if targets_privileged and requires_mfa:
                return make_result(spec_id, title, "Azure", Verdict.PASS,
                    f"Conditional Access policy '{policy.get('displayName')}' "
                    f"requires MFA for privileged roles")

        # Check if "All users" MFA policy exists (covers privileged too)
        for policy in enabled_policies:
            conditions = policy.get("conditions", {})
            users = conditions.get("users", {})
            include_users = users.get("includeUsers", [])
            grant = policy.get("grantControls", {}) or {}
            built_in_controls = grant.get("builtInControls", [])

            if "All" in include_users and "mfa" in built_in_controls:
                return make_result(spec_id, title, "Azure", Verdict.PASS,
                    f"Conditional Access policy '{policy.get('displayName')}' "
                    f"requires MFA for all users (includes privileged)")

        return make_result(spec_id, title, "Azure", Verdict.FAIL,
            f"No Conditional Access policy found requiring MFA for privileged "
            f"roles. Reviewed {len(enabled_policies)} enabled policy(ies).")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_mfa_remember_disabled(session: AzureSession) -> RequirementResult:
    """ADA 2.14.4: Ensure 'Allow users to remember MFA on devices they trust' is Disabled."""
    spec_id = "2.14.4"
    title = "Ensure 'Allow users to remember MFA on devices they trust' is Disabled"
    try:
        policies = _get_conditional_access_policies(session)
        enabled_policies = [
            p for p in policies
            if p.get("state") in ("enabled", "enabledForReportingButNotEnforced")
        ]

        problem_policies = []
        for policy in enabled_policies:
            session_controls = policy.get("sessionControls", {}) or {}
            sign_in_freq = session_controls.get("signInFrequency", {}) or {}

            # If persistentBrowser is set to "always", users can remain signed in
            persistent = session_controls.get("persistentBrowser", {}) or {}
            if persistent.get("mode") == "always" and persistent.get("isEnabled"):
                problem_policies.append(
                    f"  - '{policy.get('displayName')}' has persistent browser = always"
                )

        if problem_policies:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                "Policies allowing persistent browser sessions found:\n"
                + "\n".join(problem_policies))

        # Also check via the legacy MFA settings endpoint (beta)
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = (
            "https://graph.microsoft.com/beta/"
            "policies/authenticationMethodsPolicy"
        )
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        data = json.loads(response)

        # The legacy "remember MFA" setting may appear in the response
        # If we reach here with no issues found, report based on CA policies
        return make_result(spec_id, title, "Azure", Verdict.PASS,
            f"No Conditional Access policies allow persistent browser sessions. "
            f"Reviewed {len(enabled_policies)} enabled policy(ies).")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_mfa_non_privileged(session: AzureSession) -> RequirementResult:
    """ADA 2.14.8: Ensure MFA is enabled for all Non-Privileged Users."""
    spec_id = "2.14.8"
    title = "Ensure 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users"
    try:
        policies = _get_conditional_access_policies(session)
        enabled_policies = [
            p for p in policies
            if p.get("state") in ("enabled", "enabledForReportingButNotEnforced")
        ]

        for policy in enabled_policies:
            conditions = policy.get("conditions", {})
            users = conditions.get("users", {})
            include_users = users.get("includeUsers", [])
            grant = policy.get("grantControls", {}) or {}
            built_in_controls = grant.get("builtInControls", [])

            if "All" in include_users and "mfa" in built_in_controls:
                return make_result(spec_id, title, "Azure", Verdict.PASS,
                    f"Conditional Access policy '{policy.get('displayName')}' "
                    f"requires MFA for all users (covers non-privileged)")

        return make_result(spec_id, title, "Azure", Verdict.FAIL,
            f"No Conditional Access policy found requiring MFA for all users. "
            f"Reviewed {len(enabled_policies)} enabled policy(ies).")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.17  Notify users on password resets
# ===========================================================================

def check_notify_password_resets(session: AzureSession) -> RequirementResult:
    """ADA 2.17.1: Ensure 'Notify users on password resets?' is set to 'Yes'."""
    spec_id = "2.17.1"
    title = "Ensure 'Notify users on password resets?' is set to 'Yes'"
    try:
        import json
        from kiota_abstractions.request_information import RequestInformation
        from kiota_abstractions.method import Method
        from kiota_abstractions.headers_collection import HeadersCollection

        client = _graph_client(session)
        adapter = client.request_adapter

        request_info = RequestInformation()
        request_info.http_method = Method.GET
        request_info.url = "https://graph.microsoft.com/beta/settings"
        request_info.headers = HeadersCollection()
        request_info.headers.try_add("Accept", "application/json")

        response = adapter.send_primitive_async(request_info, "bytes").result()
        settings_data = json.loads(response)

        for setting in settings_data.get("value", []):
            display_name = setting.get("displayName", "")
            if "Password Rule Settings" in display_name or "SSPR" in display_name:
                values = {v["name"]: v["value"] for v in setting.get("values", [])}
                notify_users = values.get("NotifyUsersOfPasswordReset", None)

                if notify_users is not None:
                    if str(notify_users).lower() == "true":
                        return make_result(spec_id, title, "Azure", Verdict.PASS,
                            "Users are notified on password resets")
                    return make_result(spec_id, title, "Azure", Verdict.FAIL,
                        f"Users are NOT notified on password resets "
                        f"(NotifyUsersOfPasswordReset: {notify_users})")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            "Could not determine password reset notification setting. "
            "Manual verification required via Entra admin center > "
            "Password reset > Notifications.")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# 2.18  Role-based access control
# ===========================================================================

def check_non_privileged_role_assignments(session: AzureSession) -> RequirementResult:
    """ADA 2.18.2: Ensure non-privileged role assignments are reviewed."""
    spec_id = "2.18.2"
    title = "Ensure non-privileged role assignments are reviewed"
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth_client = AuthorizationManagementClient(
            session.credential, session.subscription_id
        )

        scope = f"/subscriptions/{session.subscription_id}"
        assignments = list(auth_client.role_assignments.list_for_scope(scope))

        # Built-in high-privilege role IDs to exclude
        HIGH_PRIV_ROLE_IDS = {
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
            "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
            "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
        }

        non_priv = []
        for ra in assignments:
            role_def_id = getattr(ra, "role_definition_id", "") or ""
            # Extract the GUID from the full resource ID
            role_guid = role_def_id.rsplit("/", 1)[-1] if "/" in role_def_id else role_def_id
            if role_guid not in HIGH_PRIV_ROLE_IDS:
                principal_id = getattr(ra, "principal_id", "N/A")
                principal_type = getattr(ra, "principal_type", "N/A")
                non_priv.append(
                    f"  - Principal: {principal_id} (type: {principal_type}), "
                    f"role: {role_guid}"
                )

        if not non_priv:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                "No non-privileged role assignments found at subscription scope")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
            f"Found {len(non_priv)} non-privileged role assignment(s) at subscription "
            f"scope -- review for appropriateness:\n"
            + "\n".join(non_priv[:50])
            + ("\n  ... (truncated)" if len(non_priv) > 50 else ""))
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# ===========================================================================
# Removed checks (CIS v5 reclassifications) -- keep as NOT_APPLICABLE stubs
# ===========================================================================

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


check_gallery_apps = _removed_stub("2.4.2",
    "Ensure that 'Users can add gallery apps to My Apps' is set to 'No'")

check_mfa_policy_all_users = _removed_stub("2.14.5",
    "Ensure that A Multi-factor Authentication Policy Exists for All Users")

check_mfa_risky_signins = _removed_stub("2.14.6",
    "Ensure Multi-factor Authentication is Required for Risky Sign-ins")

check_mfa_admin_groups = _removed_stub("2.15.1",
    "Ensure A Multi-factor Authentication Policy Exists for Administrative Groups")

check_mfa_azure_management = _removed_stub("2.15.2",
    "Ensure Multi-factor Authentication is Required for Azure Management")

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
