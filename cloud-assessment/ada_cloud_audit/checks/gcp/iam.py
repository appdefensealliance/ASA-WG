"""GCP IAM checks for ADA Cloud assessment.

Covers 8 requirements:
- 2.3.5: Essential Contacts configured for organization
- 2.6.1: Secrets not stored in Cloud Functions env vars
- 2.7.5: IAM users not assigned SA User/Token Creator roles at project level
- 2.7.6: Cloud KMS cryptokeys not publicly accessible
- 2.11.5: Service accounts have no admin privileges
- 2.12.1: Corporate login credentials used (no @gmail.com)
- 2.14.7: MFA enabled for all non-service accounts (INCONCLUSIVE)
- 2.8.6: Only GCP-managed service account keys
"""

from __future__ import annotations

import re

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.gcp.base import GCPSession
from ada_cloud_audit.models import RequirementResult, Verdict

# Patterns that suggest secrets in environment variables
SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)"),
    re.compile(r"(?i)(secret|api_key|apikey|api-key)"),
    re.compile(r"(?i)(private_key|private-key|privatekey)"),
    re.compile(r"(?i)(token|auth_token|access_token)"),
    re.compile(r"(?i)(credential|cred)"),
]

# Admin-level IAM roles
ADMIN_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/compute.admin",
    "roles/storage.admin",
    "roles/cloudsql.admin",
    "roles/cloudfunctions.admin",
}

# SA-related roles that shouldn't be granted at project level to users
SA_ROLES = {
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountTokenCreator",
}


def check_essential_contacts(session: GCPSession) -> RequirementResult:
    """ADA 2.3.5: Ensure Essential Contacts is configured for the organization."""
    spec_id = "2.3.5"
    title = "Ensure Essential Contacts is configured for the organization"

    try:
        from google.cloud.essential_contacts_v1 import EssentialContactsServiceClient
        from google.cloud.essential_contacts_v1.types import ListContactsRequest

        client = EssentialContactsServiceClient(credentials=session.credentials)
        parent = f"projects/{session.project_id}"
        request = ListContactsRequest(parent=parent)

        contacts = list(client.list_contacts(request=request))
        if contacts:
            categories = set()
            for contact in contacts:
                for cat in contact.notification_category_subscriptions:
                    categories.add(str(cat))

            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             f"Essential Contacts configured: {len(contacts)} contact(s) found "
                             f"covering categories: {', '.join(sorted(categories))}",
                             {"contact_count": len(contacts), "categories": sorted(categories)})
        else:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "No Essential Contacts configured for the project",
                             {"contact_count": 0})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking Essential Contacts: {e}")


def check_secrets_in_functions(session: GCPSession) -> RequirementResult:
    """ADA 2.6.1: Ensure secrets are not stored in Cloud Functions environment variables."""
    spec_id = "2.6.1"
    title = "Ensure secrets are not stored in Cloud Functions environment variables"

    try:
        from google.cloud.functions_v2 import FunctionServiceClient
        from google.cloud.functions_v2.types import ListFunctionsRequest

        client = FunctionServiceClient(credentials=session.credentials)
        parent = f"projects/{session.project_id}/locations/-"
        request = ListFunctionsRequest(parent=parent)

        functions_with_secrets = []
        total = 0
        for func in client.list_functions(request=request):
            total += 1
            env_vars = {}
            if func.service_config and func.service_config.environment_variables:
                env_vars = dict(func.service_config.environment_variables)
            if func.build_config and func.build_config.environment_variables:
                env_vars.update(dict(func.build_config.environment_variables))

            suspect_keys = []
            for key in env_vars:
                for pattern in SECRET_PATTERNS:
                    if pattern.search(key):
                        suspect_keys.append(key)
                        break

            if suspect_keys:
                functions_with_secrets.append(
                    f"{func.name} (suspect env vars: {', '.join(suspect_keys)})"
                )

        if total == 0:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No Cloud Functions found")

        if functions_with_secrets:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Functions with potential secrets in env vars:\n"
                             + "\n".join(functions_with_secrets),
                             {"functions_with_secrets": functions_with_secrets, "total": total})

        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"No potential secrets found in {total} Cloud Functions env vars",
                         {"total": total})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking Cloud Functions: {e}")


def _get_project_iam_policy(session: GCPSession):
    """Get the IAM policy for the project."""
    from google.cloud import resourcemanager_v3

    client = resourcemanager_v3.ProjectsClient(credentials=session.credentials)
    return client.get_iam_policy(resource=f"projects/{session.project_id}")


def check_sa_user_role(session: GCPSession) -> RequirementResult:
    """ADA 2.7.5: Ensure IAM users are not assigned SA User or Token Creator roles at project level."""
    spec_id = "2.7.5"
    title = "Ensure IAM users are not assigned Service Account User or Token Creator roles at project level"

    try:
        policy = _get_project_iam_policy(session)

        violations = []
        for binding in policy.bindings:
            if binding.role in SA_ROLES:
                user_members = [
                    m for m in binding.members
                    if m.startswith("user:") or m.startswith("group:")
                ]
                for member in user_members:
                    violations.append(f"{member} has {binding.role}")

        if violations:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Users/groups with SA roles at project level:\n" + "\n".join(violations),
                             {"violations": violations})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No IAM users have Service Account User or Token Creator roles at project level")
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking IAM policy: {e}")


def check_kms_public_access(session: GCPSession) -> RequirementResult:
    """ADA 2.7.6: Ensure Cloud KMS cryptokeys are not publicly accessible."""
    spec_id = "2.7.6"
    title = "Ensure Cloud KMS cryptokeys are not anonymously or publicly accessible"

    try:
        from google.cloud import kms_v1

        client = kms_v1.KeyManagementServiceClient(credentials=session.credentials)

        # List all key rings across all locations
        parent = f"projects/{session.project_id}/locations/-"
        public_keys = []
        total_keys = 0

        try:
            for key_ring in client.list_key_rings(parent=parent):
                for crypto_key in client.list_crypto_keys(parent=key_ring.name):
                    total_keys += 1
                    try:
                        policy = client.get_iam_policy(resource=crypto_key.name)
                        for binding in policy.bindings:
                            for member in binding.members:
                                if member in ("allUsers", "allAuthenticatedUsers"):
                                    public_keys.append(
                                        f"{crypto_key.name} ({member} has {binding.role})"
                                    )
                    except Exception:
                        pass
        except Exception as e:
            if "PERMISSION_DENIED" in str(e) or "403" in str(e):
                return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                                 f"Insufficient permissions to list KMS keys: {e}")
            raise

        if total_keys == 0:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No Cloud KMS cryptokeys found")

        if public_keys:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Publicly accessible KMS keys:\n" + "\n".join(public_keys),
                             {"public_keys": public_keys, "total_keys": total_keys})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {total_keys} Cloud KMS cryptokeys are not publicly accessible",
                         {"total_keys": total_keys})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking KMS keys: {e}")


def check_sa_admin_privileges(session: GCPSession) -> RequirementResult:
    """ADA 2.11.5: Ensure service accounts do not have admin privileges."""
    spec_id = "2.11.5"
    title = "Ensure service accounts do not have admin privileges"

    try:
        policy = _get_project_iam_policy(session)

        violations = []
        for binding in policy.bindings:
            if binding.role in ADMIN_ROLES:
                sa_members = [
                    m for m in binding.members
                    if m.startswith("serviceAccount:")
                    and not m.endswith(".iam.gserviceaccount.com")
                    or (m.startswith("serviceAccount:")
                        and "iam.gserviceaccount.com" in m)
                ]
                # Filter out Google-managed service accounts
                for member in sa_members:
                    email = member.replace("serviceAccount:", "")
                    if not email.endswith(".gserviceaccount.com") or \
                       not email.startswith("service-"):
                        violations.append(f"{member} has {binding.role}")

        if violations:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Service accounts with admin privileges:\n" + "\n".join(violations),
                             {"violations": violations})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No user-managed service accounts have admin privileges")
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking IAM policy: {e}")


def check_corporate_credentials(session: GCPSession) -> RequirementResult:
    """ADA 2.12.1: Ensure corporate login credentials are used instead of Gmail accounts."""
    spec_id = "2.12.1"
    title = "Ensure corporate login credentials are used"

    try:
        policy = _get_project_iam_policy(session)

        gmail_users = []
        for binding in policy.bindings:
            for member in binding.members:
                if member.startswith("user:") and member.endswith("@gmail.com"):
                    gmail_users.append(f"{member} has {binding.role}")

        if gmail_users:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Gmail accounts found in project IAM policy:\n" + "\n".join(gmail_users),
                             {"gmail_users": gmail_users})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "No Gmail accounts found in project IAM policy. All members use corporate credentials.")
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking IAM policy: {e}")


def check_mfa_non_service(session: GCPSession) -> RequirementResult:
    """ADA 2.14.7: Ensure MFA is enabled for all non-service accounts (INCONCLUSIVE)."""
    return make_result(
        "2.14.7",
        "Ensure multi-factor authentication is enabled for all non-service accounts",
        "GCP",
        Verdict.INCONCLUSIVE,
        "MFA enforcement for GCP users requires access to the Google Workspace Admin Console "
        "or Cloud Identity Admin Console, which is outside the scope of project-level API access. "
        "Manual verification required: check Admin Console > Security > 2-Step Verification "
        "to confirm MFA is enforced for all non-service accounts.",
    )


def check_gcp_managed_sa_keys(session: GCPSession) -> RequirementResult:
    """ADA 2.8.6: Ensure only GCP-managed service account keys exist."""
    spec_id = "2.8.6"
    title = "Ensure That There Are Only GCP-Managed Service Account Keys for Each Service Account"

    try:
        from googleapiclient import discovery

        service = discovery.build("iam", "v1", credentials=session.credentials)
        sa_list = service.projects().serviceAccounts().list(
            name=f"projects/{session.project_id}"
        ).execute()

        accounts = sa_list.get("accounts", [])
        if not accounts:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No service accounts found in the project")

        violating = []
        for sa in accounts:
            email = sa.get("email", "")
            keys_resp = service.projects().serviceAccounts().keys().list(
                name=f"projects/{session.project_id}/serviceAccounts/{email}",
                keyTypes=["USER_MANAGED"],
            ).execute()
            user_keys = keys_resp.get("keys", [])
            if user_keys:
                violating.append(f"{email} ({len(user_keys)} user-managed key(s))")

        if violating:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Service accounts with user-managed keys:\n" + "\n".join(violating),
                             {"violating": violating, "total_accounts": len(accounts)})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {len(accounts)} service accounts use only GCP-managed keys",
                         {"total_accounts": len(accounts)})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking service account keys: {e}")



def check_sa_key_rotation(session: GCPSession) -> RequirementResult:
    """ADA 2.10.3: Ensure user-managed SA keys are rotated every 90 days."""
    spec_id = "2.10.3"
    title = "Ensure User-Managed/External Keys for Service Accounts Are Rotated Every 90 Days or Fewer"

    try:
        from datetime import datetime, timezone, timedelta
        from googleapiclient import discovery

        service = discovery.build("iam", "v1", credentials=session.credentials)
        sa_list = service.projects().serviceAccounts().list(
            name=f"projects/{session.project_id}"
        ).execute()

        accounts = sa_list.get("accounts", [])
        if not accounts:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No service accounts found")

        now = datetime.now(timezone.utc)
        threshold = timedelta(days=90)
        violating = []

        for sa in accounts:
            email = sa.get("email", "")
            keys_resp = service.projects().serviceAccounts().keys().list(
                name=f"projects/{session.project_id}/serviceAccounts/{email}",
                keyTypes=["USER_MANAGED"],
            ).execute()
            for key in keys_resp.get("keys", []):
                valid_after = key.get("validAfterTime", "")
                if valid_after:
                    try:
                        key_dt = datetime.fromisoformat(valid_after.replace("Z", "+00:00"))
                        if (now - key_dt) > threshold:
                            violating.append(f"{email} (key created {valid_after})")
                    except (ValueError, TypeError):
                        pass

        if violating:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "SA keys older than 90 days:\n" + "\n".join(violating),
                             {"violating": violating})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "All user-managed SA keys are within the 90-day rotation window")
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking SA key rotation: {e}")


def check_kms_key_rotation(session: GCPSession) -> RequirementResult:
    """ADA 2.7.9: Ensure KMS encryption keys are rotated within 90 days."""
    spec_id = "2.7.9"
    title = "Ensure KMS Encryption Keys Are Rotated Within a Period of 90 Days"

    try:
        from google.cloud import kms_v1

        client = kms_v1.KeyManagementServiceClient(credentials=session.credentials)
        parent = f"projects/{session.project_id}/locations/-"

        non_compliant = []
        total_keys = 0

        for ring in client.list_key_rings(request={"parent": parent}):
            for key in client.list_crypto_keys(request={"parent": ring.name}):
                if key.purpose != kms_v1.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT:
                    continue
                total_keys += 1
                rotation = key.rotation_period
                if not rotation or rotation.total_seconds() > 7776000:  # 90 days
                    non_compliant.append(
                        f"{key.name} (rotation: {'not set' if not rotation else f'{int(rotation.total_seconds() / 86400)}d'})"
                    )

        if total_keys == 0:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No symmetric encryption KMS keys found")

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "KMS keys without 90-day rotation:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "total_keys": total_keys})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {total_keys} KMS keys have rotation period <= 90 days",
                         {"total_keys": total_keys})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking KMS key rotation: {e}")
