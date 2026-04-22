"""AWS IAM checks for ADA Cloud assessment.

Covers 11 requirements:
- 2.2.1: Support role for AWS Support
- 2.7.1: No root access keys
- 2.7.3: No full admin IAM policies attached
- 2.8.2: Password policy minimum length >= 14
- 2.8.4: Access keys rotated every 90 days
- 2.9.1: Password policy prevents reuse
- 2.10.1: Credentials unused 45+ days disabled
- 2.11.1: Root not used for daily tasks
- 2.16.1: MFA enabled for root
- 2.18.1: Users receive permissions only through groups
- 2.14.9: MFA enabled for all IAM console users
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

from ada_cloud_audit.checks.base import make_result, get_credential_report
from ada_cloud_audit.models import Verdict


def check_support_role(session: boto3.Session) -> "RequirementResult":
    """ADA 2.2.1: Ensure a support role has been created to manage incidents with AWS Support."""
    iam = session.client("iam")
    try:
        resp = iam.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess"
        )
        roles = resp.get("PolicyRoles", [])
        if roles:
            role_names = [r["RoleName"] for r in roles]
            return make_result(
                "2.2.1",
                "Ensure a support role has been created to manage incidents with AWS Support",
                "AWS",
                Verdict.PASS,
                f"AWSSupportAccess policy is attached to role(s): {', '.join(role_names)}",
                {"PolicyRoles": roles},
            )
        else:
            return make_result(
                "2.2.1",
                "Ensure a support role has been created to manage incidents with AWS Support",
                "AWS",
                Verdict.FAIL,
                "AWSSupportAccess policy is not attached to any role",
                {"PolicyRoles": []},
            )
    except ClientError as e:
        return make_result(
            "2.2.1",
            "Ensure a support role has been created to manage incidents with AWS Support",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking support role: {e}",
        )


def check_root_access_keys(session: boto3.Session) -> "RequirementResult":
    """ADA 2.7.1: Ensure no root user account access key exists."""
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        keys_present = summary.get("AccountAccessKeysPresent", 0)
        if keys_present == 0:
            return make_result(
                "2.7.1",
                "Ensure no 'root' user account access key exists",
                "AWS",
                Verdict.PASS,
                "No root user access keys exist (AccountAccessKeysPresent: 0)",
                {"AccountAccessKeysPresent": 0},
            )
        else:
            return make_result(
                "2.7.1",
                "Ensure no 'root' user account access key exists",
                "AWS",
                Verdict.FAIL,
                f"Root user access keys exist (AccountAccessKeysPresent: {keys_present})",
                {"AccountAccessKeysPresent": keys_present},
            )
    except ClientError as e:
        return make_result(
            "2.7.1",
            "Ensure no 'root' user account access key exists",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking root access keys: {e}",
        )


def check_no_full_admin_policies(session: boto3.Session) -> "RequirementResult":
    """ADA 2.7.3: Ensure IAM policies that allow full '*:*' administrative privileges are not attached."""
    iam = session.client("iam")
    try:
        paginator = iam.get_paginator("list_policies")
        violating_policies = []

        for page in paginator.paginate(OnlyAttached=True, Scope="Local"):
            for policy in page["Policies"]:
                arn = policy["Arn"]
                version = policy["DefaultVersionId"]
                try:
                    policy_version = iam.get_policy_version(
                        PolicyArn=arn, VersionId=version
                    )["PolicyVersion"]
                    document = policy_version["Document"]
                    statements = document.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for stmt in statements:
                        effect = stmt.get("Effect", "")
                        action = stmt.get("Action", "")
                        resource = stmt.get("Resource", "")

                        # Normalize to lists
                        if isinstance(action, str):
                            action = [action]
                        if isinstance(resource, str):
                            resource = [resource]

                        if (
                            effect == "Allow"
                            and "*" in action
                            and "*" in resource
                        ):
                            violating_policies.append(policy["PolicyName"])
                            break
                except ClientError:
                    pass

        if not violating_policies:
            return make_result(
                "2.7.3",
                'Ensure IAM policies that allow full "*:*" administrative privileges are not attached',
                "AWS",
                Verdict.PASS,
                "No attached customer-managed IAM policies allow full administrative privileges",
                {"violating_policies": []},
            )
        else:
            return make_result(
                "2.7.3",
                'Ensure IAM policies that allow full "*:*" administrative privileges are not attached',
                "AWS",
                Verdict.FAIL,
                f"Attached customer-managed IAM policies with full admin privileges: {', '.join(violating_policies)}",
                {"violating_policies": violating_policies},
            )
    except ClientError as e:
        return make_result(
            "2.7.3",
            'Ensure IAM policies that allow full "*:*" administrative privileges are not attached',
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking IAM policies: {e}",
        )


def check_password_policy_length(session: boto3.Session) -> "RequirementResult":
    """ADA 2.8.2: Ensure IAM password policy requires minimum length >= 14."""
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        min_length = policy.get("MinimumPasswordLength", 0)
        if min_length >= 14:
            return make_result(
                "2.8.2",
                "Ensure IAM password policy requires minimum length of 14 or greater",
                "AWS",
                Verdict.PASS,
                f"Password policy MinimumPasswordLength is {min_length} (>= 14)",
                {"MinimumPasswordLength": min_length},
            )
        else:
            return make_result(
                "2.8.2",
                "Ensure IAM password policy requires minimum length of 14 or greater",
                "AWS",
                Verdict.FAIL,
                f"Password policy MinimumPasswordLength is {min_length} (required >= 14)",
                {"MinimumPasswordLength": min_length},
            )
    except iam.exceptions.NoSuchEntityException:
        return make_result(
            "2.8.2",
            "Ensure IAM password policy requires minimum length of 14 or greater",
            "AWS",
            Verdict.FAIL,
            "No password policy configured",
        )
    except ClientError as e:
        return make_result(
            "2.8.2",
            "Ensure IAM password policy requires minimum length of 14 or greater",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking password policy: {e}",
        )


def check_access_keys_rotated(session: boto3.Session) -> "RequirementResult":
    """ADA 2.8.4: Ensure access keys are rotated every 90 days or less."""
    try:
        report = get_credential_report(session)
        now = datetime.now(timezone.utc)
        threshold = timedelta(days=90)
        violating_users = []

        for row in report:
            user = row.get("user", "")
            for key_num in ("1", "2"):
                active = row.get(f"access_key_{key_num}_active", "false").lower()
                last_rotated = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                if active == "true" and last_rotated not in ("N/A", "not_supported"):
                    try:
                        rotated_dt = datetime.fromisoformat(
                            last_rotated.replace("Z", "+00:00")
                        )
                        if (now - rotated_dt) > threshold:
                            violating_users.append(
                                f"{user} (key {key_num}: last rotated {last_rotated})"
                            )
                    except (ValueError, TypeError):
                        pass

        if not violating_users:
            return make_result(
                "2.8.4",
                "Ensure access keys are rotated every 90 days or less",
                "AWS",
                Verdict.PASS,
                "All active access keys have been rotated within the last 90 days",
                {"violating_users": []},
            )
        else:
            return make_result(
                "2.8.4",
                "Ensure access keys are rotated every 90 days or less",
                "AWS",
                Verdict.FAIL,
                f"Access keys not rotated within 90 days:\n" + "\n".join(violating_users),
                {"violating_users": violating_users},
            )
    except ClientError as e:
        return make_result(
            "2.8.4",
            "Ensure access keys are rotated every 90 days or less",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking access key rotation: {e}",
        )


def check_password_reuse_prevention(session: boto3.Session) -> "RequirementResult":
    """ADA 2.9.1: Ensure IAM password policy prevents password reuse."""
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        reuse_prevention = policy.get("PasswordReusePrevention", 0)
        if reuse_prevention >= 24:
            return make_result(
                "2.9.1",
                "Ensure IAM password policy prevents password reuse",
                "AWS",
                Verdict.PASS,
                f"Password policy PasswordReusePrevention is {reuse_prevention} (>= 24)",
                {"PasswordReusePrevention": reuse_prevention},
            )
        else:
            return make_result(
                "2.9.1",
                "Ensure IAM password policy prevents password reuse",
                "AWS",
                Verdict.FAIL,
                f"Password policy PasswordReusePrevention is {reuse_prevention} (required >= 24)",
                {"PasswordReusePrevention": reuse_prevention},
            )
    except iam.exceptions.NoSuchEntityException:
        return make_result(
            "2.9.1",
            "Ensure IAM password policy prevents password reuse",
            "AWS",
            Verdict.FAIL,
            "No password policy configured",
        )
    except ClientError as e:
        return make_result(
            "2.9.1",
            "Ensure IAM password policy prevents password reuse",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking password policy: {e}",
        )


def check_credentials_unused(session: boto3.Session) -> "RequirementResult":
    """ADA 2.10.1: Ensure credentials unused for 45 days or greater are disabled."""
    try:
        report = get_credential_report(session)
        now = datetime.now(timezone.utc)
        threshold = timedelta(days=45)
        violating_users = []

        for row in report:
            user = row.get("user", "")
            if user == "<root_account>":
                continue

            # Check password
            pwd_enabled = row.get("password_enabled", "false").lower()
            if pwd_enabled == "true":
                pwd_last_used = row.get("password_last_used", "no_information")
                if pwd_last_used in ("no_information", "N/A", "not_supported"):
                    pwd_last_changed = row.get("password_last_changed", "N/A")
                    if pwd_last_changed not in ("N/A", "not_supported"):
                        try:
                            changed_dt = datetime.fromisoformat(
                                pwd_last_changed.replace("Z", "+00:00")
                            )
                            if (now - changed_dt) > threshold:
                                violating_users.append(f"{user} (password never used, changed {pwd_last_changed})")
                        except (ValueError, TypeError):
                            pass
                elif pwd_last_used not in ("N/A", "not_supported"):
                    try:
                        used_dt = datetime.fromisoformat(
                            pwd_last_used.replace("Z", "+00:00")
                        )
                        if (now - used_dt) > threshold:
                            violating_users.append(f"{user} (password last used {pwd_last_used})")
                    except (ValueError, TypeError):
                        pass

            # Check access keys
            for key_num in ("1", "2"):
                active = row.get(f"access_key_{key_num}_active", "false").lower()
                if active == "true":
                    last_used = row.get(f"access_key_{key_num}_last_used_date", "N/A")
                    if last_used in ("N/A", "not_supported"):
                        last_rotated = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                        if last_rotated not in ("N/A", "not_supported"):
                            try:
                                rotated_dt = datetime.fromisoformat(
                                    last_rotated.replace("Z", "+00:00")
                                )
                                if (now - rotated_dt) > threshold:
                                    violating_users.append(
                                        f"{user} (access key {key_num} never used, created {last_rotated})"
                                    )
                            except (ValueError, TypeError):
                                pass
                    else:
                        try:
                            used_dt = datetime.fromisoformat(
                                last_used.replace("Z", "+00:00")
                            )
                            if (now - used_dt) > threshold:
                                violating_users.append(
                                    f"{user} (access key {key_num} last used {last_used})"
                                )
                        except (ValueError, TypeError):
                            pass

        if not violating_users:
            return make_result(
                "2.10.1",
                "Ensure credentials unused for 45 days or greater are disabled",
                "AWS",
                Verdict.PASS,
                "No credentials unused for 45+ days found",
                {"violating_users": []},
            )
        else:
            return make_result(
                "2.10.1",
                "Ensure credentials unused for 45 days or greater are disabled",
                "AWS",
                Verdict.FAIL,
                "Credentials unused for 45+ days:\n" + "\n".join(violating_users),
                {"violating_users": violating_users},
            )
    except ClientError as e:
        return make_result(
            "2.10.1",
            "Ensure credentials unused for 45 days or greater are disabled",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking unused credentials: {e}",
        )


def check_root_usage(session: boto3.Session) -> "RequirementResult":
    """ADA 2.11.1: Eliminate use of the 'root' user for administrative and daily tasks."""
    try:
        report = get_credential_report(session)
        root_row = None
        for row in report:
            if row.get("user") == "<root_account>":
                root_row = row
                break

        if root_row is None:
            return make_result(
                "2.11.1",
                "Eliminate use of the 'root' user for administrative and daily tasks",
                "AWS",
                Verdict.INCONCLUSIVE,
                "Could not find root account in credential report",
            )

        pwd_last_used = root_row.get("password_last_used", "N/A")
        key1_last_used = root_row.get("access_key_1_last_used_date", "N/A")
        key2_last_used = root_row.get("access_key_2_last_used_date", "N/A")

        evidence = (
            f"Root password last used: {pwd_last_used}\n"
            f"Root access key 1 last used: {key1_last_used}\n"
            f"Root access key 2 last used: {key2_last_used}"
        )

        return make_result(
            "2.11.1",
            "Eliminate use of the 'root' user for administrative and daily tasks",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Manual review required. {evidence}\n"
            "Verify root account is not being used for daily tasks.",
            {
                "password_last_used": pwd_last_used,
                "access_key_1_last_used_date": key1_last_used,
                "access_key_2_last_used_date": key2_last_used,
            },
        )
    except ClientError as e:
        return make_result(
            "2.11.1",
            "Eliminate use of the 'root' user for administrative and daily tasks",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking root usage: {e}",
        )


def check_root_mfa(session: boto3.Session) -> "RequirementResult":
    """ADA 2.16.1: Ensure MFA is enabled for the 'root' user account."""
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0)
        if mfa_enabled == 1:
            return make_result(
                "2.16.1",
                "Ensure MFA is enabled for the 'root' user account",
                "AWS",
                Verdict.PASS,
                "MFA is enabled for the root user account (AccountMFAEnabled: 1)",
                {"AccountMFAEnabled": 1},
            )
        else:
            return make_result(
                "2.16.1",
                "Ensure MFA is enabled for the 'root' user account",
                "AWS",
                Verdict.FAIL,
                f"MFA is NOT enabled for the root user account (AccountMFAEnabled: {mfa_enabled})",
                {"AccountMFAEnabled": mfa_enabled},
            )
    except ClientError as e:
        return make_result(
            "2.16.1",
            "Ensure MFA is enabled for the 'root' user account",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking root MFA: {e}",
        )


def check_users_permissions_through_groups(session: boto3.Session) -> "RequirementResult":
    """ADA 2.18.1: Ensure IAM Users Receive Permissions Only Through Groups."""
    iam = session.client("iam")
    try:
        users = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page["Users"])

        violating_users = []
        for user in users:
            username = user["UserName"]
            # Check attached policies
            attached = iam.list_attached_user_policies(UserName=username)
            if attached["AttachedPolicies"]:
                violating_users.append(f"{username} (has attached policies)")
                continue
            # Check inline policies
            inline = iam.list_user_policies(UserName=username)
            if inline["PolicyNames"]:
                violating_users.append(f"{username} (has inline policies)")

        if not violating_users:
            return make_result(
                "2.18.1",
                "Ensure IAM Users Receive Permissions Only Through Groups",
                "AWS",
                Verdict.PASS,
                "All IAM users receive permissions only through groups",
                {"violating_users": []},
            )
        else:
            return make_result(
                "2.18.1",
                "Ensure IAM Users Receive Permissions Only Through Groups",
                "AWS",
                Verdict.FAIL,
                "Users with direct policy attachments:\n" + "\n".join(violating_users),
                {"violating_users": violating_users},
            )
    except ClientError as e:
        return make_result(
            "2.18.1",
            "Ensure IAM Users Receive Permissions Only Through Groups",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking user permissions: {e}",
        )


def check_iam_mfa_all_users(session: boto3.Session) -> "RequirementResult":
    """ADA 2.14.9: Ensure MFA is enabled for all IAM users that have a console password."""
    try:
        report = get_credential_report(session)
        violating_users = []

        for row in report:
            user = row.get("user", "")
            if user == "<root_account>":
                continue
            pwd_enabled = row.get("password_enabled", "false").lower()
            if pwd_enabled == "true":
                mfa_active = row.get("mfa_active", "false").lower()
                if mfa_active != "true":
                    violating_users.append(user)

        if not violating_users:
            return make_result(
                "2.14.9",
                "Ensure MFA is enabled for all IAM users that have a console password",
                "AWS",
                Verdict.PASS,
                "All IAM users with console passwords have MFA enabled",
                {"violating_users": []},
            )
        else:
            return make_result(
                "2.14.9",
                "Ensure MFA is enabled for all IAM users that have a console password",
                "AWS",
                Verdict.FAIL,
                f"IAM users with console passwords but no MFA:\n" + "\n".join(violating_users),
                {"violating_users": violating_users},
            )
    except ClientError as e:
        return make_result(
            "2.14.9",
            "Ensure MFA is enabled for all IAM users that have a console password",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking MFA status: {e}",
        )
