"""AWS Account checks for ADA Cloud assessment.

Covers 2 requirements:
- 2.3.1: Contact details maintained
- 2.3.2: Security contact registered
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.models import Verdict


def check_contact_info(session: boto3.Session) -> "RequirementResult":
    """ADA 2.3.1: Maintain current contact details."""
    account = session.client("account")
    try:
        contact = account.get_contact_information()["ContactInformation"]
        fields = {
            "FullName": contact.get("FullName", ""),
            "PhoneNumber": contact.get("PhoneNumber", ""),
            "AddressLine1": contact.get("AddressLine1", ""),
            "City": contact.get("City", ""),
            "PostalCode": contact.get("PostalCode", ""),
            "CountryCode": contact.get("CountryCode", ""),
        }
        missing = [k for k, v in fields.items() if not v]

        if not missing:
            return make_result(
                "2.3.1",
                "Maintain current contact details",
                "AWS",
                Verdict.PASS,
                f"Contact information is configured: {contact.get('FullName', 'N/A')}, "
                f"{contact.get('PhoneNumber', 'N/A')}",
                {"ContactInformation": contact},
            )
        else:
            return make_result(
                "2.3.1",
                "Maintain current contact details",
                "AWS",
                Verdict.FAIL,
                f"Contact information missing fields: {', '.join(missing)}",
                {"ContactInformation": contact, "missing_fields": missing},
            )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            return make_result(
                "2.3.1",
                "Maintain current contact details",
                "AWS",
                Verdict.INCONCLUSIVE,
                "Insufficient permissions to read account contact information. "
                "Requires aws-portal:*Billing or account:GetContactInformation permission.",
            )
        return make_result(
            "2.3.1",
            "Maintain current contact details",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking contact information: {e}",
        )


def check_security_contact(session: boto3.Session) -> "RequirementResult":
    """ADA 2.3.2: Ensure security contact information is registered."""
    account = session.client("account")
    try:
        contact = account.get_alternate_contact(AlternateContactType="SECURITY")[
            "AlternateContact"
        ]
        name = contact.get("Name", "")
        email = contact.get("EmailAddress", "")
        phone = contact.get("PhoneNumber", "")

        if name and email:
            return make_result(
                "2.3.2",
                "Ensure security contact information is registered",
                "AWS",
                Verdict.PASS,
                f"Security contact is configured: {name}, {email}, {phone}",
                {"AlternateContact": contact},
            )
        else:
            return make_result(
                "2.3.2",
                "Ensure security contact information is registered",
                "AWS",
                Verdict.FAIL,
                "Security contact information is incomplete",
                {"AlternateContact": contact},
            )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            return make_result(
                "2.3.2",
                "Ensure security contact information is registered",
                "AWS",
                Verdict.FAIL,
                "No security contact information is registered",
            )
        if error_code == "AccessDeniedException":
            return make_result(
                "2.3.2",
                "Ensure security contact information is registered",
                "AWS",
                Verdict.INCONCLUSIVE,
                "Insufficient permissions to read alternate contacts. "
                "Requires account:GetAlternateContact permission.",
            )
        return make_result(
            "2.3.2",
            "Ensure security contact information is registered",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking security contact: {e}",
        )
