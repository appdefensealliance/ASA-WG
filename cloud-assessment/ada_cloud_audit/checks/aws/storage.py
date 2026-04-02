"""AWS Storage checks for ADA Cloud assessment.

Covers 3 requirements:
- 5.4.1: EBS volume encryption enabled in all regions
- 5.4.2: EFS file system encryption enabled
- 5.5.1: S3 buckets configured with Block Public Access
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ada_cloud_audit.checks.base import make_result, run_multi_region
from ada_cloud_audit.models import Verdict


def check_ebs_encryption(session: boto3.Session) -> "RequirementResult":
    """ADA 5.4.1: Ensure EBS Volume Encryption is Enabled in all Regions."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        ec2 = session.client("ec2", region_name=region)
        try:
            resp = ec2.get_ebs_encryption_by_default()
            enabled = resp.get("EbsEncryptionByDefault", False)
            if enabled:
                return True, "EBS encryption by default is enabled", {"EbsEncryptionByDefault": True}
            else:
                return False, "EBS encryption by default is NOT enabled", {"EbsEncryptionByDefault": False}
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

    return run_multi_region(
        session,
        "5.4.1",
        "Ensure EBS Volume Encryption is Enabled in all Regions",
        "AWS",
        _check_region,
    )


def check_efs_encryption(session: boto3.Session) -> "RequirementResult":
    """ADA 5.4.2: Ensure that encryption is enabled for EFS file systems."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        efs = session.client("efs", region_name=region)
        try:
            paginator = efs.get_paginator("describe_file_systems")
            unencrypted = []
            total = 0
            for page in paginator.paginate():
                for fs in page["FileSystems"]:
                    total += 1
                    if not fs.get("Encrypted", False):
                        unencrypted.append(fs["FileSystemId"])
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if total == 0:
            return True, "No EFS file systems found", {}
        if unencrypted:
            return (
                False,
                f"Unencrypted EFS file systems: {', '.join(unencrypted)}",
                {"unencrypted": unencrypted, "total": total},
            )
        return True, f"All {total} EFS file systems are encrypted", {"total": total}

    return run_multi_region(
        session,
        "5.4.2",
        "Ensure that encryption is enabled for EFS file systems",
        "AWS",
        _check_region,
    )


def check_s3_block_public_access(session: boto3.Session) -> "RequirementResult":
    """ADA 5.5.1: Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'."""
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        if not buckets:
            return make_result(
                "5.5.1",
                "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
                "AWS",
                Verdict.PASS,
                "No S3 buckets found in the account",
            )

        non_compliant = []
        compliant = []
        required_settings = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]

        for bucket in buckets:
            name = bucket["Name"]
            try:
                config = s3.get_public_access_block(Bucket=name)[
                    "PublicAccessBlockConfiguration"
                ]
                missing = [s for s in required_settings if not config.get(s, False)]
                if missing:
                    non_compliant.append(f"{name} (missing: {', '.join(missing)})")
                else:
                    compliant.append(name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    non_compliant.append(f"{name} (no public access block configured)")
                else:
                    non_compliant.append(f"{name} (error: {e.response['Error']['Code']})")

        if not non_compliant:
            return make_result(
                "5.5.1",
                "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
                "AWS",
                Verdict.PASS,
                f"All {len(compliant)} S3 buckets have Block Public Access enabled",
                {"compliant_count": len(compliant)},
            )
        else:
            return make_result(
                "5.5.1",
                "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
                "AWS",
                Verdict.FAIL,
                f"S3 buckets without full Block Public Access:\n" + "\n".join(non_compliant),
                {
                    "non_compliant": non_compliant,
                    "compliant_count": len(compliant),
                },
            )
    except ClientError as e:
        return make_result(
            "5.5.1",
            "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking S3 public access: {e}",
        )
