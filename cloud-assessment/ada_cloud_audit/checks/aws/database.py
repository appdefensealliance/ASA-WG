"""AWS Database checks for ADA Cloud assessment.

Covers 5 requirements:
- 6.4.1: RDS encryption-at-rest enabled
- 6.5.1: RDS not publicly accessible
- 6.12.1: RDS auto minor version upgrade enabled
- 6.15.8: Database logging enabled
- 6.1.2: RDS Multi-AZ deployments
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ada_cloud_audit.checks.base import make_result, run_multi_region
from ada_cloud_audit.models import Verdict


def check_rds_encryption(session: boto3.Session) -> "RequirementResult":
    """ADA 6.4.1: Ensure that encryption-at-rest is enabled for RDS Instances."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        rds = session.client("rds", region_name=region)
        try:
            paginator = rds.get_paginator("describe_db_instances")
            unencrypted = []
            total = 0
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    total += 1
                    if not db.get("StorageEncrypted", False):
                        unencrypted.append(db["DBInstanceIdentifier"])
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if total == 0:
            return True, "No RDS instances found", {}
        if unencrypted:
            return (
                False,
                f"Unencrypted RDS instances: {', '.join(unencrypted)}",
                {"unencrypted": unencrypted, "total": total},
            )
        return True, f"All {total} RDS instances have encryption at rest enabled", {"total": total}

    return run_multi_region(
        session,
        "6.4.1",
        "Ensure that encryption-at-rest is enabled for RDS Instances",
        "AWS",
        _check_region,
    )


def check_rds_public_access(session: boto3.Session) -> "RequirementResult":
    """ADA 6.5.1: Ensure that public access is not given to RDS Instance."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        rds = session.client("rds", region_name=region)
        try:
            paginator = rds.get_paginator("describe_db_instances")
            publicly_accessible = []
            total = 0
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    total += 1
                    if db.get("PubliclyAccessible", False):
                        publicly_accessible.append(db["DBInstanceIdentifier"])
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if total == 0:
            return True, "No RDS instances found", {}
        if publicly_accessible:
            return (
                False,
                f"Publicly accessible RDS instances: {', '.join(publicly_accessible)}",
                {"publicly_accessible": publicly_accessible, "total": total},
            )
        return True, f"All {total} RDS instances are not publicly accessible", {"total": total}

    return run_multi_region(
        session,
        "6.5.1",
        "Ensure that public access is not given to RDS Instance",
        "AWS",
        _check_region,
    )


def check_rds_auto_minor_upgrade(session: boto3.Session) -> "RequirementResult":
    """ADA 6.12.1: Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        rds = session.client("rds", region_name=region)
        try:
            paginator = rds.get_paginator("describe_db_instances")
            non_compliant = []
            total = 0
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    total += 1
                    if not db.get("AutoMinorVersionUpgrade", False):
                        non_compliant.append(db["DBInstanceIdentifier"])
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if total == 0:
            return True, "No RDS instances found", {}
        if non_compliant:
            return (
                False,
                f"RDS instances without auto minor upgrade: {', '.join(non_compliant)}",
                {"non_compliant": non_compliant, "total": total},
            )
        return True, f"All {total} RDS instances have auto minor version upgrade enabled", {"total": total}

    return run_multi_region(
        session,
        "6.12.1",
        "Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances",
        "AWS",
        _check_region,
    )


def check_rds_logging_enabled(session: boto3.Session) -> "RequirementResult":
    """ADA 6.15.8: Database logging should be enabled."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        rds = session.client("rds", region_name=region)
        try:
            paginator = rds.get_paginator("describe_db_instances")
            no_logging = []
            total = 0
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    total += 1
                    exports = db.get("EnabledCloudwatchLogsExports", [])
                    if not exports:
                        no_logging.append(db["DBInstanceIdentifier"])
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if total == 0:
            return True, "No RDS instances found", {}
        if no_logging:
            return (
                False,
                f"RDS instances without CloudWatch log exports: {', '.join(no_logging)}",
                {"no_logging": no_logging, "total": total},
            )
        return True, f"All {total} RDS instances have database logging enabled", {"total": total}

    return run_multi_region(
        session,
        "6.15.8",
        "Database logging should be enabled",
        "AWS",
        _check_region,
    )


def check_rds_multi_az(session: boto3.Session) -> "RequirementResult":
    """ADA 6.1.2: Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        rds = session.client("rds", region_name=region)
        try:
            paginator = rds.get_paginator("describe_db_instances")
            non_multi_az = []
            total = 0
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    total += 1
                    if not db.get("MultiAZ", False):
                        non_multi_az.append(
                            f"{db['DBInstanceIdentifier']} (Engine: {db.get('Engine', 'unknown')})"
                        )
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if total == 0:
            return True, "No RDS instances found", {}
        if non_multi_az:
            return (
                False,
                f"RDS instances without Multi-AZ: {', '.join(non_multi_az)}",
                {"non_multi_az": non_multi_az, "total": total},
            )
        return True, f"All {total} RDS instances have Multi-AZ enabled", {"total": total}

    return run_multi_region(
        session,
        "6.1.2",
        "Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS",
        "AWS",
        _check_region,
    )
