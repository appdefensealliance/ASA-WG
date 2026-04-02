"""Base utilities for checks: provider-agnostic helpers and AWS-specific session management."""

from __future__ import annotations

import logging
from typing import Any, Callable

from ada_cloud_audit.models import (
    RequirementResult,
    Verdict,
    get_domain,
    get_section_id,
    get_section_name,
)

logger = logging.getLogger(__name__)


def make_result(
    spec_id: str,
    title: str,
    platform: str,
    verdict: Verdict,
    evidence: str,
    details: dict | None = None,
) -> RequirementResult:
    """Convenience factory for RequirementResult with auto-populated section/domain."""
    return RequirementResult(
        spec_id=spec_id,
        title=title,
        platform=platform,
        section_id=get_section_id(spec_id),
        section_name=get_section_name(spec_id),
        domain=get_domain(spec_id),
        verdict=verdict,
        evidence=evidence,
        details=details or {},
    )


def get_enabled_regions(session: Any) -> list[str]:
    """Return list of enabled regions for the AWS account."""
    ec2 = session.client("ec2")
    response = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    return [r["RegionName"] for r in response["Regions"]]


def run_multi_region(
    session: Any,
    spec_id: str,
    title: str,
    platform: str,
    region_check: Callable,
    regions: list[str] | None = None,
) -> RequirementResult:
    """Run a check across all enabled regions and aggregate results.

    region_check receives (session, region_name) and returns (pass_bool, evidence_str, details_dict).
    The check passes only if all regions pass.
    """
    from botocore.exceptions import ClientError

    if regions is None:
        regions = get_enabled_regions(session)

    all_evidence = []
    all_details = {}
    overall_pass = True

    for region in regions:
        try:
            passed, evidence, details = region_check(session, region)
            all_evidence.append(f"[{region}] {evidence}")
            all_details[region] = details
            if not passed:
                overall_pass = False
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_msg = e.response["Error"]["Message"]
            all_evidence.append(f"[{region}] Error: {error_code} - {error_msg}")
            all_details[region] = {"error": str(e)}
            # Don't fail on access denied in regions where service isn't available
            if error_code not in ("OptInRequired", "AuthFailure"):
                overall_pass = False
        except Exception as e:
            all_evidence.append(f"[{region}] Error: {e}")
            all_details[region] = {"error": str(e)}
            overall_pass = False

    verdict = Verdict.PASS if overall_pass else Verdict.FAIL
    return make_result(
        spec_id=spec_id,
        title=title,
        platform=platform,
        verdict=verdict,
        evidence="\n".join(all_evidence),
        details=all_details,
    )


def get_credential_report(session: Any) -> list[dict]:
    """Generate and retrieve the IAM credential report as a list of dicts."""
    import csv
    import io
    import base64
    import time

    iam = session.client("iam")

    # Generate report (may need to wait)
    for _ in range(10):
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(1)

    report = iam.get_credential_report()
    content = report["Content"]
    if isinstance(content, bytes):
        decoded = content.decode("utf-8")
    else:
        decoded = base64.b64decode(content).decode("utf-8")

    reader = csv.DictReader(io.StringIO(decoded))
    return list(reader)
