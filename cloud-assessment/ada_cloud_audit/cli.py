"""CLI entry point for ADA Cloud assessment tool."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

from ada_cloud_audit.models import AssessmentReport, Provider, Verdict
from ada_cloud_audit.checks.registry import get_checks_for_provider
from ada_cloud_audit.report.json_report import write_json_report

logger = logging.getLogger("ada_cloud_audit")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ada-cloud-audit",
        description="ADA Cloud App and Config assessment automation tool. "
        "Runs security checks against a cloud tenant and generates compliance reports.",
    )
    parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp"],
        default="aws",
        help="Cloud provider to assess (default: aws)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS profile name (default: default profile / env vars)",
    )
    parser.add_argument(
        "--project",
        default=None,
        help="GCP project ID (required for --provider gcp)",
    )
    parser.add_argument(
        "--subscription",
        default=None,
        help="Azure subscription ID (required for --provider azure, or set AZURE_SUBSCRIPTION_ID)",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS default region (e.g. us-east-1). Auto-detected on EC2 instances.",
    )
    parser.add_argument(
        "--regions",
        nargs="*",
        default=None,
        help="Specific regions to check (default: all enabled regions)",
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Output directory (default: ./output)",
    )
    parser.add_argument(
        "--lab-name",
        default="",
        help="Security test lab name for report header",
    )
    parser.add_argument(
        "--app-name",
        default="",
        help="Application name for report header",
    )
    parser.add_argument(
        "--app-version",
        default="",
        help="Application version for report header",
    )
    parser.add_argument(
        "--company",
        default="",
        help="Company name for report header",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Skip .docx generation, produce only JSON",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Detailed console output during assessment",
    )
    return parser.parse_args(argv)


def run_assessment(args: argparse.Namespace) -> AssessmentReport:
    """Run all checks for the specified provider and return the assessment report."""
    provider = Provider(args.provider.upper())

    # Create provider-specific session
    if provider == Provider.AZURE:
        from azure.identity import DefaultAzureCredential
        from ada_cloud_audit.checks.azure.base import AzureSession

        credential = DefaultAzureCredential()
        subscription_id = args.subscription or os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not subscription_id:
            logger.error("Azure subscription ID required. Use --subscription or set AZURE_SUBSCRIPTION_ID.")
            sys.exit(1)
        session = AzureSession(credential=credential, subscription_id=subscription_id)
    elif provider == Provider.GCP:
        import google.auth
        from ada_cloud_audit.checks.gcp.base import GCPSession

        credentials, default_project = google.auth.default()
        project_id = args.project or default_project
        if not project_id:
            logger.error("GCP project ID required. Use --project or set GOOGLE_CLOUD_PROJECT.")
            sys.exit(1)
        session = GCPSession(credentials=credentials, project_id=project_id)
    else:
        import boto3
        session_kwargs = {}
        if args.profile:
            session_kwargs["profile_name"] = args.profile
        if args.region:
            session_kwargs["region_name"] = args.region
        session = boto3.Session(**session_kwargs)

        # Ensure the session has a region.  EC2 instance roles and minimal
        # AWS CLI configs often omit the default region, which causes every
        # regional service client to fail with "You must specify a region."
        if session.region_name is None:
            # Try the EC2 instance metadata service (IMDS) for the
            # current region — works on any EC2 instance.
            try:
                import urllib.request
                url = "http://169.254.169.254/latest/meta-data/placement/region"
                req = urllib.request.Request(url, headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
                # IMDSv2: get token first
                token_req = urllib.request.Request(
                    "http://169.254.169.254/latest/api/token",
                    method="PUT",
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                )
                token = urllib.request.urlopen(token_req, timeout=2).read().decode()
                req = urllib.request.Request(url, headers={"X-aws-ec2-metadata-token": token})
                detected_region = urllib.request.urlopen(req, timeout=2).read().decode().strip()
            except Exception:
                detected_region = "us-east-1"
                logger.warning(
                    "No AWS region configured and IMDS not available. "
                    "Falling back to %s. Use --region or AWS_DEFAULT_REGION to override.",
                    detected_region,
                )
            session_kwargs["region_name"] = detected_region
            session = boto3.Session(**session_kwargs)

    checks = get_checks_for_provider(provider)
    if not checks:
        logger.error("No checks registered for provider: %s", provider.value)
        sys.exit(1)

    report = AssessmentReport(
        provider=provider,
        lab_name=args.lab_name,
        app_name=args.app_name,
        app_version=args.app_version,
        company=args.company,
    )

    # Sort checks by spec_id for consistent ordering
    sorted_checks = sorted(checks.items(), key=lambda x: [int(p) for p in x[0].split(".")])

    total = len(sorted_checks)
    for i, (spec_id, check_fn) in enumerate(sorted_checks, 1):
        logger.info("[%d/%d] Running check %s ...", i, total, spec_id)
        if args.verbose:
            print(f"[{i}/{total}] Running check {spec_id}: {check_fn.__doc__ or ''}")

        try:
            result = check_fn(session)
            report.results.append(result)

            symbol = {
                Verdict.PASS: "PASS",
                Verdict.FAIL: "FAIL",
                Verdict.NOT_APPLICABLE: "N/A",
                Verdict.INCONCLUSIVE: "INC",
            }.get(result.verdict, "???")

            if args.verbose:
                print(f"  -> {symbol}: {result.evidence[:120]}")
            logger.info("  %s %s: %s", symbol, spec_id, result.title)
        except Exception as e:
            logger.error("  ERROR running check %s: %s", spec_id, e)
            if args.verbose:
                print(f"  -> ERROR: {e}")
            from ada_cloud_audit.checks.base import make_result
            report.results.append(
                make_result(
                    spec_id,
                    check_fn.__doc__ or spec_id,
                    provider.value,
                    Verdict.INCONCLUSIVE,
                    f"Unexpected error running check: {e}",
                )
            )

    return report


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    print(f"\nADA Cloud Assessment Tool")
    print(f"Provider: {args.provider.upper()}")
    if args.provider.upper() == "AZURE":
        print(f"Subscription: {args.subscription or os.environ.get('AZURE_SUBSCRIPTION_ID', '(not set)')}")
    elif args.provider.upper() == "GCP":
        project_id = args.project or "(default from credentials)"
        print(f"Project: {project_id}")
    else:
        print(f"Profile: {args.profile or 'default'}")
    print(f"Output: {args.output_dir}")
    print()

    # Run assessment
    report = run_assessment(args)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Write JSON report
    json_path = os.path.join(args.output_dir, "assessment_results.json")
    write_json_report(report, json_path)
    print(f"\nJSON report written to: {json_path}")

    # Write DOCX reports if not json-only
    if not args.json_only:
        try:
            from ada_cloud_audit.report.compliance_report import write_compliance_report
            from ada_cloud_audit.report.developer_report import write_developer_report

            compliance_path = os.path.join(
                args.output_dir, "Cloud App and Config Compliance Report.docx"
            )
            developer_path = os.path.join(
                args.output_dir, "Cloud App and Config Developer Test Report.docx"
            )

            # Locate templates
            repo_root = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            template_dir = os.path.join(
                repo_root, "Submission Forms and Templates", "Lab Templates"
            )

            compliance_template = os.path.join(
                template_dir, "Cloud App and Config Compliance Report.docx"
            )
            developer_template = os.path.join(
                template_dir, "Cloud App and Config Developer Test Report.docx"
            )

            if os.path.exists(compliance_template):
                write_compliance_report(report, compliance_template, compliance_path)
                print(f"Compliance report written to: {compliance_path}")
            else:
                print(f"WARNING: Compliance report template not found at {compliance_template}")

            if os.path.exists(developer_template):
                write_developer_report(report, developer_template, developer_path)
                print(f"Developer test report written to: {developer_path}")
            else:
                print(f"WARNING: Developer test report template not found at {developer_template}")
        except ImportError:
            print("WARNING: python-docx not installed, skipping DOCX report generation")
        except Exception as e:
            print(f"WARNING: Error generating DOCX reports: {e}")

    # Print summary
    pass_count = sum(1 for r in report.results if r.verdict == Verdict.PASS)
    fail_count = sum(1 for r in report.results if r.verdict == Verdict.FAIL)
    na_count = sum(1 for r in report.results if r.verdict == Verdict.NOT_APPLICABLE)
    inc_count = sum(1 for r in report.results if r.verdict == Verdict.INCONCLUSIVE)
    total = len(report.results)

    print(f"\n{'='*50}")
    print(f"Assessment Summary ({total} requirements)")
    print(f"{'='*50}")
    print(f"  PASS:           {pass_count}")
    print(f"  FAIL:           {fail_count}")
    print(f"  NOT APPLICABLE: {na_count}")
    print(f"  INCONCLUSIVE:   {inc_count}")
    print(f"{'='*50}")
