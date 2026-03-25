"""JSON report output for ADA Cloud assessment results."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ada_cloud_audit.models import AssessmentReport


def report_to_dict(report: AssessmentReport) -> dict:
    """Convert an AssessmentReport to a JSON-serializable dictionary."""
    return {
        "metadata": {
            "provider": report.provider.value,
            "lab_name": report.lab_name,
            "app_name": report.app_name,
            "app_version": report.app_version,
            "company": report.company,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_requirements": len(report.results),
        },
        "summary": {
            "pass": sum(1 for r in report.results if r.verdict.value == "P"),
            "fail": sum(1 for r in report.results if r.verdict.value == "F"),
            "not_applicable": sum(1 for r in report.results if r.verdict.value == "NA"),
            "inconclusive": sum(1 for r in report.results if r.verdict.value == "INC"),
        },
        "results": [
            {
                "spec_id": r.spec_id,
                "title": r.title,
                "platform": r.platform,
                "domain": r.domain,
                "section_id": r.section_id,
                "section_name": r.section_name,
                "verdict": r.verdict.value,
                "evidence": r.evidence,
                "details": r.details,
            }
            for r in report.results
        ],
    }


def write_json_report(report: AssessmentReport, output_path: str) -> None:
    """Write the assessment report as a JSON file."""
    data = report_to_dict(report)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
