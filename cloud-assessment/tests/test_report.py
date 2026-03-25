"""Tests for report generation."""

import json
import os
import tempfile

import pytest

from ada_cloud_audit.models import (
    AssessmentReport,
    Provider,
    RequirementResult,
    Verdict,
)
from ada_cloud_audit.report.json_report import write_json_report, report_to_dict


def _make_sample_report():
    return AssessmentReport(
        provider=Provider.AWS,
        lab_name="Test Lab",
        app_name="TestApp",
        app_version="1.0",
        company="Test Corp",
        results=[
            RequirementResult(
                spec_id="2.8.2",
                title="Ensure IAM password policy requires minimum length of 14 or greater",
                platform="AWS",
                section_id="2.8",
                section_name="Establish and Maintain a Secure Configuration Process",
                domain="Identity and Access Management",
                verdict=Verdict.PASS,
                evidence="Password policy MinimumPasswordLength is 14 (>= 14)",
                details={"MinimumPasswordLength": 14},
            ),
            RequirementResult(
                spec_id="2.7.1",
                title="Ensure no 'root' user account access key exists",
                platform="AWS",
                section_id="2.7",
                section_name="Configure Data Access Control Lists",
                domain="Identity and Access Management",
                verdict=Verdict.FAIL,
                evidence="Root user access keys exist",
                details={"AccountAccessKeysPresent": 1},
            ),
            RequirementResult(
                spec_id="4.3.5",
                title="WITHDRAWN",
                platform="AWS",
                section_id="4.3",
                section_name="Implement and Manage a Firewall on Servers",
                domain="Networking",
                verdict=Verdict.NOT_APPLICABLE,
                evidence="Requirement withdrawn",
            ),
        ],
    )


def test_report_to_dict():
    report = _make_sample_report()
    data = report_to_dict(report)

    assert data["metadata"]["provider"] == "AWS"
    assert data["metadata"]["lab_name"] == "Test Lab"
    assert data["metadata"]["total_requirements"] == 3
    assert data["summary"]["pass"] == 1
    assert data["summary"]["fail"] == 1
    assert data["summary"]["not_applicable"] == 1
    assert len(data["results"]) == 3


def test_write_json_report():
    report = _make_sample_report()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_path = f.name

    try:
        write_json_report(report, output_path)
        with open(output_path) as f:
            data = json.load(f)

        assert data["metadata"]["provider"] == "AWS"
        assert len(data["results"]) == 3
    finally:
        os.unlink(output_path)


def test_section_verdict():
    report = _make_sample_report()
    # Section 2.8 has only a PASS -> should be PASS
    assert report.section_verdict("2.8") == Verdict.PASS
    # Section 2.7 has only a FAIL -> should be FAIL
    assert report.section_verdict("2.7") == Verdict.FAIL
    # Section 4.3 has only an NA -> should be PASS (all NA counts as pass)
    assert report.section_verdict("4.3") == Verdict.PASS
    # Non-existent section -> NA
    assert report.section_verdict("99.99") == Verdict.NOT_APPLICABLE


def test_domain_verdict():
    report = _make_sample_report()
    # IAM has a FAIL -> should be FAIL
    assert report.domain_verdict("Identity and Access Management") == Verdict.FAIL
    # Networking has only NA -> should be PASS
    assert report.domain_verdict("Networking") == Verdict.PASS
