"""Data models for ADA cloud assessment results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Provider(Enum):
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"


class Verdict(Enum):
    PASS = "P"
    FAIL = "F"
    NOT_APPLICABLE = "NA"
    INCONCLUSIVE = "INC"


@dataclass
class RequirementResult:
    """Result of evaluating a single ADA requirement."""

    spec_id: str           # e.g. "2.8.2"
    title: str             # e.g. "Ensure IAM password policy requires minimum length of 14 or greater"
    platform: str          # e.g. "AWS"
    section_id: str        # e.g. "2.8"
    section_name: str      # e.g. "Establish and Maintain a Secure Configuration Process"
    domain: str            # e.g. "Identity and Access Management"
    verdict: Verdict
    evidence: str          # Formatted evidence text for the report
    details: dict = field(default_factory=dict)  # Raw API response data


@dataclass
class AssessmentReport:
    """Complete assessment report for a cloud tenant."""

    provider: Provider
    results: list[RequirementResult] = field(default_factory=list)
    lab_name: str = ""
    app_name: str = ""
    app_version: str = ""
    company: str = ""

    def section_verdict(self, section_id: str) -> Verdict:
        """Compute aggregate verdict for a section.

        FAIL if any requirement fails; PASS if all pass or NA;
        INCONCLUSIVE if any inconclusive and none fail.
        """
        section_results = [r for r in self.results if r.section_id == section_id]
        if not section_results:
            return Verdict.NOT_APPLICABLE
        if any(r.verdict == Verdict.FAIL for r in section_results):
            return Verdict.FAIL
        if any(r.verdict == Verdict.INCONCLUSIVE for r in section_results):
            return Verdict.INCONCLUSIVE
        return Verdict.PASS

    def domain_verdict(self, domain: str) -> Verdict:
        """Compute aggregate verdict for a domain."""
        domain_results = [r for r in self.results if r.domain == domain]
        if not domain_results:
            return Verdict.NOT_APPLICABLE
        if any(r.verdict == Verdict.FAIL for r in domain_results):
            return Verdict.FAIL
        if any(r.verdict == Verdict.INCONCLUSIVE for r in domain_results):
            return Verdict.INCONCLUSIVE
        return Verdict.PASS


# Domain and section constants for the ADA Cloud profile
DOMAINS = {
    "1": "Compute",
    "2": "Identity and Access Management",
    "3": "Logging and Monitoring",
    "4": "Networking",
    "5": "Data Protection",
    "6": "Database Services",
}

SECTIONS = {
    "1.1": "Establish and Maintain a Software Inventory",
    "1.2": "Ensure Authorized Software is Currently Supported",
    "1.3": "Ensure Secure Configuration of Compute Resources",
    "1.4": "Ensure Secure Configuration of Compute Resources",
    "1.5": "Ensure Network Configuration is Secure",
    "1.6": "Manage Default Accounts on Infrastructure and Software",
    "1.7": "Centralize Access Control",
    "1.8": "Establish and Maintain a Secure Configuration Process",
    "1.9": "Ensure Secure Configuration of Platform Services",
    "1.10": "Ensure Secure Configuration of Virtual Machines",
    "2.1": "Establish and Maintain a Data Recovery Process",
    "2.2": "Designate Personnel to Manage Incident Handling",
    "2.3": "Establish and Maintain Contact Information for Reporting Security Incidents",
    "2.4": "Restrict Application Consent and Registration",
    "2.5": "Establish and Maintain Key and Secret Management",
    "2.6": "Establish and Maintain an Inventory of Authentication and Authorization Systems",
    "2.7": "Configure Data Access Control Lists",
    "2.8": "Establish and Maintain a Secure Configuration Process",
    "2.9": "Use Unique Passwords",
    "2.10": "Disable Dormant Accounts",
    "2.11": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
    "2.12": "Centralize Account Management",
    "2.13": "Require Re-confirmation of Authentication Information",
    "2.14": "Require MFA for Externally-Exposed Applications",
    "2.15": "Require MFA for Administrative Groups",
    "2.16": "Require MFA for Administrative Access",
    "2.17": "Password Reset Notifications",
    "2.18": "Define and Maintain Role-Based Access Control",
    "3.1": "Establish and Maintain Detailed Enterprise Asset Inventory",
    "3.2": "Establish and Maintain a Secure Configuration Process",
    "3.3": "Establish and Maintain Contact Information for Reporting Security Incidents",
    "3.4": "Ensure S3 Bucket Access Logging",
    "3.5": "Configure Data Access Control Lists",
    "3.6": "Establish and Maintain a Secure Configuration Process",
    "3.7": "Establish and Maintain a Secure Configuration Process",
    "3.8": "Configure Data Access Control Lists",
    "3.9": "Monitoring and Alerting",
    "3.10": "Audit Log Retention",
    "3.11": "Collect Detailed Audit Logs",
    "4.1": "Establish and Maintain a Secure Configuration Process",
    "4.2": "Implement and Manage a Firewall on End-User Devices",
    "4.3": "Implement and Manage a Firewall on Servers",
    "5.1": "Ensure Data Recovery and Integrity",
    "5.2": "Configure Data Access Control Lists",
    "5.3": "Encrypt Data in Transit",
    "5.4": "Encrypt Confidential Data at Rest",
    "5.5": "Configure Data Access Control Lists",
    "5.6": "Establish and Maintain a Secure Configuration Process",
    "5.7": "Establish and Maintain a Secure Configuration Process",
    "5.8": "Establish and Maintain a Secure Configuration Process",
    "5.9": "Establish and Maintain a Secure Configuration Process",
    "6.1": "Database Configuration Flags",
    "6.2": "Database Configuration Flags",
    "6.3": "Encrypt Data in Transit",
    "6.4": "Encrypt Confidential Data at Rest",
    "6.5": "Configure Data Access Control Lists",
    "6.6": "Database Configuration Flags",
    "6.7": "Configure Data Access Control Lists",
    "6.8": "Establish and Maintain Network Architecture Diagrams",
    "6.9": "Configure Data Access Control Lists",
    "6.10": "Database Configuration Flags",
    "6.11": "Configure Authentication for Database Services",
    "6.12": "Manage Changes",
    "6.13": "Database Configuration Flags",
    "6.14": "Database Logging Configuration",
    "6.15": "Database Logging",
    "6.16": "Ensure Secure Configuration of Cache Services",
    "6.17": "Ensure Secure Configuration of NoSQL Services",
    "6.18": "Ensure Secure Configuration of Data Integration Services",
}


def get_domain(spec_id: str) -> str:
    """Get the domain name for a given spec ID."""
    major = spec_id.split(".")[0]
    return DOMAINS.get(major, "Unknown")


def get_section_id(spec_id: str) -> str:
    """Get the section ID from a spec ID (e.g., '2.8.2' -> '2.8')."""
    parts = spec_id.split(".")
    return f"{parts[0]}.{parts[1]}"


def get_section_name(spec_id: str) -> str:
    """Get the section name for a given spec ID."""
    sid = get_section_id(spec_id)
    return SECTIONS.get(sid, "Unknown")
