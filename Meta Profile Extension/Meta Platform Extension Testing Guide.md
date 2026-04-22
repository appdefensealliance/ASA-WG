# App Defense Alliance Meta Platform Extension Testing Guide

Version 0.5 \- DRAFT \- 08-APR 26

# Revision History

| Version | Date | Description |
| :---- | :---- | :---- |
| 0.5 | 4/8/26 | Initial draft based on Meta Platform Extension Specification v0.5 |

# About This Guide

This testing guide supports the App Defense Alliance (ADA) Meta Platform Extension Specification, providing detailed test cases and acceptance criteria for evaluating organizational security controls required by platform providers. Unlike the CASA and MASA testing guides, which assess technical product security through automated tooling and application testing, this guide focuses on organizational evidence — policies, configurations, records, and attestations — reviewed through document inspection.

This guide was developed by the ADA Application Security Assessment Working Group (ASA WG).

# Applicability

This document is intended for security specialists, auditors, and compliance personnel who assess organizations against the Meta Platform Extension Specification. It is also useful for developers preparing evidence packages for ADA certification.

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License.](https://creativecommons.org/licenses/by-sa/4.0/)

# Evidence Guidance for Organizational Controls

The Meta Platform Extension assesses organizational security practices rather than application code or infrastructure configuration. This distinction affects the nature of evidence and testing procedures.

**AL1 (Lab Verified)**: The developer provides documentary evidence — policies, screenshots of tool configurations, training records, signed agreements, and written attestations. The ADA-approved lab reviews the evidence for completeness and plausibility. The lab does not independently verify the implementation.

**AL2**: N/A for this version of the Meta Platform Extension.

**Evidence Currency**: All evidence must reflect the organization's current practices. Policies must be currently in force (not draft or expired). Training records must include activity within the most recent 12 months. Configuration screenshots must be dated within 90 days of the assessment.

**Proportionality for Small Organizations**: For solo developers or very small teams (fewer than 5 personnel), certain requirements may be satisfied through simplified evidence. For example, a solo developer may attest that they are the only person with access to platform data, satisfying the account lifecycle requirement without a formal access review process. The lab should exercise judgment about proportionality while ensuring that the underlying security objective is met.

# Table of Contents

1 [Endpoint Security](#1-endpoint-security)

1.1 [Protect platform data on organizational devices](#11-protect-platform-data-on-organizational-devices)

* 1.1.1 [Technical controls for device storage protection](#111-technical-controls-for-device-storage-protection)
* 1.1.2 [Acceptable use policy for device storage](#112-acceptable-use-policy-for-device-storage)
* 1.1.3 [Personnel acknowledgement of device protections](#113-personnel-acknowledgement-of-device-protections)
* 1.1.4 [Advisory against unnecessary device storage](#114-advisory-against-unnecessary-device-storage)

1.2 [Maintain endpoint software currency](#12-maintain-endpoint-software-currency)

* 1.2.1 [Patch identification process](#121-patch-identification-process)
* 1.2.2 [Risk-based patch prioritization](#122-risk-based-patch-prioritization)
* 1.2.3 [Ongoing patching activity](#123-ongoing-patching-activity)

2 [Organizational Access Control](#2-organizational-access-control)

2.1 [Enforce MFA or equivalent for all tools processing platform data](#21-enforce-mfa-or-equivalent-for-all-tools-processing-platform-data)

* 2.1.1 [MFA for collaboration tools](#211-mfa-for-collaboration-tools)
* 2.1.2 [MFA for code repositories](#212-mfa-for-code-repositories)
* 2.1.3 [MFA for deployment tools](#213-mfa-for-deployment-tools)
* 2.1.4 [Password complexity alternative](#214-password-complexity-alternative)

2.2 [Manage account lifecycle across all systems](#22-manage-account-lifecycle-across-all-systems)

* 2.2.1 [Annual access review](#221-annual-access-review)
* 2.2.2 [Unused access revocation](#222-unused-access-revocation)
* 2.2.3 [Departure access revocation](#223-departure-access-revocation)

3 [Personnel Security](#3-personnel-security)

3.1 [Implement personnel security processes](#31-implement-personnel-security-processes)

* 3.1.1 [Personnel security processes attestation](#311-personnel-security-processes-attestation)
* 3.1.2 [Background verification (optional supporting evidence)](#312-background-verification-optional-supporting-evidence)
* 3.1.3 [Confidentiality agreements (optional supporting evidence)](#313-confidentiality-agreements-optional-supporting-evidence)
* 3.1.4 [Security training (optional supporting evidence)](#314-security-training-optional-supporting-evidence)
* 3.1.5 [Separation process (optional supporting evidence)](#315-separation-process-optional-supporting-evidence)

4 [Vulnerability Management](#4-vulnerability-management)

4.1 [Maintain publicly accessible vulnerability disclosure channel](#41-maintain-publicly-accessible-vulnerability-disclosure-channel)

* 4.1.1 [Public vulnerability reporting mechanism](#411-public-vulnerability-reporting-mechanism)
* 4.1.2 [Monitored contact fallback](#412-monitored-contact-fallback)

4.2 [Implement security event investigation process](#42-implement-security-event-investigation-process)

* 4.2.1 [Documented investigation process](#421-documented-investigation-process)
* 4.2.2 [Investigation response timeframe](#422-investigation-response-timeframe)

5 [Platform Credential and Client Software Security](#5-platform-credential-and-client-software-security)

5.1 [Protect platform credentials from client-side exposure](#51-protect-platform-credentials-from-client-side-exposure)

* 5.1.1 [Secure storage of platform access tokens](#511-secure-storage-of-platform-access-tokens)
* 5.1.2 [Non-exposure of platform app secrets](#512-non-exposure-of-platform-app-secrets)

5.2 [Maintain client application software currency](#52-maintain-client-application-software-currency)

* 5.2.1 [Mobile dependency patching process](#521-mobile-dependency-patching-process)
* 5.2.2 [Supported platform version](#522-supported-platform-version)

# 1 Endpoint Security

## 1.1 Protect platform data on organizational devices

### Description

Organizations shall implement controls to protect platform data stored on or accessed from endpoint devices used by their personnel. Protection may be achieved through technical controls (full disk encryption or data loss prevention software) or through administrative controls (an acceptable use policy governing the handling of platform data on devices).

### Rationale

Platform data processed on endpoint devices is vulnerable to unauthorized access through device loss, theft, or compromise. Providing flexibility between technical and administrative controls ensures that organizations of all sizes can implement meaningful protections.

### Audit

---

### 1.1.1 Technical controls for device storage protection

The organization shall implement one or more of the following protections for platform data stored on organizational or personal devices: (a) full disk encryption enforced across organizational devices, or (b) endpoint data loss prevention (DLP) software configured to monitor and log actions related to platform data on all managed devices.

**Evidence**

*AL1*

1. If full disk encryption is used: Provide screenshots of the group policy, MDM configuration, or equivalent management console showing that FDE is enforced across organizational devices (e.g., BitLocker via Active Directory Group Policy, FileVault via Jamf/Kandji, LUKS via Ansible playbook).
2. If DLP is used: Provide screenshots of the DLP management console showing (a) the DLP product in use, (b) active policies configured to address platform data, and (c) evidence that the policies are deployed to managed devices.
3. If neither FDE nor DLP is implemented, this spec is satisfied by providing evidence for 1.1.2 (acceptable use policy) instead. Provide a written statement indicating that the organization relies on an AUP rather than technical controls.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review provided evidence for adherence with the requirements.
2. Verify that the FDE or DLP configuration applies to devices used by personnel with access to platform data.

**Verification**

*AL1*

1. The organization implements FDE enforced via centralized management (group policy, MDM, or equivalent), OR
2. The organization implements DLP software with active policies covering platform data deployed to managed devices, OR
3. The organization relies on an acceptable use policy per 1.1.2 (only acceptable if neither FDE nor DLP is implemented).

---

### 1.1.2 Acceptable use policy for device storage

Where technical controls per 1.1.1 are not implemented, the organization shall maintain a documented acceptable use policy that (a) defines allowable business purposes for processing platform data on devices, and (b) requires deletion of platform data when the business purpose no longer exists.

**Evidence**

*AL1*

1. Provide the current acceptable use policy document (or relevant excerpt) that addresses platform data on devices.
2. Provide evidence that the policy is currently in force (e.g., policy effective date, approval signature, or publication on internal policy portal).

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the AUP for the presence of both required elements: (a) defined business purposes for platform data on devices and (b) deletion requirement when the business purpose ends.
2. Verify the policy is current (not expired or draft).

**Verification**

*AL1*

1. The AUP explicitly defines the allowable business purposes for processing platform data on devices.
2. The AUP requires deletion of platform data when the business purpose no longer exists.
3. The AUP is currently in force.
4. Note: This spec is only required when technical controls (1.1.1) are not implemented.

---

### 1.1.3 Personnel acknowledgement of device protections

Personnel who may process platform data on devices shall be informed of the applicable technical protections or acceptable use policy and shall acknowledge their obligations.

**Evidence**

*AL1*

1. Provide evidence that personnel have been informed of the applicable device protections. Acceptable evidence includes: signed acknowledgement forms, email records of policy distribution, screenshots of a training/policy portal showing employee completion status, or onboarding checklist records.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review provided evidence to confirm that personnel with access to platform data have been informed of the applicable protections.

**Verification**

*AL1*

1. Evidence demonstrates that personnel who access platform data have been informed of the applicable device protection controls (technical or administrative) and have acknowledged their obligations.

---

### 1.1.4 Advisory against unnecessary device storage

Where storage of platform data on organizational devices is not required, the organization shall advise personnel not to store platform data on such devices.

**Evidence**

*AL1*

1. If platform data storage on devices is not required for business operations: Provide evidence that personnel have been advised not to store platform data on devices. Acceptable evidence includes a written policy statement, email communication, or training material excerpt.
2. If platform data storage on devices IS required: This spec is not applicable. Provide a written statement explaining the business requirement.

*AL2* N/A

**Test Procedure**

*AL1*

1. Determine whether platform data storage on devices is required based on the developer's business operations.
2. If not required: review evidence that personnel have been advised not to store platform data on devices.
3. If required: accept the written explanation and verify that 1.1.1 and/or 1.1.2 are satisfied.

**Verification**

*AL1*

1. If device storage of platform data is not required: personnel have been advised not to store it.
2. If device storage is required: the organization satisfies 1.1.1 (technical controls) and/or 1.1.2 (AUP).

---

## 1.2 Maintain endpoint software currency

### Description

Organizations shall maintain a process for identifying, prioritizing, and applying security patches to operating systems, browsers, and security software on endpoint devices used by personnel who build, operate, or access systems processing platform data.

### Rationale

Unpatched endpoint software exposes organizations to known vulnerabilities. A defined patching process — even a manually tracked one — ensures that endpoint vulnerabilities are systematically addressed.

### Audit

---

### 1.2.1 Patch identification process

The organization shall have a defined and repeatable process for identifying security patches available for operating systems, browsers, and security software on endpoint devices.

**Evidence**

*AL1*

1. Provide a written description of the patch identification process, including: which endpoint software is tracked (at minimum: OS, browsers, and security/antivirus software), how available patches are identified (e.g., automated patch management tool, vendor notification subscriptions, manual checks), and the frequency of patch identification checks.
2. If an automated patch management tool is used (e.g., WSUS, Jamf, SCCM, Intune): provide a screenshot of the tool showing patch discovery or available update status.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the written description for completeness — does it cover OS, browsers, and security software?
2. If automated tooling is claimed, verify the screenshot shows a functional configuration.

**Verification**

*AL1*

1. The organization has a documented process for identifying available security patches.
2. The process covers at minimum: operating systems, browsers, and security/antivirus software on endpoint devices.
3. The process includes a defined mechanism for discovering available patches (automated or manual).

---

### 1.2.2 Risk-based patch prioritization

Available patches shall be prioritized based on risk (e.g., CVSS severity).

**Evidence**

*AL1*

1. Provide a written description of how patches are prioritized. The description should reference a risk-based approach (e.g., CVSS severity, vendor criticality rating, or equivalent).
2. Optionally: provide an example of a recent prioritization decision (e.g., a spreadsheet or tool output showing patches ranked by severity).

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the prioritization process for a risk-based approach.

**Verification**

*AL1*

1. The organization has a documented, risk-based approach to prioritizing patches (e.g., critical/high CVSS patches applied before low-severity patches).

---

### 1.2.3 Ongoing patching activity

Patches shall be applied as an ongoing activity, with evidence of patching activity within the most recent 12-month period.

**Evidence**

*AL1*

1. Provide evidence of patching activity within the most recent 12-month period. Acceptable evidence includes: patch management tool reports showing applied patches, screenshots of system update histories, spreadsheet or log tracking applied patches with dates, or a written attestation with specific examples of patches applied and approximate dates.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review evidence to confirm at least one instance of patching activity within the last 12 months.
2. Verify the evidence covers endpoint devices (not only server infrastructure, which is covered by CASA 6.1 / Cloud Profile 3.7).

**Verification**

*AL1*

1. Evidence demonstrates that patches have been applied to endpoint devices within the most recent 12-month period.
2. Patching activity is ongoing (not a one-time event).

---

# 2 Organizational Access Control

## 2.1 Enforce MFA or equivalent for all tools processing platform data

### Description

Organizations shall enforce multi-factor authentication (MFA) or equivalent account takeover prevention measures for all tools and services used by personnel with access to platform data.

### Rationale

Compromise of organizational accounts can provide attackers with access to platform data, credentials, or the ability to inject malicious code. Requiring MFA or equivalent protections across all tools closes the gap between ADA's application/cloud MFA requirements and the broader organizational attack surface.

### Audit

---

### 2.1.1 MFA for collaboration tools

MFA or equivalent account takeover prevention shall be enforced for all access to collaboration and communication tools (e.g., email, messaging platforms).

**Evidence**

*AL1*

1. Provide a list of collaboration and communication tools used by personnel with access to platform data (e.g., Google Workspace, Microsoft 365, Slack).
2. For each tool: provide a screenshot of the administrative console showing that MFA is enforced (e.g., Google Admin Console \> Security \> 2-Step Verification showing "Enforcement: On"; Azure AD Conditional Access policy requiring MFA; Slack workspace settings showing "Require two-factor authentication for your workspace").
3. If MFA is not implemented: provide evidence per 2.1.4 (password complexity alternative) instead.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the list of tools for completeness — does it cover the primary collaboration and communication tools used by the organization?
2. For each tool, verify the screenshot shows MFA enforcement (not merely availability).

**Verification**

*AL1*

1. MFA is enforced (not merely available) for all collaboration and communication tools used by personnel with access to platform data, OR
2. The organization implements a password complexity policy per 2.1.4.

---

### 2.1.2 MFA for code repositories

MFA or equivalent account takeover prevention shall be enforced for all access to code repositories and version control systems.

**Evidence**

*AL1*

1. Provide a list of code repositories and version control systems used (e.g., GitHub, GitLab, Bitbucket, Azure DevOps).
2. For each: provide a screenshot of the organization/workspace settings showing MFA enforcement (e.g., GitHub organization settings showing "Require two-factor authentication" enabled).
3. If MFA is not implemented: provide evidence per 2.1.4 instead.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the list for completeness.
2. For each system, verify the screenshot shows MFA enforcement at the organization level.

**Verification**

*AL1*

1. MFA is enforced for all code repositories and version control systems, OR
2. The organization implements a password complexity policy per 2.1.4.

---

### 2.1.3 MFA for deployment tools

MFA or equivalent account takeover prevention shall be enforced for all access to software deployment and CI/CD tools.

**Evidence**

*AL1*

1. Provide a list of deployment and CI/CD tools used (e.g., Jenkins, GitHub Actions, CircleCI, AWS CodePipeline, Terraform Cloud).
2. For each: provide a screenshot showing MFA enforcement for access to the tool.
3. If the deployment tool authenticates via an SSO provider that enforces MFA: provide evidence that the SSO provider enforces MFA (cross-reference with 2.1.1 or 2.1.2 evidence if the same provider is used).
4. If MFA is not implemented: provide evidence per 2.1.4 instead.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the list for completeness.
2. For each tool, verify MFA enforcement — either directly or via an SSO provider that enforces MFA.

**Verification**

*AL1*

1. MFA is enforced for all deployment and CI/CD tools, either directly or via SSO with MFA enforcement, OR
2. The organization implements a password complexity policy per 2.1.4.

---

### 2.1.4 Password complexity alternative

Where MFA is not implemented, the organization shall enforce a password complexity policy that meets or exceeds industry standards.

**Evidence**

*AL1*

1. Provide the written password complexity policy.
2. Provide screenshots of the configuration that enforces the policy (e.g., identity provider settings, Active Directory Group Policy, or SaaS tool password settings).

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the password policy for all required elements (see Verification).
2. Review screenshots to confirm the policy is technically enforced (not merely documented).

**Verification**

*AL1*

1. The password policy meets or exceeds all of the following:
   * 1.1. Minimum 14-character length.
   * 1.2. Requires numbers and special characters.
   * 1.3. Password reuse is restricted.
   * 1.4. Minimum 1-day password age (prevents immediate reuse cycling).
   * 1.5. Authentication backoff delays or temporary lockout (e.g., 15 minutes after 5 consecutive failed attempts).
   * 1.6. Hard account lockout after 10 consecutive failed login attempts.
2. The policy is technically enforced, not merely documented.
3. Note: This spec is only required when MFA (2.1.1-2.1.3) is not implemented for one or more tools. Organizations enforcing MFA across all tools may skip this spec.

---

## 2.2 Manage account lifecycle across all systems

### Description

Organizations shall implement processes to manage the lifecycle of access grants across all systems that process platform data.

### Rationale

Stale or orphaned accounts represent a significant attack surface. Extending lifecycle management beyond cloud infrastructure (covered by Cloud Profile 2.10, 2.13) to all systems ensures comprehensive access governance.

### Audit

---

### 2.2.1 Annual access review

Access grants to systems processing platform data shall be reviewed at least every 12 months, and access that is no longer required shall be revoked.

**Evidence**

*AL1*

1. Provide evidence of at least one access review conducted within the most recent 12-month period. Acceptable evidence includes: a completed access review spreadsheet or report, screenshots of an identity governance tool showing review completion, email records documenting the review and any access revocations, or a written attestation with specific details (date of review, systems reviewed, any access revoked).
2. For solo developers or very small teams: a written attestation confirming that the developer is the only person with access to platform data, with a list of relevant systems, is acceptable.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review evidence to confirm an access review was conducted within the last 12 months.
2. Verify the review covered systems that process platform data.

**Verification**

*AL1*

1. At least one access review was conducted within the most recent 12 months.
2. The review covered systems that process platform data.
3. Access that was no longer required was revoked (or none was identified as unnecessary).

---

### 2.2.2 Unused access revocation

Access that is no longer being used shall be identified and revoked.

**Evidence**

*AL1*

1. Provide a written description of how unused access is identified (e.g., reviewing last login dates, automated dormancy reports, manual review during the annual access review per 2.2.1).
2. Optionally: provide an example of unused access that was identified and revoked, or confirm that no unused access was found during the most recent review.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the described process for identifying unused access.

**Verification**

*AL1*

1. The organization has a process (formal or informal) for identifying and revoking unused access to systems processing platform data.

---

### 2.2.3 Departure access revocation

All access grants shall be promptly revoked when a person departs the organization.

**Evidence**

*AL1*

1. Provide a written description of the offboarding/departure process as it relates to access revocation. The description should cover how the organization ensures that all system access is revoked when a person departs.
2. Optionally: provide evidence of a recent departure where access was revoked (e.g., ticket records, identity provider deactivation logs — redact personal details as appropriate).
3. For solo developers: a written attestation that no one else has access, or that the developer is the only person involved, is acceptable.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the departure process for completeness — does it cover revoking access across all relevant systems?

**Verification**

*AL1*

1. The organization has a defined process for revoking all access to systems processing platform data when a person departs.
2. The process is prompt (access is revoked at or near the time of departure, not weeks or months later).

---

# 3 Personnel Security

## 3.1 Implement personnel security processes

### Description

Organizations shall have security processes in place for personnel who access platform data. Such processes could include background checks, confidentiality agreements, security awareness training, or asset return and access revocation procedures upon separation from the organization. Organizations are expected to implement processes appropriate to their size, risk profile, and applicable legal requirements.

### Rationale

Technical controls alone cannot fully protect platform data. Personnel security processes — however tailored to the organization — reduce insider risk and help ensure that individuals understand their obligations when handling platform data.

### Audit

---

### 3.1.1 Personnel security processes attestation

The organization shall attest that it has one or more security processes in place for personnel who access platform data, and shall identify which process types it implements.

**Evidence**

*AL1*

1. Provide a written attestation confirming that the organization has security processes in place for personnel who access platform data.
2. The attestation shall identify which of the following process types the organization implements (one or more):
   * Background checks completed before gaining access to platform data
   * Confidentiality agreements signed before gaining access to platform data
   * Training for new personnel on information security policies and procedures
   * Regular, ongoing security awareness training (e.g., annually)
   * Training related to specific job roles that access platform data
   * Return of assets (e.g., a laptop or mobile phone) upon separation from the organization
3. For solo developers or very small teams: a written attestation describing any applicable security practices is acceptable, even if informal.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the attestation for completeness — does it confirm that personnel security processes exist and identify at least one process type?
2. Verify the attestation is plausible given the organization's size and nature.

**Verification**

*AL1*

1. The organization attests that it has one or more security processes in place for personnel who access platform data.
2. The attestation identifies at least one implemented process type from the categories listed in the evidence guidance.
3. If optional supporting evidence is provided per 3.1.2–3.1.6, review it for consistency with the attestation.

---

The following subsections (3.1.2–3.1.6) describe optional supporting evidence that organizations may provide to demonstrate specific personnel security processes identified in their 3.1.1 attestation. These subsections are not individually required — they serve as evidence guidance for organizations that wish to substantiate specific process types.

---

### 3.1.2 Background verification (optional supporting evidence)

Where the organization has identified background verification as an implemented process type, the following evidence may be provided.

**Evidence**

*AL1*

1. A written description of the organization's background verification practices for personnel who access platform data.
2. Supporting evidence such as: a policy document requiring background checks, a template or sample (redacted) background check form, or a screenshot of the vendor/service used for background checks.
3. If background checks are not permitted by local law: a written explanation citing the applicable legal restriction.

*AL2* N/A

**Test Procedure**

*AL1*

1. If provided, review the description and evidence for plausibility and consistency with the 3.1.1 attestation.
2. If a legal exemption is cited, note it in the assessment report.

---

### 3.1.3 Confidentiality agreements (optional supporting evidence)

Where the organization has identified confidentiality agreements as an implemented process type, the following evidence may be provided.

**Evidence**

*AL1*

1. A template or sample (redacted) confidentiality or non-disclosure agreement used for personnel who access platform data.
2. Supporting evidence such as: a policy requiring NDAs, a screenshot of an HR system showing NDA completion tracking, or a redacted signed NDA.

*AL2* N/A

**Test Procedure**

*AL1*

1. If provided, review the template NDA for relevance — does it cover confidentiality obligations for data accessed through the organization's work?

---

### 3.1.4 Security training (optional supporting evidence)

Where the organization has identified security training (onboarding, annual, or role-specific) as an implemented process type, the following evidence may be provided.

**Evidence**

*AL1*

1. For onboarding training: a training syllabus or slide deck, a screenshot of a training platform showing onboarding training assigned to new hires, an onboarding checklist that includes security training, or a sample training completion record.
2. For ongoing/annual training: training platform records showing completion rates and dates, email records of training distribution, attendance records for live training sessions, or a written attestation with specific details (training date, topic, number of participants).
3. For role-specific training: a description of the specialized training provided to roles with access to platform data, with supporting evidence as described above.

*AL2* N/A

**Test Procedure**

*AL1*

1. If provided, review the evidence for plausibility and consistency with the 3.1.1 attestation.
2. For ongoing training, confirm that training activity occurred within the most recent 12 months.

---

### 3.1.5 Separation process (optional supporting evidence)

Where the organization has identified an asset return or separation process as an implemented process type, the following evidence may be provided.

**Evidence**

*AL1*

1. A written description of the separation/offboarding process, covering asset return and/or access revocation.
2. A checklist, workflow, or ticket template used during offboarding.
3. For solo developers: a written attestation that the developer owns all equipment and is the sole person with access is acceptable.

*AL2* N/A

**Test Procedure**

*AL1*

1. If provided, review the separation process for relevance — does it address asset return and/or access revocation?

---

# 4 Vulnerability Management

## 4.1 Maintain publicly accessible vulnerability disclosure channel

### Description

Organizations shall maintain a publicly accessible mechanism through which external parties can report security vulnerabilities.

### Rationale

External security researchers are often the first to discover vulnerabilities. Without a clear reporting channel, vulnerabilities may go unreported or be disclosed publicly without the organization having an opportunity to remediate.

### Audit

---

### 4.1.1 Public vulnerability reporting mechanism

A publicly accessible mechanism shall exist for external parties to report security vulnerabilities (e.g., security-specific email address, web form, or vulnerability disclosure program/policy page).

**Evidence**

*AL1*

1. Provide the URL of the vulnerability disclosure program, security contact page, or equivalent.
2. Alternatively: provide a screenshot of the publicly accessible vulnerability reporting mechanism (e.g., a security.txt file, a "Report a Vulnerability" page, or a bug bounty platform listing).
3. If a formal VDP is not maintained, see 4.1.2 for the monitored contact fallback.

*AL2* N/A

**Test Procedure**

*AL1*

1. Verify the provided URL or mechanism is publicly accessible and clearly describes how to report security vulnerabilities.

**Verification**

*AL1*

1. A publicly accessible mechanism for reporting security vulnerabilities exists, OR
2. The organization satisfies 4.1.2 (monitored contact fallback).

---

### 4.1.2 Monitored contact fallback

Where a formal vulnerability disclosure program is not maintained, an easily accessible email address, phone number, or contact form shall be available and regularly monitored.

**Evidence**

*AL1*

1. Provide the security contact information (e.g., [security@company.com](mailto:security@company.com), phone number, or contact form URL).
2. Provide evidence that the contact is regularly monitored. Acceptable evidence includes: a screenshot showing the email inbox or contact form submission queue, a written description of who monitors the contact and at what frequency, or evidence of a response to a past report.

*AL2* N/A

**Test Procedure**

*AL1*

1. Verify the contact information is easily accessible (e.g., published on the organization's website).
2. Review evidence of monitoring.

**Verification**

*AL1*

1. An easily accessible email address, phone number, or contact form is available for reporting security concerns.
2. The contact is regularly monitored (at least weekly).
3. Note: This spec is only required when a formal VDP (4.1.1) is not maintained.

---

## 4.2 Implement security event investigation process

### Description

Organizations shall maintain a documented process for investigating security events detected through audit logs, monitoring systems, or other mechanisms.

### Rationale

Generating audit logs and monitoring alerts is only effective if detected events are investigated. This requirement operationalizes the logging capabilities required by the Cloud Profile.

### Audit

---

### 4.2.1 Documented investigation process

A documented process shall exist for investigating security events detected in audit logs or monitoring systems.

**Evidence**

*AL1*

1. Provide the documented security event investigation process. Acceptable formats include: an incident response plan (or relevant section), a runbook or playbook for security event investigation, a written description of the investigation workflow (who investigates, escalation path, documentation requirements).

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the documented process for completeness — does it describe how security events are investigated once detected?

**Verification**

*AL1*

1. A documented process exists for investigating security events.
2. The process describes at minimum: how events are triaged, who is responsible for investigation, and how findings are documented.

---

### 4.2.2 Investigation response timeframe

Security event investigations shall be initiated within a documented timeframe.

**Evidence**

*AL1*

1. Provide the documented response timeframe for initiating investigations. This may be included in the investigation process document (4.2.1) or specified separately.
2. The timeframe may vary by severity (e.g., critical events within 4 hours, other events within 24 hours).

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the documented timeframe for reasonableness and specificity.

**Verification**

*AL1*

1. The organization has a documented timeframe for initiating security event investigations.
2. The timeframe is specific (e.g., "within 24 hours" not "promptly").

---

# 5 Platform Credential and Client Software Security

## 5.1 Protect platform credentials from client-side exposure

### Description

Organizations shall ensure that platform access tokens are stored using secure, platform-appropriate mechanisms and are not accessible to unauthorized applications. Platform app secrets shall not be included in client-side code or any artifact accessible to end users.

### Rationale

Platform credentials exposed in client-side code or insecure storage can be extracted by attackers. On mobile devices, tokens stored outside platform-provided secure storage may be accessible to other installed applications. On the web, secrets embedded in JavaScript are visible to anyone who inspects the page source.

### Audit

---

### 5.1.1 Secure storage of platform access tokens

Platform access tokens shall be stored using platform-appropriate secure storage mechanisms and shall not be accessible to unauthorized applications (e.g., Android Keystore or iOS Keychain for mobile apps; HttpOnly cookies or server-side session storage for web apps).

**Evidence**

*AL1*

1. Provide a written description of how platform access tokens are stored, specifying the storage mechanism used (e.g., "Access tokens are stored server-side in an encrypted database and delivered to the browser via HttpOnly, Secure cookies" or "Access tokens are stored in the Android Keystore").
2. If the application is web-only: provide a description or code snippet showing that tokens are managed server-side or stored in HttpOnly cookies (not in localStorage or JavaScript-accessible storage).
3. If the application includes a mobile component: provide a description or code snippet showing that tokens are stored using the platform's secure storage API (Android Keystore, iOS Keychain, or equivalent).

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the description for adherence with the requirement — is the described storage mechanism appropriate for the platform?
2. Verify the storage mechanism is not a known-insecure approach (e.g., SharedPreferences on Android without encryption, localStorage on web for sensitive tokens).

**Verification**

*AL1*

1. Platform access tokens are stored using a platform-appropriate secure mechanism.
2. Tokens are not accessible to unauthorized applications or scripts.

---

### 5.1.2 Non-exposure of platform app secrets

Platform app secrets shall not be included in client-side code, compiled application binaries, or any artifact accessible to end users.

**Evidence**

*AL1*

1. Provide a written statement confirming that the platform app secret is not included in client-side code, compiled binaries, or any user-accessible artifact.
2. Provide a brief description of where the app secret is stored (e.g., "App secret is stored in AWS Secrets Manager and accessed server-side only" or "App secret is stored as an environment variable on the server").
3. If the application includes a mobile component: confirm the app secret is not embedded in the mobile app binary.

*AL2* N/A

**Test Procedure**

*AL1*

1. Review the provided statement and description for plausibility.
2. Confirm the described storage location is server-side and not accessible to end users.

**Verification**

*AL1*

1. The platform app secret is not included in any client-side code, compiled binary, or user-accessible artifact.
2. The app secret is stored server-side using a secure mechanism.

---

## 5.2 Maintain client application software currency

### Description

Where the organization distributes mobile applications that access platform data, it shall maintain a process for identifying, prioritizing, and applying patches to third-party software dependencies, and shall target a currently supported platform version. Web-only developers satisfy this requirement with a written statement confirming no mobile application exists.

### Rationale

Mobile applications that access platform data are attack surfaces. Outdated dependencies may contain known vulnerabilities, and targeting an unsupported platform version means the application runs without current security protections.

### Audit

---

### 5.2.1 Mobile dependency patching process

Where the organization distributes mobile applications that access platform data, a defined process shall exist for identifying, prioritizing, and applying patches to third-party software dependencies.

**Evidence**

*AL1*

1. If the organization distributes a mobile application that accesses platform data: Provide a written description of the process for identifying and applying patches to third-party dependencies in the mobile app. Acceptable evidence also includes: dependency scanning tool output, a list of third-party libraries with version tracking, or build system configuration showing dependency management.
2. If the organization does NOT distribute a mobile application: Provide a written statement confirming that no mobile application accesses platform data. This spec is then satisfied.

*AL2* N/A

**Test Procedure**

*AL1*

1. If a mobile app exists: review the description for a defined process covering dependency identification, prioritization, and patching.
2. If no mobile app exists: accept the written statement.

**Verification**

*AL1*

1. The organization has a defined process for managing third-party dependencies in mobile applications that access platform data, OR
2. The organization confirms no such mobile application exists.

---

### 5.2.2 Supported platform version

Mobile applications shall target a currently supported platform version (e.g., a recent Android API level or iOS version that receives security updates from the platform vendor).

**Evidence**

*AL1*

1. If the organization distributes a mobile application: Provide the current targetSdkVersion (Android) or minimum deployment target (iOS) from the app's build configuration.
2. If no mobile application exists: this spec inherits the N/A determination from 5.2.1.

*AL2* N/A

**Test Procedure**

*AL1*

1. If a mobile app exists: verify the declared platform target is a version that currently receives security updates from the platform vendor (Google/Apple).
2. If no mobile app exists: accept the N/A determination.

**Verification**

*AL1*

1. The mobile application targets a platform version that currently receives security updates, OR
2. No mobile application exists (N/A per 5.2.1).
