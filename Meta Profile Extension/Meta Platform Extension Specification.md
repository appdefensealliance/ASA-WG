# App Defense Alliance Meta Platform Extension Specification

Version 0.5 \- DRAFT \- 07-APR 26

# Revision History

| Version | Date | Description |
| :---- | :---- | :---- |
| 0.5 | 4/7/26 | Initial draft based on DPA-to-ADA gap analysis |

# Contributors

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

### Application Security Assessment Working Group Leads

* Alex Duff (Meta) \- ASA WG Chair
* Brooke Davis (Google) \- ASA WG Vice Chair

### Meta Platform Extension Leads

* Alex Duff (Meta)

### Contributors

* Alex Duff (Meta)

# About This Specification

This specification defines the **Meta Platform Extension**, a supplemental set of organizational security requirements under the App Defense Alliance (ADA) certification scheme. Unlike ADA's existing profiles (MASA, CASA, Cloud App and Config Profile), which assess product and infrastructure security controls, this Extension addresses organizational security processes that are relevant to the Meta Platform Data Protection Assessment process.

## Purpose

Platform providers such as Meta assess third-party developers against both technical product security and organizational security practices. ADA's existing profiles comprehensively cover product and infrastructure security but do not address organizational controls such as endpoint management, personnel security, or organizational access governance. This Extension closes that gap.

## Relationship to Core Profiles

The Meta Platform Extension is an **Extension**, not a standalone Profile. Developers pursue the Extension **alongside** one or more core ADA profiles:

- **MASA** (Mobile Application Security Assessment) — for mobile applications
- **CASA** (Cloud Application Security Assessment) — for web applications and APIs
- **Cloud App and Config Profile** — for cloud infrastructure

The Extension does not duplicate any requirement already covered by MASA, CASA, or the Cloud Profile. Where a core profile partially addresses an organizational concern, this specification notes the complementary relationship.

## Alignment with Platform Data Protection Requirements

The requirements in this Extension are informed by Meta's Data Protection Assessment (DPA) program and reflect the required organizational security controls expected of certain developers on the Meta Platform. The requirements are designed to be achievable by organizations of all sizes, including solo developers, while maintaining meaningful security assurance.

# Applicability

This specification applies to any organization that:

1. Accesses platform data through APIs or other integration mechanisms, AND
2. Is pursuing or holds an ADA certification under MASA, CASA, or the Cloud App and Config Profile

The requirements apply to the **organization and its personnel** rather than to a specific application or infrastructure component. "Personnel" includes employees, contractors, and any individuals with access to platform data.

# Definitions

| Term | Definition |
| :---- | :---- |
| (AL1) ADA Assurance Level 1 (Lab Verified) | The developer provides evidence and statements of compliance to each audit test case. The ADA-approved lab reviews the evidence against the requirements. For organizational controls, acceptable evidence includes policies, screenshots of configurations, training records, and attestations. |
| Acceptable Use Policy (AUP) | A documented organizational policy that defines the allowable purposes for processing platform data on devices and requires deletion of platform data when the business purpose no longer exists. |
| Endpoint device | Any computing device (laptop, desktop, mobile phone, tablet) used by personnel to access, process, or store platform data, whether organization-owned or personally owned. |
| Full Disk Encryption (FDE) | Encryption of all data on a storage device, including temporary files and swap space, using an industry-standard algorithm (e.g., BitLocker, FileVault, LUKS). |
| Data Loss Prevention (DLP) | Software that monitors, detects, and controls the movement of data on endpoint devices, configured to address platform data. |
| Multi-Factor Authentication (MFA) | An authentication mechanism requiring two or more independent factors: something the user knows (password), something the user has (token, device), or something the user is (biometric). |
| Password complexity policy | A documented and enforced policy meeting or exceeding industry standards for password strength, including minimum length, character diversity, reuse restrictions, and account lockout provisions. See requirement 2.1.4 for specific criteria. |
| Personnel | Employees, contractors, and any other individuals who access platform data on behalf of the organization. |
| Platform data | Data obtained from or through a platform provider's APIs, SDKs, or other integration mechanisms, including user data, access tokens, and derived data. |
| Vulnerability Disclosure Program (VDP) | A formal program that defines how external parties can report security vulnerabilities, including scope, safe harbor provisions, and response commitments. |

# Table of Contents

1 [Endpoint Security](#1-endpoint-security)

1.1 [Protect platform data on organizational devices](#11-protect-platform-data-on-organizational-devices)

1.2 [Maintain endpoint software currency](#12-maintain-endpoint-software-currency)

2 [Organizational Access Control](#2-organizational-access-control)

2.1 [Enforce multi-factor authentication or equivalent account takeover prevention for all tools processing platform data](#21-enforce-multi-factor-authentication-or-equivalent-account-takeover-prevention-for-all-tools-processing-platform-data)

2.2 [Manage account lifecycle across all systems](#22-manage-account-lifecycle-across-all-systems)

3 [Personnel Security](#3-personnel-security)

3.1 [Implement personnel security processes](#31-implement-personnel-security-processes)

4 [Vulnerability Management](#4-vulnerability-management)

4.1 [Maintain publicly accessible vulnerability disclosure channel](#41-maintain-publicly-accessible-vulnerability-disclosure-channel)

4.2 [Implement security event investigation process](#42-implement-security-event-investigation-process)

5 [Platform Credential and Client Software Security](#5-platform-credential-and-client-software-security)

5.1 [Protect platform credentials from client-side exposure](#51-protect-platform-credentials-from-client-side-exposure)

5.2 [Maintain client application software currency](#52-maintain-client-application-software-currency)

Appendix C: [Lab Personnel Competency Requirements](#appendix-c-lab-personnel-competency-requirements)

# 1 Endpoint Security

## 1.1 Protect platform data on organizational devices

### Description

Organizations shall implement controls to protect platform data stored on or accessed from endpoint devices used by their personnel. Protection may be achieved through technical controls (full disk encryption or data loss prevention software) or through administrative controls (an acceptable use policy governing the handling of platform data on devices). Where storage of platform data on devices is not required, personnel shall be advised accordingly.

### Rationale

Platform data processed on endpoint devices is vulnerable to unauthorized access through device loss, theft, or compromise. Without appropriate protections, sensitive data may be exposed if a device is lost or accessed by unauthorized parties. Providing flexibility between technical and administrative controls ensures that organizations of all sizes and maturity levels can implement meaningful protections proportionate to their operations.

### Scope

- All endpoint devices (organization-owned and personally owned) used by personnel who access platform data

### Audit

| Spec | Description |
| :---- | :---- |
| 1.1.1 | The organization shall implement one or more of the following protections for platform data stored on organizational or personal devices: (a) full disk encryption enforced across organizational devices (e.g., via group policy for BitLocker or FileVault), or (b) endpoint data loss prevention (DLP) software configured to monitor and log actions related to platform data on all managed devices. |
| 1.1.2 | Where technical controls per 1.1.1 are not implemented, the organization shall maintain a documented acceptable use policy that (a) defines allowable business purposes for processing platform data on devices, and (b) requires deletion of platform data when the business purpose no longer exists. |
| 1.1.3 | Personnel who may process platform data on devices shall be informed of the applicable technical protections or acceptable use policy and shall acknowledge their obligations. |
| 1.1.4 | Where storage of platform data on organizational devices is not required, the organization shall advise personnel not to store platform data on such devices. |

---

## 1.2 Maintain endpoint software currency

### Description

Organizations shall maintain a process for identifying, prioritizing, and applying security patches to operating systems, browsers, and security software on endpoint devices used by personnel who build, operate, or access systems processing platform data. The process may be manual or automated but shall demonstrate ongoing activity.

### Rationale

Unpatched endpoint software exposes organizations to known vulnerabilities that attackers can exploit to gain access to developer workstations and, by extension, platform data. While ADA's CASA profile (6.1) addresses server-side software components and the Cloud Profile (3.7) covers server operating systems, neither addresses the endpoint devices used by development and operations personnel. A defined patching process — even a manually tracked one — ensures that endpoint vulnerabilities are systematically addressed.

### Scope

- Endpoint devices used by personnel who build, operate, or access systems processing platform data

### Audit

| Spec | Description |
| :---- | :---- |
| 1.2.1 | The organization shall have a defined and repeatable process for identifying security patches available for operating systems, browsers, and security software on endpoint devices. |
| 1.2.2 | Available patches shall be prioritized based on risk (e.g., CVSS severity). |
| 1.2.3 | Patches shall be applied as an ongoing activity, with evidence of patching activity within the most recent 12-month period. |

**Complements**: CASA 6.1 (server-side software components), Cloud Profile 3.7 (server operating systems)

---

# 2 Organizational Access Control

## 2.1 Enforce multi-factor authentication or equivalent account takeover prevention for all tools processing platform data

### Description

Organizations shall enforce multi-factor authentication (MFA) or equivalent account takeover prevention measures for all tools and services used by personnel with access to platform data. This includes collaboration and communication tools, code repositories, and software deployment systems. Where MFA is not implemented, a password complexity policy meeting or exceeding industry standards shall be enforced as an alternative.

### Rationale

Compromise of organizational accounts — email, messaging, code repositories, or CI/CD systems — can provide attackers with access to platform data, credentials, or the ability to inject malicious code. ADA's existing profiles address MFA for application administrative interfaces (CASA 3.3) and cloud platform accounts (Cloud Profile 2.14-2.16), but do not cover the broader set of organizational tools through which personnel access or manage platform data. Requiring MFA or equivalent protections across all such tools closes this gap.

### Scope

- All tools and services used by personnel with access to platform data, including but not limited to collaboration tools, code repositories, and deployment systems

### Audit

| Spec | Description |
| :---- | :---- |
| 2.1.1 | MFA or equivalent account takeover prevention shall be enforced for all access to collaboration and communication tools (e.g., email, messaging platforms). |
| 2.1.2 | MFA or equivalent account takeover prevention shall be enforced for all access to code repositories and version control systems. |
| 2.1.3 | MFA or equivalent account takeover prevention shall be enforced for all access to software deployment and CI/CD tools. |
| 2.1.4 | Where MFA is not implemented, the organization shall enforce a password complexity policy that meets or exceeds industry standards: minimum 14-character length, number and special character requirements, password reuse restrictions, minimum 1-day password age, authentication backoff delays or temporary lockout (e.g., 15 minutes after 5 consecutive failed attempts), and hard account lockout after 10 consecutive failed login attempts. |

**Complements**: CASA 3.3 (application administrative interface MFA), Cloud Profile 2.14-2.16 (cloud platform account MFA)

---

## 2.2 Manage account lifecycle across all systems

### Description

Organizations shall implement processes to manage the lifecycle of access grants across all systems that process platform data. This includes periodic review of access, identification and revocation of unused access, and prompt revocation of access when personnel depart the organization.

### Rationale

Stale or orphaned accounts represent a significant attack surface. Former personnel or unused accounts can be exploited by attackers to gain unauthorized access to platform data. The Cloud Profile addresses dormant cloud accounts (2.10) and cloud access revocation (2.13), but these controls are limited to cloud infrastructure. This requirement extends lifecycle management to all systems and tools that process platform data.

### Scope

- All systems and tools with access to platform data

### Audit

| Spec | Description |
| :---- | :---- |
| 2.2.1 | Access grants to systems processing platform data shall be reviewed at least every 12 months, and access that is no longer required shall be revoked. |
| 2.2.2 | Access that is no longer being used shall be identified and revoked. |
| 2.2.3 | All access grants shall be promptly revoked when a person departs the organization. |

**Complements**: Cloud Profile 2.10 (dormant cloud accounts), Cloud Profile 2.13 (cloud access revocation)

---

# 3 Personnel Security

## 3.1 Implement personnel security processes

### Description

Organizations shall have security processes in place for personnel who access platform data. Such processes could include background checks, confidentiality agreements, security awareness training, or asset return and access revocation procedures upon separation from the organization. Organizations are expected to implement processes appropriate to their size, risk profile, and applicable legal requirements.

### Rationale

Technical controls alone cannot fully protect platform data. Personnel security processes — however tailored to the organization — reduce insider risk and help ensure that individuals understand their obligations when handling platform data. These are foundational organizational controls that no product-focused security profile addresses.

### Scope

- All personnel with access to platform data

### Audit

| Spec | Description |
| :---- | :---- |
| 3.1.1 | The organization shall attest that it has one or more security processes in place for personnel who access platform data, and shall identify which process types it implements. |

---

# 4 Vulnerability Management

## 4.1 Maintain publicly accessible vulnerability disclosure channel

### Description

Organizations shall maintain a publicly accessible mechanism through which external parties can report security vulnerabilities. This may be a formal vulnerability disclosure program (VDP) with defined scope and safe harbor provisions, or at minimum an easily accessible and regularly monitored contact method such as an email address, phone number, or web form.

### Rationale

External security researchers and members of the public are often the first to discover vulnerabilities in an organization's systems. Without a clear and accessible channel for reporting, these vulnerabilities may go unreported or be disclosed publicly without the organization having an opportunity to remediate them. A formal VDP is preferred, but any monitored contact mechanism ensures that reports can be received and acted upon.

### Scope

- Organization-wide

### Audit

| Spec | Description |
| :---- | :---- |
| 4.1.1 | A publicly accessible mechanism shall exist for external parties to report security vulnerabilities (e.g., security-specific email address, web form, or vulnerability disclosure program/policy page). |
| 4.1.2 | Where a formal vulnerability disclosure program is not maintained, an easily accessible email address, phone number, or contact form shall be available and regularly monitored. |

**Complements**: Cloud Profile 2.3 (internal incident contacts)

---

## 4.2 Implement security event investigation process

### Description

Organizations shall maintain a documented process for investigating security events detected through audit logs, monitoring systems, or other mechanisms. Investigations shall be initiated within a documented timeframe appropriate to the severity of the event.

### Rationale

Generating audit logs and monitoring alerts is only effective if detected events are actually investigated. The Cloud Profile requires audit logging infrastructure (domains 3.4-3.6) and incident handling personnel (2.2), but does not require a documented process for investigating security events once detected. This requirement ensures that the monitoring capabilities required by the Cloud Profile are operationalized through a defined investigation workflow.

### Scope

- All systems processing platform data

### Audit

| Spec | Description |
| :---- | :---- |
| 4.2.1 | A documented process shall exist for investigating security events detected in audit logs or monitoring systems. |
| 4.2.2 | Security event investigations shall be initiated within a documented timeframe. |

**Complements**: Cloud Profile 2.2 (incident handling personnel), Cloud Profile 3.4-3.6 (audit logging infrastructure)

# 5 Platform Credential and Client Software Security

## 5.1 Protect platform credentials from client-side exposure

### Description

Organizations shall ensure that platform access tokens are stored using secure, platform-appropriate mechanisms and are not accessible to unauthorized applications. Platform app secrets shall not be included in client-side code or any artifact accessible to end users.

### Rationale

Platform credentials (access tokens and app secrets) exposed in client-side code or insecure storage can be extracted by attackers and used to access platform data. On mobile devices, tokens stored outside platform-provided secure storage (e.g., in shared preferences or external storage) may be accessible to other installed applications. On the web, tokens or secrets embedded in JavaScript or HTML source are visible to any user who inspects the page source. ADA's MASA profile addresses these risks for mobile apps (1.1.1, 1.2.1), and CASA addresses server-side token and secret management (2.3, 6.7), but neither covers the cross-platform organizational practice of ensuring credentials are never exposed client-side. This requirement provides that coverage.

### Scope

- All applications (web and mobile) that access platform data

### Audit

| Spec | Description |
| :---- | :---- |
| 5.1.1 | Platform access tokens shall be stored using platform-appropriate secure storage mechanisms and shall not be accessible to unauthorized applications (e.g., Android Keystore or iOS Keychain for mobile apps; HttpOnly cookies or server-side session storage for web apps). |
| 5.1.2 | Platform app secrets shall not be included in client-side code, compiled application binaries, or any artifact accessible to end users. |

**Complements**: CASA 2.3 (session token security), CASA 6.7 (server-side secrets), MASA 1.1.1 (secure storage), MASA 1.2.1 (cryptography)

**Note**: Developers who hold MASA certification satisfy 5.1 automatically through MASA 1.1.1 and 1.2.1.

---

## 5.2 Maintain client application software currency

### Description

Where the organization distributes mobile applications that access platform data, it shall maintain a process for identifying, prioritizing, and applying patches to third-party software dependencies, and shall target a currently supported platform version.

### Rationale

Mobile applications that access platform data are attack surfaces in their own right. Outdated third-party dependencies may contain known vulnerabilities, and targeting an unsupported platform version may mean the application runs without current security protections. ADA's MASA profile addresses this for assessed mobile apps (1.6.1, 1.6.2), but developers pursuing only CASA \+ Cloud \+ Extension certifications (e.g., for a web app that also has a companion mobile app) would otherwise have no coverage for mobile dependency management. This requirement closes that gap.

### Scope

- Mobile applications that access platform data (if applicable)
- Web-only developers satisfy this requirement with a written statement confirming no mobile application exists

### Audit

| Spec | Description |
| :---- | :---- |
| 5.2.1 | Where the organization distributes mobile applications that access platform data, a defined process shall exist for identifying, prioritizing, and applying patches to third-party software dependencies. |
| 5.2.2 | Mobile applications shall target a currently supported platform version (e.g., a recent Android API level or iOS version that receives security updates from the platform vendor). |

**Complements**: MASA 1.6.1 (platform version), MASA 1.6.2 (vulnerable components)

**Note**: Developers who hold MASA certification satisfy 5.2 automatically. Web-only developers provide a written statement confirming no mobile application exists.

# Appendix A: Complementary Core Profile Requirements

This appendix identifies where Extension requirements complement (but do not duplicate) existing core profile requirements.

| Extension Requirement | Complementary Core Requirement | Relationship |
| :---- | :---- | :---- |
| 1.2 Endpoint software currency | CASA 6.1 (server-side components) | CASA covers server/backend components; Extension covers endpoint devices |
| 1.2 Endpoint software currency | Cloud Profile 3.7 (server OS patching) | Cloud covers server OS; Extension covers workstation/developer device OS |
| 2.1 Organizational MFA | CASA 3.3 (app admin MFA) | CASA covers application administrative interfaces; Extension covers organizational tools |
| 2.1 Organizational MFA | Cloud Profile 2.14-2.16 (cloud MFA) | Cloud covers cloud platform accounts; Extension covers collaboration, code repos, CI/CD |
| 2.2 Account lifecycle | Cloud Profile 2.10 (dormant accounts) | Cloud covers cloud accounts; Extension extends to all systems |
| 2.2 Account lifecycle | Cloud Profile 2.13 (access revocation) | Cloud covers cloud access; Extension extends to all systems |
| 4.1 Vulnerability disclosure | Cloud Profile 2.3 (incident contacts) | Cloud requires internal contacts; Extension requires public-facing disclosure channel |
| 4.2 Security event investigation | Cloud Profile 2.2 (incident personnel) | Cloud designates personnel; Extension requires investigation process |
| 4.2 Security event investigation | Cloud Profile 3.4-3.6 (audit logging) | Cloud requires log generation; Extension requires event investigation workflow |
| 5.1 Platform credential security | CASA 2.3 (session tokens) | CASA covers server-side session token security; Extension covers client-side credential exposure |
| 5.1 Platform credential security | CASA 6.7 (server-side secrets) | CASA requires secure server-side storage; Extension ensures secrets are not exposed client-side |
| 5.1 Platform credential security | MASA 1.1.1 (secure storage) | MASA covers mobile app secure storage; Extension covers the same control cross-platform |
| 5.2 Client software currency | MASA 1.6.1 (platform version) | MASA covers assessed mobile apps; Extension covers mobile apps of CASA/Cloud-only developers |
| 5.2 Client software currency | MASA 1.6.2 (vulnerable components) | MASA covers assessed mobile apps; Extension covers mobile apps of CASA/Cloud-only developers |

# Appendix B: Lab Personnel Competency Requirements

This appendix defines the minimum competency requirements for ADA Security Test Laboratory (ASTL) personnel who conduct assessments against the Meta Platform Extension. These requirements supplement the ASTL Evaluator/Evaluation Team Competency requirements in the ADA Security Test Lab Authorization document (Section 6.2.2).

## Context

The existing ASTL competency requirements (Section 6.2.2) mandate offensive security certifications (e.g., OSCP, GWAPT, OSWE) appropriate for hands-on penetration testing of web and mobile applications. The Meta Platform Extension requires a different competency profile: assessors review organizational evidence — policies, configuration screenshots, training records, and attestations — and exercise professional judgment about evidence completeness, plausibility, and proportionality. The work is comparable to an information security management system audit rather than an application security test.

## Engagement Team — Minimum Competency

Personnel performing assessments against the Meta Platform Extension shall meet **one** of the following:

### Option A — Relevant Professional Certification

One or more of the following currently valid certifications:

- Certified Information Systems Auditor (CISA)
- ISO/IEC 27001 Lead Auditor (from an accredited training provider)
- Certified Information Security Manager (CISM)
- Certified Information Systems Security Professional (CISSP)

### Option B — Demonstrated Experience

A minimum of two (2) years of professional experience conducting information security assessments, audits, or compliance evaluations. Qualifying experience includes, but is not limited to: ISO/IEC 27001 audits, SOC 2 readiness or Type II assessments, regulatory compliance reviews, third-party risk assessments, or equivalent organizational security evaluations.

The ASTL shall maintain records documenting qualifying experience for personnel who rely on this option.

### Option C — Existing ADA ASTL Qualification

Personnel who already meet the Engagement Team competency requirements under Section 6.2.2 of the ADA Security Test Lab Authorization document for any existing ADA profile (MASA, CASA, or Cloud App and Config Profile) are deemed qualified to assess the Meta Platform Extension without additional certification or experience requirements.

## Engagement Quality Control Reviewer

The existing Engagement Quality Control Reviewer requirements apply without modification:

- Academic training: EQF Level \>= 4
- Complementary training: Knowledge of organizational security management practices

## Rationale

The Meta Platform Extension assesses organizational security controls through document review at AL1 (Verified Self Assessment). No hands-on application testing, code review, or infrastructure scanning is performed. The competency requirements above ensure that assessors have the audit methodology, policy evaluation, and professional judgment skills necessary for this type of assessment, without imposing requirements designed for a fundamentally different activity.
