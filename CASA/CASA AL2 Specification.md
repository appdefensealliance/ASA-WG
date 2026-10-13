# App Defense Alliance CASA Specification — Assurance Level 2
Version 3.0 - 2026-10-13

> **Version history** is maintained via GitHub Releases and `CHANGELOG.md`.

# About This Specification

Assurance Level 2 (AL2) is **AL1 plus 15 additional requirements**. Everything in the AL1 Specification v3.0 — assurance-level definitions, scoping guidance, the 70 AL1 requirements, verdicts and certification rules — applies unchanged at AL2 and is not repeated here. This document lists only what AL2 adds.

# When AL2 Applies

AL2 is required where the platform provider calls for it — typically for applications with high user adoption, access to the most sensitive data classes, or material findings at AL1. The additional requirements are those whose test needs **lab adjudication or interactive access** beyond what an automated pass/fail signal can decide: cross-tenant authorization, privilege escalation, business-logic session and verifier lifecycles, token revocation, upload handling and malicious-code review.

# Relationship to CASA 2.1.1

AL2 remains AL1 plus lab-adjudicated requirements. Of its 15 additional requirements, 9 absorb the 14 CASA 2.1.1 test cases that need human context — object-level and function-level authorization, brute-force throttling, verifier and session lifecycles, SSRF, template/XML injection, file upload and webhook replay — and the remainder are new.

| **CASA 2.1.1 test cases** | **Count** | **Where they are in v3.0** |
| --- | --- | --- |
| Carried forward | 34 | AL1, same objective, lab-executed |
| Split | 1 | Randomness in AL1 (SAST-06); verifier lifecycle in AL2 (AUT-11) |
| Elevated to AL2 | 14 | AL2 |
| Retired | 6 | No deterministic test; the adjacent testable property is retained where one exists |
| **Total** | **55** | |

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

# Additional Requirements (15)

## 2. Static Code Analysis & Secrets (+1)

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **SAST-14** | No back doors, undocumented accounts, time bombs or malicious logic | ASVS V10.2.3, V10.2.4, V10.2.5 (L3); CWE-506, CWE-511 | `All` |

## 5. Authentication & Session Management (+3)

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **AUT-09** | Anti-automation on authentication endpoints — **no more than 100 failed attempts per account per hour**, or enforced CAPTCHA / MFA / soft lockout | ASVS V2.2.1 (L1); NIST SP 800-63B §5.2.2; OWASP WSTG-ATHN-03 | `Web_Application` |
| **AUT-10** | Idle session timeout enforced; re-authentication required after the idle period | ASVS V3.3.2 (L1) | `Web_Application` |
| **AUT-11** | Password change or reset terminates other active sessions; **out-of-band authentication codes are single-use and expire ≤ 10 minutes**; password-reset links are single-use and expire ≤ 60 minutes; both are CSPRNG-generated with ≥ 20 bits of entropy | ASVS V2.7.2 (L1), V2.7.3 (L1); V3.3.3 (L2), V2.7.6 (L2); reset-link lifetime *ADA-defined* (ASVS 4.0.3 sets none); NIST SP 800-63B §5.1.3 | `Web_Application` |

## 6. Authorization & Injection (+7)

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **AZI-07** | Access control enforced on a trusted server-side layer, not in the client | ASVS V4.1.1 (L1) | `Web_Application` |
| **AZI-08** | No Insecure Direct Object Reference / Broken Object Level Authorization, including **cross-tenant** access | ASVS V4.2.1 (L1); OWASP API1:2023; CWE-639 | `Web_Application` |
| **AZI-09** | No horizontal or vertical privilege escalation; function-level authorization enforced | ASVS V4.1.3 (L1); OWASP API5:2023; CWE-269 | `Web_Application` |
| **AZI-10** | Access-control attributes are not user-manipulable; access control fails securely on exception | ASVS V4.1.2, V4.1.5 (L1) | `Web_Application` |
| **AZI-11** | Server-Side Request Forgery prevented on all URL-fetching functionality | ASVS V5.2.6 (L1); OWASP API7:2023; CWE-918 | `Web_Application` |
| **AZI-12** | No server-side template injection, XPath/XML injection, or XXE | ASVS V5.2.5, V5.3.10, V5.5.2 (L1); CWE-1336, CWE-611 | `Web_Application` |
| **AZI-13** | File uploads restricted to expected types, stored outside the web root with least privilege, and never directly executable | ASVS V12.4.1, V12.5.1 (L1); V12.2.1 (L2); CWE-434 | `Web_Application` |

## 7. Application Use of OAuth 2.0 / OpenID Connect (+2)

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **OAU-10** | The application handles identity-provider-issued refresh tokens correctly: superseded tokens are discarded on rotation, tokens are never duplicated across storage locations, and refresh failures do not trigger silent re-authorization without user context | RFC 9700 §4.14.2 | `All` |
| **OAU-11** | Tokens are revoked on user logout, on user-initiated revocation, and on account deletion | RFC 7009; ASVS V3.5.1 (L2) | `All` |

## 8. Mobile Supplement (+1)

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **MOB-10** | All link-borne input arriving through deep links and universal links is validated before use | MASA 1.5.1.2 / 2.5.1.6; CWE-939 | `Mobile` |

## 9. Webhook Security (+1)

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **WHK-04** | Replay protection via signed timestamps with a bounded acceptance window, plus idempotency handling | CASA v2.1.1 §7.2.3; CWE-294 | `Web_Application` |
