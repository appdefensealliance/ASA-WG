# App Defense Alliance CASA 3.0 (AL2) Test Guide
Version 3.0 - 2026-10-16

> **Version history** is maintained via GitHub Releases and `CHANGELOG.md`.

# About This Guide

This guide defines the evidence, test procedure and verification criteria for the **14 requirements that AL2 adds to AL1**. The AL1 Testing Guide v3.0 applies in full at AL2 and is not repeated. Each AL2 test is lab-adjudicated: a tool or scripted harness produces candidates and the lab decides, within the stated adjudication budget (239 minutes in total across the 14 tests). Evidence formats, verdict rules and compensating-control rules are those of the AL1 Testing Guide.

# Access Required at AL2

In addition to AL1 access: at least two provisioned tenants or organisations with at least two roles each (AZI-08, AZI-09, AZI-10); accounts the lab may lock, reset and re-authenticate (AUT-09, AUT-10, AUT-11); source code for SAST-14 and a reproducible build where the control requires it.

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

# Test Cases

## 2. Static Code Analysis & Secrets

### SAST-14 No back doors, undocumented accounts, time bombs or malicious logic

External Reference: ASVS V10.2.3, V10.2.4, V10.2.5 (L3); CWE-506, CWE-511 · Applicable profile: `All`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run back-door and logic-bomb rules over the source: hardcoded account comparisons and date- or time-triggered branches in security paths. Build the application from source and compare the resulting artifact digest with the shipped artifact.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep, CodeQL, reproducible-build toolchain.
3. Lab adjudication of tool output: budget 20 minutes per application.

**Verification**

* **PASS** — Zero constructs survive assessor triage as an authentication bypass, an undocumented account, or a time- or date-triggered branch in a security-relevant path, **and** the shipped artifact digest reproduces from source.
* **FAIL** — ≥ 1 triage-confirmed back door, undocumented account or logic bomb, or a shipped artifact that does not reproduce from the source provided.

---

## 5. Authentication & Session Management

### AUT-09 Anti-automation on authentication endpoints — **no more than 100 failed attempts per account per hour**, or enforced CAPTCHA / MFA / soft lockout

External Reference: ASVS V2.2.1 (L1); NIST SP 800-63B §5.2.2; OWASP WSTG-ATHN-03 · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Issue 120 failed authentications against a lab-owned account within 60 minutes and record every response.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness.
3. Lab adjudication of tool output: budget 15 minutes per application.

**Verification**

* **PASS** — By attempt 101 the endpoint returns HTTP 429, a CAPTCHA challenge, an MFA step-up, or a lockout response, and the assessor confirms the response is an enforcement rather than a generic error.
* **FAIL** — Attempt 101 and beyond receive an ordinary authentication-failure response with no throttle, challenge or lockout.

---

### AUT-10 Idle session timeout enforced; re-authentication required after the idle period

External Reference: ASVS V3.3.2 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Hold an authenticated session idle for 15 minutes, 1 hour, 4 hours and 8 hours, replaying a protected request at the HTTP layer at each step.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness.
3. Lab adjudication of tool output: budget 12 minutes per application.

**Verification**

* **PASS** — A protected request is rejected with 401 or 403 at or before the application's stated idle window, and re-authentication is required, with the assessor confirming the rejection is expiry rather than an unrelated error.
* **FAIL** — The session remains valid past the idle window, or expiry is enforced only by client-side script.

---

### AUT-11 Password change or reset terminates other active sessions; **out-of-band authentication codes are single-use and expire ≤ 10 minutes**; password-reset links are single-use and expire ≤ 60 minutes; both are CSPRNG-generated with ≥ 20 bits of entropy

External Reference: ASVS V2.7.2 (L1), V2.7.3 (L1); V3.3.3 (L2), V2.7.6 (L2); reset-link lifetime *ADA-defined* (ASVS 4.0.3 sets none); NIST SP 800-63B §5.1.3 · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. In session A change the password and replay session B. Request an out-of-band code and a reset link; use each twice, and use each after its stated lifetime.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness.
3. Lab adjudication of tool output: budget 20 minutes per application.

**Verification**

* **PASS** — Session B is invalidated by the password change; the out-of-band code is rejected on second use and after 10 minutes; the reset link is rejected on second use and after 60 minutes; both values pass a 200-sample min-entropy estimate ≥ 20 bits.
* **FAIL** — Session B survives, either verifier is accepted twice, either is accepted past its threshold, or entropy is below 20 bits.

---

## 6. Authorization & Injection

### AZI-07 Access control enforced on a trusted server-side layer, not in the client

External Reference: ASVS V4.1.1 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. From the authenticated crawl, inventory every client-side control and compare, endpoint by endpoint, the server's behaviour when that control is bypassed. Where source is available, scan client code for authorization decisions.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Burp Suite, semgrep.
3. Lab adjudication of tool output: budget 15 minutes per application.

**Verification**

* **PASS** — Every affordance hidden or disabled in the client is also refused by the server when invoked directly, and no authorization decision is taken solely in client code.
* **FAIL** — ≥ 1 endpoint whose only enforcement is the client affordance.

---

### AZI-08 No Insecure Direct Object Reference / Broken Object Level Authorization, including **cross-tenant** access

External Reference: ASVS V4.2.1 (L1); OWASP API1:2023; CWE-639 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Using two provisioned tenants, replay every object identifier observed in tenant A from a tenant B session, and across roles within one tenant.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Burp Suite, Autorize.
3. Lab adjudication of tool output: budget 25 minutes per application.

**Verification**

* **PASS** — Every cross-tenant and cross-user object request returns 403 or 404 with no object content, for every object class exercised.
* **FAIL** — ≥ 1 object readable or writable across a tenant or user boundary.

---

### AZI-09 No horizontal or vertical privilege escalation; function-level authorization enforced

External Reference: ASVS V4.1.3 (L1); OWASP API5:2023; CWE-269 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Build a role matrix from the provisioned roles and accounts, exercise every function from every role, and invoke administrator-only routes directly from a low-privilege session.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Burp Suite, Autorize.
3. Lab adjudication of tool output: budget 25 minutes per application.

**Verification**

* **PASS** — No function is executable by a role the matrix does not grant it to, horizontally or vertically.
* **FAIL** — ≥ 1 function executable from an unauthorised role.

---

### AZI-10 Access-control attributes are not user-manipulable; access control fails securely on exception

External Reference: ASVS V4.1.2, V4.1.5 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. On every endpoint, tamper with access-control attributes (role, tenant identifier, scope, token claims) and inject faults that force the authorization layer to raise an exception.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Burp Suite, jwt_tool.
3. Lab adjudication of tool output: budget 15 minutes per application.

**Verification**

* **PASS** — No tampered attribute changes the authorization outcome, and every induced exception results in denial.
* **FAIL** — ≥ 1 tampered attribute grants access, or an induced exception results in allow.

---

### AZI-11 Server-Side Request Forgery prevented on all URL-fetching functionality

External Reference: ASVS V5.2.6 (L1); OWASP API7:2023; CWE-918 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Exercise every URL-accepting parameter against an out-of-band interaction server, cloud-metadata addresses, redirect chains and DNS-rebinding payloads.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Burp Suite, interactsh.
3. Lab adjudication of tool output: budget 15 minutes per application.

**Verification**

* **PASS** — No out-of-band interaction is recorded from the application for any payload, and no metadata endpoint content is returned.
* **FAIL** — ≥ 1 out-of-band interaction attributable to the application, or metadata content reflected.

---

### AZI-12 No server-side template injection, XPath/XML injection, or XXE

External Reference: ASVS V5.2.5, V5.3.10, V5.5.2 (L1); CWE-1336, CWE-611 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Craft template-injection, XPath and XML payloads, including external-entity sets, for every parameter that reaches a template or XML parser.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): tplmap, Burp Suite.
3. Lab adjudication of tool output: budget 15 minutes per application.

**Verification**

* **PASS** — No payload evaluates: no arithmetic evaluation marker, no entity expansion, no out-of-band XXE callback.
* **FAIL** — ≥ 1 payload evaluates or triggers an out-of-band callback.

---

### AZI-13 File uploads restricted to expected types, stored outside the web root with least privilege, and never directly executable

External Reference: ASVS V12.4.1, V12.5.1 (L1); V12.2.1 (L2); CWE-434 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Upload a crafted file matrix — polyglot files, double extensions, MIME mismatches, oversize files and archive bombs — then attempt to retrieve and execute each from its stored path.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Burp Suite, scripted upload harness.
3. Lab adjudication of tool output: budget 15 minutes per application.

**Verification**

* **PASS** — Every upload outside the declared type allowlist is rejected; every accepted upload is retrieved with a non-executable content type from a path outside the document root.
* **FAIL** — ≥ 1 disallowed type accepted, or ≥ 1 uploaded file retrievable as executable or from inside the document root.

---

## 7. Application Use of OAuth 2.0 / OpenID Connect

### OAU-10 The application handles identity-provider-issued refresh tokens correctly: superseded tokens are discarded on rotation, tokens are never duplicated across storage locations, and refresh failures do not trigger silent re-authorization without user context

External Reference: RFC 9700 §4.14.2 · Applicable profile: `All`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Refresh the token repeatedly, induce a refresh failure, revoke the token server-side, and enumerate every storage location after each cycle.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness, Playwright, MobSF.
3. Lab adjudication of tool output: budget 20 minutes per application.

**Verification**

* **PASS** — After each rotation exactly one refresh token exists across all storage locations and the superseded value is rejected; a refresh failure surfaces a user-visible re-authorization rather than a silent background grant.
* **FAIL** — A superseded refresh token remains stored or usable, a token is duplicated across locations, or a refresh failure triggers silent re-authorization.

---

### OAU-11 Tokens are revoked on user logout, on user-initiated revocation, and on account deletion

External Reference: RFC 7009; ASVS V3.5.1 (L2) · Applicable profile: `All`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Perform logout, in-application revocation and account deletion, and after each replay the access and refresh tokens against an identity-provider API and against the application backend.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness.
3. Lab adjudication of tool output: budget 15 minutes per application.

**Verification**

* **PASS** — After each of the three events the access token and the refresh token are both rejected by the identity provider (`invalid_token`) and by the application backend.
* **FAIL** — ≥ 1 token still accepted after logout, revocation or account deletion.

---

## 8. Webhook Security

### WHK-04 Replay protection via signed timestamps with a bounded acceptance window, plus idempotency handling

External Reference: CASA v2.1.1 §7.2.3; CWE-294 · Applicable profile: `Web_Application`

**Evidence**

1. Redacted HAR 1.2 capture of delivery attempts, `testssl.sh` JSON for the receiver host, and SARIF 2.1.0 for static checks.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Re-deliver a captured, validly signed payload immediately, at the acceptance-window boundary and beyond it, and deliver payloads with duplicate idempotency keys.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted delivery harness.
3. Lab adjudication of tool output: budget 12 minutes per application.

**Verification**

* **PASS** — A validly signed payload replayed outside the stated acceptance window is rejected, and a duplicate delivery inside the window produces exactly one state change, with the assessor confirming the deduplication is idempotency handling rather than coincidence.
* **FAIL** — A payload is accepted outside the window, or a duplicate delivery produces a second state change.

---
