# App Defense Alliance CASA Specification — Assurance Level 1
Version 3.0 - 2026-10-13

> **Version history** is maintained via GitHub Releases and `CHANGELOG.md`.

# Introduction

CASA builds on the internationally recognised OWASP Application Security Verification Standard (ASVS) and selects from it the requirements that can be tested with clear acceptance criteria. Version 3.0 goes one step further: every AL1 requirement has a defined pass signal, a defined fail signal and a required open evidence format, so that any ADA-approved lab, anywhere, produces the same verdict on the same application.

# Applicability

This document is intended for developers, ADA-approved labs, platform providers and security specialists who build, assess or rely on the assessment of cloud and web applications and their clients.

# References

1. OWASP Application Security Verification Standard 4.0.3
2. OWASP Mobile Application Security Verification Standard (MASVS) and ADA MASA
3. IETF RFC 9700 (OAuth 2.0 Security Best Current Practice), RFC 8252, RFC 7636, RFC 8725, RFC 6750
4. NIST SP 800-63B, SP 800-52 Rev. 2, SP 800-131A Rev. 2
5. OASIS SARIF 2.1.0; CycloneDX; SPDX; W3C HAR 1.2

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

# Relationship to CASA 2.1.1

CASA v3.0 is a maturation of CASA 2.1.1, not a rewrite. The AL1 and AL2 assurance levels, the OWASP ASVS foundation, the ADA-approved lab network and the 12-month certification cycle are unchanged. Of the 55 test cases in the 2.1.1 Testing Guide, 34 are carried into AL1 with the same objective and are now lab-executed; 1 is split between AL1 and AL2; 14 are elevated to AL2 because they need lab adjudication; 6 are retired because no deterministic test exists for them. 30 deterministic requirements are new to AL1, of which 9 form the MASA AL1 Specification, incorporated by reference.

| **CASA 2.1.1 test cases** | **Count** | **Where they are in v3.0** |
| --- | --- | --- |
| Carried forward | 34 | AL1, same objective, lab-executed |
| Split | 1 | Randomness in AL1 (SAST-06); verifier lifecycle in AL2 (AUT-11) |
| Elevated to AL2 | 14 | AL2 |
| Retired | 6 | No deterministic test; the adjacent testable property is retained where one exists |
| **Total** | **55** | |

| **New deterministic requirements in AL1** | **Count** | **Examples** |
| --- | --- | --- |
| Software supply chain integrity | 3 | SBOM published and verified against a lab-generated SBOM; container image scanning; known-malicious package detection |
| OAuth client hygiene, token security and session entropy | 5 | System-browser authorization on native clients; no client secret in public binaries; backend token validation; ≥ 64-bit session entropy; session rotation at login |
| Server configuration and response headers | 10 | CSP, clickjacking, nosniff, anti-caching, strict CORS, generic error pages, no unauthenticated admin interface, HSTS, TLS implementation vulnerabilities |
| Static code and secrets | 3 | No committed private keys; mass-assignment protection; safe deserialization |
| Mobile supplement, published as the MASA AL1 Specification | 9 | Signing, debuggability, cleartext and TLS validation, platform target, exported components, WebView hardening, storage and backup hygiene, SDK vulnerabilities. All verified statically from the release artifact; no separate mobile engagement |
| **Total** | **30** | |

# Assurance Levels

| **Level** | **Who executes the tests** | **What it establishes** |
| --- | --- | --- |
| **(AL0) ADA Assurance Level 0 — Developer Self-Assessment** | The developer runs the full AL1 test set against the application, following the AL1 Test Guide and its evidence formats, and submits the result and evidence bundle to the certification body. No lab is involved. | Self-assessed baseline: the same requirements, pass signals and fail signals as AL1, decided from developer-produced evidence that has not been lab-verified. |
| **(AL1) ADA Assurance Level 1 — Lab-Executed Automated Assessment** | The ADA-approved lab runs every test against the application, its build artifacts or its source, using automated tooling. The developer provides access and artifacts, not evidence. | Deterministic baseline: every control has a defined pass signal and fail signal, and the lab's tool output is the evidence. |
| **(AL2) ADA Assurance Level 2 — Lab Assessment** | The ADA-approved lab runs every AL1 test **plus** the additional AL2 tests, which require lab adjudication or interactive access. | AL1 baseline plus authorization, business-logic and lifecycle properties that need human judgement. |

At AL1 and AL2, developer-supplied scan output, developer-run scanners and developer attestations are not accepted; security properties are never accepted on assertion. At AL0 the developer's own tool output is the submission and carries no lab verification.

# Specification Scoping Guidance

**Declared surfaces.** The developer declares the surfaces to be assessed — web origins, mobile packages, native or desktop artifacts, browser extensions, webhook receivers. The lab assesses exactly the declared surfaces and does not search for undeclared ones. A surface that is not declared is recorded `Not_Covered` on the certification record; a declared surface to which the developer withholds access is recorded **FAIL** for every affected control.

**Profiles.** Four profile names are used: `Web_Application`, `Mobile`, `Native`, `All`. Platform detail is a qualifier (`Android`, `iOS`, `Desktop`, `Device`, `Extension`), not a separate profile.

| **Profile** | **Applies to** | **Domains** |
| --- | --- | --- |
| `Web_Application` | The browser-facing web application and every HTTP API behind it, including APIs that serve mobile and native clients | 1–8 |
| `Mobile` | Android and iOS clients | 1, 2, 7 + the MASA AL1 Specification + backend via `Web_Application` |
| `Native` | Desktop, console, IoT/device clients and browser extensions | 1, 2, 7 + the MASA AL1 requirements marked `Native` |
| `All` | Every assessed surface | — |

Certification is **per surface**: the record states each assessed surface with its verdict (for example `Web_Application: PASS · Mobile (Android): PASS · Mobile (iOS): Not_Covered`) rather than implying whole-product coverage.

**Authenticated testing** is mandatory for applications requesting sensitive or restricted data; Domains 5 and 6 cannot be assessed unauthenticated. Accepted access mechanisms, in preference order: (1) lab self-provisioned account through public signup; (2) developer-provisioned sandbox accounts, at least two roles and two accounts per role; (3) scoped, time-boxed tokens (≤ 14 days); (4) lab-recorded login macro for SSO/MFA-gated flows. Bot protections may be relaxed for lab source IPs only — never globally.

**Third-party infrastructure.** Third-party infrastructure used by the target application is out of scope for this specification.

**Mobile clients.** Applications that declare a `Mobile` surface must additionally satisfy the **MASA AL1 Specification v3.0** (9 requirements, MOB-01 to MOB-09), published separately. Every MASA AL1 requirement is verified statically from the submitted release binary — no device farm, no instrumented runtime, no separate engagement. MASA AL1 verdicts are recorded on the same certification record, against the `Mobile` surface; the requirements marked `Native` also apply to declared `Native` surfaces. For a declared `Mobile` surface the binary is the application itself: if the developer withholds it, every MASA AL1 requirement is `FAIL`, not `Not_Covered`.

# Requirements

AL1 comprises **61 requirements in 8 domains**. Each row names the requirement, the standard it derives from and the profile it applies to. The Test Guide defines, for every requirement, the evidence the lab must produce and the pass and fail criteria.

## 1. Software Composition & Supply Chain (5)

**Objective:** establish that the deployed dependency graph and runtime base contain no reachable, known-exploitable vulnerabilities, and that the inventory is verifiable.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **SCA-01** | No dependency contains a reachable Critical/High vulnerability, or any CISA KEV entry | ASVS 4.0.3 V14.2.1 (L1); CWE-1395 | `All` |
| **SCA-02** | No component is end-of-life, unmaintained, or sourced from an untrusted repository | ASVS V14.2.4 (L2); OpenSSF Scorecard `Maintained` | `All` |
| **SCA-03** | Container base images and OS packages contain no unmitigated Critical/High CVEs | CIS Docker Benchmark §4; *ADA-defined* | `Web_Application` |
| **SCA-04** | A complete, machine-readable SBOM is published for the assessed build, and it matches an SBOM the assessor generates independently | ASVS V14.2.5 (L2); NTIA Minimum Elements; CycloneDX 1.5 | `All` |
| **SCA-05** | No dependency matches a known-malicious package advisory (typosquat, protestware, compromised maintainer) | OpenSSF Malicious Packages; CWE-1357 | `All` |

## 2. Static Code Analysis & Secrets (13)

**Objective:** identify defects in non-observable internal implementation — cryptography, secrets handling, injection-prone constructs — that dynamic testing cannot reach.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **SAST-01** | No hardcoded passwords, API keys, tokens or credentials in source, resources or build config | CWE-798; ASVS V2.10.4 (L2) | `All` |
| **SAST-02** | No private keys, certificates or trust material committed to the repository or shipped in artifacts | CWE-321, CWE-798; *ADA-defined* (ASVS 4.0.3 has no requirement on committed trust material) | `All` |
| **SAST-03** | No deprecated or broken cipher algorithms (DES, 3DES, RC4, Blowfish, ECB mode) | CWE-327; NIST SP 800-131A Rev.2; ASVS V6.2.5 (L2) | `All` |
| **SAST-04** | No weak hash functions (MD5, SHA-1) used in any security-relevant context | CWE-328; NIST SP 800-131A Rev.2 | `All` |
| **SAST-05** | Passwords stored using an approved memory-hard KDF with per-user salt | ASVS V2.4.1 (L2); NIST SP 800-63B §5.1.1.2 (Argon2id, scrypt, bcrypt, PBKDF2) | `Web_Application` |
| **SAST-06** | All security-relevant randomness uses a CSPRNG | CWE-338; ASVS V6.3.1, V6.3.2 (L2) | `All` |
| **SAST-07** | Frameworks protect against mass assignment / unsafe auto-binding | ASVS V5.1.2 (L1); CWE-915; OWASP API6:2023 | `Web_Application` |
| **SAST-08** | Database access exclusively uses parameterized queries, ORMs or escaped input | ASVS V5.3.4 (L1); CWE-89 | `Web_Application` |
| **SAST-09** | Deserialization of untrusted data is avoided or integrity-protected | ASVS V5.5.3 (L1); CWE-502 | `All` |
| **SAST-10** | No dynamic code execution on untrusted input (`eval`, `Function`, `exec`, reflection) | ASVS V5.2.4 (L1); CWE-95 | `All` |
| **SAST-11** | File paths are not constructed from unvalidated user-supplied metadata | ASVS V12.3.1 (L1); CWE-22 | `Web_Application` |
| **SAST-12** | Server-side secrets are held in a managed secrets store, not in config files or environment baked into images | ASVS V6.4.1 (L2); CWE-522 | `Web_Application` |
| **SAST-13** | Credentials, payment details and tokens are never written to logs; session tokens appear only in irreversible hashed form | ASVS V7.1.1 (L1); CWE-532 | `Web_Application` |

## 3. Transport Security (6)

**Objective:** confirm that every declared host enforces modern, correctly configured TLS — no cleartext, no legacy protocol versions or weak cipher suites, a valid certificate, HSTS, and no known TLS implementation vulnerabilities.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **TLS-01** | TLS enforced on all endpoints; no cleartext fallback; HTTP redirects to HTTPS | ASVS V9.1.1 (L1) | `Web_Application` |
| **TLS-02** | Only TLS 1.2 and TLS 1.3 enabled; SSLv3, TLS 1.0 and TLS 1.1 rejected | ASVS V9.1.3 (L1); NIST SP 800-52 Rev.2 | `Web_Application` |
| **TLS-03** | Only strong cipher suites; NULL, EXPORT, anonymous, RC4 and legacy CBC suites rejected; forward secrecy preferred | ASVS V9.1.2 (L1); NIST SP 800-52 Rev.2 | `Web_Application` |
| **TLS-04** | Certificate chain is valid, trusted, unexpired and matches the hostname | ASVS V9.2.1 (L2); CA/Browser Forum Baseline Requirements | `Web_Application` |
| **TLS-05** | `Strict-Transport-Security` present with `max-age` ≥ 31536000 | ASVS V14.4.5 (L1) | `Web_Application` |
| **TLS-06** | No known TLS implementation vulnerabilities (Heartbleed, ROBOT, insecure renegotiation, CRIME) | *ADA-defined*; OWASP WSTG-CRYP-01 | `Web_Application` |

## 4. Server Configuration & Response Headers (11)

**Objective:** confirm that the deployed web surface is hardened — no directory listing, debug endpoint, version or stack disclosure, unauthenticated administrative interface or takeover-prone DNS record — and that it sends the response headers that contain browser-side attacks: content security policy, framing protection, `nosniff`, anti-caching and a strict CORS policy.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **CFG-01** | Directory browsing disabled; file and directory enumeration not possible | ASVS V4.3.2 (L1) | `Web_Application` |
| **CFG-02** | Framework and server debug modes disabled in production | ASVS V14.3.2 (L1) | `Web_Application` |
| **CFG-03** | No detailed version or stack disclosure in headers or response bodies | ASVS V14.3.3 (L1) | `Web_Application` |
| **CFG-04** | Content-Security-Policy enforced; `script-src` excludes `unsafe-inline` and `unsafe-eval` | ASVS V14.4.3 (L1) | `Web_Application` |
| **CFG-05** | Clickjacking prevented via `frame-ancestors` or `X-Frame-Options` | ASVS V14.4.7 (L1) | `Web_Application` |
| **CFG-06** | `X-Content-Type-Options: nosniff` on all responses | ASVS V14.4.4 (L1) | `Web_Application` |
| **CFG-07** | Anti-caching headers on all authenticated and sensitive responses | ASVS V8.2.1 (L1) | `Web_Application` |
| **CFG-08** | CORS uses a strict allow list; no wildcard with credentials; no unvalidated origin reflection | ASVS V14.5.3 (L1); CWE-942 | `Web_Application` |
| **CFG-09** | 4xx/5xx responses return generic messages; no stack traces, internal paths or routing detail | ASVS V7.4.1 (L1); CWE-209 | `Web_Application` |
| **CFG-10** | No administrative interface reachable without authentication | CWE-306; *ADA-defined* | `Web_Application` |
| **CFG-11** | No dangling DNS record on any declared host or its CNAME chain permits subdomain takeover | ASVS V10.3.3 (L1); CWE-350 | `Web_Application` |

## 5. Authentication & Session Management (8)

**Objective:** confirm, from an authenticated session, that the application's own sign-in and session handling resists credential abuse and session hijacking — no default credentials, high-entropy session tokens that rotate at sign-in, no tokens in URLs, server-side logout, hardened cookies, safely signed and short-lived stateless tokens, and no sensitive data left in browser storage.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **AUT-01** | No default, shared or vendor-supplied credentials accepted | ASVS V2.5.4 (L1) | `Web_Application` |
| **AUT-02** | Session tokens possess ≥ 64 bits of entropy | ASVS V3.2.2 (L1) | `Web_Application` |
| **AUT-03** | A new session token is issued upon authentication (session fixation prevented) | ASVS V3.2.1 (L1); CWE-384 | `Web_Application` |
| **AUT-04** | Session tokens and credentials never appear in URLs, query strings or `Referer` | ASVS V3.1.1 (L1); CWE-598 | `Web_Application` |
| **AUT-05** | Logout invalidates the session server-side, including refresh tokens | ASVS V3.3.1 (L1) | `Web_Application` |
| **AUT-06** | Session cookies set `Secure`, `HttpOnly` and `SameSite` (`Lax` or `Strict`) | ASVS V3.4.1, V3.4.2, V3.4.3 (L1) | `Web_Application` |
| **AUT-07** | Stateless tokens are signed with a strong algorithm; `alg:none`, algorithm confusion and key substitution rejected; non-revocable tokens expire ≤ 24 hours | ASVS V3.5.3 (L2); RFC 8725 (JWT BCP); CWE-347 | `Web_Application` |
| **AUT-08** | Client-side storage holds no sensitive data or authentication material, and is cleared on logout | ASVS V8.2.3 (L1) | `Web_Application` |

## 6. Authorization & Injection (6)

**Objective:** confirm that authenticated functionality resists the common request-forgery and injection classes — cross-site request forgery, cross-site scripting, SQL and NoSQL injection, OS command injection, file inclusion and path traversal, open redirects and HTTP parameter pollution. Cross-tenant object-level authorization and privilege-escalation testing need human judgement and are assessed at AL2.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **AZI-01** | Strong anti-CSRF mechanism on all state-changing authenticated functionality | ASVS V4.2.2 (L1); CWE-352 | `Web_Application` |
| **AZI-02** | No Cross-Site Scripting — reflected, stored or DOM-based | ASVS V5.3.3 (L1); CWE-79 | `Web_Application` |
| **AZI-03** | No SQL or NoSQL injection | ASVS V5.3.4 (L1); CWE-89, CWE-943 | `Web_Application` |
| **AZI-04** | No OS command injection | ASVS V5.3.8 (L1); CWE-78 | `Web_Application` |
| **AZI-05** | No Local/Remote File Inclusion or path traversal | ASVS V5.3.9, V12.3.2, V12.3.3 (L1); CWE-22, CWE-98 | `Web_Application` |
| **AZI-06** | No open redirect or unvalidated forward; HTTP parameter pollution handled safely | ASVS V5.1.5, V5.1.1 (L1); CWE-601 | `Web_Application` |

## 7. Application Use of OAuth 2.0 / OpenID Connect (9)

**Objective:** the identity provider operates the authorization server and enforces its own correctness (grant types, redirect-URI matching, consent, token issuance); this domain does **not** assess the authorization server. It assesses what the application does with the OAuth 2.0 / OIDC mechanism: which flow it uses, how it binds the flow to the user agent, where it performs authorization on native clients, and how it stores and transmits the tokens it receives.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **OAU-01** | Only the Authorization Code flow is used — Implicit and Resource Owner Password Credentials grants are prohibited | RFC 9700 §2.1.2, §2.4 (OAuth 2.0 Security BCP); RFC 6749 | `All` |
| **OAU-02** | PKCE with `S256` is enforced on **all** authorization code flows, public and confidential | RFC 7636; RFC 9700 §2.1.1; MASA 1.3.1.1 / 2.3.1.1 | `All` |
| **OAU-03** | The application registers only exact, non-wildcard redirect URIs, and its own callback endpoint contains no open redirect or forwarding chain. *(Exact-match enforcement is performed by the identity provider; what is assessed here is what the application registers and what its callback does)* | RFC 9700 §2.1; CWE-601 | `All` |
| **OAU-04** | `state` and OIDC `nonce` are CSPRNG-generated, bound to the user agent session, and validated on return | RFC 9700 §4.7; OIDC Core §3.1.2.1; CWE-352 | `All` |
| **OAU-05** | Native, mobile and desktop clients perform authorization in the **system browser** (Custom Tabs / `ASWebAuthenticationSession`) — never an embedded WebView | RFC 8252 §8.12 | `Mobile`, `Native` |
| **OAU-06** | No client secret is embedded in a public client binary, bundle or extension package | RFC 8252 §8.5; CWE-798 | `Mobile`, `Native` |
| **OAU-07** | Access and refresh tokens are held in platform secure storage — Keystore, Keychain, or `HttpOnly Secure` cookie. Never `localStorage`, `SharedPreferences` plaintext, or disk cache | MASA 1.1.1.1 / 2.1.1.1; CWE-922; ASVS V6.4.1 (L2) *(server-side token storage only)* | `All` |
| **OAU-08** | Access tokens are transmitted only in the `Authorization` header; never in query strings or URL fragments | RFC 6750 §2.3; ASVS V3.1.1 (L1) | `All` |
| **OAU-09** | Where the application's own backend accepts identity-provider ID tokens or access tokens as proof of identity, it validates signature, `iss`, `aud`, `exp` and `scope` against the identity provider's published keys; `alg:none` and algorithm confusion are rejected | RFC 9700 §4.9; RFC 8725; CWE-347 | `Web_Application` |

## 8. Webhook Security (3)

**Objective:** where the developer declares a webhook receiver or an outbound callback facility, confirm that webhook traffic is HTTPS-only, that payloads are authenticated with HMAC-SHA256 or stronger and verified in constant time, and that user-supplied callback URLs cannot reach internal addresses. WHK-01 and WHK-02 apply to declared receivers and WHK-03 to declared callback facilities; where the relevant declaration is absent, those controls are recorded `Not_Covered`, and the assessor does not search for webhooks.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **WHK-01** | Webhook traffic is delivered exclusively over HTTPS with TLS 1.2+; cleartext endpoints are refused | CASA v2.1.1 §7.1.1; Standard Webhooks | `Web_Application` |
| **WHK-02** | Payloads are authenticated with HMAC-SHA256 or stronger, verified using a timing-safe comparison | CASA v2.1.1 §7.2.1, §7.2.2; CWE-208 | `Web_Application` |
| **WHK-03** | User-supplied callback URLs are SSRF-protected; signing secrets are not hardcoded or committed to version control | CASA v2.1.1 §7.3.1, §7.3.2; CWE-918 | `Web_Application` |

# Verdicts and Certification

| **Verdict** | **Meaning** |
| --- | --- |
| `PASS` | Assessed and conformant — the control's pass signal is satisfied |
| `FAIL` | Assessed and non-conformant — the fail signal is satisfied — **or** not assessable because the developer withheld access to a declared surface |
| `PASS_WITH_COMPENSATING_CONTROL` | Non-conformant as specified, with a mitigation the lab has independently verified by test; never available for a Critical or High finding |
| `NOT_APPLICABLE` | The control's precondition is absent on the declared surfaces (for example, no password storage) |
| `Not_Covered` | Applicable but not assessed: a required source or build artifact was not provided, or the control depends on a surface the developer did not declare. **Never equivalent to `PASS`** |

**Severity.** Findings are scored CVSS v3.1 Base (v4.0 accepted when published by the authoritative source — NVD, else OSV.dev, else vendor advisory). Critical (9.0–10.0) and High (7.0–8.9) fail. A dependency vulnerability fails only if the vulnerable symbol is reachable from application entry points; any CISA KEV entry fails regardless. Disputed or unscored CVEs are informational.

**Certification preconditions.** No certification record is issued while any Critical or High finding, or any withheld-access `FAIL`, is open; each must be fixed and re-verified by the lab. The lab retains the evidence bundle for at least 24 months and produces it to ADA or the platform provider on request.

# Definitions

| **Term** | **Meaning** |
| --- | --- |
| ADA-approved lab (assessor) | An assessor accredited by the App Defense Alliance to perform CASA assessments; "lab" and "assessor" are used interchangeably |
| Platform provider | The party that relies on the certification record to grant the application access to user data |
| Identity provider | The OAuth 2.0 authorization server / OpenID Connect provider whose tokens the application obtains and handles |
| Certification record | The attestation (for example a Letter of Validation) issued through the platform provider on the basis of the lab's result |
| Declared surface | A web origin, mobile package, native artifact, extension or webhook endpoint the developer names for assessment |
| Reference tooling | Tools named in the Test Guide as known-good implementations of a test; any tool producing the required evidence format may be substituted |
| SARIF / CycloneDX / SPDX / HAR | Open interchange formats required for evidence: OASIS SARIF 2.1.0; CycloneDX 1.5+ / SPDX 2.3+ SBOMs; W3C HAR 1.2 traffic captures |
