# AI Tool Minimum Security Register

**Draft proposal for Working Group review — 29 October 2026.**

The AI Tool minimum combines the secure web application baseline established by
published CASA with leading security practices informed by market research.
The [Minimum Security Register](AI%20Tool%20Minimum%20Security%20Register.md)
defines the baseline, applicability conditions, actor allocation and assurance limits.

## Certification scope

Standalone Tool certification scope and call-level authentication are separate.
A Tool is in scope when its intended integration processes confidential data or
enables sensitive operations. A public-only, read-only Tool may be excluded only
when it receives no confidential inputs, credentials or private context, accesses
no protected resources and performs no sensitive state-changing operation.
Public output or lack of authentication alone does not establish exclusion.

Relevant public/discovery interfaces of an in-scope Tool remain assessed. Genuine
public calls may be unauthenticated. An excluded public-only Tool remains
untrusted external input in Agent assessment, with applicable prompt-injection,
authorization, HITL and safe-outcome controls retained. Exclusion is not a
certification pass or proof of safety. This proposal does not introduce a blanket
public-application exemption from published CASA.

## Deployment and actor applicability

| Boundary | Treatment |
| --- | --- |
| Remote HTTP Tool | Applicable CASA baseline and supplemental leading practices; additional Tool safeguards SHOULD be implemented. |
| Local Android Tool, including stdio and AppFunctions | Retain current applicable strength and exclusions in the [Local Android Requirements](AI%20Tool%20Local%20Android%20Requirements.md). |
| Android Agent calling a remote Tool | Assess the Tool as remote; retain the Agent's mobile/platform duties. |
| Local Android Tool using downstream HTTP | Remains local unless it invokes an independently exposed remote Tool boundary. |
| Hybrid arrangement | Identify and assess each component and invocation/execution boundary. |
| Other local, desktop and mobile variants | Retain the existing source requirements and applicability pending a separate decision; published MASA is unchanged. |

Device-local HTTP and incidental outbound HTTP do not themselves determine the
deployment category. Literal MCP fields and discovery rules apply to the selected
MCP interface; public Internet reachability applies when publishing to the relevant
public directory. Protocol and platform publication rules bind their actual implementer.

Tool assessment covers the Tool's authorization, metadata and implemented
transport/OAuth roles. Independently controlled Agent UI/HITL, OAuth-client and
authorization-server duties must be recorded as dependencies and assessed under
the responsible profile. A Tool certificate does not prove those components.
Published CASA integration and third-party-authentication applicability remain intact.

## Normative strength and authority

Every applicable published CASA v2.1.1 requirement, alternative, criterion and
exception remains mandatory. The register preserves all 48 audit IDs and their
published AL1/AL2 criteria. Supplemental properties are conditional; they are not
21 unconditional new requirements.

MUST/SHALL states a scoped mandatory outcome. SHOULD states a recommendation;
its absence is advisory unless an independently mandatory property fails.
Priority and normative strength are separate. No P0/P1/P2 classification is assigned.
Optional credentials or proofs used to establish mandatory authority must still
pass their required verification. Missing an unused enhancement is not a failure;
invalid required authority must never grant protected access.

For protected access, the implementation's supported, correctly verified OAuth
JWT or authoritative opaque-token introspection can establish authority. This is
an admissible-evidence choice, not a requirement to support or accept both formats.
User, account, audience, resource, scope, expiry and revocation remain enforced.

The Agent's independently stronger requirements remain in force, including
untrusted-output defenses, per-action HITL and noncryptographic parameter binding,
stable action identifiers, nonce/session controls and uncertain-outcome honesty.

## Assurance claims

Minimum conformance demonstrates the concrete applicable properties in this
register. Independently verified Tool-side human approval, all-message/catalogue
cryptographic integrity and durable exactly-once effects require the corresponding
enhanced mechanisms and evidence. An Agent-signed receipt alone does not prove
human approval. Agent parameter binding is an Agent obligation and cannot prove
what a malicious Tool actually executed. A stricter Agent may decline a Tool
without its required identifier, freshness or admission capability.

## Published CASA baseline

The following 48 IDs retain their published scope, alternatives and AL1/AL2
verification unchanged. Complete saved criteria are in the
[machine-readable register](AI%20Tool%20Minimum%20Security%20Register.json).
The pinned published source governs; current draft CASA changes are not imported.

| CASA ID | Published audit title | Source |
| --- | --- | --- |
| 1.1.1 | Authentication is resistant to brute force attacks | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#111-authentication-is-resistant-to-brute-force-attacks) |
| 1.1.2 | System generated initial passwords or activation codes shall be securely randomly generated and expire after a short period. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#112-system-generated-initial-passwords-or-activation-codes-shall-be-securely-randomly-generated-and-expire-after-a-short-period) |
| 1.1.3 | Passwords shall be stored in a form that is resistant to offline attacks. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#113-passwords-shall-be-stored-in-a-form-that-is-resistant-to-offline-attacks) |
| 1.2.1 | Default credentials shall not be present on publicly exposed interfaces. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#121-default-credentials-shall-not-be-present-on-publicly-exposed-interfaces) |
| 1.3.1 | Out of band verifier shall expire in a reasonable timeframe. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#131-out-of-band-verifier-shall-expire-in-a-reasonable-timeframe) |
| 1.3.2 | Out of band verifier shall only be used once. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#132-out-of-band-verifier-shall-only-be-used-once) |
| 1.3.3 | Out of band verifier shall be securely random | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#133-out-of-band-verifier-shall-be-securely-random) |
| 1.3.4 | Out of band verifier shall be resistant to brute force attacks | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#134-out-of-band-verifier-shall-be-resistant-to-brute-force-attacks) |
| 2.1.1 | The application shall not reveal passwords or session tokens in URL parameters. In cases where the application provides an API, the application shall prevent (or give developers an option to prevent) exposing sensitive information like API keys or session tokens within the URL query strings. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#211-the-application-shall-not-reveal-passwords-or-session-tokens-in-url-parameters-in-cases-where-the-application-provides-an-api-the-application-shall-prevent-or-give-developers-an-option-to-prevent-exposing-sensitive-information-like-api-keys-or-session-tokens-within-the-url-query-strings) |
| 2.2.1 | Users shall have the ability to logout of the application. Logout or session expiration shall invalidate all stateful session tokens, including refresh tokens. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#221-users-shall-have-the-ability-to-logout-of-the-application-logout-or-session-expiration-shall-invalidate-all-stateful-session-tokens-including-refresh-tokens) |
| 2.2.2 | The application shall provide the option (or acts by default) to terminate all other active sessions, including stateful refresh tokens, after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#222-the-application-shall-provide-the-option-or-acts-by-default-to-terminate-all-other-active-sessions-including-stateful-refresh-tokens-after-a-successful-password-change-including-change-via-password-resetrecovery-and-that-this-is-effective-across-the-application-federated-login-if-present-and-any-relying-parties) |
| 2.2.3 | Non-revocable stateless authentication tokens must expire within 24 hours of being issued | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#223-non-revocable-stateless-authentication-tokens-must-expire-within-24-hours-of-being-issued) |
| 2.3.1 | Cookie-based session tokens shall have the 'Secure' attribute set. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#231-cookie-based-session-tokens-shall-have-the-secure-attribute-set) |
| 2.3.2 | Cookie-based session tokens shall have the 'HttpOnly' attribute set. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#232-cookie-based-session-tokens-shall-have-the-httponly-attribute-set) |
| 2.3.3 | The application shall use session tokens rather than static API secrets and keys, except with legacy implementations. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#233-the-application-shall-use-session-tokens-rather-than-static-api-secrets-and-keys-except-with-legacy-implementations) |
| 2.3.4 | Stateless session tokens shall use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#234-stateless-session-tokens-shall-use-digital-signatures-encryption-and-other-countermeasures-to-protect-against-tampering-enveloping-replay-null-cipher-and-key-substitution-attacks) |
| 2.4.1 | Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#241-verify-the-application-ensures-a-full-valid-login-session-or-requires-re-authentication-or-secondary-verification-before-allowing-any-sensitive-transactions-or-account-modifications) |
| 3.1.1 | The application shall enforce least privilege access control rules on a trusted service layer. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#311-the-application-shall-enforce-least-privilege-access-control-rules-on-a-trusted-service-layer) |
| 3.1.2 | All user and data attributes and policy information used by access controls shall not be able to be manipulated by end users unless specifically authorized. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#312-all-user-and-data-attributes-and-policy-information-used-by-access-controls-shall-not-be-able-to-be-manipulated-by-end-users-unless-specifically-authorized) |
| 3.1.3 | Access controls shall fail securely including when an exception occurs. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#313-access-controls-shall-fail-securely-including-when-an-exception-occurs) |
| 3.1.4 | Sensitive resources shall be protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#314-sensitive-resources-shall-be-protected-against-insecure-direct-object-reference-idor-attacks-targeting-creation-reading-updating-and-deletion-of-records-such-as-creating-or-updating-someone-elses-record-viewing-everyones-records-or-deleting-all-records) |
| 3.1.5 | The application or framework shall enforce a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#315-the-application-or-framework-shall-enforce-a-strong-anti-csrf-mechanism-to-protect-authenticated-functionality-and-effective-anti-automation-or-anti-csrf-protects-unauthenticated-functionality) |
| 3.1.6 | Directory browsing shall be disabled unless deliberately desired. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#316-directory-browsing-shall-be-disabled-unless-deliberately-desired) |
| 3.2.1 | Application shall implement only secure and recommended OAuth 2.0 flows, such as the Authorization Code Flow or the Authorization Code Flow with PKCE, while avoiding the use of deprecated flows like the Implicit Flow or the Resource Owner Password Credentials Flow. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#321-application-shall-implement-only-secure-and-recommended-oauth-20-flows-such-as-the-authorization-code-flow-or-the-authorization-code-flow-with-pkce-while-avoiding-the-use-of-deprecated-flows-like-the-implicit-flow-or-the-resource-owner-password-credentials-flow) |
| 3.2.2 | Application shall securely validate the redirect_uri and state parameters during the OAuth 2.0 authorization process to prevent open redirect and CSRF vulnerabilities. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#322-application-shall-securely-validate-the-redirect_uri-and-state-parameters-during-the-oauth-20-authorization-process-to-prevent-open-redirect-and-csrf-vulnerabilities) |
| 3.3.1 | Application administrative interfaces shall use appropriate multi-factor authentication to prevent unauthorized use. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#331-application-administrative-interfaces-shall-use-appropriate-multi-factor-authentication-to-prevent-unauthorized-use) |
| 4.1.1 | Application shall enforce the use of TLS for all connections and default to TLS 1.2+. In cases where support for legacy clients is necessary, TLS 1.0 and 1.1 may be supported if mitigations are implemented to minimize the risk of downgrade attacks and known TLS exploits. Regardless of the TLS version in use, the application shall default to secure cipher suites and reject those with known vulnerabilities. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#411-application-shall-enforce-the-use-of-tls-for-all-connections-and-default-to-tls-12-in-cases-where-support-for-legacy-clients-is-necessary-tls-10-and-11-may-be-supported-if-mitigations-are-implemented-to-minimize-the-risk-of-downgrade-attacks-and-known-tls-exploits-regardless-of-the-tls-version-in-use-the-application-shall-default-to-secure-cipher-suites-and-reject-those-with-known-vulnerabilities) |
| 4.1.2 | Connections to and from the server shall use trusted TLS certificates. Where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs and specific self-signed certificates. All others should be rejected. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#412-connections-to-and-from-the-server-shall-use-trusted-tls-certificates-where-internally-generated-or-self-signed-certificates-are-used-the-server-must-be-configured-to-only-trust-specific-internal-cas-and-specific-self-signed-certificates-all-others-should-be-rejected) |
| 4.1.3 | No instances of weak cryptography which meaningfully impact the confidentiality or integrity of data. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#413-no-instances-of-weak-cryptography-which-meaningfully-impact-the-confidentiality-or-integrity-of-data) |
| 4.1.4 | All cryptographic modules shall fail securely, and errors are handled in a way that does not enable Padding Oracle attacks. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#414-all-cryptographic-modules-shall-fail-securely-and-errors-are-handled-in-a-way-that-does-not-enable-padding-oracle-attacks) |
| 5.1.1 | Protect against HTTP parameter pollution. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#511-protect-against-http-parameter-pollution) |
| 5.1.2 | URL redirects and forwards are limited to allowlisted URLs or a warning is displayed when redirecting to untrusted content. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#512-url-redirects-and-forwards-are-limited-to-allowlisted-urls-or-a-warning-is-displayed-when-redirecting-to-untrusted-content) |
| 5.1.3 | Avoid the use of eval() or other dynamic code execution features. When there is no alternative, any user input is sanitized and sandboxed before being executed. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#513-avoid-the-use-of-eval-or-other-dynamic-code-execution-features-when-there-is-no-alternative-any-user-input-is-sanitized-and-sandboxed-before-being-executed) |
| 5.1.4 | Protect against template injection attacks by ensuring that any user input being included is sanitized or sandboxed. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#514-protect-against-template-injection-attacks-by-ensuring-that-any-user-input-being-included-is-sanitized-or-sandboxed) |
| 5.1.5 | Prevent Server-Side Request Forgery (SSRF) | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#515-prevent-server-side-request-forgery-ssrf) |
| 5.1.6 | Protect against XPath or XML injection attacks | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#516-protect-against-xpath-or-xml-injection-attacks) |
| 5.1.7 | Context-aware output escaping or sanitization protects against reflected, stored, and DOM based XSS. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#517-context-aware-output-escaping-or-sanitization-protects-against-reflected-stored-and-dom-based-xss) |
| 5.1.8 | Protect against database injection attacks | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#518-protect-against-database-injection-attacks) |
| 5.1.9 | Protect against OS command injections | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#519-protect-against-os-command-injections) |
| 5.1.10 | Protect against local file inclusion or remote file inclusion attacks | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#5110-protect-against-local-file-inclusion-or-remote-file-inclusion-attacks) |
| 5.2.1 | Protect against malicious file uploads by limiting uploads to expected file types and preventing direct execution of uploaded content. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#521-protect-against-malicious-file-uploads-by-limiting-uploads-to-expected-file-types-and-preventing-direct-execution-of-uploaded-content) |
| 6.1.1 | The application only uses software components without known exploitable vulnerabilities. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#611-the-application-only-uses-software-components-without-known-exploitable-vulnerabilities) |
| 6.2.1 | Disable debug modes in production environments | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#621-disable-debug-modes-in-production-environments) |
| 6.3.1 | The origin header shall not be used for authentication of access control decisions | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#631-the-origin-header-shall-not-be-used-for-authentication-of-access-control-decisions) |
| 6.4.1 | The application shall not be susceptible to subdomain takeovers. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#641-the-application-shall-not-be-susceptible-to-subdomain-takeovers) |
| 6.5.1 | The application shall not log credentials or payment details. Session tokens shall only be stored in logs in an irreversible, hashed form. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#651-the-application-shall-not-log-credentials-or-payment-details-session-tokens-shall-only-be-stored-in-logs-in-an-irreversible-hashed-form) |
| 6.6.1 | Browser storage is securely cleared during logout | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#661-browser-storage-is-securely-cleared-during-logout) |
| 6.7.1 | The application shall securely store access tokens, API keys, and other server-side secrets. | [Published criteria](https://github.com/appdefensealliance/ASA-WG/blob/7ad3cce0cbb8d6ece5a096afe4a669c1604af583/CASA/CASA%20Test%20Guide.md#671-the-application-shall-securely-store-access-tokens-api-keys-and-other-server-side-secrets) |

## Supplemental leading security practices

Apply each property only to its recorded interface, operation and actor. Optional CIMD adoption does not waive verification when CIMD supplies mandatory authority.

### MIN-S01 Public HTTPS and transport confidentiality

**Scoped required outcome:** Expose the directory MCP endpoint over public HTTPS; protect the authenticated exchange in transit.

**Applicability:** Public-internet connector endpoint and applicable OAuth endpoints

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR05](#mr05), [MR10](#mr10), [MR12](#mr12), [MR13](#mr13), [MR14](#mr14).

**Related CASA criteria:** 4.1.1, 4.1.2. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S02 OAuth authorization-code integration for protected user access

**Scoped required outcome:** Use the supported standards-based OAuth authorization-code integration for protected user data/actions, with valid client registration for the selected flow.

**Applicability:** Services requiring end-user/account authentication

**Interface condition:** MCP-style interface / corresponding selected MCP or OAuth profile only

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR03](#mr03), [MR05](#mr05), [MR07](#mr07), [MR13](#mr13), [MR14](#mr14).

**Related CASA criteria:** 3.2.1, 3.2.2. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S03 S256 PKCE advertised and enforced

**Scoped required outcome:** Support S256 PKCE and publish the corresponding discovery capability; do not accept a code-exchange flow that lacks required PKCE.

**Applicability:** OAuth authorization-code connections

**Interface condition:** MCP-style interface / corresponding selected MCP or OAuth profile only

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR07](#mr07).

**Related CASA criteria:** 3.2.1. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S04 Protected-resource and authorization-server discovery

**Scoped required outcome:** Serve correct HTTPS protected-resource metadata with canonical resource and authorization-server identity, and standards-compliant reachable OAuth/OIDC authorization-server metadata; use the required401 discovery challenge.

**Applicability:** OAuth-enabled MCP endpoints

**Interface condition:** MCP-style interface / corresponding selected MCP or OAuth profile only

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR02](#mr02), [MR07](#mr07).

**Related CASA criteria:** 4.1.1. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S05 Resource audience binding and no token passthrough

**Scoped required outcome:** Issue/accept credentials only for the intended MCP resource; reject wrong-audience tokens and do not pass a client token unchanged through to an upstream resource for another audience.

**Applicability:** Protected tool calls and upstream API delegation

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR02](#mr02), [MR07](#mr07).

**Related CASA criteria:** 3.1.1, 2.3.4. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S06 Verify user credentials and enforce access at the server

**Scoped required outcome:** Validate credentials and authorization before executing protected operations or returning protected data; reject invalid/missing/expired credentials and enforce the user/resource/scope boundary at a trusted service layer.

**Applicability:** Protected/user-specific tools and consequential actions

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR02](#mr02), [MR04](#mr04), [MR06](#mr06), [MR07](#mr07), [MR09](#mr09), [MR13](#mr13).

**Related CASA criteria:** 3.1.1, 3.1.3, 2.3.4. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S07 Exact redirect validation and OAuth state protection

**Scoped required outcome:** Validate registered redirect destinations and securely validate OAuth state; do not allow untrusted redirect substitution.

**Applicability:** OAuth redirects/callbacks

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR02](#mr02), [MR07](#mr07).

**Related CASA criteria:** 3.2.2. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S08 CIMD identity and redirect metadata validation

**Scoped required outcome:** Validate the client metadata identity against itsHTTPSURL and registered redirect values and accept only supported token-endpoint client-authentication methods.

**Applicability:** Only if the selected connection implements CIMD

**Interface condition:** MCP-style interface / corresponding selected MCP or OAuth profile only

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR02](#mr02), [MR07](#mr07).

**Related CASA criteria:** 3.2.2. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S09 Keep authentication material out of URLs

**Scoped required outcome:** Do not expose authentication material in URL query strings or published URLs; use protected header/cookie transport as appropriate.

**Applicability:** Secrets/access/session tokens in connector/API/OAuth requests

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR03](#mr03), [MR07](#mr07), [MR08](#mr08).

**Related CASA criteria:** 2.1.1. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S10 Secure token/secret handling and storage

**Scoped required outcome:** Keep credentials/tokens confidential and securely stored, using appropriate protected authentication channels rather than exposing them publicly.

**Applicability:** Credentials/tokens stored or handled by the connector

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR02](#mr02), [MR07](#mr07), [MR14](#mr14).

**Related CASA criteria:** 6.7.1. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S11 Refresh-token and replay protection

**Scoped required outcome:** Protect public-client refresh tokens against replay, validate refresh failures/expiry, and apply required rotation or sender constraints under the selectedOAuthprofile.

**Applicability:** Public OAuth clients and token refresh

**Interface condition:** MCP-style interface / corresponding selected MCP or OAuth profile only

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR01](#mr01), [MR07](#mr07).

**Related CASA criteria:** 2.3.4. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S12 Truthful read-only and destructive operation classification

**Scoped required outcome:** Provide truthful applicable risk annotations: distinguish read-only operations and identify destructive/irreversible operations so safeguards can act on actual behavior.

**Applicability:** Every exposed operation; hints according to operation type

**Interface condition:** MCP-style interface / corresponding selected MCP or OAuth profile only

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR09](#mr09), [MR11](#mr11).

**Related CASA criteria:** No exact published counterpart recorded. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S13 Accurate narrow tool descriptions and transparent side effects

**Scoped required outcome:** Describe what each tool actually does, when it is invoked and relevant side effects/limits; descriptions must match schema and behavior and not hide functionality.

**Applicability:** Exposed tool metadata

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR09](#mr09).

**Related CASA criteria:** No exact published counterpart recorded. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S14 Separate read-only and state-changing tool surfaces

**Scoped required outcome:** Separate read-only and state-changing operations; do not expose one catch-all tool that mixes safe and unsafe methods.

**Applicability:** Tools exposing reads and writes

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR04](#mr04), [MR09](#mr09).

**Related CASA criteria:** No exact published counterpart recorded. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S15 No hidden behavioral directives or unauthorized tool steering

**Scoped required outcome:** Do not include hidden/obfuscated/encoded behavior instructions, seek secrets/protected context, cause unrequested external actions, or steer the model to bypass security/user intent.

**Applicability:** Descriptions/schemas and other model-readable connector metadata

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR09](#mr09).

**Related CASA criteria:** No exact published counterpart recorded. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S16 Do not circumvent platform or upstream security boundaries

**Scoped required outcome:** Do not evade agent safety/system/sandbox controls or upstream API authorization/access restrictions; keep tool execution within authorized operation boundaries.

**Applicability:** Tool behavior and downstream access

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR09](#mr09), [MR15](#mr15).

**Related CASA criteria:** No exact published counterpart recorded. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S17 Server-side input validation and injection defenses

**Scoped required outcome:** Validate arguments server-side and reject invalid/unauthorized inputs; do not trust model-generated data to enforce security.

**Applicability:** Untrusted model/client-supplied arguments

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR09](#mr09), [MR13](#mr13).

**Related CASA criteria:** 5.1.1, 5.1.3, 5.1.4, 5.1.5, 5.1.6, 5.1.7, 5.1.8, 5.1.9, 5.1.10. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S18 Minimize inputs, outputs and collected conversation/log content

**Scoped required outcome:** Collect/process/return only function- and task-necessary content, and do not collect extraneous conversation data even for logging.

**Applicability:** Tool inputs/results and data/logcollection

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR09](#mr09), [MR12](#mr12), [MR13](#mr13).

**Related CASA criteria:** 6.5.1. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S19 No covert reconstruction of Agent memory/history or conversation profiles

**Scoped required outcome:** Do not pull/reconstruct/infer full Agent conversation history or hidden memory, and do not expand taskscoped inputs into covert persistent conversation profiling.

**Applicability:** Agent memory/chat/history and long-lived connector context

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR09](#mr09).

**Related CASA criteria:** No exact published counterpart recorded. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S20 Informed consent for irreversible/consequential actions

**Scoped required outcome:** Require informed human confirmation for consequential/irreversible operations and preserve correct sensitivity labels; annotations are not a substitute for authentication/authorization or consent safeguards.

**Applicability:** Sensitive or irreversible actions, not every read or every write

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR06](#mr06), [MR09](#mr09), [MR13](#mr13).

**Related CASA criteria:** 2.4.1, 3.1.1. Related criteria are not a claim of equivalence or implementation compliance.

### MIN-S21 Legitimate endpoint/domain/API provenance

**Scoped required outcome:** Own/control declared endpoints/domains or legitimately proxy authorized APIs; do not impersonate another provider or bypass access restrictions.

**Applicability:** Connector endpoint and downstream APIs

**Interface condition:** Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface

**Actor condition:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Research references:** [MR03](#mr03), [MR04](#mr04), [MR09](#mr09).

**Related CASA criteria:** No exact published counterpart recorded. Related criteria are not a claim of equivalence or implementation compliance.

## Disposition of earlier retention/governance proposal

PR #324 supplied six outline topics. The dispositions below preserve the unresolved policy work without adopting its TBD sections as certification gates.

| Topic | Proposed disposition | Treatment |
| --- | --- | --- |
| 13.1 Temporal over-retention | ADVISORY_AND_EXISTING_BOUNDARIES | Data minimization and authorized task boundaries remain mandatory (Tool 9.1.1, MIN-S18/S19). A documented retention/deletion schedule is recommended; no new universal duration is adopted. |
| 13.2 Geographic governance | DEFERRED_POLICY_SCOPE | A geographic-residency or jurisdiction-specific certification gate is deferred to separate WG policy work. Existing applicable legal/platform obligations remain; this proposal does not certify jurisdictional compliance. |
| 13.3 Compliance transparency | ASSESSMENT_RECORD_AND_DEFERRED_POLICY_SCOPE | Record components, applicability, dependencies and implemented enhancements. Broad regulatory compliance attestations and legal-recordkeeping gates are deferred to separate policy work. |
| 13.4 Model allowlisting | EXISTING_AGENT_CONTROL_AND_TOOL_ADVISORY | Retain Agent per-model assessment and model/configuration boundaries. Tool-side approved-model policy is recommended where a Tool uses a model; no universal model list or sanctions-validation gate is created. |
| 13.5 External data-source governance | COVERED_SECURITY_OUTCOMES | Trusted-layer authorization, least privilege, input validation, task minimization and legitimate API provenance apply (Tool 1.2.1/2.4.1/3.1.1/9.1.1, MIN-S05/S06/S16/S17/S18/S21). Broad organizational governance evidence remains advisory. |
| 13.6 Configuration/parameter governance | COVERED_SECURITY_OUTCOMES_AND_ADVISORY_MECHANISM | Untrusted arguments must not bypass declared constraints or mandatory authorization/security outcomes (Tool 3.1.1 and TG-2.5, MIN-S15/S17). A prescribed model-parameter allowlist or fixed temperature/filter policy is recommended where relevant, not a universal Tool gate. |

## Market-research sources and currency

Research was captured on 26 October 2026. These sources inform the proposed technical properties; directory publication rules are not evidence of identical requirements for all private APIs, SDKs or tunnels. Source recommendations and host behavior are distinguished from adopted normative outcomes in the JSON evidence trace.

<a id="mr01"></a>

- **MR01:** <https://claude.com/docs/connectors/building/authentication.md>

<a id="mr02"></a>

- **MR02:** <https://claude.com/docs/connectors/building/lazy-authentication>

<a id="mr03"></a>

- **MR03:** <https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy>

<a id="mr04"></a>

- **MR04:** <https://claude.com/docs/connectors/building/review-criteria.md>

<a id="mr05"></a>

- **MR05:** <https://claude.com/docs/connectors/building/submission.md>

<a id="mr06"></a>

- **MR06:** <https://claude.com/docs/connectors/verification.md>

<a id="mr07"></a>

- **MR07:** <https://developers.openai.com/plugins/build/auth.md>

<a id="mr08"></a>

- **MR08:** <https://developers.openai.com/plugins/deploy/submission-errors.md>

<a id="mr09"></a>

- **MR09:** <https://developers.openai.com/plugins/plugin-guidelines.md>

<a id="mr10"></a>

- **MR10:** <https://developers.openai.com/plugins/build/mcp-server.md>

<a id="mr11"></a>

- **MR11:** <https://developers.openai.com/plugins/reference.md>

<a id="mr12"></a>

- **MR12:** <https://developers.openai.com/plugins/deploy/app-review.md>

<a id="mr13"></a>

- **MR13:** <https://developers.openai.com/plugins/guides/security-privacy.md>

<a id="mr14"></a>

- **MR14:** <https://developers.openai.com/plugins/deploy/submission.md>

<a id="mr15"></a>

- **MR15:** <https://openai.com/policies/developer-apps-terms/>


## Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
