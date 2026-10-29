# AI Tool Testing Guide

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

## Assessment gates and evidence

Determine certification eligibility before scoring. For every applicable test,
record the assessed component, actor, operation, deployment and selected protocol.
Assess each mandatory outcome against its identified CASA/supplemental requirement.
Record absent, implemented and insufficient SHOULD mechanisms as advisory findings.
If an advisory exercise reveals a mandatory breach, fail that mandatory property.
Fixtures, evidence requests and acceptance text must not make unused optional
receipts, signatures or durable idempotency hidden minimum gates.

Published CASA AL1/AL2 criteria remain unchanged. AI Tool AL0/AL1 static review and
AL2 functional exercises use the appropriate source tier; these are not Agent AL2
evidence defaults. Label evidence as functional observations, named implementation
artifacts/attestations or document review as appropriate. A Resource Server cannot
be credited with independently controlled Agent UI or OAuth client/AS behavior.

The [case ledger](AI%20Tool%20Assessment%20Cases.json) preserves all 210 source cases,
their original tier and their individually proposed gate and variant disposition.
For mixed cases, assess the baseline outcome and enhancement independently.

## 1.1 Client/Server Authentication for Protected Access

<!-- ada:test Tool:1.1 covers=Tool:1.1.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.1.1.

### Mandatory outcome

For protected/user-specific remote calls, the Tool MUST validate the selected OAuth credential and user/resource/scope authority before execution; MUST reject missing/invalid credentials on protected operations. Public-safe and discovery operations MAY be unauthenticated only when they expose no protected data or unauthorized action.

### Recommended enhancement

Dedicated MCP-host identity authentication beyond end-user authorization SHOULD be provided. mTLS client identification and rotated keys SHOULD be defense in depth, not public-directory substitutes for the supported user OAuth profile.

**Applicable CASA references:** 3.1.1, 3.1.3. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.1/V01 — BASELINE_GATE:** On protected/user-specific routes, validate the selected baseline user credential and authorization before execution; ordinary OAuth JWT or opaque introspection acceptable.
- **1.1/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Cryptographic Binding MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.1/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: no protected route executes without valid required authority. SHOULD: universal authentication even on demonstrably safe public/discovery routes.
- **1.1/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: deny missing required authority on protected routes. Public-safe/discovery unauthenticated access is permitted; no universal unauthenticated-access failure.
- **1.1/V05 — BASELINE_GATE:** Reject invalid/expired/malformed required credentials before protected data or actions; public-safe operations must not silently use invalid credentials as authority.
- **1.1/V06 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Session Persistence MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.

## 1.2 Message Freshness and Session Binding

<!-- ada:test Tool:1.2 covers=Tool:1.4.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.4.1.

### Mandatory outcome

Applicable stateful session/refresh logout/expiry invalidation and default-or-option password-change termination MUST be preserved. Only non-revocable STATELESS authentication tokens MUST expire within 24 hours. Stateless-session anti-tampering/replay controls MUST meet CASA 2.3.4.

### Recommended enhancement

Message-level nonce/timestamp validation, inactivity timers and duplicate JSON-RPC replay caches SHOULD be implemented. Their absence alone is advisory unless it exposes an applicable mandatory authentication/session weakness.

**Applicable CASA references:** 2.2.1, 2.2.2, 2.2.3, 2.3.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.2/V01 — BASELINE_GATE:** The required security outcome for Session Management MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.2/V02 — ADVISORY:** The Expiration Timers scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.2/V03 — ADVISORY:** The Freshness Validation scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.2/V04 — ADVISORY:** The Inactivity Timeouts scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.2/V05 — ADVISORY:** The Replay Resistance scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.2/V06 — BASELINE_GATE:** After actual session termination/expiry, reject stateful authority per CASA 2.2.1; preserve independently scoped persistent grants and stateless 24-hour rule.

## 1.3 Strict Redirect URI and State Validation

<!-- ada:test Tool:1.3 covers=Tool:1.5.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.5.1.

### Mandatory outcome

Where OAuth applies, the Tool MUST securely validate redirect_uri AND state to prevent open redirects and CSRF; the supported connector flow MUST validate exact registered vendor redirects, preserving applicable native-loopback port conditions. Secure recommended flows MUST exclude Implicit/ROPC. Actual auth/admin web components MUST retain applicable CASA controls regardless of old WebApp-integrated-Tool comments.

### Recommended enhancement

An explicit user/session/issuer/client/redirect/PKCE transaction tuple, documented short state expiry, single-use state and authenticated cross-device handoff SHOULD be used. If an omission actually permits CSRF/session substitution, it is a mandatory-outcome failure, not excused by advisory mechanism strength.

**Applicable CASA references:** 3.2.1, 3.2.2, 3.1.5. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.3/V01 — BASELINE_GATE:** The required security outcome for OAuth Logic MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.3/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in State Generation MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.3/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: effective secure state/session/redirect validation againstCSRF and unauthorized account association. SHOULD: literal six-field transaction tuple, specified one-use and documented short-period storage implementation.
- **1.3/V04 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Redirect URI Construction MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.3/V05 — BASELINE_GATE:** The required security outcome for Allowlist Enforcement MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.3/V06 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Legacy Methods MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.3/V07 — BASELINE_GATE:** The required security outcome for Redirect URI Validation MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.3/V08 — BASELINE_GATE:** The required security outcome for User and Session Binding MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.3/V09 — MIXED_BASELINE_AND_ADVISORY:** SHOULD: enforce single-use callback/state mechanism; MUST reject replay when it actually breaks mandatoryOAuthstate/authentication protections.
- **1.3/V10 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Secure Transport MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.

## 1.4 S256 PKCE for the Selected Public OAuth Profile

<!-- ada:test Tool:1.4 covers=Tool:1.5.2 -->

**Gate:** BASELINE_GATE. **Requirement:** 1.5.2.

### Mandatory outcome

For the selected public remote user OAuth authorization-code profile, S256 PKCE MUST be supported/advertised and the authorization code flow MUST generate/use the verifier and reject omitted/altered required verifier. Client-generation and authorization-server-verification duties MUST be allocated to the actor that implements them.

### Recommended enhancement

PKCE SHOULD be used beyond this demonstrated common public-remote profile where appropriate.

**Applicable CASA references:** 3.2.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.4/V01 — BASELINE_GATE:** The required security outcome for OAuth Initiation Logic MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.4/V02 — BASELINE_GATE:** The required security outcome for Token Exchange MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.4/V03 — BASELINE_GATE:** The required security outcome for Vulnerabilities MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.4/V04 — BASELINE_GATE:** Actor implementing the selected authorization-code verifier MUST reject omitted or altered requiredS256verifier; do not attribute authorization-server checks to a ResourceServer that does not implement that endpoint.

## 1.5 User Identity Propagation

<!-- ada:test Tool:1.5 covers=Tool:2.2.2 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 2.2.2.

### Mandatory outcome

Protected multi-user requests MUST derive verified user/tenant authority from valid credentials or trusted introspection, never an assumed connection or attacker-selected identifier alone; MUST scope access and deny invalid/wrong-user/out-of-scope calls before protected output/side effects.

### Recommended enhancement

Dedicated short-lived identity JWTs, per-query JWT.sub syntax, centralized propagation and identity-labelled downstream logs SHOULD be used where appropriate. Opaque token validation is equally acceptable.

**Applicable CASA references:** 3.1.1, 3.1.2, 3.1.3, 3.1.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.5/V01 — BASELINE_GATE:** The required security outcome for Token Handling MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.5/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Downstream Authentication MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.5/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Middleware Injection MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.5/V04 — BASELINE_GATE:** The required security outcome for Permission Enforcement MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.5/V05 — ADVISORY:** The Downstream Logs scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.5/V06 — BASELINE_GATE:** The required security outcome for Token Scoping MUST be met under the above baseline scope; no extra literal implementation is implied.

## 1.6 Secure Downstream Transport

<!-- ada:test Tool:1.6 covers=Tool:1.3.2 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.3.2.

### Mandatory outcome

Applicable TLS protection/trust MUST satisfy the full published CASA4.1.1/4.1.2 clauses, including default1.2+, necessary legacy mitigations and Additional Context exceptions. Public MCP/auth exchanges MUST use HTTPS. Bearer credentials MUST NOT appear in URL query strings. Credentials MUST NOT be disclosed to unauthorized redirected destinations.

### Recommended enhancement

TLS 1.3 SHOULD be preferred. Independently reauthorizing every cross-origin redirect SHOULD be the chosen hardening approach; equivalent enforcement of the mandatory authorized-destination/no-secret-disclosure outcome remains required.

**Applicable CASA references:** 4.1.1, 4.1.2, 2.1.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.6/V01 — ADVISORY:** The Downstream Clients Identification scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.6/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in TLS Enforcement MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.6/V03 — BASELINE_GATE:** The required security outcome for Data in Transit Protection MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.6/V04 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Redirect Credential Handling MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.6/V05 — BASELINE_GATE:** The required security outcome for Secure Outbound Traffic MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.6/V06 — BASELINE_GATE:** The required security outcome for Redirect Destination Substitution MUST be met under the above baseline scope; no extra literal implementation is implied.

## 1.7 Integrated Transport Security and Message Integrity

<!-- ada:test Tool:1.7 covers=Tool:7.1.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 7.1.1.

### Mandatory outcome

Public remote endpoint MUST use HTTPS and meet full applicable CASA TLS/trust/crypto criteria, defaultTLS 1.2+ with exact legacy/internal-CA/Additional Context routes.

### Recommended enhancement

TLS 1.3, all-message MAC/signatures, secureIPC/OS permissions and local loopback-only binding SHOULD be considered for this public-remote impact model. Existing local/mobile strengths are not automatically changed; held variants require separate assessment.

**Applicable CASA references:** 4.1.1, 4.1.2, 4.1.3, 4.1.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.7/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: CASAdefaultTLS 1.2+, secure ciphers and exact legacy/AdditionalContext conditions. SHOULD: stricterTLS 1.3-only configuration.
- **1.7/V02 — BASELINE_GATE:** The required security outcome for Validation Check MUST be met under the above baseline scope; no extra literal implementation is implied.
- **1.7/V03 — CURRENT_UNCHANGED_OUTSIDE_TARGET_VARIANT:** This local/mobile-specific scenario remains unchanged outside the remote-HTTP target variant; no decision to demote it is made.
- **1.7/V04 — ADVISORY:** SHOULD: refuseTLS 1.2 when implementing the preferredTLS 1.3enhancement; a validCASA-compliantTLS 1.2path does not fail baseline.
- **1.7/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: trusted certificate checks with explicitly narrow internalCA/self-signed route preserved. SHOULD: public-CA-only preference beyond that floor. An arbitrary/untrusted cert is a baseline failure; a justified specifically trusted internal cert is not.
- **1.7/V06 — ADVISORY:** The Replay Attack Resistance scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.7/V07 — CURRENT_UNCHANGED_OUTSIDE_TARGET_VARIANT:** This local/mobile-specific scenario remains unchanged outside the remote-HTTP target variant; no decision to demote it is made.

## 1.8 Sensitive Action Idempotency and Ambiguous Outcomes

<!-- ada:test Tool:1.8 covers=Tool:1.4.2 -->

**Gate:** ADVISORY. **Requirement:** 1.4.2.

### Mandatory outcome

No new business-intent identifier baseline gate is introduced here; ordinary baseline authorization and session/token replay protections still apply.

### Recommended enhancement

Sensitive side-effect actions SHOULD use stable user-approved intent/idempotency identifiers bound to user/account/operation/material parameters; distinct separately approved actions SHOULD have distinct identifiers. Durable duplicate suppression SHOULD survive restarts for the documented retry/uncertainty window. Ambiguous outcomes SHOULD be reconciled, never blindly retried or represented as authoritative success without evidence.

**Applicable CASA references:** Apply the independent CASA register. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.8/V01 — ADVISORY:** The Durable Duplicate Suppression scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.8/V02 — ADVISORY:** Tool SHOULD retain safe-retry/uncertain-outcome reconciliation. IndependentAgent no-blind-retry/unknown-outcome honesty remainsMUST under its own specification; Toolstable-intent absence alone not a Toolbaseline failure.
- **1.8/V03 — ADVISORY:** The No Duplicate Consequence scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.8/V04 — ADVISORY:** Tool SHOULD report authoritative or explicitindeterminate outcomes. Do not claim minimumTool conformance assures exact-once execution; Agent retains its stricter outcomehonesty duties.

## 1.9 Connector Lifecycle Revocation

<!-- ada:test Tool:1.9 covers=Tool:1.4.3 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.4.3.

### Mandatory outcome

The Tool MUST deny protected activity after applicable authority is revoked/expired and MUST enforce the published stateful session/refresh invalidation events. An Agent logout MUST NOT be invented as revocation of a distinct persistent connector grant; enforce the actual grant lifecycle.

### Recommended enhancement

Explicit unlink/removal/deactivation propagation, revocation convergence-time documentation, queued-work/callback/retry lifecycle handling and authoritative committed-work reconciliation SHOULD be implemented. No new fixed propagation SLA is mandatory.

**Applicable CASA references:** 2.2.1, 2.2.2, 3.1.1, 3.1.3. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **1.9/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Complete Lifecycle Handling MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.9/V02 — ADVISORY:** The Defined Enforcement Time scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **1.9/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Post-Revocation Denial MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **1.9/V04 — ADVISORY:** The Accurate Committed Status scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 2.1 Scoped Authorization and User Context Propagation

<!-- ada:test Tool:2.1 covers=Tool:1.2.1 -->

**Gate:** BASELINE_GATE. **Requirement:** 1.2.1.

### Mandatory outcome

For protected/user-specific operations, the Tool MUST verify user authority and uniformly enforce resource/object/attribute permissions before returning data, existence-sensitive metadata or causing side effects. Its service credential MUST NOT substitute for user authorization.

### Recommended enhancement

User context SHOULD be propagated centrally through handlers and downstream clients; a particular middleware architecture is not mandatory.

**Applicable CASA references:** 3.1.1, 3.1.2, 3.1.3, 3.1.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **2.1/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Tool Handlers MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.1/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Token Usage MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.1/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Context Extraction MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.1/V04 — BASELINE_GATE:** The required security outcome for Authorization Logic MUST be met under the above baseline scope; no extra literal implementation is implied.
- **2.1/V05 — BASELINE_GATE:** The required security outcome for Privilege Separation MUST be met under the above baseline scope; no extra literal implementation is implied.
- **2.1/V06 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Scoped Execution MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.1/V07 — BASELINE_GATE:** The required security outcome for Metadata Propagation MUST be met under the above baseline scope; no extra literal implementation is implied.

## 2.2 Validation of User Context

<!-- ada:test Tool:2.2 covers=Tool:1.2.2 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.2.2.

### Mandatory outcome

The Tool MUST authenticate protected user context by valid signed-token verification OR trusted opaque-token introspection, including applicable issuer, audience/resource, expiry and scope checks. Bare unsigned user_id is not authentication. Protected downstream access MUST remain user-authorized.

### Recommended enhancement

An issuer-minted per-request signed user identity assertion forwarded by the Agent and cryptographic per-action parameter binding SHOULD be supported as stronger mechanisms, not mandatory formats.

**Applicable CASA references:** 2.3.4, 3.1.1, 3.1.3. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **2.2/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: baseline signed-token verification OR trustedopaque introspection and scope/issuer/audience/expiry checks. SHOULD: a particularpublickey/JWKS library architecture beyond validverification.
- **2.2/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Downstream Flow MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.2/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: no bare unverified identity used for protectedauthority. SHOULD: dedicated signedusercontext metadata; normalopaque introspection remainsvalid.
- **2.2/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: reject unsigned/tampered credentials purporting to be signedJWTs and invalidrequiredidentity. No missingJWS failure for a validopaque-token introspection path.
- **2.2/V05 — BASELINE_GATE:** The required security outcome for Payload Tampering MUST be met under the above baseline scope; no extra literal implementation is implied.
- **2.2/V06 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Token Exchange MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.

## 2.3 Server-Side Consent Backstop for Sensitive Actions

<!-- ada:test Tool:2.3 covers=Tool:2.1.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 2.1.1.

### Mandatory outcome

The Tool MUST provide truthful applicable MCP readOnlyHint/destructiveHint fields: readOnlyHint:true for read-only operations and destructiveHint:true for applicable irreversible/destructive operations. This does not invent every-tool Boolean presence or uniform additive-write semantics. It MUST NOT misrepresent writes as reads or bypass core Agent consequential-action human confirmation. Authentication/authorization and exposed-admin MFA MUST remain independent. Full valid login OR secondary verification remains the CASA 2.4.1 alternative.

### Recommended enhancement

Independent Tool-owned server-side confirmation/elicitation or fail-closed consent backstop SHOULD be used. Tool challenges/receipts SHOULD bind user/account/operation/recipient/material parameters/validity/one execution and reject mismatches/replay; explicit bounded-batch enumeration SHOULD be provided. No independent Tool confirmation or cryptographic receipt is a new baseline certification gate. consent_required MAY be emitted.

**Applicable CASA references:** 2.4.1, 3.3.1, 3.1.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **2.3/V01 — ADVISORY:** The Elicitation Logic scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.3/V02 — ADVISORY:** The Configuration Enforcement scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.3/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: truthful risk/behavior labels and no bypass of coreAgent HITL. SHOULD: particularToolelicitation prompt/independentconfirmationUX.
- **2.3/V04 — ADVISORY:** The Confirmation Binding scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.3/V05 — ADVISORY:** The Unauthorized Execution scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.3/V06 — ADVISORY:** The Configuration Bypass scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.3/V07 — ADVISORY:** The No Agent-Asserted Consent scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.3/V08 — ADVISORY:** The No Confirmation Substitution or Replay scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 2.4 Principle of Least Privilege and Scoped Permissions

<!-- ada:test Tool:2.4 covers=Tool:2.4.1 -->

**Gate:** BASELINE_GATE. **Requirement:** 2.4.1.

### Mandatory outcome

The Tool MUST enforce least-privilege permissions at a trusted service layer and deny unauthorized operations independent of model promises or annotations.

### Recommended enhancement

Fine-grained scoped-permission design SHOULD be used; do not invent a fixed scope list.

**Applicable CASA references:** 3.1.1, 3.1.2, 3.1.3, 3.1.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **2.4/V01 — BASELINE_GATE:** The required security outcome for IAM and RBAC MUST be met under the above baseline scope; no extra literal implementation is implied.
- **2.4/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Scope Definitions MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.4/V03 — BASELINE_GATE:** The required security outcome for Scope Boundaries MUST be met under the above baseline scope; no extra literal implementation is implied.
- **2.4/V04 — BASELINE_GATE:** The required security outcome for Rejection MUST be met under the above baseline scope; no extra literal implementation is implied.

## 2.5 Tool Function Allow-listing and Parameter Validation

<!-- ada:test Tool:2.5 covers=Tool:TG-2.5 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** TG-2.5.

### Mandatory outcome

The exposed public remote surface MUST preserve truthful declared behavior and separated read/write controls; untrusted parameters MUST be validated and applicable authorization MUST precede every reachable protected execution path. Declared schema types and constraints MUST be enforced when claimed, including rejecting extra fields when additionalProperties:false is declared; no global extra-field ban applies when the schema permits them. Undeclared mixed read/write catch-alls or bypass routes violating this outcome fail baseline.

### Recommended enhancement

Exhaustive route manifests, strict rejection of every extra schema field irrespective of declared additionalProperties rules, and codepath parity evidence SHOULD be used. Do not prohibit a legitimate fixed-purpose/freeform read query solely by wholesale executor bans.

**Applicable CASA references:** 3.1.1, 3.1.3. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **2.5/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Manifest and Export Match MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.5/V02 — BASELINE_GATE:** The required security outcome for Parameter Handling MUST be met under the above baseline scope; no extra literal implementation is implied.
- **2.5/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Route Coverage MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.5/V04 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Undeclared Functions MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.5/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: validate declared schema types/constraints, including rejection of extra fields when additionalProperties:false is claimed. SHOULD: a global no-extra-field rule where the declared schema otherwise permits additional properties. Mandatory authorization must still precede execution.
- **2.5/V06 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Route Parity MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.

## 2.6 No Token Passthrough / Downstream Token Exchange

<!-- ada:test Tool:2.6 covers=Tool:1.2.3 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.2.3.

### Mandatory outcome

On user-behalf downstream access, the Tool MUST NOT pass the inbound MCP access token through to an upstream API for a different audience. It MUST use separately authorized resource-scoped credentials preserving the end-user authorization boundary. RFC8693 exchange or equivalent OBO is acceptable, not the only mandated wire procedure.

### Recommended enhancement

Shorter downstream token lifetimes and sender constraints/DPoP SHOULD be applied, including remote/high-value deployments. Stronger delegation chains SHOULD be supported where practical.

**Applicable CASA references:** 3.1.1, 2.3.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **2.6/V01 — BASELINE_GATE:** The required security outcome for No Passthrough MUST be met under the above baseline scope; no extra literal implementation is implied.
- **2.6/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: preserve user-authorized resource-scoped no-cross-audience-passthrough outcome. SHOULD: specificRFC8693/OBOexchange architecture when anothertrustedservice-layer design otherwise meets requiredoutcome.
- **2.6/V03 — ADVISORY:** SHOULD: shorterdownstreamlifetimes/PoP, including remote/high-value. Applicablepublic-clientrefresh rotation/replay andCASA24hscopedrules remainseparate minimum requirements.
- **2.6/V04 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Downstream Traffic MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **2.6/V05 — BASELINE_GATE:** The required security outcome for Replay Across Audience MUST be met under the above baseline scope; no extra literal implementation is implied.

## 2.7 Out-of-Band Confirmation for High-Risk Actions

<!-- ada:test Tool:2.7 covers=Tool:2.1.2 -->

**Gate:** ADVISORY. **Requirement:** 2.1.2.

### Mandatory outcome

Baseline Agent HITL, Tool honest risk labels, authentication and CASAadmin-MFA/sensitive-account protections remain mandatory where applicable.

### Recommended enhancement

Independent-channel OOB confirmation SHOULD be used for highest-risk actions, including remote/high-value deployments; a safe server-side fallback SHOULD be provided where infeasible. Pre-registered channel/authenticated provider page and matching/expiry/single-use checks SHOULD preserve the current security content. No absent OOB channel alone fails baseline.

**Applicable CASA references:** Apply the independent CASA register. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **2.7/V01 — ADVISORY:** The High-Risk Classification scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.7/V02 — ADVISORY:** The Independent Channel scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.7/V03 — ADVISORY:** The Confirmation Binding scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.7/V04 — ADVISORY:** The Forged Approval Rejected scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.7/V05 — ADVISORY:** The Independent Confirmation Enforced scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **2.7/V06 — ADVISORY:** The No Confirmation Substitution or Replay scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 3.1 Externalized Secret Management

<!-- ada:test Tool:3.1 covers=Tool:1.3.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.3.1.

### Mandatory outcome

Server-side tokens/API keys/secrets MUST use a documented appropriate access-control policy and cryptographically secure storage; access MUST be logged OR monitored without logging secret values. Secrets MUST remain confidential, including public packages/metadata.

### Recommended enhancement

Externalized runtime secret retrieval, avoiding embedded secret literals, periodic rotation procedures and breach-revocation playbooks SHOULD be implemented. No specific environment-variable or product is mandatory.

**Applicable CASA references:** 6.7.1, 6.5.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **3.1/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Hardcoded Secrets MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.1/V02 — ADVISORY:** The Client Initialization scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.1/V03 — ADVISORY:** The String Literals scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.1/V04 — ADVISORY:** The Rotation Policies scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.1/V05 — ADVISORY:** The Revocation Protocols scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.1/V06 — ADVISORY:** The Runtime Retrieval scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.1/V07 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Secret Isolation MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.

## 3.2 Automated PII and Credential Masking in Logs

<!-- ada:test Tool:3.2 covers=Tool:1.6.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.6.1.

### Mandatory outcome

Credentials/payment details MUST NOT be logged; session tokens may appear only as irreversible hashes under the exact published CASA exception. Logging MUST NOT collect extraneous conversation content beyond the task/function.

### Recommended enhancement

Central automatic interception/redaction across stdout/stderr/files, broad PII/secret detection and masking SHOULD be used. Any method is acceptable only if the mandatory no-secret logging outcome is met.

**Applicable CASA references:** 6.5.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **3.2/V01 — ADVISORY:** The Logging Calls scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.2/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Full Object Logging MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.2/V03 — ADVISORY:** The Redaction Middleware scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.2/V04 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Sensitive Key Masking MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.2/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: no credentials/paymentdetails and no plaintextsessiontokens inlogs; irreversibletokenhashes allowed. SHOULD: universalbroadPII/scanner/interception implementation.

## 3.3 Secure Session Tokens

<!-- ada:test Tool:3.3 covers=Tool:1.6.2 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 1.6.2.

### Mandatory outcome

All applicable published session/URL/cookie/browser-storage/secret-storage/TLS controls MUST remain, with every original exception and criterion. This includes Secure/HttpOnly when cookie sessions apply, legacy static-secret exception, scoped24h expiry, refresh invalidation, browser-store logout deletion and hashed-only session-token logs.

### Recommended enhancement

Avoiding argv/temp-file exposure and preferential environment/header carriers SHOULD be adopted beyond the mandatory common MCP bearer-header/query rules.

**Applicable CASA references:** 2.1.1, 2.2.1, 2.2.2, 2.2.3, 2.3.1, 2.3.2, 2.3.3, 2.3.4, 4.1.1, 4.1.2, 6.5.1, 6.6.1, 6.7.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **3.3/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Hardcoded Tokens MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.3/V02 — BASELINE_GATE:** The required security outcome for Logging MUST be met under the above baseline scope; no extra literal implementation is implied.
- **3.3/V03 — ADVISORY:** The Initialization scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.3/V04 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Traffic Analysis MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.3/V05 — BASELINE_GATE:** The required security outcome for Log Inspection MUST be met under the above baseline scope; no extra literal implementation is implied.
- **3.3/V06 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Environment Check MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.

## 3.4 Exfiltration Defense

<!-- ada:test Tool:3.4 covers=Tool:5.1.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 5.1.1.

### Mandatory outcome

The Tool MUST prevent unauthorized secret/resource access and corruption through exposed APIs and MUST limit collected/returned task data to the shared necessary-purpose boundary.

### Recommended enhancement

Defense-in-depth memory-safe secret buffers, runtime isolation, reflection/taint analysis and layered exfiltration protection SHOULD be retained.

**Applicable CASA references:** 3.1.1, 3.1.2, 3.1.4, 5.1.5, 5.1.9, 5.1.10, 6.5.1, 6.7.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **3.4/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Secret Lifecycle Mapping MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.4/V02 — ADVISORY:** The Automated Secret Hunting scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.4/V03 — ADVISORY:** The Secrets Management scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.4/V04 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Path & Reflection MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.4/V05 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Taint & Reflection Analysis MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.4/V06 — BASELINE_GATE:** The required security outcome for Internal Exfiltration Probe MUST be met under the above baseline scope; no extra literal implementation is implied.
- **3.4/V07 — BASELINE_GATE:** The required security outcome for Exfiltration Stress Test MUST be met under the above baseline scope; no extra literal implementation is implied.
- **3.4/V08 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Corruption & Integrity MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.

## 3.5 PII Detection

<!-- ada:test Tool:3.5 covers=Tool:TG-3.5 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** TG-3.5.

### Mandatory outcome

Unauthorized or task-extraneous personal data output MUST be prevented; applicable credential/payment log protections remain. Legitimate purpose-required, authorized data is not categorically prohibited.

### Recommended enhancement

Detecting all SSN/national ID/email/phone/Luhn-valid-card/high-entropy patterns and redacting via a universal PII detector SHOULD be adopted, not a baseline detector-product/category gate.

**Applicable CASA references:** 3.1.1, 6.5.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **3.5/V01 — ADVISORY:** The Response Handling scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.5/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Seed Data Redaction MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.5/V03 — BASELINE_GATE:** The required security outcome for Authorization Scopes MUST be met under the above baseline scope; no extra literal implementation is implied.

## 3.6 Data Minimization

<!-- ada:test Tool:3.6 covers=Tool:9.1.1 -->

**Gate:** BASELINE_GATE. **Requirement:** 9.1.1.

### Mandatory outcome

The Tool MUST collect/process/return only function/task-necessary content and MUST NOT covertly reconstruct full Agent history/hidden memory or persistent conversation profiles.

### Recommended enhancement

Purpose-shaped output schemas/queries, supplemental PII detectors and heuristic redaction SHOULD implement the mandatory minimization outcome; no categorical legitimate-user-file ban is imported.

**Applicable CASA references:** Apply the independent CASA register. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **3.6/V01 — BASELINE_GATE:** The required security outcome for Schema Review MUST be met under the above baseline scope; no extra literal implementation is implied.
- **3.6/V02 — BASELINE_GATE:** The required security outcome for Functional Execution MUST be met under the above baseline scope; no extra literal implementation is implied.

## 3.7 Protect Sensitive Data in Logs

<!-- ada:test Tool:3.7 covers=Tool:12.2.2 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 12.2.2.

### Mandatory outcome

No credentials/payment details in logs and hashed-only session-token representation MUST be enforced; extra conversation collection for logging MUST NOT occur.

### Recommended enhancement

Automated broad PII/identity/proprietary-output masking, centralized filters and heuristic sensitive-variable tracking SHOULD be retained.

**Applicable CASA references:** 6.5.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **3.7/V01 — ADVISORY:** The Sensitive Variables scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.7/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Trace Logging Sinks MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.7/V03 — ADVISORY:** The Redaction Middleware scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **3.7/V04 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Raw Data Logging MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **3.7/V05 — ADVISORY:** SHOULD: mask allplainuserIDs/uniquePII identifiers. MUST separately forbid credentials/paymentdetails and plaintextsessiontokens; do not invent aCASA categoricaluserID loggingban.
- **3.7/V06 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Sensitive Telemetry & Log Output MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.

## 4.1 Output Sanitization

<!-- ada:test Tool:4.1 covers=Tool:TG-4.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** TG-4.1.

### Mandatory outcome

Where rendered output/XML parsing is applicable, mandatory contextual XSS/XML protections MUST pass. No optional-widget exclusion waives actual auth/admin rendering controls.

### Recommended enhancement

Universal structured-output schemas and stripping every HTML/JavaScript/shell/SQL metacharacter in non-executable data SHOULD be considered, not imposed indiscriminately where it destroys legitimate content.

**Applicable CASA references:** 5.1.6, 5.1.7. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **4.1/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Output Handlers MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **4.1/V02 — ADVISORY:** The Schema Validation scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **4.1/V03 — ADVISORY:** The Raw Strings scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **4.1/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: applicable contextualXSS/XML/outputexecutionsafety. SHOULD: stripping allSQL/shell/HTML metacharacters in ordinarynon-executabledata; blanketstripping is not a mandatorycompatibility rule.
- **4.1/V05 — ADVISORY:** The Malformed JSON scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 4.2 Parameterized Arguments and Unsafe Sink Blocking

<!-- ada:test Tool:4.2 covers=Tool:3.1.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 3.1.1.

### Mandatory outcome

The Tool MUST validate untrusted arguments server-side and meet each applicable published injection/XSS/SSRF/file control; required rejection/neutralization MUST precede execution. Generic schema validation alone is not full coverage.

### Recommended enhancement

Parameterized APIs, exhaustive static allowlists at every internal boundary and unsafe-sink blocking SHOULD be used. eval/shell presence alone is not a categorical failure where secure expected functionality satisfies CASA.

**Applicable CASA references:** 5.1.1, 5.1.3, 5.1.4, 5.1.5, 5.1.6, 5.1.7, 5.1.8, 5.1.9, 5.1.10, 5.2.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **4.2/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Unsafe Execution Sinks MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **4.2/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Parameterization MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **4.2/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Validation Logic MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **4.2/V04 — BASELINE_GATE:** The required security outcome for Fuzz Tool Parameters / Safe Rejection MUST be met under the above baseline scope; no extra literal implementation is implied.

## 4.3 Detect and Block Unsafe Sinks

<!-- ada:test Tool:4.3 covers=Tool:8.4.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 8.4.1.

### Mandatory outcome

Applicable code/command/path/SSRF vulnerabilities MUST be prevented under full CASA conditions.

### Recommended enhancement

Hardened runtimes, unsafe-sink scanning, parameterized commands and path canonicalization SHOULD be used as engineering approaches.

**Applicable CASA references:** 5.1.3, 5.1.5, 5.1.9, 5.1.10. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **4.3/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Pattern Scan MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **4.3/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in URL Generation Check MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **4.3/V03 — BASELINE_GATE:** The required security outcome for Sandbox Escape Probing MUST be met under the above baseline scope; no extra literal implementation is implied.

## 4.4 Maximum Response Size

<!-- ada:test Tool:4.4 covers=Tool:TG-4.4 -->

**Gate:** ADVISORY. **Requirement:** TG-4.4.

### Mandatory outcome

No universal 1 MB response gate is established. Mandatory data minimization still applies where relevant.

### Recommended enhancement

Configurable response truncation/pagination/rejection and a 1 MB suggested default with purpose justification for larger responses SHOULD be retained.

**Applicable CASA references:** Apply the independent CASA register. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **4.4/V01 — ADVISORY:** The Output Serialization scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **4.4/V02 — ADVISORY:** The Size Limit Configuration scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **4.4/V03 — ADVISORY:** The Oversized Handling Logic scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **4.4/V04 — ADVISORY:** The Boundary Enforcement scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 5.1 Stateless Request Level Isolation

<!-- ada:test Tool:5.1 covers=Tool:2.2.1,Tool:8.2.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 2.2.1, 8.2.1.

### Mandatory outcome

The Tool MUST prevent unauthorized cross-user/tenant data access or side effects across reused runtimes, caches and concurrent requests.

### Recommended enhancement

Stateless request architecture, no user-specific globals, context purge/recycling and unique request-ID correlation SHOULD be used; equivalent safely scoped caches are not categorically forbidden.

**Applicable CASA references:** 3.1.1, 3.1.2, 3.1.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **5.1/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Global State MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **5.1/V02 — ADVISORY:** The Context Reset scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **5.1/V03 — ADVISORY:** The Request ID Propagation scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **5.1/V04 — BASELINE_GATE:** The required security outcome for Session Bleed MUST be met under the above baseline scope; no extra literal implementation is implied.
- **5.1/V05 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Log Correlation MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **5.1/V06 — ADVISORY:** The Memory Isolation scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 5.2 Ensure Sandbox Protections

<!-- ada:test Tool:5.2 covers=Tool:2.2.3 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 2.2.3.

### Mandatory outcome

The Tool MUST prevent applicable code/OS/file injection, traversal and SSRF while respecting the published necessary-functionality, sanitization/sandboxing and allowlist conditions. It MUST NOT bypass platform or upstream security boundaries.

### Recommended enhancement

Hardened runtime, unsafe-sink detectors, strict path-canonicalization patterns and sandbox-specific restriction policies SHOULD be applied. Legitimate code execution is not categorically forbidden when CASA exceptions are met.

**Applicable CASA references:** 5.1.3, 5.1.5, 5.1.9, 5.1.10. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **5.2/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Unsafe Execution MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **5.2/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Missing Path Validation MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **5.2/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Hardcoded Network Requests MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **5.2/V04 — BASELINE_GATE:** The required security outcome for Sandbox Escape Prevention MUST be met under the above baseline scope; no extra literal implementation is implied.
- **5.2/V05 — BASELINE_GATE:** The required security outcome for Directory Traversal Mitigation MUST be met under the above baseline scope; no extra literal implementation is implied.
- **5.2/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: preventSSRF under publishednecessary-functionality/validation/allowlist conditions. SHOULD: stricteralways-static-allowlist/nointernaldestination approach; legitimate necessary requests cannot be categorically banned by omittingCASA exceptions.

## 5.3 Tenant Isolation Outcomes

<!-- ada:test Tool:5.3 covers=Tool:TG-5.3 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** TG-5.3.

### Mandatory outcome

Cross-tenant unauthorized data, existence-sensitive metadata and side effects MUST be denied using verified authority; attacker-selected tenant ID is not sufficient authorization.

### Recommended enhancement

A tenant-ID filter in every individual database/vector-store query SHOULD be the implementation approach, not the only acceptable correctly enforced isolation design.

**Applicable CASA references:** 3.1.1, 3.1.2, 3.1.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **5.3/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Query Inspection MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **5.3/V02 — BASELINE_GATE:** The required security outcome for Context Verification MUST be met under the above baseline scope; no extra literal implementation is implied.
- **5.3/V03 — BASELINE_GATE:** The required security outcome for Cross-Tenant Access MUST be met under the above baseline scope; no extra literal implementation is implied.

## 6.1 Cryptographic Message Integrity Validation

<!-- ada:test Tool:6.1 covers=Tool:3.3.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 3.3.1.

### Mandatory outcome

The Tool MUST validate baseline credential/session signatures or trusted introspection and preserve applicable strong cryptography/key storage. It MUST NOT accept a tampered/invalid baseline credential.

### Recommended enhancement

End-to-end signatures/MACs across all JSON-RPC messages, descriptors and resources SHOULD be implemented; unsigned ordinary messages alone MUST NOT be a baseline failure when required authentication/TLS/outcome controls pass.

**Applicable CASA references:** 2.3.4, 4.1.3, 6.7.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **6.1/V01 — ADVISORY:** The Integrity Mechanisms scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **6.1/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Key Management MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **6.1/V03 — ADVISORY:** SHOULD: require a whole-message signature/MAC. Unsigned ordinaryJSON-RPCdoes not fail baseline ifrequiredcredential/TLS/securitycontrols pass.
- **6.1/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: reject tamperedbaselineauthentication material and preserve applicableCASAstateless integrity. SHOULD: detect/rejecteverytamperedJSON-RPCmessage by applicationmessageMAC.

## 6.2 Semantic Integrity and Descriptive Accuracy

<!-- ada:test Tool:6.2 covers=Tool:6.2.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 6.2.1.

### Mandatory outcome

Metadata MUST accurately describe purpose, inputs, behavior and material side effects. Truthful applicable MCP readOnlyHint and destructiveHint fields MUST be supplied, including readOnlyHint:true for reads and destructiveHint:true for applicable irreversible/destructive operations; neither every-tool Boolean presence nor one additive-write value is invented. Read/write surfaces MUST be separated, not hidden in mixed generic catch-alls.

### Recommended enhancement

Human-readable titles, universal openWorldHint, a64-character name target, idempotent hints, every-operation granularity and expanded code/docstring audits SHOULD be used where security-useful; none is falsely claimed shared mandatory. Vendor-specific still-binding publication rules are separate.

**Applicable CASA references:** Apply the independent CASA register. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **6.2/V01 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Manifest Review MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **6.2/V02 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Code-to-Metadata Mapping MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **6.2/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Heuristic Analysis MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **6.2/V04 — BASELINE_GATE:** The required security outcome for Functional Verification MUST be met under the above baseline scope; no extra literal implementation is implied.
- **6.2/V05 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in I/O Monitoring MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **6.2/V06 — ADVISORY:** The Agent-Simulated Testing scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 6.3 Resource Pinning and Signature Verification

<!-- ada:test Tool:6.3 covers=Tool:8.5.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 8.5.1.

### Mandatory outcome

No-known-exploitable-component requirement MUST remain, including exact published guide CVSS>=7 and documented unused-vulnerable-code/no-update-with-regular-patching exceptions.

### Recommended enhancement

Dependency/plugin hash pinning, tool/model-weight signatures, SBOMs and authenticated update testing SHOULD remain AI-specific supply-chain recommendations.

**Applicable CASA references:** 6.1.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **6.3/V01 — ADVISORY:** The Check Dependency Files scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **6.3/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: exactpublishedCASA 6.1.1 exploitablecomponent/CVSS>=7 andjustificationpaths. SHOULD: SBOM andstrongerupdate/hashsignature evidence.
- **6.3/V03 — ADVISORY:** The Update Verification scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 6.4 No Embedded Model-Directed Control Directives

<!-- ada:test Tool:6.4 covers=Tool:6.1.1 -->

**Gate:** BASELINE_GATE. **Requirement:** 6.1.1.

### Mandatory outcome

The Tool MUST NOT embed hidden/obfuscated model-directed behavioral steering or unauthorized tool-chain instructions in its metadata/results, and MUST enforce its own authorization/input validation independently of Agent/model. It MUST NOT rely on optional provenance tags as its security boundary.

### Recommended enhancement

Provenance tags and structured/typed output SHOULD be provided where useful; tags do not establish consumer trust.

**Applicable CASA references:** 3.1.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **6.4/V01 — BASELINE_GATE:** The required security outcome for Descriptions & Schemas MUST be met under the above baseline scope; no extra literal implementation is implied.
- **6.4/V02 — BASELINE_GATE:** The required security outcome for Output Construction MUST be met under the above baseline scope; no extra literal implementation is implied.
- **6.4/V03 — BASELINE_GATE:** The required security outcome for Independent Enforcement MUST be met under the above baseline scope; no extra literal implementation is implied.
- **6.4/V04 — BASELINE_GATE:** The required security outcome for Content Inspection MUST be met under the above baseline scope; no extra literal implementation is implied.
- **6.4/V05 — BASELINE_GATE:** The required security outcome for Authorization Independence MUST be met under the above baseline scope; no extra literal implementation is implied.

## 7.1 Financial Resource & Cost Governance

<!-- ada:test Tool:7.1 covers=Tool:10.1.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 10.1.1.

### Mandatory outcome

Metered operations MUST still meet applicable authorization and core Agent consequential-action HITL; no blanket auth gate is added to demonstrably public-safe resources merely because metered.

### Recommended enhancement

Cost awareness, cumulative tracking, a$100 advisory guardrail, configurable documented higher thresholds and per-user/per-tool budget limits SHOULD be retained.

**Applicable CASA references:** 3.1.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **7.1/V01 — ADVISORY:** The Paid Assets Identification scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.1/V02 — ADVISORY:** The Threshold Verification scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.1/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Authentication Check MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **7.1/V04 — ADVISORY:** The Cost Tracking Validation scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.1/V05 — ADVISORY:** The Stress Testing scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 7.2 Per User Endpoint Rate Limiting

<!-- ada:test Tool:7.2 covers=Tool:10.3.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 10.3.1.

### Mandatory outcome

Authorization and protected-resource existence confidentiality MUST NOT depend on reaching a rate threshold. Published authentication anti-automation alternatives and low-entropy OOB rate-limiting condition MUST remain exactly scoped; not every app is forced to choose rate limiting from1.1.1 alternatives.

### Recommended enhancement

Configurable per-user concurrent-session aggregation, target/action/resource aggregate limits, rationale and unrelated-user noninterference SHOULD be retained.

**Applicable CASA references:** 1.1.1, 1.3.4, 3.1.1, 3.1.4. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **7.2/V01 — ADVISORY:** The Request Handling scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.2/V02 — ADVISORY:** The Abuse Dimensions scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.2/V03 — BASELINE_GATE:** The required security outcome for Authorization Independence MUST be met under the above baseline scope; no extra literal implementation is implied.
- **7.2/V04 — ADVISORY:** The Configurability scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.2/V05 — ADVISORY:** The Enforcement scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.2/V06 — ADVISORY:** The Isolation scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 7.3 Maximum Payload and Recursion Depth Constraints

<!-- ada:test Tool:7.3 covers=Tool:10.2.1 -->

**Gate:** ADVISORY. **Requirement:** 10.2.1.

### Mandatory outcome

No universal payload/depth numeric baseline is established by the reviewed shared evidence; applicable injection/access controls still apply.

### Recommended enhancement

Configurable incoming byte/depth/recursive-call limits SHOULD be enforced. Excess-limit safe error/truncation handling SHOULD be tested.

**Applicable CASA references:** Apply the independent CASA register. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **7.3/V01 — ADVISORY:** The Payload Size Limits scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.3/V02 — ADVISORY:** The Recursion Depth Limits scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.3/V03 — ADVISORY:** The Payload Size Limits scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **7.3/V04 — ADVISORY:** The Recursion Depth Limits scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 8.1 Implement comprehensive logging using structured logging formats

<!-- ada:test Tool:8.1 covers=Tool:12.2.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 12.2.1.

### Mandatory outcome

Secret access MUST be logged OR monitored per CASA 6.7.1, and all logging MUST obey credential/payment/hash and task-content restrictions.

### Recommended enhancement

Machine-readable significant-event logging, invocation outcome metadata, timestamps/correlation IDs and summaries/hashes SHOULD be provided. Logging all model inputs/outputs is not a mandate or permission for transcript collection.

**Applicable CASA references:** 6.7.1, 6.5.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **8.1/V01 — ADVISORY:** The Structured Format scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **8.1/V02 — ADVISORY:** The External Tool Execution Paths scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **8.1/V03 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Telemetry Coverage MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **8.1/V04 — ADVISORY:** The Metadata and Correlation scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **8.1/V05 — ADVISORY:** The Silent Failures scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **8.1/V06 — ADVISORY:** The Unstructured Calls scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **8.1/V07 — MIXED_BASELINE_AND_ADVISORY:** The mandatory outcome in Log Capture Validation MUST meet the above baseline scope. The stronger original implementation/scenario SHOULD be assessed as advisory; an optional mechanism absence is not baseline failure.
- **8.1/V08 — ADVISORY:** The Machine-Readability scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.

## 8.2 Invocation Audit Trail

<!-- ada:test Tool:8.2 covers=Tool:TG-8.2 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** TG-8.2.

### Mandatory outcome

Secret access MUST be logged OR monitored; log content MUST meet the unchanged credential/payment/session hash and task-content boundaries.

### Recommended enhancement

A per-invocation JSON record with all six timestamp/Agent ID/function/version/input-hash-or-summary/outcome fields SHOULD be retained. Absence of one field is advisory unless an independent mandatory security property fails.

**Applicable CASA references:** 6.7.1, 6.5.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **8.2/V01 — ADVISORY:** The Log Generation scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **8.2/V02 — ADVISORY:** The Structured Format scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **8.2/V03 — ADVISORY:** The Log Inspection scenario SHOULD be assessed against the recommended enhancement. Absence or failure of unused optional capability is advisory unless a separately identified mandatory requirement is violated.
- **8.2/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: logcontent secrecy andtaskminimization whenlogs exist; secretaccess loggedORmonitored. SHOULD: allsixfields andJSONformat for everyinvocation.

## 7.7.1 Validate Origin Header on HTTP Transports

<!-- ada:test Tool:7.7.1 covers=Tool:7.7.1 -->

**Gate:** MIXED_BASELINE_AND_ADVISORY. **Requirement:** 7.7.1.

### Mandatory outcome

Applicable anti-CSRF/anti-automation outcomes MUST be preserved. Origin MUST NOT act as an authentication credential or sole access-control basis. Where the implementation selects an MCP HTTP transport profile with normative Origin-validation requirements, the implementing actor MUST meet those applicable profile requirements; an unselected protocol or unspecified hardening rule is not imported.

### Recommended enhancement

Origin allowlists/DNS-rebinding defenses beyond the selected protocol's normative requirements SHOULD be implemented as additional hardening. This does not demote the selected transport's required Origin validation. Current local/internal variants remain held.

**Applicable CASA references:** 3.1.5, 6.3.1. These relationships do not replace exact published criteria.

### Procedure and verification

Establish applicability and required authority first. Exercise the original scenarios with credentials and fixtures for the declared interface; observe protected output and side effects at the Tool boundary. Apply the following individual dispositions. For a mixed case, verify the mandatory outcome and record the mechanism separately.

- **7.7.1/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: enforce the selected MCP HTTP transport profile's applicable normative Origin-validation requirements, and do not use Origin as authentication. SHOULD: extra custom allowlists or hardening beyond that selected profile; no unrelated standard is imported.
- **7.7.1/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: reject Origin/rebinding requests when required by the implementation's selected MCP HTTP profile or an applicable baseline CSRF outcome. SHOULD: additional hardening beyond those requirements. Local/internal variants remain held, not blindly demoted.

## Supplemental minimum coverage

Each entry follows the register's actor, protocol and publication conditions. These 21 entries are coverage entries rather than unconditional Tool gates.

### MIN-S01 Public HTTPS and transport confidentiality

<!-- ada:test Tool:MIN-S01 covers=Tool:MIN-S01 -->

**Applicability:** Public-internet connector endpoint and applicable OAuth endpoints. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify HTTPS and all applicable published CASA TLS/certificate-trust criteria. Require public Internet reachability only for the relevant directory publication; do not substitute TLS 1.3-only or public-CA-only criteria for published alternatives.

### MIN-S02 OAuth authorization-code integration for protected user access

<!-- ada:test Tool:MIN-S02 covers=Tool:MIN-S02 -->

**Applicability:** Services requiring end-user/account authentication. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Exercise the supported OAuth authorization-code integration for protected user/account access. Verify valid client registration for the selected flow; do not require every registration mechanism. Confirm that genuine public-safe calls expose no protected data or sensitive operation.

### MIN-S03 S256 PKCE advertised and enforced

<!-- ada:test Tool:MIN-S03 covers=Tool:MIN-S03 -->

**Applicability:** OAuth authorization-code connections. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify S256 generation, code-exchange enforcement and capability advertisement for the OAuth client, authorization-server or resource-server duties actually implemented by the assessed component. Record externally owned duties as integration dependencies.

### MIN-S04 Protected-resource and authorization-server discovery

<!-- ada:test Tool:MIN-S04 covers=Tool:MIN-S04 -->

**Applicability:** OAuth-enabled MCP endpoints. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify HTTPS protected-resource metadata, canonical resource and authorization-server identity, reachable correct OAuth/OIDC metadata and the required discovery challenge. Apply the declared protocol and host-specific issuer/fallback/error contract.

### MIN-S05 Resource audience binding and no token passthrough

<!-- ada:test Tool:MIN-S05 covers=Tool:MIN-S05 -->

**Applicability:** Protected tool calls and upstream API delegation. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Present wrong-resource/audience credentials and verify denial. Confirm that a client token is not passed unchanged to an upstream resource with another audience. Either supported signed-token verification or authoritative opaque introspection may establish authority.

### MIN-S06 Verify user credentials and enforce access at the server

<!-- ada:test Tool:MIN-S06 covers=Tool:MIN-S06 -->

**Applicability:** Protected/user-specific tools and consequential actions. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Exercise missing, forged, invalid, expired, wrong-user and insufficient-scope credentials. Verify issuer/signature or authoritative introspection, intended resource and user authority before protected output or side effects. Metadata hints and model text never supply authorization.

### MIN-S07 Exact redirect validation and OAuth state protection

<!-- ada:test Tool:MIN-S07 covers=Tool:MIN-S07 -->

**Applicability:** OAuth redirects/callbacks. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Exercise unregistered redirect substitution and invalid or mismatched OAuth state. Verify redirect and state protection against open redirects and CSRF, preserving applicable native callback exceptions. PKCE alone does not replace state protection.

### MIN-S08 CIMD identity and redirect metadata validation

<!-- ada:test Tool:MIN-S08 covers=Tool:MIN-S08 -->

**Applicability:** Only if the selected connection implements CIMD. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** If CIMD is selected, verify the HTTPS client document identity against its client_id URL, registered redirects and supported token-endpoint authentication methods. Absence of unused CIMD is not a failure.

### MIN-S09 Keep authentication material out of URLs

<!-- ada:test Tool:MIN-S09 covers=Tool:MIN-S09 -->

**Applicability:** Secrets/access/session tokens in connector/API/OAuth requests. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Reject MCP bearer-token query transport and verify that authentication material is not exposed in URLs. Retain the exact published CASA API body/header alternatives where applicable.

### MIN-S10 Secure token/secret handling and storage

<!-- ada:test Tool:MIN-S10 covers=Tool:MIN-S10 -->

**Applicability:** Credentials/tokens stored or handled by the connector. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify credential confidentiality and published CASA secure storage, documented access policy and secret-access logging or monitoring. Do not prescribe a single vault, packaging or submission mechanism.

### MIN-S11 Refresh-token and replay protection

<!-- ada:test Tool:MIN-S11 covers=Tool:MIN-S11 -->

**Applicability:** Public OAuth clients and token refresh. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify public-client refresh-token replay protection, credential validity and expiry under the selected OAuth profile. Retain permitted rotation or sender-constraint remedies; do not infer a universal token lifetime or business-action idempotency requirement.

### MIN-S12 Truthful read-only and destructive operation classification

<!-- ada:test Tool:MIN-S12 covers=Tool:MIN-S12 -->

**Applicability:** Every exposed operation; hints according to operation type. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Compare applicable readOnlyHint/destructiveHint values with actual operation behavior and side effects. Apply literal MCP fields only to MCP interfaces; do not require universal openWorldHint or unrelated compatibility limits.

### MIN-S13 Accurate narrow tool descriptions and transparent side effects

<!-- ada:test Tool:MIN-S13 covers=Tool:MIN-S13 -->

**Applicability:** Exposed tool metadata. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Compare operation descriptions, parameter schemas and disclosed side effects with reachable behavior. Verify accurate narrow metadata and no misleading routing or undisclosed operation.

### MIN-S14 Separate read-only and state-changing tool surfaces

<!-- ada:test Tool:MIN-S14 covers=Tool:MIN-S14 -->

**Applicability:** Tools exposing reads and writes. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify that reads and writes have separate declared operation surfaces and that authorization cannot be bypassed through a mixed catch-all route. Do not prohibit a legitimate fixed-purpose or freeform read query solely because it accepts free text.

### MIN-S15 No hidden behavioral directives or unauthorized tool steering

<!-- ada:test Tool:MIN-S15 covers=Tool:MIN-S15 -->

**Applicability:** Descriptions/schemas and other model-readable connector metadata. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Exercise model-readable descriptions, schemas and returned content for hidden or obfuscated behavioral steering. Verify honest producer metadata without treating producer tags as proof that an untrusted counterparty is safe.

### MIN-S16 Do not circumvent platform or upstream security boundaries

<!-- ada:test Tool:MIN-S16 covers=Tool:MIN-S16 -->

**Applicability:** Tool behavior and downstream access. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify that downstream access respects the upstream resource and platform security boundaries. Tool calls must not use access or credentials to circumvent protected API restrictions.

### MIN-S17 Server-side input validation and injection defenses

<!-- ada:test Tool:MIN-S17 covers=Tool:MIN-S17 -->

**Applicability:** Untrusted model/client-supplied arguments. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Exercise hostile and malformed arguments against declared types/constraints and applicable injection, SSRF, IDOR and file-traversal outcomes. Reject extra fields where additionalProperties:false is declared; do not impose that constraint on schemas permitting them.

### MIN-S18 Minimize inputs, outputs and collected conversation/log content

<!-- ada:test Tool:MIN-S18 covers=Tool:MIN-S18 -->

**Applicability:** Tool inputs/results and data/logcollection. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify that inputs, results and collection stay within authorized task-necessary data boundaries. Retain published secret and sensitive-log protections; a heuristic PII detector is not the only admissible implementation.

### MIN-S19 No covert reconstruction of Agent memory/history or conversation profiles

<!-- ada:test Tool:MIN-S19 covers=Tool:MIN-S19 -->

**Applicability:** Agent memory/chat/history and long-lived connector context. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Exercise conversational history, memory and long-lived context boundaries. Verify that the Tool does not covertly reconstruct or collect unauthorized user history/profile data outside the declared task purpose.

### MIN-S20 Informed consent for irreversible/consequential actions

<!-- ada:test Tool:MIN-S20 covers=Tool:MIN-S20 -->

**Applicability:** Sensitive or irreversible actions, not every read or every write. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Assess the Tool's truthful sensitivity metadata, no-circumvention and authorization. Record actual Agent human confirmation and shown-versus-executed fidelity as Agent obligations. Independent Tool elicitation, out-of-band approval and signed receipts remain recommended enhancements.

### MIN-S21 Legitimate endpoint/domain/API provenance

<!-- ada:test Tool:MIN-S21 covers=Tool:MIN-S21 -->

**Applicability:** Connector endpoint and downstream APIs. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

**Verification:** Verify legitimate endpoint/domain control and downstream API provenance. Distinguish the technical access/ownership evidence from publisher-review process and avoid crediting undocumented proxy or impersonation routes.

## Local and other retained variants

Use the [Local Android Requirements](AI%20Tool%20Local%20Android%20Requirements.md) for the retained local Android test bodies, original applicability and mandatory strength. Other local/mobile variants continue to use the pinned source pending a separate decision.

## Contributors

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

## Application Security Assessment Working Group Leads
* Alex Duff (Meta) \- ASA WG Chair
* Anna Bhirud (Google) \- ASA WG Vice Chair

## AI Profile Leads

* Brad Ree (Google)
* Alex Duff (Meta)

## Contributors

* Debdutta Guha(Google)
* Nic Watson (Google)
* Abhiraman Gcl (Google)
* Daniel Bond (Meta)
* Tony Balkan (Microsoft)
* Dario Freni (Google)
* Anna Bhirud(Google)
* TBD

## Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
