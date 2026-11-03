# AI Tool Testing Guide

<!-- ai-alpha-preview: AI-profiles-0.1.0-alpha.1 -->
**AI profiles 0.1.0-alpha.1 — proposed WG alpha for pilot assessment; not a basis for ADA certificates.**

This candidate's prospective requirements do not authorize certificate issuance. [AI-only publication scope and exact released baseline references](AI%20Alpha%20Publication%20Scope.md) govern the pilot; WG/SC adoption and release preparation remain outstanding.

**Draft proposal for Working Group review — 31 October 2026.**

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
| Other local, desktop and mobile standalone Tool variants | Outside this alpha's standalone Tool route; historical source is context, not a certification procedure by commit reference. Desktop/mobile Agent runtime obligations and released DASA/MASA remain applicable. |

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
nonce/session controls and uncertain-outcome honesty. Stable business-action IDs
follow the conditional Agent rule in Contract C4 and Agent §6.1.3; they are not an
unconditional prerequisite.

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

<!-- assessment-rules -->
## Individual case grading

- **Source precedence:** Assertions implement the referenced proposed Tool requirements. All applicable published CASA criteria, alternatives and exceptions remain independently mandatory; related CASA IDs are not a replacement for the full floor.
- **Tiers:** Keep each original_assurance_tier. AL0/AL1 review uses relevant declared artifacts and interface evidence; AL2 exercises the corresponding running implementation. External actor duties are dependency records, not Tool-owned passes.
- **Minimum result:** PASS only when every applicable mandatory assertion has sufficient passing evidence; FAIL for any demonstrated mandatory breach; INSUFFICIENT_EVIDENCE when a required observation is unavailable; NOT_APPLICABLE only with a documented scope/actor/feature basis. An advisory-only case has no minimum assertion and is NOT_SCORED for the minimum; it does not establish a certification pass. Independently discovered mandatory breaches are still recorded against the breached requirement.
- **Enhancement result:** Record each enhancement as IMPLEMENTED, ABSENT, WEAK, NOT_APPLICABLE or INSUFFICIENT_EVIDENCE. Absent/weak enhancements are advisory. Do not require an unused enhancement, its fixture, or its evidence to pass the minimum.
- **Mandatory breach from advisory:** If an advisory exercise reveals a breach of an independently mandatory requirement, record a minimum failure with that requirement and observed effect. Any optional credential/proof used to establish required authority must undergo its required validation.
- **Positive controls:** Use the legitimate authorized/control inputs in assessment_context and the assertion exercise. A security denial passes only with enough evidence that no prohibited output/effect occurred; a generic error is insufficient. Do not classify legitimate purpose-required private output as a leak.
- **Result record:** Record each assertion ID, responsible actor, applicability/exception basis, implementation or enhancement status, evidence references, observed output/effect and assertion result. Keep the case minimum result separate from each enhancement result. A dependency record does not establish the external actor implementation as Tool-owned.
- **Retained variants:** This assessment overlay applies only to remote_http_tool. Local Android retains the original case text, tier and original applicability from AI Tool Local Android Requirements.md; other local/mobile variants retain their current source disposition pending their separate scope decision.
<!-- /assessment-rules -->

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

<!-- assessment-context:1.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool resource server
- **Applicability:** Protected remote operations and declared public-safe/discovery routes.
- **Setup and positive/negative controls:** Use the declared supported OAuth verifier, seeded users/accounts A and B, resource-scoped valid/invalid credentials, and an operation counter. Include a genuinely public-safe route without credentials.
- **Observe:** Capture verifier decisions, returned protected data, selected user/account and operation-counter changes.
<!-- /assessment-context:1.1 -->

- **1.1/V01 — BASELINE_GATE:** MUST: Validate the supported credential and user/resource/scope before protected output or execution.
  - **1.1/V01/M01 exercise:** Send valid then missing/invalid supported credentials to a protected operation.
  - **1.1/V01/M01 source requirements:** Tool:1.1.1.
- **1.1/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Use the current verified user/account/grant and applicable declared session binding; reject authority/resource mismatches and prevent stale cross-user context from authorizing effects. SHOULD: Provide cryptographic host/session identity binding beyond ordinary validated user authority.
  - **1.1/V02/M01 exercise:** Reuse a connection across valid declared request contexts; attempt wrong-user/account/resource access and stale-context substitution.
  - **1.1/V02/M01 source requirements:** Tool:1.1.1.
  - **1.1/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Provide cryptographic host/session identity binding beyond ordinary validated user authority.
  - **1.1/V02/S01 source requirements:** Tool:1.1.1.
- **1.1/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Deny protected execution without required valid authority; anonymous public-safe access cannot acquire protected data or sensitive effects. SHOULD: Authenticate even genuine public-safe routes.
  - **1.1/V03/M01 exercise:** Call each exposed protected route without credentials; call a genuine public-safe route anonymously.
  - **1.1/V03/M01 source requirements:** Tool:1.1.1.
  - **1.1/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Authenticate even genuine public-safe routes.
  - **1.1/V03/S01 source requirements:** Tool:1.1.1.
- **1.1/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Reject missing authority before protected output/effects; genuine public-safe calls may remain anonymous. SHOULD: Require authentication on otherwise public-safe operations.
  - **1.1/V04/M01 exercise:** Repeat protected and public-safe calls without the required credential.
  - **1.1/V04/M01 source requirements:** Tool:1.1.1.
  - **1.1/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Require authentication on otherwise public-safe operations.
  - **1.1/V04/S01 source requirements:** Tool:1.1.1.
- **1.1/V05 — BASELINE_GATE:** MUST: Reject invalid required authority before protected data or actions; do not use an invalid credential as authority on a public path.
  - **1.1/V05/M01 exercise:** Present expired, malformed and wrong-audience supported credentials.
  - **1.1/V05/M01 source requirements:** Tool:1.1.1.
- **1.1/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: Keep request authority isolated by verified user/account/grant and stop invalid authority reuse; valid same-user grant reuse is permitted. SHOULD: Freeze host/session identity through a dedicated cryptographic session-binding mechanism.
  - **1.1/V06/M01 exercise:** Alternate users/accounts and concurrent sessions; then reuse an expired/revoked grant.
  - **1.1/V06/M01 source requirements:** Tool:1.1.1.
  - **1.1/V06/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Freeze host/session identity through a dedicated cryptographic session-binding mechanism.
  - **1.1/V06/S01 source requirements:** Tool:1.1.1.

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

<!-- assessment-context:1.2 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool session/authentication component
- **Applicability:** The implemented stateful/stateless authentication model; an optional message nonce or inactivity timer is tested only if implemented.
- **Setup and positive/negative controls:** Exercise valid active authority, logout, expiry, password change and the published termination option. For implemented enhancements, submit expired/repeated nonces and wait the declared inactivity interval. Distinguish independent persistent grants.
- **Observe:** Capture session validity, protected responses and side effects after each event; record the applicable published session criterion.
<!-- /assessment-context:1.2 -->

- **1.2/V01 — BASELINE_GATE:** MUST: Meet each applicable published session criterion, including server invalidation and non-revocable stateless-token expiry within 24 hours and stateless anti-tampering/replay controls.
  - **1.2/V01/M01 exercise:** Exercise active authority, logout, expiry and the published password-change termination option; inspect stateless validity and integrity.
  - **1.2/V01/M01 source requirements:** Tool:1.4.1.
- **1.2/V02 — ADVISORY:** SHOULD: There is a verified implementation of an expiration timer (TTL) that ensures active sessions are terminated after a defined period of inactivity.
  - **1.2/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: There is a verified implementation of an expiration timer (TTL) that ensures active sessions are terminated after a defined period of inactivity.
  - **1.2/V02/S01 source requirements:** Tool:1.4.1.
- **1.2/V03 — ADVISORY:** SHOULD: The server enforces validation of 'timestamp' or 'nonce' fields within incoming JSON-RPC objects to block stale or duplicate requests.
  - **1.2/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server enforces validation of 'timestamp' or 'nonce' fields within incoming JSON-RPC objects to block stale or duplicate requests.
  - **1.2/V03/S01 source requirements:** Tool:1.4.1.
- **1.2/V04 — ADVISORY:** SHOULD: The server automatically terminates the connection after the defined timeout period of inactivity.
  - **1.2/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server automatically terminates the connection after the defined timeout period of inactivity.
  - **1.2/V04/S01 source requirements:** Tool:1.4.1.
- **1.2/V05 — ADVISORY:** SHOULD: Duplicate JSON-RPC requests are successfully rejected by the server based on an expired timestamp or used nonce.
  - **1.2/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Duplicate JSON-RPC requests are successfully rejected by the server based on an expired timestamp or used nonce.
  - **1.2/V05/S01 source requirements:** Tool:1.4.1.
- **1.2/V06 — BASELINE_GATE:** MUST: Reject authority invalidated by applicable session termination; a separately valid independent grant is judged by its own lifecycle.
  - **1.2/V06/M01 exercise:** Issue a protected call using terminated/timed-out session authority, then a separately valid grant control.
  - **1.2/V06/M01 source requirements:** Tool:1.4.1.

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

<!-- assessment-context:1.3 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool OAuth client/authorization server, for the roles it implements
- **Applicability:** Applicable OAuth flows, callback endpoints and actual auth/admin web components. Externally owned role duties are recorded as dependencies.
- **Setup and positive/negative controls:** Use an authorized callback as the positive control. Substitute unregistered redirect URIs, missing/swapped state and concurrent-user callbacks; replay completed callbacks. Exercise the applicable registered native-loopback port alternative and secure channels.
- **Observe:** Capture authorization requests, callback associations, token retention and protected effects; do not credit external role behavior as Tool implementation.
<!-- /assessment-context:1.3 -->

- **1.3/V01 — BASELINE_GATE:** MUST: Validate applicable redirect URI and state and exclude deprecated Implicit/ROPC flows.
  - **1.3/V01/M01 exercise:** Complete an authorized OAuth flow, then alter redirect URI and state.
  - **1.3/V01/M01 source requirements:** Tool:1.5.1.
- **1.3/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Reject state that does not establish the initiating authorization transaction; prevent CSRF and unauthorized association. SHOULD: Generate state with a dedicated cryptographically secure random mechanism.
  - **1.3/V02/M01 exercise:** Swap, omit or forge state between two authorization flows.
  - **1.3/V02/M01 source requirements:** Tool:1.5.1.
  - **1.3/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Generate state with a dedicated cryptographically secure random mechanism.
  - **1.3/V02/S01 source requirements:** Tool:1.5.1.
- **1.3/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Validate redirect and state so substitution cannot cause CSRF or bind credentials to the wrong authorization context. SHOULD: Bind the complete explicit transaction tuple with short-lived, single-use state and secure cross-device handoff.
  - **1.3/V03/M01 exercise:** Swap user/session/issuer/client/redirect/PKCE transaction values and inspect the resulting association.
  - **1.3/V03/M01 source requirements:** Tool:1.5.1.
  - **1.3/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Bind the complete explicit transaction tuple with short-lived, single-use state and secure cross-device handoff.
  - **1.3/V03/S01 source requirements:** Tool:1.5.1.
- **1.3/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Accept only authorized registered redirects under the applicable profile; prevent open redirect or credential disclosure. SHOULD: Construct redirects independently of all dynamic user input.
  - **1.3/V04/M01 exercise:** Supply an attacker-controlled redirect URI and a valid registered redirect, including the applicable native-loopback alternative.
  - **1.3/V04/M01 source requirements:** Tool:1.5.1.
  - **1.3/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Construct redirects independently of all dynamic user input.
  - **1.3/V04/S01 source requirements:** Tool:1.5.1.
- **1.3/V05 — BASELINE_GATE:** MUST: Enforce the applicable registered redirect set and native-loopback port condition; an unregistered destination must not receive credentials or authorization.
  - **1.3/V05/M01 exercise:** Compare configured/registered redirects with valid and unregistered callback destinations.
  - **1.3/V05/M01 source requirements:** Tool:1.5.1.
- **1.3/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: Exclude deprecated OAuth flows and satisfy the applicable secure-transport requirements. SHOULD: Remove every legacy authentication method beyond those prohibited by the selected profile and published floor.
  - **1.3/V06/M01 exercise:** Attempt Implicit/ROPC flows and unencrypted authentication alongside the supported secure flow.
  - **1.3/V06/M01 source requirements:** Tool:1.5.1.
  - **1.3/V06/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Remove every legacy authentication method beyond those prohibited by the selected profile and published floor.
  - **1.3/V06/S01 source requirements:** Tool:1.5.1.
- **1.3/V07 — BASELINE_GATE:** MUST: Reject an unauthorized redirect before code/token disclosure or account association.
  - **1.3/V07/M01 exercise:** Request authorization with an unregistered redirect URI.
  - **1.3/V07/M01 source requirements:** Tool:1.5.1.
- **1.3/V08 — BASELINE_GATE:** MUST: Reject cross-context state/redirect substitution without retaining unauthorized credentials or creating a wrong-user association.
  - **1.3/V08/M01 exercise:** Swap concurrent-user/session callbacks and then complete each original flow correctly.
  - **1.3/V08/M01 source requirements:** Tool:1.5.1.
- **1.3/V09 — MIXED_BASELINE_AND_ADVISORY:** MUST: A replay must not bypass applicable state/redirect validation or cause CSRF/unauthorized association. SHOULD: Consume each callback/state exactly once and enforce a short expiry independently of whether replay would otherwise be unauthorized.
  - **1.3/V09/M01 exercise:** Replay completed callbacks/state and attempt a new account association or protected access.
  - **1.3/V09/M01 source requirements:** Tool:1.5.1.
  - **1.3/V09/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Consume each callback/state exactly once and enforce a short expiry independently of whether replay would otherwise be unauthorized.
  - **1.3/V09/S01 source requirements:** Tool:1.5.1.
- **1.3/V10 — MIXED_BASELINE_AND_ADVISORY:** MUST: Protect applicable OAuth exchanges with HTTPS and satisfy the full published transport/trust criteria. SHOULD: Exclude all legacy transport methods beyond the applicable published conditions.
  - **1.3/V10/M01 exercise:** Attempt unencrypted OAuth endpoints, then the valid secure flow and any documented applicable CASA exception.
  - **1.3/V10/M01 source requirements:** Tool:1.5.1.
  - **1.3/V10/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Exclude all legacy transport methods beyond the applicable published conditions.
  - **1.3/V10/S01 source requirements:** Tool:1.5.1.

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

<!-- assessment-context:1.4 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool OAuth client or authorization server, for the role identified by the assertion
- **Applicability:** Selected public-remote OAuth authorization-code profile. External client/AS duties are dependencies rather than Tool-owned passes.
- **Setup and positive/negative controls:** Complete a valid S256 authorization-code flow. Repeat with omitted/altered verifier and attempted downgrade; correlate the challenge, verifier and issuing transaction.
- **Observe:** Capture redacted authorize/token exchanges and code redemption. Score generation on the implemented client and verification on the implemented AS.
<!-- /assessment-context:1.4 -->

- **1.4/V01 — BASELINE_GATE:** MUST: The implementing OAuth client generates a secure verifier and sends code_challenge_method=S256 for the selected authorization-code profile.
  - **1.4/V01/M01 exercise:** Inspect the implemented client's authorize request and correlate its generated verifier/challenge.
  - **1.4/V01/M01 source requirements:** Tool:1.5.2.
- **1.4/V02 — BASELINE_GATE:** MUST: The implementing OAuth client retrieves the correct transaction verifier securely and supplies it at redemption.
  - **1.4/V02/M01 exercise:** Redeem a valid code and inspect the implemented client's token exchange.
  - **1.4/V02/M01 source requirements:** Tool:1.5.2.
- **1.4/V03 — BASELINE_GATE:** MUST: Static client authentication or state cannot replace required S256 PKCE in the selected profile.
  - **1.4/V03/M01 exercise:** Attempt a selected-profile authorization-code flow using only client_secret or state.
  - **1.4/V03/M01 source requirements:** Tool:1.5.2.
- **1.4/V04 — BASELINE_GATE:** MUST: The implementing authorization server rejects redemption lacking the required matching verifier before token issuance.
  - **1.4/V04/M01 exercise:** Redeem a code with omitted/wrong verifier, then the correct verifier at the implemented AS.
  - **1.4/V04/M01 source requirements:** Tool:1.5.2.

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

<!-- assessment-context:1.5 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool resource server and owned downstream clients
- **Applicability:** Protected multi-user operations, including reused runtimes and downstream access.
- **Setup and positive/negative controls:** Seed users A/B, distinct accounts, read-only and write grants, permitted and foreign resources. Exercise a valid request and swapped identity/account/scope against each relevant handler.
- **Observe:** Observe verified execution context, downstream authority, protected output and side effects; log identity fields are enhanced evidence only.
<!-- /assessment-context:1.5 -->

- **1.5/V01 — BASELINE_GATE:** MUST: Derive execution user/tenant authority from validated credentials or authoritative introspection, not the attacker-selected identifier.
  - **1.5/V01/M01 exercise:** Send verified A/B authority and an attacker-selected user identifier to the same handler.
  - **1.5/V01/M01 source requirements:** Tool:2.2.2.
- **1.5/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Downstream service credentials must not substitute for required user authorization or permit cross-user/out-of-scope effects. SHOULD: Instantiate downstream clients with propagated user tokens rather than separately authorized service credentials.
  - **1.5/V02/M01 exercise:** Attempt foreign-resource access through an owned downstream client using a broad service credential.
  - **1.5/V02/M01 source requirements:** Tool:2.2.2.
  - **1.5/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Instantiate downstream clients with propagated user tokens rather than separately authorized service credentials.
  - **1.5/V02/S01 source requirements:** Tool:2.2.2.
- **1.5/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Every exposed protected path enforces verified user/resource authority before protected effects. SHOULD: Centralize identity propagation in non-bypassable middleware.
  - **1.5/V03/M01 exercise:** Exercise primary and alternate handlers with missing/wrong user authority.
  - **1.5/V03/M01 source requirements:** Tool:2.2.2.
  - **1.5/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Centralize identity propagation in non-bypassable middleware.
  - **1.5/V03/S01 source requirements:** Tool:2.2.2.
- **1.5/V04 — BASELINE_GATE:** MUST: Deny unauthorized foreign data, existence-sensitive metadata and side effects before disclosure/execution.
  - **1.5/V04/M01 exercise:** Request B's resource as A and perform the valid A-resource control.
  - **1.5/V04/M01 source requirements:** Tool:2.2.2.
- **1.5/V05 — ADVISORY:** SHOULD: Downstream audit logs should correctly record the action under the end-user's identity, not a service account.
  - **1.5/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Downstream audit logs should correctly record the action under the end-user's identity, not a service account.
  - **1.5/V05/S01 source requirements:** Tool:2.2.2.
- **1.5/V06 — BASELINE_GATE:** MUST: Enforce actual resource and operation scope before protected output or effects.
  - **1.5/V06/M01 exercise:** Attempt writes with read-only authority and resources outside the granted scope.
  - **1.5/V06/M01 source requirements:** Tool:2.2.2.

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

<!-- assessment-context:1.6 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool-owned outbound network client
- **Applicability:** Applicable downstream sensitive-data/authentication transport, with published trust/TLS alternatives and exceptions.
- **Setup and positive/negative controls:** Use an authorized TLS destination and the applicable approved trust configuration. Test plaintext attempts, untrusted/expired certificates and redirects to authorized and unauthorized origins with seeded credentials.
- **Observe:** Capture transport negotiation and destination requests; observe whether protected data or credentials reach an unauthorized or unencrypted sink.
<!-- /assessment-context:1.6 -->

- **1.6/V01 — ADVISORY:** SHOULD: All outgoing network clients are successfully identified in the codebase.
  - **1.6/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: All outgoing network clients are successfully identified in the codebase.
  - **1.6/V01/S01 source requirements:** Tool:1.3.2.
- **1.6/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Sensitive/authentication transport meets the applicable published TLS/trust floor and exceptions. SHOULD: Use secure URL construction uniformly beyond the published conditions and prefer TLS 1.3.
  - **1.6/V02/M01 exercise:** Negotiate allowed/prohibited transports to an owned downstream endpoint.
  - **1.6/V02/M01 source requirements:** Tool:1.3.2.
  - **1.6/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Use secure URL construction uniformly beyond the published conditions and prefer TLS 1.3.
  - **1.6/V02/S01 source requirements:** Tool:1.3.2.
- **1.6/V03 — BASELINE_GATE:** MUST: Protect sensitive data in transit under the applicable published TLS/trust criteria and permitted alternatives.
  - **1.6/V03/M01 exercise:** Transmit seeded sensitive information over the supported protected transport and probe plaintext downgrade.
  - **1.6/V03/M01 source requirements:** Tool:1.3.2.
- **1.6/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Credentials and sensitive data cannot reach an unauthorized redirected destination. SHOULD: Independently reauthorize every origin-changing redirect through an explicit per-destination mechanism.
  - **1.6/V04/M01 exercise:** Redirect an authenticated request to an unauthorized origin and to a separately authorized destination.
  - **1.6/V04/M01 source requirements:** Tool:1.3.2.
  - **1.6/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Independently reauthorize every origin-changing redirect through an explicit per-destination mechanism.
  - **1.6/V04/S01 source requirements:** Tool:1.3.2.
- **1.6/V05 — BASELINE_GATE:** MUST: No secret/authentication data reaches an unencrypted transport prohibited by the applicable floor; no bearer credential appears in a URL query.
  - **1.6/V05/M01 exercise:** Capture seeded credentials during ordinary and attempted unencrypted downstream requests.
  - **1.6/V05/M01 source requirements:** Tool:1.3.2.
- **1.6/V06 — BASELINE_GATE:** MUST: The unapproved destination receives neither credentials nor protected data.
  - **1.6/V06/M01 exercise:** Redirect an authorized destination to the controlled unapproved origin.
  - **1.6/V06/M01 source requirements:** Tool:1.3.2.

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

<!-- assessment-context:1.7 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool HTTP endpoint and owned network clients
- **Applicability:** Public-remote TLS/trust criteria. Local IPC cases retain their source variant and are not graded by this remote rubric.
- **Setup and positive/negative controls:** Exercise TLS 1.2/1.3 and prohibited configurations against the exact applicable CASA criterion; test untrusted/expired certificates and a documented internal-CA route where applicable. Test message replay only for implemented enhancement.
- **Observe:** Record negotiated version, trust decisions, accepted exceptions and requests; distinguish preferred TLS/message mechanisms from mandatory transport outcomes.
<!-- /assessment-context:1.7 -->

- **1.7/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Meet full applicable CASA transport/cipher criteria, including default TLS 1.2+ and exact permitted legacy conditions. SHOULD: Require TLS 1.3 as the preferred stronger minimum.
  - **1.7/V01/M01 exercise:** Probe TLS 1.2/1.3 and cipher configurations against the exact published transport criterion.
  - **1.7/V01/M01 source requirements:** Tool:7.1.1.
  - **1.7/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Require TLS 1.3 as the preferred stronger minimum.
  - **1.7/V01/S01 source requirements:** Tool:7.1.1.
- **1.7/V02 — BASELINE_GATE:** MUST: Do not bypass required X.509 trust/validity verification; preserve the published documented internal-CA and other applicable alternatives.
  - **1.7/V02/M01 exercise:** Present an untrusted/invalid certificate with the applicable valid-trust control.
  - **1.7/V02/M01 source requirements:** Tool:7.1.1.
- **1.7/V03 — CURRENT_UNCHANGED_OUTSIDE_TARGET_VARIANT:** Outside remote_http_tool: assess the original case only under its original applicable local/platform variant.
- **1.7/V04 — ADVISORY:** SHOULD: The server refuses any handshake attempting to use TLS 1.2 or lower.
  - **1.7/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server refuses any handshake attempting to use TLS 1.2 or lower.
  - **1.7/V04/S01 source requirements:** Tool:7.1.1.
- **1.7/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: Reject certificates failing the applicable published trust criteria; evaluate admitted internal-CA exceptions under their exact conditions. SHOULD: Reject all self-signed server certificates beyond the published documented trust alternatives.
  - **1.7/V05/M01 exercise:** Present expired/untrusted certificates and a valid documented internal-CA chain where applicable.
  - **1.7/V05/M01 source requirements:** Tool:7.1.1.
  - **1.7/V05/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Reject all self-signed server certificates beyond the published documented trust alternatives.
  - **1.7/V05/S01 source requirements:** Tool:7.1.1.
- **1.7/V06 — ADVISORY:** SHOULD: Duplicate messages are successfully rejected by the server based on an expired timestamp or used nonce.
  - **1.7/V06/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Duplicate messages are successfully rejected by the server based on an expired timestamp or used nonce.
  - **1.7/V06/S01 source requirements:** Tool:7.1.1.
- **1.7/V07 — CURRENT_UNCHANGED_OUTSIDE_TARGET_VARIANT:** Outside remote_http_tool: assess the original case only under its original applicable local/platform variant.

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

<!-- assessment-context:1.8 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool action execution/status component
- **Applicability:** Optional durable business-action idempotency and outcome reconciliation; ordinary authorization/session requirements are assessed independently.
- **Setup and positive/negative controls:** Use a mock consequential action counter. Send concurrent same-intent requests, separately approved distinct intents, restart/replay, and drop the response after commit; query status during the documented uncertainty window.
- **Observe:** Observe committed action counts, intent binding, durable state and reported status. An absent enhancement needs no fixture implementation to pass the minimum.
<!-- /assessment-context:1.8 -->

- **1.8/V01 — ADVISORY:** SHOULD: Every execution request for a Sensitive Action capable of an external side effect requires a stable identifier bound to the complete user-approved action, and duplicate-suppression state survives process restarts for the documented retry and outcome-uncertainty period. If the Tool mints the identifier, its preparation step cannot create the external side effect.
  - **1.8/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Every execution request for a Sensitive Action capable of an external side effect requires a stable identifier bound to the complete user-approved action, and duplicate-suppression state survives process restarts for the documented retry and outcome-uncertainty period. If the Tool mints the identifier, its preparation step cannot create the external side effect.
  - **1.8/V01/S01 source requirements:** Tool:1.4.2.
- **1.8/V02 — ADVISORY:** SHOULD: Ambiguous outcomes cannot cause blind retry or fabricated success.
  - **1.8/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Ambiguous outcomes cannot cause blind retry or fabricated success.
  - **1.8/V02/S01 source requirements:** Tool:1.4.2.
- **1.8/V03 — ADVISORY:** SHOULD: Concurrent requests and retries do not create an unintended duplicate external side effect.
  - **1.8/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Concurrent requests and retries do not create an unintended duplicate external side effect.
  - **1.8/V03/S01 source requirements:** Tool:1.4.2.
- **1.8/V04 — ADVISORY:** SHOULD: The Tool reports an authoritative status where available and otherwise reports an explicit indeterminate outcome.
  - **1.8/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The Tool reports an authoritative status where available and otherwise reports an explicit indeterminate outcome.
  - **1.8/V04/S01 source requirements:** Tool:1.4.2.

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

<!-- assessment-context:1.9 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool authority/session component
- **Applicability:** Applicable credential/grant revocation, expiry and published session termination; distinguish independent persistent grants.
- **Setup and positive/negative controls:** Use a valid grant, then trigger supported logout, expiration, password-change termination/option, unlink or revocation. Exercise a new call, queued work, callback and retry; include a committed-before-event control.
- **Observe:** Record the actual authority termination event, accepted credentials, post-event side effects and authoritative committed status; no new fixed convergence SLA is imposed.
<!-- /assessment-context:1.9 -->

- **1.9/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Enforce applicable grant/token revocation and published session/refresh termination; distinguish independent persistent grants. SHOULD: Propagate every supported unlink/removal/deactivation event to capabilities, approvals, queued work, callbacks and retries.
  - **1.9/V01/M01 exercise:** Revoke/expire applicable authority and attempt subsequent protected operations across supported paths.
  - **1.9/V01/M01 source requirements:** Tool:1.4.3.
  - **1.9/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Propagate every supported unlink/removal/deactivation event to capabilities, approvals, queued work, callbacks and retries.
  - **1.9/V01/S01 source requirements:** Tool:1.4.3.
- **1.9/V02 — ADVISORY:** SHOULD: The maximum revocation-enforcement time is documented.
  - **1.9/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The maximum revocation-enforcement time is documented.
  - **1.9/V02/S01 source requirements:** Tool:1.4.3.
- **1.9/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: No protected operation can execute using invalidated authority, including any execution path that still requires that authority. SHOULD: Cancel all uncommitted queued work and prevent callback/retry new effects through explicit lifecycle propagation.
  - **1.9/V03/M01 exercise:** After authority termination becomes effective, execute new calls and supported queued/retry/callback paths.
  - **1.9/V03/M01 source requirements:** Tool:1.4.3.
  - **1.9/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Cancel all uncommitted queued work and prevent callback/retry new effects through explicit lifecycle propagation.
  - **1.9/V03/S01 source requirements:** Tool:1.4.3.
- **1.9/V04 — ADVISORY:** SHOULD: Work committed before revocation is reported according to authoritative downstream state.
  - **1.9/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Work committed before revocation is reported according to authoritative downstream state.
  - **1.9/V04/S01 source requirements:** Tool:1.4.3.

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

<!-- assessment-context:2.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool resource server and owned downstream handlers
- **Applicability:** All exposed protected operations; service identity alone cannot replace user authorization.
- **Setup and positive/negative controls:** Use users A/B and least-privilege grants with permitted and foreign objects. Exercise primary and alternate exposed handlers, an attacker-selected user identifier, and a service credential without the required user grant.
- **Observe:** Observe decisions at the trusted authorization layer, protected metadata/data and downstream effects; implementation architecture is separate.
<!-- /assessment-context:2.1 -->

- **2.1/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Required authorization precedes protected effects on every tested execution path. SHOULD: Maintain and inspect a comprehensive callTool-handler inventory.
  - **2.1/V01/M01 exercise:** Exercise each reachable protected handler with valid and missing/wrong authority.
  - **2.1/V01/M01 source requirements:** Tool:1.2.1.
  - **2.1/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Maintain and inspect a comprehensive callTool-handler inventory.
  - **2.1/V01/S01 source requirements:** Tool:1.2.1.
- **2.1/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Service identity cannot authorize an operation for an unverified or unauthorized user; confidential embedded keys remain protected. SHOULD: Avoid broad service credentials throughout downstream client design.
  - **2.1/V02/M01 exercise:** Present a broad service credential without A's resource authority.
  - **2.1/V02/M01 source requirements:** Tool:1.2.1.
  - **2.1/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Avoid broad service credentials throughout downstream client design.
  - **2.1/V02/S01 source requirements:** Tool:1.2.1.
- **2.1/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Trusted verified authority determines user/resource permissions; unverified metadata is not authentication. SHOULD: Propagate a dedicated user-context field centrally through all request metadata.
  - **2.1/V03/M01 exercise:** Supply attacker-selected user/account parameters alongside a different valid credential.
  - **2.1/V03/M01 source requirements:** Tool:1.2.1.
  - **2.1/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Propagate a dedicated user-context field centrally through all request metadata.
  - **2.1/V03/S01 source requirements:** Tool:1.2.1.
- **2.1/V04 — BASELINE_GATE:** MUST: The trusted layer enforces user/resource/object/attribute permissions before output or effects.
  - **2.1/V04/M01 exercise:** Use verified A context to request allowed and forbidden downstream resources.
  - **2.1/V04/M01 source requirements:** Tool:1.2.1.
- **2.1/V05 — BASELINE_GATE:** MUST: Deny unauthorized data, existence-sensitive metadata and effects.
  - **2.1/V05/M01 exercise:** Access B's resource with A's authority, including existence-sensitive queries.
  - **2.1/V05/M01 source requirements:** Tool:1.2.1.
- **2.1/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: Downstream credential use preserves the user's authorized resource/operation boundary; service credentials cannot expand it. SHOULD: Use a dedicated narrowly scoped end-user token on each downstream call.
  - **2.1/V06/M01 exercise:** Compare downstream scope with the verified user's permissions and attempt an out-of-scope operation.
  - **2.1/V06/M01 source requirements:** Tool:1.2.1.
  - **2.1/V06/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Use a dedicated narrowly scoped end-user token on each downstream call.
  - **2.1/V06/S01 source requirements:** Tool:1.2.1.
- **2.1/V07 — BASELINE_GATE:** MUST: Tool authorization remains independent of Agent-supplied consent or identity claims; applicable truthfulness/Agent-HITL obligations retain their own actor allocation.
  - **2.1/V07/M01 exercise:** Supply a forged consent/context claim with wrong user/resource authority; compare with a valid authorized call.
  - **2.1/V07/M01 source requirements:** Tool:1.2.1.

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

<!-- assessment-context:2.2 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool credential verifier and owned downstream clients
- **Applicability:** The declared supported signed-token or authoritative opaque-token verifier; no universal dual-format or OBO implementation requirement.
- **Setup and positive/negative controls:** Use a valid declared-format credential. Alter payload/signature or opaque token/introspection state; test missing/wrong issuer, audience, expiry or scope and an unsigned user identifier. Include legitimately authorized downstream access.
- **Observe:** Capture redacted verification/introspection evidence, execution context, downstream audience and protected effects.
<!-- /assessment-context:2.2 -->

- **2.2/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Correctly verify the supported credential, including applicable issuer/audience/expiry/scope; inactive or tampered authority cannot grant protected access. SHOULD: Use a dedicated signed identity assertion and trusted JWKS verification architecture.
  - **2.2/V01/M01 exercise:** Validate declared-format credentials, then alter signature/key or authoritative introspection result.
  - **2.2/V01/M01 source requirements:** Tool:1.2.2.
  - **2.2/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Use a dedicated signed identity assertion and trusted JWKS verification architecture.
  - **2.2/V01/S01 source requirements:** Tool:1.2.2.
- **2.2/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Protected downstream access remains user-authorized and audience-appropriate. SHOULD: Acquire a downstream token through a specific On-Behalf-Of exchange.
  - **2.2/V02/M01 exercise:** Use verified A authority for a legitimate downstream operation and an out-of-scope one.
  - **2.2/V02/M01 source requirements:** Tool:1.2.2.
  - **2.2/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Acquire a downstream token through a specific On-Behalf-Of exchange.
  - **2.2/V02/S01 source requirements:** Tool:1.2.2.
- **2.2/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Bare identity is not authentication; establish valid authority using the declared signed-token or authoritative opaque-token verifier. SHOULD: Require a cryptographically signed per-request user identity artifact.
  - **2.2/V03/M01 exercise:** Attempt protected access using only a bare user ID/email; complete the valid supported-format control.
  - **2.2/V03/M01 source requirements:** Tool:1.2.2.
  - **2.2/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Require a cryptographically signed per-request user identity artifact.
  - **2.2/V03/S01 source requirements:** Tool:1.2.2.
- **2.2/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Reject invalid authority in the supported format before protected access; properly verified opaque tokens need not decode as JWTs. SHOULD: Support dedicated signed identity assertions in addition to ordinary verified grants.
  - **2.2/V04/M01 exercise:** For signed-token support, submit missing signatures/alg:none; for opaque support, submit inactive/mismatched introspection authority.
  - **2.2/V04/M01 source requirements:** Tool:1.2.2.
  - **2.2/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Support dedicated signed identity assertions in addition to ordinary verified grants.
  - **2.2/V04/S01 source requirements:** Tool:1.2.2.
- **2.2/V05 — BASELINE_GATE:** MUST: Tampered or invalid required authority cannot produce protected output or side effects.
  - **2.2/V05/M01 exercise:** Alter a supported signed credential payload or opaque credential/introspection context.
  - **2.2/V05/M01 source requirements:** Tool:1.2.2.
- **2.2/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: Preserve correct user/resource/audience scope on downstream access without ambient service-credential substitution. SHOULD: Mint a specific user-scoped exchanged token for downstream requests.
  - **2.2/V06/M01 exercise:** Capture actual downstream authority and test foreign-user/resource access.
  - **2.2/V06/M01 source requirements:** Tool:1.2.2.
  - **2.2/V06/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Mint a specific user-scoped exchanged token for downstream requests.
  - **2.2/V06/S01 source requirements:** Tool:1.2.2.

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

<!-- assessment-context:2.3 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool metadata/auth component; Tool confirmation component when implemented
- **Applicability:** Applicable MCP operation annotations and Tool authorization. Actual Agent HITL is assessed under the Agent standard, not credited to the Tool.
- **Setup and positive/negative controls:** Compare declared reads/destructive operations with mock effects. For implemented Tool confirmation, exercise valid approval, disabling attempts, wrong user/account/recipient/parameters, expiry, reuse and fully enumerated versus altered batches.
- **Observe:** Observe metadata honesty and Tool authorization independently; separately record implemented Tool UI/challenges, approval binding and effects.
<!-- /assessment-context:2.3 -->

- **2.3/V01 — ADVISORY:** SHOULD: The code should consistently enforce an elicitation or confirmation flow prior to executing sensitive or state-changing actions.
  - **2.3/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The code should consistently enforce an elicitation or confirmation flow prior to executing sensitive or state-changing actions.
  - **2.3/V01/S01 source requirements:** Tool:2.1.1.
- **2.3/V02 — ADVISORY:** SHOULD: Configuration logic should lock confirmation prompts, preventing unprivileged users from disabling them.
  - **2.3/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Configuration logic should lock confirmation prompts, preventing unprivileged users from disabling them.
  - **2.3/V02/S01 source requirements:** Tool:2.1.1.
- **2.3/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Accurately disclose purpose/material effects and supply truthful applicable readOnlyHint/destructiveHint; do not represent writes as reads. SHOULD: Implement a clear Tool-owned confirmation UI articulating the full action/security implications.
  - **2.3/V03/M01 exercise:** Compare metadata/schema and implemented confirmation text with mock read/destructive effects.
  - **2.3/V03/M01 source requirements:** Tool:2.1.1.
  - **2.3/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Implement a clear Tool-owned confirmation UI articulating the full action/security implications.
  - **2.3/V03/S01 source requirements:** Tool:2.1.1.
- **2.3/V04 — ADVISORY:** SHOULD: Each Tool-controlled confirmation challenge or artifact is bound to the authenticated user and complete action and cannot be used outside its validity period or for more than one execution. A bounded batch qualifies as one action only when it is completely enumerated.
  - **2.3/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Each Tool-controlled confirmation challenge or artifact is bound to the authenticated user and complete action and cannot be used outside its validity period or for more than one execution. A bounded batch qualifies as one action only when it is completely enumerated.
  - **2.3/V04/S01 source requirements:** Tool:2.1.1.
- **2.3/V05 — ADVISORY:** SHOULD: The server should automatically halt execution and request explicit authorization when high-risk tools are triggered without out-of-band consent.
  - **2.3/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server should automatically halt execution and request explicit authorization when high-risk tools are triggered without out-of-band consent.
  - **2.3/V05/S01 source requirements:** Tool:2.1.1.
- **2.3/V06 — ADVISORY:** SHOULD: The system should explicitly reject unprivileged user attempts to disable confirmation prompt settings.
  - **2.3/V06/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The system should explicitly reject unprivileged user attempts to disable confirmation prompt settings.
  - **2.3/V06/S01 source requirements:** Tool:2.1.1.
- **2.3/V07 — ADVISORY:** SHOULD: The Tool should not execute a Sensitive Action on an Agent-supplied "consent obtained" claim alone; it should request server-side confirmation or fail closed when it cannot establish that the user confirmed the specific action.
  - **2.3/V07/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The Tool should not execute a Sensitive Action on an Agent-supplied "consent obtained" claim alone; it should request server-side confirmation or fail closed when it cannot establish that the user confirmed the specific action.
  - **2.3/V07/S01 source requirements:** Tool:2.1.1.
- **2.3/V08 — ADVISORY:** SHOULD: The Tool should reject expired, consumed, mismatched, and replayed confirmations before the Sensitive Action occurs.
  - **2.3/V08/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The Tool should reject expired, consumed, mismatched, and replayed confirmations before the Sensitive Action occurs.
  - **2.3/V08/S01 source requirements:** Tool:2.1.1.

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

<!-- assessment-context:2.4 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool trusted authorization layer
- **Applicability:** Applicable user/resource/object/attribute permissions and documented necessary functionality.
- **Setup and positive/negative controls:** Compare documented operational needs with requested IAM/OAuth scopes. Exercise authorized read/write and disallowed write/resource/attribute access with least-privilege credentials.
- **Observe:** Capture requested privileges and authorization decisions before protected data or side effects; a fixed scope taxonomy is not required.
<!-- /assessment-context:2.4 -->

- **2.4/V01 — BASELINE_GATE:** MUST: Enforce least privilege and necessary functionality under the applicable published permission criteria.
  - **2.4/V01/M01 exercise:** Compare requested IAM/RBAC/OAuth privileges with documented necessary operations; attempt unauthorized access.
  - **2.4/V01/M01 source requirements:** Tool:2.4.1.
- **2.4/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Excess privilege cannot bypass the applicable trusted-layer user/resource restrictions or necessary-functionality criteria. SHOULD: Adopt fine-grained scope definitions avoiding administrative/wildcard grants where practicable.
  - **2.4/V02/M01 exercise:** Inspect broad/wildcard privileges and execute allowed versus unauthorized resource/action controls.
  - **2.4/V02/M01 source requirements:** Tool:2.4.1.
  - **2.4/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Adopt fine-grained scope definitions avoiding administrative/wildcard grants where practicable.
  - **2.4/V02/S01 source requirements:** Tool:2.4.1.
- **2.4/V03 — BASELINE_GATE:** MUST: Deny operations outside the actual authorized scope before side effects.
  - **2.4/V03/M01 exercise:** Attempt a write with read-only authority.
  - **2.4/V03/M01 source requirements:** Tool:2.4.1.
- **2.4/V04 — BASELINE_GATE:** MUST: Deny unauthorized resource-level operations without protected data or effects.
  - **2.4/V04/M01 exercise:** Attempt an unauthorized object/attribute operation and then a valid authorized one.
  - **2.4/V04/M01 source requirements:** Tool:2.4.1.

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

<!-- assessment-context:2.5 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool exposed dispatch/validation/authorization layer
- **Applicability:** Every reachable protected execution path; schema constraints apply as declared, including additionalProperties semantics.
- **Setup and positive/negative controls:** Inventory advertised functions and reachable MCP/HTTP/alternate dispatch paths. Send a valid request and wrong types, boundary values, extra fields, undeclared operations and missing/wrong authority to each distinct enforcement path.
- **Observe:** Record route inventory, observed read/write behavior, validation/auth decisions and side effects. Any sampling needs evidence of shared enforcement and a recorded rationale.
<!-- /assessment-context:2.5 -->

- **2.5/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Exposed behavior and metadata are truthful; read/write separation and authorization/validation apply to reachable protected operations. SHOULD: Maintain an exhaustive export-to-manifest inventory.
  - **2.5/V01/M01 exercise:** Compare advertised functions with observed reachable dispatch operations and material effects.
  - **2.5/V01/M01 source requirements:** Tool:TG-2.5.
  - **2.5/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Maintain an exhaustive export-to-manifest inventory.
  - **2.5/V01/S01 source requirements:** Tool:TG-2.5.
- **2.5/V02 — BASELINE_GATE:** MUST: Enforce the declared types/constraints server-side before protected execution; valid permitted values remain admissible.
  - **2.5/V02/M01 exercise:** Send valid values, wrong types and boundary violations against each declared schema constraint.
  - **2.5/V02/M01 source requirements:** Tool:TG-2.5.
- **2.5/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: No reachable protected execution path bypasses applicable validation or authorization. SHOULD: Publish an exhaustive route-to-codepath/enforcement manifest.
  - **2.5/V03/M01 exercise:** Enumerate advertised and alternate reachable dispatch paths and send invalid/unauthorized calls to distinct enforcement paths.
  - **2.5/V03/M01 source requirements:** Tool:TG-2.5.
  - **2.5/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Publish an exhaustive route-to-codepath/enforcement manifest.
  - **2.5/V03/S01 source requirements:** Tool:TG-2.5.
- **2.5/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: An undeclared path cannot bypass truthful behavior, read/write separation or protected validation/authorization; a legitimate separately exposed API is judged by its actual scope. SHOULD: Reject every operation missing from one exhaustive Tool manifest.
  - **2.5/V04/M01 exercise:** Invoke an undeclared operation and a valid declared operation.
  - **2.5/V04/M01 source requirements:** Tool:TG-2.5.
  - **2.5/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Reject every operation missing from one exhaustive Tool manifest.
  - **2.5/V04/S01 source requirements:** Tool:TG-2.5.
- **2.5/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: Reject declared constraint violations, including extra fields when additionalProperties:false; do not reject permitted extra fields solely by a global ban. SHOULD: Reject all additional fields even where a schema permits them.
  - **2.5/V05/M01 exercise:** Send wrong types/out-of-range values and extra fields to schemas that permit versus forbid additional properties.
  - **2.5/V05/M01 source requirements:** Tool:TG-2.5.
  - **2.5/V05/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Reject all additional fields even where a schema permits them.
  - **2.5/V05/S01 source requirements:** Tool:TG-2.5.
- **2.5/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: Every reachable protected route enforces its applicable security outcome; sampled paths need recorded evidence of shared enforcement and a justified coverage rationale. SHOULD: Provide comprehensive codepath-parity evidence and exhaustive route manifests.
  - **2.5/V06/M01 exercise:** Repeat the same invalid/unauthorized probe on each distinct reachable enforcement path; include valid controls.
  - **2.5/V06/M01 source requirements:** Tool:TG-2.5.
  - **2.5/V06/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Provide comprehensive codepath-parity evidence and exhaustive route manifests.
  - **2.5/V06/S01 source requirements:** Tool:TG-2.5.

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

<!-- assessment-context:2.6 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool-owned downstream client and any owned receiving verifier
- **Applicability:** User-behalf downstream requests to a resource distinct from the inbound audience. External receiving-verifier duties are dependency evidence, not Tool-owned passes.
- **Setup and positive/negative controls:** Use separate inbound and downstream audiences and a valid resource-scoped grant. Capture downstream credentials and attempt cross-audience replay at the owned verifier if present; exercise the declared exchange or equivalent authorization method.
- **Observe:** Observe actual token audience, user/grant scope and protected downstream effects; per-request minting and a specific RFC exchange are enhancements.
<!-- /assessment-context:2.6 -->

- **2.6/V01 — BASELINE_GATE:** MUST: Never pass the inbound token to a different resource audience.
  - **2.6/V01/M01 exercise:** Capture a downstream request to an audience different from the inbound MCP audience.
  - **2.6/V01/M01 source requirements:** Tool:1.2.3.
- **2.6/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Use separately authorized resource/audience-scoped credentials preserving the user's boundary. SHOULD: Use RFC 8693 or a specific OBO exchange architecture.
  - **2.6/V02/M01 exercise:** Exercise the declared downstream authorization method and an unauthorized resource control.
  - **2.6/V02/M01 source requirements:** Tool:1.2.3.
  - **2.6/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Use RFC 8693 or a specific OBO exchange architecture.
  - **2.6/V02/S01 source requirements:** Tool:1.2.3.
- **2.6/V03 — ADVISORY:** SHOULD: Downstream tokens are short-lived and sender-constrained for remote/high-value deployments.
  - **2.6/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Downstream tokens are short-lived and sender-constrained for remote/high-value deployments.
  - **2.6/V03/S01 source requirements:** Tool:1.2.3.
- **2.6/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: The downstream credential is independently authorized for that resource and user/grant; it cannot be a cross-audience inbound token. SHOULD: Mint a freshly exchanged downstream token per request.
  - **2.6/V04/M01 exercise:** Capture repeated legitimate downstream requests and compare inbound/downstream audiences.
  - **2.6/V04/M01 source requirements:** Tool:1.2.3.
  - **2.6/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Mint a freshly exchanged downstream token per request.
  - **2.6/V04/S01 source requirements:** Tool:1.2.3.
- **2.6/V05 — BASELINE_GATE:** MUST: An owned receiving verifier rejects cross-audience authority before protected access. External verifier behavior is dependency evidence; Tool client audience preservation is assessed in V01/V02/V04.
  - **2.6/V05/M01 exercise:** Present the downstream credential to a different audience at a Tool-owned receiving verifier, when present; otherwise record the external verifier as a dependency.
  - **2.6/V05/M01 source requirements:** Tool:1.2.3.

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

<!-- assessment-context:2.7 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool independent-confirmation component, when implemented
- **Applicability:** Optional independent-channel confirmation for declared highest-risk actions; Agent HITL is assessed separately.
- **Setup and positive/negative controls:** Use a mock action counter and registered independent channel. Attempt Agent-only forged approval, wrong account/operation/recipient/parameters, expired/consumed approval and valid independent approval.
- **Observe:** Observe channel independence, binding and effects; absence of OOB alone is advisory, with actual authorization breaches classified independently.
<!-- /assessment-context:2.7 -->

- **2.7/V01 — ADVISORY:** SHOULD: The highest-risk operations should be explicitly identified.
  - **2.7/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The highest-risk operations should be explicitly identified.
  - **2.7/V01/S01 source requirements:** Tool:2.1.2.
- **2.7/V02 — ADVISORY:** SHOULD: Confirmation for those operations should be routed over a channel independent of the Agent (should for remote/high-value deployments), with a fail-closed fallback to §2.3 rather than Agent-relayed consent.
  - **2.7/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Confirmation for those operations should be routed over a channel independent of the Agent (should for remote/high-value deployments), with a fail-closed fallback to §2.3 rather than Agent-relayed consent.
  - **2.7/V02/S01 source requirements:** Tool:2.1.2.
- **2.7/V03 — ADVISORY:** SHOULD: Out-of-band confirmation should be bound to the authenticated user and complete action and should expire or be consumed as specified.
  - **2.7/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Out-of-band confirmation should be bound to the authenticated user and complete action and should expire or be consumed as specified.
  - **2.7/V03/S01 source requirements:** Tool:2.1.2.
- **2.7/V04 — ADVISORY:** SHOULD: The tool should not execute a highest-risk action approved only through the Agent channel.
  - **2.7/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The tool should not execute a highest-risk action approved only through the Agent channel.
  - **2.7/V04/S01 source requirements:** Tool:2.1.2.
- **2.7/V05 — ADVISORY:** SHOULD: The action should execute only after confirmation over the independent channel.
  - **2.7/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The action should execute only after confirmation over the independent channel.
  - **2.7/V05/S01 source requirements:** Tool:2.1.2.
- **2.7/V06 — ADVISORY:** SHOULD: Expired, consumed, mismatched, or replayed out-of-band confirmations should be rejected before execution.
  - **2.7/V06/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Expired, consumed, mismatched, or replayed out-of-band confirmations should be rejected before execution.
  - **2.7/V06/S01 source requirements:** Tool:2.1.2.

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

<!-- assessment-context:3.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool secret storage/runtime component
- **Applicability:** Server-side secrets, public packages/metadata and secret access; published storage/access-policy/logged-OR-monitored alternatives remain.
- **Setup and positive/negative controls:** Use mock secrets in secure storage and package/config fixtures. Exercise authorized and unauthorized readers, client initialization, process-environment exposure and declared rotation/revocation procedures.
- **Observe:** Observe storage protection, public exposure, access policy and logged or monitored access without secret values.
<!-- /assessment-context:3.1 -->

- **3.1/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Secrets remain confidential under documented access policy and cryptographically secure storage; public artifacts cannot expose them. SHOULD: Eliminate every embedded credential literal through externalized runtime retrieval.
  - **3.1/V01/M01 exercise:** Inspect distributed/public package/config artifacts and actual secret storage/access.
  - **3.1/V01/M01 source requirements:** Tool:1.3.1.
  - **3.1/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Eliminate every embedded credential literal through externalized runtime retrieval.
  - **3.1/V01/S01 source requirements:** Tool:1.3.1.
- **3.1/V02 — ADVISORY:** SHOULD: External service clients should exclusively initialize using environment variables or dedicated configuration providers.
  - **3.1/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: External service clients should exclusively initialize using environment variables or dedicated configuration providers.
  - **3.1/V02/S01 source requirements:** Tool:1.3.1.
- **3.1/V03 — ADVISORY:** SHOULD: No credentials should be supplied as string literals.
  - **3.1/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: No credentials should be supplied as string literals.
  - **3.1/V03/S01 source requirements:** Tool:1.3.1.
- **3.1/V04 — ADVISORY:** SHOULD: Documented policies for secret rotation should be present and verified.
  - **3.1/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Documented policies for secret rotation should be present and verified.
  - **3.1/V04/S01 source requirements:** Tool:1.3.1.
- **3.1/V05 — ADVISORY:** SHOULD: Breach response protocols for immediate secret revocation should be defined.
  - **3.1/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Breach response protocols for immediate secret revocation should be defined.
  - **3.1/V05/S01 source requirements:** Tool:1.3.1.
- **3.1/V06 — ADVISORY:** SHOULD: The server successfully accesses sensitive secrets from authorized environment variables or Secret Management Services.
  - **3.1/V06/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server successfully accesses sensitive secrets from authorized environment variables or Secret Management Services.
  - **3.1/V06/S01 source requirements:** Tool:1.3.1.
- **3.1/V07 — MIXED_BASELINE_AND_ADVISORY:** MUST: Protect server-side secrets with appropriate access controls and secure storage; access is logged OR monitored without secret values. SHOULD: Isolate process environments through dedicated hardened runtime mechanisms.
  - **3.1/V07/M01 exercise:** Attempt unauthorized reads of the mock secret store/process environment and exercise authorized access.
  - **3.1/V07/M01 source requirements:** Tool:1.3.1.
  - **3.1/V07/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Isolate process environments through dedicated hardened runtime mechanisms.
  - **3.1/V07/S01 source requirements:** Tool:1.3.1.

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

<!-- assessment-context:3.2 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool logging and telemetry component
- **Applicability:** Credential/payment log prohibition, exact permitted session-hash representation and necessary task-content boundary.
- **Setup and positive/negative controls:** Seed credentials, payment details, session tokens and authorized task content in headers, objects and errors. Exercise success and failure paths; inspect applicable stdout/stderr/file/telemetry sinks and supported filters.
- **Observe:** Search captured sinks for seeded values, forbidden reversible representations and extraneous conversation content; record broad masking mechanisms separately.
<!-- /assessment-context:3.2 -->

- **3.2/V01 — ADVISORY:** SHOULD: All logging functions should be identified.
  - **3.2/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: All logging functions should be identified.
  - **3.2/V01/S01 source requirements:** Tool:1.6.1.
- **3.2/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Logged objects contain no prohibited credential/payment values or task-extraneous conversation content. SHOULD: Intercept every full object/header through an explicit processing/redaction layer.
  - **3.2/V02/M01 exercise:** Log header/request objects containing seeded credentials/payment data on success and failure paths.
  - **3.2/V02/M01 source requirements:** Tool:1.6.1.
  - **3.2/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Intercept every full object/header through an explicit processing/redaction layer.
  - **3.2/V02/S01 source requirements:** Tool:1.6.1.
- **3.2/V03 — ADVISORY:** SHOULD: A dedicated redaction utility or middleware should intercept objects prior to logging.
  - **3.2/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: A dedicated redaction utility or middleware should intercept objects prior to logging.
  - **3.2/V03/S01 source requirements:** Tool:1.6.1.
- **3.2/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: No prohibited credential/payment values are logged; session-token representation meets the exact irreversible-hash exception. SHOULD: Mask every broadly sensitive parameter/PII category with a centralized detector.
  - **3.2/V04/M01 exercise:** Submit sensitive keys/parameters and inspect all applicable log sinks.
  - **3.2/V04/M01 source requirements:** Tool:1.6.1.
  - **3.2/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Mask every broadly sensitive parameter/PII category with a centralized detector.
  - **3.2/V04/S01 source requirements:** Tool:1.6.1.
- **3.2/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: Required log-content restrictions hold at the actual sinks, independently of masking method. SHOULD: Automatically redact all broader sensitive-token/parameter categories across sinks.
  - **3.2/V05/M01 exercise:** Exercise normal, error and verbose logging with seeded secret/payment/session values and permitted task data.
  - **3.2/V05/M01 source requirements:** Tool:1.6.1.
  - **3.2/V05/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Automatically redact all broader sensitive-token/parameter categories across sinks.
  - **3.2/V05/S01 source requirements:** Tool:1.6.1.

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

<!-- assessment-context:3.3 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool session-token storage/transport/logging component
- **Applicability:** Implemented session model and applicable published cookie/browser-storage/TLS/storage exceptions.
- **Setup and positive/negative controls:** Use mock active/expired tokens; inspect protected transport, logs, browser storage/cookies when applicable and token files/config. Include the exact permitted static-secret or irreversible-log-hash alternative if applicable.
- **Observe:** Observe token confidentiality, actual permissions and applicable lifetime/invalidation/transport criteria; argv or preferred carriers are enhancements.
<!-- /assessment-context:3.3 -->

- **3.3/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Session credentials remain confidential and meet applicable published storage/lifetime criteria and exact exceptions. SHOULD: Remove every token-format literal through externalized runtime retrieval.
  - **3.3/V01/M01 exercise:** Inspect public/distributed artifacts and token storage using the applicable documented static-secret exception control.
  - **3.3/V01/M01 source requirements:** Tool:1.6.2.
  - **3.3/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Remove every token-format literal through externalized runtime retrieval.
  - **3.3/V01/S01 source requirements:** Tool:1.6.2.
- **3.3/V02 — BASELINE_GATE:** MUST: Never log credentials/payment details; session tokens are represented only by the exact permitted irreversible hash.
  - **3.3/V02/M01 exercise:** Log session/context objects containing a seeded active token.
  - **3.3/V02/M01 source requirements:** Tool:1.6.2.
- **3.3/V03 — ADVISORY:** SHOULD: The server should not accept credentials via command-line arguments (argv).
  - **3.3/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server should not accept credentials via command-line arguments (argv).
  - **3.3/V03/S01 source requirements:** Tool:1.6.2.
- **3.3/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Meet applicable TLS, URL, cookie/browser-storage and selected MCP bearer-carrier criteria with their published exceptions; required confidentiality cannot be bypassed. SHOULD: Harden additional credential carriers and eliminate argv/temp-file exposure beyond mandatory carrier rules.
  - **3.3/V04/M01 exercise:** Capture token traffic, including URL/cookie/browser carriers where applicable.
  - **3.3/V04/M01 source requirements:** Tool:1.6.2.
  - **3.3/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Harden additional credential carriers and eliminate argv/temp-file exposure beyond mandatory carrier rules.
  - **3.3/V04/S01 source requirements:** Tool:1.6.2.
- **3.3/V05 — BASELINE_GATE:** MUST: No plaintext/reversibly represented session token appears in logs; only the exact permitted irreversible hash is admitted.
  - **3.3/V05/M01 exercise:** Enable verbose logging and search for seeded plaintext/reversible session credentials.
  - **3.3/V05/M01 source requirements:** Tool:1.6.2.
- **3.3/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: Credential storage/access meets applicable published confidentiality/access-control criteria; world-readable secret exposure fails. SHOULD: Avoid all temporary-file and environment-file token storage even when properly protected.
  - **3.3/V06/M01 exercise:** Attempt unauthorized access to mock tokens in temporary/config/environment files.
  - **3.3/V06/M01 source requirements:** Tool:1.6.2.
  - **3.3/V06/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Avoid all temporary-file and environment-file token storage even when properly protected.
  - **3.3/V06/S01 source requirements:** Tool:1.6.2.

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

<!-- assessment-context:3.4 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool API, secret/config storage and owned unsafe sinks
- **Applicability:** Unauthorized operational secret/resource access, mutation and task-extraneous output.
- **Setup and positive/negative controls:** Seed mock internal keys and protected configuration. Probe environment dumps, traversal, reflection and overwrites with controlled payloads; follow with a valid benign request.
- **Observe:** Observe protected responses, secret/config state, unauthorized effects and benign recovery; no real operational credential is needed in the fixture.
<!-- /assessment-context:3.4 -->

- **3.4/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent unauthorized operational-secret disclosure/mutation and preserve appropriate secure secret storage/access. SHOULD: Maintain exhaustive secret-lifecycle and loading-path analysis.
  - **3.4/V01/M01 exercise:** Exercise authorized secret access and attempted unauthorized credential reads/mutations through exposed paths.
  - **3.4/V01/M01 source requirements:** Tool:5.1.1.
  - **3.4/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Maintain exhaustive secret-lifecycle and loading-path analysis.
  - **3.4/V01/S01 source requirements:** Tool:5.1.1.
- **3.4/V02 — ADVISORY:** SHOULD: No hardcoded or mock credentials should exist within source code and config snippets.
  - **3.4/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: No hardcoded or mock credentials should exist within source code and config snippets.
  - **3.4/V02/S01 source requirements:** Tool:5.1.1.
- **3.4/V03 — ADVISORY:** SHOULD: Secrets should be isolated within memory-safe buffers.
  - **3.4/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Secrets should be isolated within memory-safe buffers.
  - **3.4/V03/S01 source requirements:** Tool:5.1.1.
- **3.4/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Attacker-controlled paths cannot produce unauthorized secret/file access under the applicable published file controls. SHOULD: Eliminate all dynamic path/reflection control through prescribed path-validation patterns.
  - **3.4/V04/M01 exercise:** Supply traversal/dynamic paths targeting seeded operational secrets and an authorized path control.
  - **3.4/V04/M01 source requirements:** Tool:5.1.1.
  - **3.4/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Eliminate all dynamic path/reflection control through prescribed path-validation patterns.
  - **3.4/V04/S01 source requirements:** Tool:5.1.1.
- **3.4/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: Untrusted input cannot cause applicable unauthorized secret access or injection effects. SHOULD: Perform comprehensive static taint/reflection analysis and layered unsafe-sink blocking.
  - **3.4/V05/M01 exercise:** Send controlled reflection/code/path probes to each actual sink.
  - **3.4/V05/M01 source requirements:** Tool:5.1.1.
  - **3.4/V05/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Perform comprehensive static taint/reflection analysis and layered unsafe-sink blocking.
  - **3.4/V05/S01 source requirements:** Tool:5.1.1.
- **3.4/V06 — BASELINE_GATE:** MUST: Unauthorized operational keys and protected host files are not returned or exposed.
  - **3.4/V06/M01 exercise:** Request an environment dump and traverse to the seeded internal secret file.
  - **3.4/V06/M01 source requirements:** Tool:5.1.1.
- **3.4/V07 — BASELINE_GATE:** MUST: No internally held operational secret is disclosed through unauthorized or task-extraneous output.
  - **3.4/V07/M01 exercise:** Stress exposed APIs with authorized controlled secret-extraction probes.
  - **3.4/V07/M01 source requirements:** Tool:5.1.1.
- **3.4/V08 — MIXED_BASELINE_AND_ADVISORY:** MUST: Unauthorized configuration/resource mutation is prevented; protected state retains its authorized contents. SHOULD: Maintain availability and benign recovery under broader exhaustion/overwrite stress through runtime hardening.
  - **3.4/V08/M01 exercise:** Attempt unauthorized configuration overwrite and then a benign authorized request.
  - **3.4/V08/M01 source requirements:** Tool:5.1.1.
  - **3.4/V08/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Maintain availability and benign recovery under broader exhaustion/overwrite stress through runtime hardening.
  - **3.4/V08/S01 source requirements:** Tool:5.1.1.

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

<!-- assessment-context:3.5 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool response authorization/minimization component
- **Applicability:** Unauthorized or task-extraneous personal data output; legitimate purpose-required authorized output is permitted.
- **Setup and positive/negative controls:** Seed synthetic email, phone, national-ID and payment-pattern records. Request one purpose-required field under valid authority, then request unrelated fields/other-user records or use missing/wrong scope. Exercise implemented broad detectors separately.
- **Observe:** Observe returned fields, user/resource authorization and documented purpose; authorized private output is the positive control, not automatically a leak.
<!-- /assessment-context:3.5 -->

- **3.5/V01 — ADVISORY:** SHOULD: Output response handlers should utilize robust detection logic for all should PII categories and apply redaction before returning data.
  - **3.5/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Output response handlers should utilize robust detection logic for all should PII categories and apply redaction before returning data.
  - **3.5/V01/S01 source requirements:** Tool:TG-3.5.
- **3.5/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent unauthorized/task-extraneous personal output while permitting purpose-required authorized data; protected credentials/payment logs remain separately constrained. SHOULD: Detect and redact every seeded PII pattern with a universal detector beyond required authorization/purpose boundaries.
  - **3.5/V02/M01 exercise:** Request purpose-required synthetic private data with valid authority, then unrelated/foreign data or wrong scope.
  - **3.5/V02/M01 source requirements:** Tool:TG-3.5.
  - **3.5/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Detect and redact every seeded PII pattern with a universal detector beyond required authorization/purpose boundaries.
  - **3.5/V02/S01 source requirements:** Tool:TG-3.5.
- **3.5/V03 — BASELINE_GATE:** MUST: Private output is limited to the authorized user/resource and necessary purpose; unauthorized/out-of-scope records are not returned.
  - **3.5/V03/M01 exercise:** Repeat a documented purpose-required private-data request with valid, wrong and missing authority/scope.
  - **3.5/V03/M01 source requirements:** Tool:TG-3.5.

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

<!-- assessment-context:3.6 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool request/query/response component
- **Applicability:** Task/function-necessary processing and output; no covert Agent-history reconstruction.
- **Setup and positive/negative controls:** Define a narrow authorized task, such as rewards balance, with seeded unrelated identity/history fields. Inspect interface/query fields and execute the task with surplus context available.
- **Observe:** Observe requested/processed/returned fields and any conversation-profile storage relative to the documented necessary purpose.
<!-- /assessment-context:3.6 -->

- **3.6/V01 — BASELINE_GATE:** MUST: Collect/process/return only task/function-necessary content without covert full-history reconstruction.
  - **3.6/V01/M01 exercise:** Compare declared input/query/output fields with the narrow authorized task and available surplus history.
  - **3.6/V01/M01 source requirements:** Tool:9.1.1.
- **3.6/V02 — BASELINE_GATE:** MUST: Return only necessary authorized task data; do not covertly collect or expose unrelated fields/history.
  - **3.6/V02/M01 exercise:** Request rewards points while unrelated identity/history fields are available.
  - **3.6/V02/M01 source requirements:** Tool:9.1.1.

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

<!-- assessment-context:3.7 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool logging/telemetry component
- **Applicability:** Published credential/payment/session-hash and necessary task-content restrictions.
- **Setup and positive/negative controls:** Seed mock secrets, user identifiers, prompts and API responses. Exercise ordinary/error/verbose paths and collect persistent logs/telemetry; include a permitted irreversible session hash.
- **Observe:** Inspect sink contents against mandatory categories and task necessity; distinguish broader PII masking and central filter architecture.
<!-- /assessment-context:3.7 -->

- **3.7/V01 — ADVISORY:** SHOULD: Variables indicating sensitive data should be clearly identifiable within the codebase.
  - **3.7/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Variables indicating sensitive data should be clearly identifiable within the codebase.
  - **3.7/V01/S01 source requirements:** Tool:12.2.2.
- **3.7/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Mandatory forbidden values do not reach logs; permitted session representation is limited to the exact irreversible-hash exception. SHOULD: Route every broadly sensitive variable through prescribed centralized sanitization.
  - **3.7/V02/M01 exercise:** Trace seeded credential/payment/session values into actual log sinks.
  - **3.7/V02/M01 source requirements:** Tool:12.2.2.
  - **3.7/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Route every broadly sensitive variable through prescribed centralized sanitization.
  - **3.7/V02/S01 source requirements:** Tool:12.2.2.
- **3.7/V03 — ADVISORY:** SHOULD: Centralized redaction middleware should be present and capable of masking inputs destined for the logging layer.
  - **3.7/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Centralized redaction middleware should be present and capable of masking inputs destined for the logging layer.
  - **3.7/V03/S01 source requirements:** Tool:12.2.2.
- **3.7/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Logged content excludes prohibited values and task-extraneous conversation collection. SHOULD: Apply explicit broad filters before every prompt/response logging call.
  - **3.7/V04/M01 exercise:** Exercise logging of raw prompts/API responses containing seeded prohibited values and surplus conversation content.
  - **3.7/V04/M01 source requirements:** Tool:12.2.2.
  - **3.7/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Apply explicit broad filters before every prompt/response logging call.
  - **3.7/V04/S01 source requirements:** Tool:12.2.2.
- **3.7/V05 — ADVISORY:** SHOULD: Specific User IDs or unique PII identifiers should not be written to logs in plain text formats.
  - **3.7/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Specific User IDs or unique PII identifiers should not be written to logs in plain text formats.
  - **3.7/V05/S01 source requirements:** Tool:12.2.2.
- **3.7/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: All actual persistent sinks meet mandatory credential/payment/session-hash and task-content restrictions. SHOULD: Mask all broader PII/proprietary categories with central automated filters.
  - **3.7/V06/M01 exercise:** Generate seeded sensitive data on success/error paths and inspect persistent telemetry/log output.
  - **3.7/V06/M01 source requirements:** Tool:12.2.2.
  - **3.7/V06/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Mask all broader PII/proprietary categories with central automated filters.
  - **3.7/V06/S01 source requirements:** Tool:12.2.2.

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

<!-- assessment-context:4.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool-owned rendered-output/XML component, when applicable
- **Applicability:** Applicable contextual XSS/XML controls. Inert data is distinguished from executable/rendered sinks; actual auth/admin pages retain applicable controls.
- **Setup and positive/negative controls:** Use benign markup/code text plus inert XSS and XML-parser probes in the actual rendering/parsing context. Exercise JSON/schema handling only when that enhancement is implemented.
- **Observe:** Observe executable browser/parser effects and returned data at the identified sink; no global metacharacter stripping is required for inert content.
<!-- /assessment-context:4.1 -->

- **4.1/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Apply contextual XSS/XML defenses preventing the corresponding executable/parser vulnerability. SHOULD: Encode/escape every output through a universal handler even where content is inert.
  - **4.1/V01/M01 exercise:** Render/parse benign and malicious fixture content at the actual applicable output sink.
  - **4.1/V01/M01 source requirements:** Tool:TG-4.1.
  - **4.1/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Encode/escape every output through a universal handler even where content is inert.
  - **4.1/V01/S01 source requirements:** Tool:TG-4.1.
- **4.1/V02 — ADVISORY:** SHOULD: Structured outputs should be successfully validated against a schema before transmission.
  - **4.1/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Structured outputs should be successfully validated against a schema before transmission.
  - **4.1/V02/S01 source requirements:** Tool:TG-4.1.
- **4.1/V03 — ADVISORY:** SHOULD: There should be no code paths returning raw, unvalidated strings.
  - **4.1/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: There should be no code paths returning raw, unvalidated strings.
  - **4.1/V03/S01 source requirements:** Tool:TG-4.1.
- **4.1/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent applicable XSS/XML effects at the actual sink; inert text need not lose all metacharacters. SHOULD: Strip every HTML/JavaScript/shell/SQL metacharacter across all outputs.
  - **4.1/V04/M01 exercise:** Send XSS/XML probes to applicable rendered/parser sinks and benign code/markup text to inert output.
  - **4.1/V04/M01 source requirements:** Tool:TG-4.1.
  - **4.1/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Strip every HTML/JavaScript/shell/SQL metacharacter across all outputs.
  - **4.1/V04/S01 source requirements:** Tool:TG-4.1.
- **4.1/V05 — ADVISORY:** SHOULD: The tool should successfully return a schema-compliant error when provided inputs producing malformed JSON.
  - **4.1/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The tool should successfully return a schema-compliant error when provided inputs producing malformed JSON.
  - **4.1/V05/S01 source requirements:** Tool:TG-4.1.

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

<!-- assessment-context:4.2 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool server-side validators and owned execution sinks
- **Applicability:** Each applicable published injection/XSS/SSRF/file outcome with necessary-functionality and exception conditions preserved.
- **Setup and positive/negative controls:** Use benign supported queries/commands and controlled injection, path, URL and malformed-argument probes for the actual sinks. Record which published control applies to each probe.
- **Observe:** Observe validation/neutralization before execution and canary/DB/file effects; a schema-only pass does not prove all injection controls.
<!-- /assessment-context:4.2 -->

- **4.2/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent applicable code/command injection under published necessary-functionality and sanitization/sandboxing conditions. SHOULD: Remove every eval/direct-shell execution sink through hardened APIs.
  - **4.2/V01/M01 exercise:** Exercise legitimate expected code/command functionality and controlled injection probes at actual sinks.
  - **4.2/V01/M01 source requirements:** Tool:3.1.1.
  - **4.2/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Remove every eval/direct-shell execution sink through hardened APIs.
  - **4.2/V01/S01 source requirements:** Tool:3.1.1.
- **4.2/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Untrusted input cannot alter unauthorized query/command semantics under the applicable published controls. SHOULD: Use parameterized APIs at every internal query/system-call boundary.
  - **4.2/V02/M01 exercise:** Send query/command injection payloads and benign values to implemented DB/system sinks.
  - **4.2/V02/M01 source requirements:** Tool:3.1.1.
  - **4.2/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Use parameterized APIs at every internal query/system-call boundary.
  - **4.2/V02/S01 source requirements:** Tool:3.1.1.
- **4.2/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Server-side validation/neutralization prevents each applicable published injection/access/file vulnerability before execution. SHOULD: Use exhaustive predefined static allowlists at every internal boundary.
  - **4.2/V03/M01 exercise:** Send malicious and valid arguments to each actual exposed validator/sink.
  - **4.2/V03/M01 source requirements:** Tool:3.1.1.
  - **4.2/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Use exhaustive predefined static allowlists at every internal boundary.
  - **4.2/V03/S01 source requirements:** Tool:3.1.1.
- **4.2/V04 — BASELINE_GATE:** MUST: Reject or neutralize the malicious command semantics before unauthorized underlying execution.
  - **4.2/V04/M01 exercise:** Send a controlled command-injection payload and valid literal/expected-functionality control.
  - **4.2/V04/M01 source requirements:** Tool:3.1.1.

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

<!-- assessment-context:4.3 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool-owned command/path/network sinks
- **Applicability:** Applicable code/command/path/SSRF outcomes and published allowed-destination conditions.
- **Setup and positive/negative controls:** Exercise legitimate commands/URLs, injected shell syntax and unauthorized file/network canaries. Review declared runtime/scanning/allowlist mechanisms when implemented.
- **Observe:** Observe actual commands, file access and destination requests; presence of eval/shell or absence of a scanner is not itself the mandatory verdict.
<!-- /assessment-context:4.3 -->

- **4.3/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent applicable unauthorized command/code execution; sink presence alone is not the verdict. SHOULD: Scan/remove every unsafe execution or shell-enabled subprocess pattern.
  - **4.3/V01/M01 exercise:** Probe actual command/code sinks with a controlled injection and inspect implemented scanners.
  - **4.3/V01/M01 source requirements:** Tool:8.4.1.
  - **4.3/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Scan/remove every unsafe execution or shell-enabled subprocess pattern.
  - **4.3/V01/S01 source requirements:** Tool:8.4.1.
- **4.3/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent applicable SSRF under the full published allowed-destination and necessary-functionality conditions. SHOULD: Check every dynamic URL against a prescribed static allowlist.
  - **4.3/V02/M01 exercise:** Request an authorized destination and controlled unauthorized internal/network canary.
  - **4.3/V02/M01 source requirements:** Tool:8.4.1.
  - **4.3/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Check every dynamic URL against a prescribed static allowlist.
  - **4.3/V02/S01 source requirements:** Tool:8.4.1.
- **4.3/V03 — BASELINE_GATE:** MUST: Prevent the unauthorized command or boundary bypass under applicable published injection conditions.
  - **4.3/V03/M01 exercise:** Inject shell syntax targeting an unauthorized command or host-resource canary.
  - **4.3/V03/M01 source requirements:** Tool:8.4.1.

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

<!-- assessment-context:4.4 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool output-size component, when implemented
- **Applicability:** Optional declared response-size limits; necessary-purpose data boundaries apply independently.
- **Setup and positive/negative controls:** Use responses just below, at and above the declared threshold, including a justified larger threshold. Exercise safe truncation, pagination or rejection with parseable outputs.
- **Observe:** Observe transmitted byte size, declared configuration and result completeness/error semantics; no universal 1 MB minimum gate is introduced.
<!-- /assessment-context:4.4 -->

- **4.4/V01 — ADVISORY:** SHOULD: The codebase should systematically intercept outbound responses to evaluate data size bounds before serialization or transmission.
  - **4.4/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The codebase should systematically intercept outbound responses to evaluate data size bounds before serialization or transmission.
  - **4.4/V01/S01 source requirements:** Tool:TG-4.4.
- **4.4/V02 — ADVISORY:** SHOULD: A maximum size constraint should be explicitly configurable, defaulting to 1 MB or less unless a larger threshold is documented and justified by the tool's specific use case.
  - **4.4/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: A maximum size constraint should be explicitly configurable, defaulting to 1 MB or less unless a larger threshold is documented and justified by the tool's specific use case.
  - **4.4/V02/S01 source requirements:** Tool:TG-4.4.
- **4.4/V03 — ADVISORY:** SHOULD: The implementation should contain valid code blocks that safely truncate, paginate, or reject data when a payload exceeds the defined threshold.
  - **4.4/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The implementation should contain valid code blocks that safely truncate, paginate, or reject data when a payload exceeds the defined threshold.
  - **4.4/V03/S01 source requirements:** Tool:TG-4.4.
- **4.4/V04 — ADVISORY:** SHOULD: The active system should successfully prevent oversized natural language or structured outputs from reaching the host by returning a validly truncated, paginated, or size-limit rejected error payload
  - **4.4/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The active system should successfully prevent oversized natural language or structured outputs from reaching the host by returning a validly truncated, paginated, or size-limit rejected error payload
  - **4.4/V04/S01 source requirements:** Tool:TG-4.4.

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

<!-- assessment-context:5.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool request/cache/runtime component
- **Applicability:** User/tenant isolation across reused state, caches, concurrent requests and logs.
- **Setup and positive/negative controls:** Seed private keywords/data for users A/B. Alternate and interleave requests on reused workers/caches, inspect scoped logs, and repeat after any implemented purge/restart.
- **Observe:** Observe user B responses/context/log access for unauthorized user A data; safely partitioned state and caches are admissible alternatives.
<!-- /assessment-context:5.1 -->

- **5.1/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Reused/global state cannot expose or mutate unauthorized other-user data. SHOULD: Confine all user data to request-local storage through a stateless architecture.
  - **5.1/V01/M01 exercise:** Interleave A/B requests across reused workers and caches with seeded private values.
  - **5.1/V01/M01 source requirements:** Tool:2.2.1, Tool:8.2.1.
  - **5.1/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Confine all user data to request-local storage through a stateless architecture.
  - **5.1/V01/S01 source requirements:** Tool:2.2.1, Tool:8.2.1.
- **5.1/V02 — ADVISORY:** SHOULD: There should be an explicit "Context Reset" or process recycling logic for different tenant contexts.
  - **5.1/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: There should be an explicit "Context Reset" or process recycling logic for different tenant contexts.
  - **5.1/V02/S01 source requirements:** Tool:2.2.1, Tool:8.2.1.
- **5.1/V03 — ADVISORY:** SHOULD: A unique Request ID should be initialized, passed to all internal sub-functions, and included in every structured log entry.
  - **5.1/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: A unique Request ID should be initialized, passed to all internal sub-functions, and included in every structured log entry.
  - **5.1/V03/S01 source requirements:** Tool:2.2.1, Tool:8.2.1.
- **5.1/V04 — BASELINE_GATE:** MUST: B cannot access unauthorized A data, existence-sensitive metadata or side effects.
  - **5.1/V04/M01 exercise:** Execute A then B requests and inspect B-accessible results/context/logs.
  - **5.1/V04/M01 source requirements:** Tool:2.2.1, Tool:8.2.1.
- **5.1/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: Request/log handling does not expose unauthorized cross-user data; mandatory log-content restrictions remain. SHOULD: Tag every log line with a unique request ID and keep a complete per-request correlation trail.
  - **5.1/V05/M01 exercise:** Interleave requests and inspect access-controlled logs for cross-user data and correlation fields.
  - **5.1/V05/M01 source requirements:** Tool:2.2.1, Tool:8.2.1.
  - **5.1/V05/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Tag every log line with a unique request ID and keep a complete per-request correlation trail.
  - **5.1/V05/S01 source requirements:** Tool:2.2.1, Tool:8.2.1.
- **5.1/V06 — ADVISORY:** SHOULD: The server should either restart or explicitly purge tenant-specific heap data after the completion of a request.
  - **5.1/V06/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server should either restart or explicitly purge tenant-specific heap data after the completion of a request.
  - **5.1/V06/S01 source requirements:** Tool:2.2.1, Tool:8.2.1.

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

<!-- assessment-context:5.2 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool-owned execution/file/network boundary
- **Applicability:** Applicable injection, traversal, SSRF and platform-boundary outcomes; prescribed sandbox architecture is recommended.
- **Setup and positive/negative controls:** Use valid allowed operations and controlled command, traversal and unauthorized-destination probes. Include a legitimate internal destination only if authorized under the applicable published conditions.
- **Observe:** Observe actual command/file/network effects and denied requests at the implemented boundary; do not treat all internal networking as categorically forbidden.
<!-- /assessment-context:5.2 -->

- **5.2/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent applicable unauthorized command execution or platform-boundary bypass. SHOULD: Use parameterized arguments and eliminate shell execution through prescribed sandbox hardening.
  - **5.2/V01/M01 exercise:** Exercise legitimate command functionality and controlled injection probes.
  - **5.2/V01/M01 source requirements:** Tool:2.2.3.
  - **5.2/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Use parameterized arguments and eliminate shell execution through prescribed sandbox hardening.
  - **5.2/V01/S01 source requirements:** Tool:2.2.3.
- **5.2/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent unauthorized traversal/file access under applicable published file controls. SHOULD: Apply normalization/canonicalization at every file-I/O boundary.
  - **5.2/V02/M01 exercise:** Send traversal paths to a seeded unauthorized host file and an allowed-file control.
  - **5.2/V02/M01 source requirements:** Tool:2.2.3.
  - **5.2/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Apply normalization/canonicalization at every file-I/O boundary.
  - **5.2/V02/S01 source requirements:** Tool:2.2.3.
- **5.2/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent applicable SSRF and unauthorized network access under the published allowlist/necessary-functionality conditions. SHOULD: Enforce a static destination allowlist for every dynamic URL.
  - **5.2/V03/M01 exercise:** Send legitimate authorized destinations and SSRF probes targeting unauthorized canaries.
  - **5.2/V03/M01 source requirements:** Tool:2.2.3.
  - **5.2/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Enforce a static destination allowlist for every dynamic URL.
  - **5.2/V03/S01 source requirements:** Tool:2.2.3.
- **5.2/V04 — BASELINE_GATE:** MUST: Reject or neutralize the malicious semantics before unauthorized command execution or boundary escape.
  - **5.2/V04/M01 exercise:** Inject command syntax that would create a controlled unauthorized side effect.
  - **5.2/V04/M01 source requirements:** Tool:2.2.3.
- **5.2/V05 — BASELINE_GATE:** MUST: Unauthorized host-file and operational-configuration access is denied before disclosure.
  - **5.2/V05/M01 exercise:** Attempt out-of-bounds traversal and read the seeded protected host file.
  - **5.2/V05/M01 source requirements:** Tool:2.2.3.
- **5.2/V06 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent applicable SSRF/unauthorized access; authorized internal services are judged by published conditions, not a blanket internal-network ban. SHOULD: Reject every destination absent from a prescribed static allowlist.
  - **5.2/V06/M01 exercise:** Request an unauthorized internal/domain canary and a legitimately authorized destination.
  - **5.2/V06/M01 source requirements:** Tool:2.2.3.
  - **5.2/V06/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Reject every destination absent from a prescribed static allowlist.
  - **5.2/V06/S01 source requirements:** Tool:2.2.3.

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

<!-- assessment-context:5.3 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool trusted tenant authorization layer
- **Applicability:** Unauthorized tenant data, existence metadata and effects across implemented stores/caches.
- **Setup and positive/negative controls:** Seed tenants A/B, verified A authority, a benign A request and attacker-supplied B identifiers/query filters. Exercise alternate handlers and cache reuse.
- **Observe:** Observe trusted tenant resolution and protected output/effects; per-query filters are one recommended design, not the only permitted architecture.
<!-- /assessment-context:5.3 -->

- **5.3/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Enforce verified tenant authorization before foreign data/metadata/effects. SHOULD: Add an explicit tenant-ID filter to every DB/vector-store query.
  - **5.3/V01/M01 exercise:** Query seeded tenant B data as tenant A across implemented stores/caches.
  - **5.3/V01/M01 source requirements:** Tool:TG-5.3.
  - **5.3/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Add an explicit tenant-ID filter to every DB/vector-store query.
  - **5.3/V01/S01 source requirements:** Tool:TG-5.3.
- **5.3/V02 — BASELINE_GATE:** MUST: Trusted verified authority determines permitted tenant access; a supplied identifier cannot grant cross-tenant authority.
  - **5.3/V02/M01 exercise:** Supply B's tenant identifier while authenticated as A.
  - **5.3/V02/M01 source requirements:** Tool:TG-5.3.
- **5.3/V03 — BASELINE_GATE:** MUST: Deny unauthorized foreign data, existence-sensitive metadata and effects before disclosure/execution.
  - **5.3/V03/M01 exercise:** Request B's objects/existence metadata as A, then perform an allowed A-resource request.
  - **5.3/V03/M01 source requirements:** Tool:TG-5.3.

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

<!-- assessment-context:6.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool cryptographic verifier/key-storage component
- **Applicability:** Mandatory credential/session validation and applicable crypto/storage; optional whole-message integrity assessed separately.
- **Setup and positive/negative controls:** Use valid declared-format credentials and owned keys. Tamper credential payload/signature/introspection and, if message signing exists, unsigned/tampered JSON-RPC payloads and missing/wrong key material.
- **Observe:** Observe verifier decisions, protected effects and secure key access; unsigned ordinary messages alone do not fail the minimum.
<!-- /assessment-context:6.1 -->

- **6.1/V01 — ADVISORY:** SHOULD: : The codebase should properly implement cryptographic signatures or HMAC validation for all incoming JSON-RPC payloads within the message handling and transport layer.
  - **6.1/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: : The codebase should properly implement cryptographic signatures or HMAC validation for all incoming JSON-RPC payloads within the message handling and transport layer.
  - **6.1/V01/S01 source requirements:** Tool:3.3.1.
- **6.1/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Required credential verification uses trusted keys; secret key material meets applicable published secure-storage/access and logged-OR-monitored criteria. Public verification keys require trusted integrity, not secrecy. SHOULD: Externalize and rotate optional whole-message signing/MAC keys through a dedicated management architecture.
  - **6.1/V02/M01 exercise:** Attempt unauthorized replacement of trusted verification keys and unauthorized reads of mock secret key material.
  - **6.1/V02/M01 source requirements:** Tool:3.3.1.
  - **6.1/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Externalize and rotate optional whole-message signing/MAC keys through a dedicated management architecture.
  - **6.1/V02/S01 source requirements:** Tool:3.3.1.
- **6.1/V03 — ADVISORY:** SHOULD: : The server should explicitly drop or reject any messages that lack a valid signature or fail the integrity validation check.
  - **6.1/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: : The server should explicitly drop or reject any messages that lack a valid signature or fail the integrity validation check.
  - **6.1/V03/S01 source requirements:** Tool:3.3.1.
- **6.1/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Reject tampered/invalid required authority before protected effects; unsigned ordinary messages alone are not a minimum failure. SHOULD: Detect and reject every tampered or unsigned JSON-RPC message through end-to-end integrity validation.
  - **6.1/V04/M01 exercise:** Tamper required credentials/introspection and, when implemented, separately tamper ordinary message signatures.
  - **6.1/V04/M01 source requirements:** Tool:3.3.1.
  - **6.1/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Detect and reject every tampered or unsigned JSON-RPC message through end-to-end integrity validation.
  - **6.1/V04/S01 source requirements:** Tool:3.3.1.

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

<!-- assessment-context:6.2 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool metadata and exposed execution component
- **Applicability:** Accurate purpose/inputs/material effects and applicable MCP readOnlyHint/destructiveHint; conditional publication rules retain their scope.
- **Setup and positive/negative controls:** Compare exported metadata against benign executions and mock read/write/destructive effects. Probe hidden parameters, unrelated resource access and vague high-privilege descriptions.
- **Observe:** Observe actual effects and metadata claims; titles, fixed name length, universal openWorldHint and full docstring audits are separate enhancements.
<!-- /assessment-context:6.2 -->

- **6.2/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Metadata accurately describes purpose, inputs and material effects, with truthful applicable MCP hints and separated reads/writes. SHOULD: Perform exhaustive manifest-to-function-name/type audits and expanded publication metadata checks.
  - **6.2/V01/M01 exercise:** Compare advertised purpose/types/hints with valid read/write/destructive operation effects.
  - **6.2/V01/M01 source requirements:** Tool:6.2.1.
  - **6.2/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Perform exhaustive manifest-to-function-name/type audits and expanded publication metadata checks.
  - **6.2/V01/S01 source requirements:** Tool:6.2.1.
- **6.2/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: No hidden behavior or parameter bypass contradicts declared operation/authorization boundaries. SHOULD: Require complete docstrings and code-to-metadata audits for every export, including dead-code/shadow-parameter analysis.
  - **6.2/V02/M01 exercise:** Probe hidden parameters and compare execution/material effects with the published description.
  - **6.2/V02/M01 source requirements:** Tool:6.2.1.
  - **6.2/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Require complete docstrings and code-to-metadata audits for every export, including dead-code/shadow-parameter analysis.
  - **6.2/V02/S01 source requirements:** Tool:6.2.1.
- **6.2/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Describe actual purpose and material effects accurately and narrowly enough to avoid misleading operation claims. SHOULD: Perform broad heuristic/code-complexity audits of every high-privilege description.
  - **6.2/V03/M01 exercise:** Exercise high-privilege operations presented with generic/vague descriptions.
  - **6.2/V03/M01 source requirements:** Tool:6.2.1.
  - **6.2/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Perform broad heuristic/code-complexity audits of every high-privilege description.
  - **6.2/V03/S01 source requirements:** Tool:6.2.1.
- **6.2/V04 — BASELINE_GATE:** MUST: Returned behavior and material side effects match the accurate declared purpose and applicable hints.
  - **6.2/V04/M01 exercise:** Execute declared operations with benign fixture inputs and monitor their effects.
  - **6.2/V04/M01 source requirements:** Tool:6.2.1.
- **6.2/V05 — MIXED_BASELINE_AND_ADVISORY:** MUST: Access and effects stay within declared necessary purpose and applicable authorized boundaries. SHOULD: Correlate every I/O/system call with expanded semantic integrity monitoring.
  - **6.2/V05/M01 exercise:** Probe unrelated resource/network access and compare observed effects with metadata/authority.
  - **6.2/V05/M01 source requirements:** Tool:6.2.1.
  - **6.2/V05/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Correlate every I/O/system call with expanded semantic integrity monitoring.
  - **6.2/V05/S01 source requirements:** Tool:6.2.1.
- **6.2/V06 — ADVISORY:** SHOULD: The AI Agent's interpretation of the metadata should accurately align with the actual code implementation without semantic gaps.
  - **6.2/V06/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The AI Agent's interpretation of the metadata should accurately align with the actual code implementation without semantic gaps.
  - **6.2/V06/S01 source requirements:** Tool:6.2.1.

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

<!-- assessment-context:6.3 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool dependency/update component
- **Applicability:** Published vulnerable-component criterion and exact justified exceptions; optional pinning/signatures/SBOM mechanisms.
- **Setup and positive/negative controls:** Identify installed versions and scan against known CVEs/CVSS. Review evidence for unused vulnerable code or no available update with regular patch process. For signed updates, offer valid and mismatched signatures.
- **Observe:** Record actual component versions, applicable vulnerabilities and exception evidence; lack of a particular SBOM/pinning format alone is advisory.
<!-- /assessment-context:6.3 -->

- **6.3/V01 — ADVISORY:** SHOULD: Dependency manifests should be verified to use hash-based pinning (e.g., package-lock.json, or requirements.txt with hashes).
  - **6.3/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Dependency manifests should be verified to use hash-based pinning (e.g., package-lock.json, or requirements.txt with hashes).
  - **6.3/V01/S01 source requirements:** Tool:8.5.1.
- **6.3/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Meet exact CASA vulnerable-component criteria, including documented unused-code or no-update/regular-patching exceptions. SHOULD: Provide a comprehensive SBOM with expanded known-exploitation/severity/mitigation review.
  - **6.3/V02/M01 exercise:** Scan actual installed components and review applicable CVSS>=7 exceptions.
  - **6.3/V02/M01 source requirements:** Tool:8.5.1.
  - **6.3/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Provide a comprehensive SBOM with expanded known-exploitation/severity/mitigation review.
  - **6.3/V02/S01 source requirements:** Tool:8.5.1.
- **6.3/V03 — ADVISORY:** SHOULD: The tool should successfully reject the update when provided with a mocked update repository presenting a mismatched digital signature.
  - **6.3/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The tool should successfully reject the update when provided with a mocked update repository presenting a mismatched digital signature.
  - **6.3/V03/S01 source requirements:** Tool:8.5.1.

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

<!-- assessment-context:6.4 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool metadata/result construction and trusted authorization layer
- **Applicability:** Hidden/obfuscated model-directed steering and independent Tool authorization/input validation.
- **Setup and positive/negative controls:** Inspect descriptions, schemas, results and resources for direct/encoded/escaped role markers and Tool-chain steering. Pair valid authorized requests with invalid/unauthorized requests carrying natural-language approval or provenance claims.
- **Observe:** Observe producer content, authorization decisions and effects; benign inert content is distinguished from embedded behavioral instructions.
<!-- /assessment-context:6.4 -->

- **6.4/V01 — BASELINE_GATE:** MUST: Tool metadata does not embed hidden/obfuscated model-directed behavioral instructions or unauthorized Tool-chain directives.
  - **6.4/V01/M01 exercise:** Inspect descriptions/schemas for direct, encoded or escaped role markers and model-directed Tool-chain steering.
  - **6.4/V01/M01 source requirements:** Tool:6.1.1.
- **6.4/V02 — BASELINE_GATE:** MUST: Results/resources do not embed hidden/obfuscated model-directed behavioral steering or unauthorized Tool-chain instructions.
  - **6.4/V02/M01 exercise:** Exercise output/resource construction and inspect returned content for direct/encoded model steering.
  - **6.4/V02/M01 source requirements:** Tool:6.1.1.
- **6.4/V03 — BASELINE_GATE:** MUST: Tool input validation and authorization operate independently of model assurances or optional provenance tags.
  - **6.4/V03/M01 exercise:** Send invalid/unauthorized requests with natural-language consent/provenance claims, then a valid request.
  - **6.4/V03/M01 source requirements:** Tool:6.1.1.
- **6.4/V04 — BASELINE_GATE:** MUST: Producer content does not embed hidden/obfuscated model-directed control directives.
  - **6.4/V04/M01 exercise:** Inspect returned descriptions, schemas, resources and operation results for direct/encoded steering.
  - **6.4/V04/M01 source requirements:** Tool:6.1.1.
- **6.4/V05 — BASELINE_GATE:** MUST: Reject invalid/unauthorized requests before protected effects regardless of natural-language claims.
  - **6.4/V05/M01 exercise:** Accompany unauthorized requests with forged natural-language approval or provenance tags.
  - **6.4/V05/M01 source requirements:** Tool:6.1.1.

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

<!-- assessment-context:7.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool metered-operation authorization and optional budget component
- **Applicability:** Protected/metered operations under their actual authority; Agent consequential-action HITL is separately assessed.
- **Setup and positive/negative controls:** Use a mock meter and a protected paid operation plus a genuinely public-safe metered route. Exercise missing/wrong/valid authority and the implemented cost threshold/tracking configuration.
- **Observe:** Observe authorization and paid effects independently of optional cumulative limits; $100 is an advisory guardrail, not a universal gate.
<!-- /assessment-context:7.1 -->

- **7.1/V01 — ADVISORY:** SHOULD: All APIs and resources carrying a financial cost should be successfully identified in the codebase.
  - **7.1/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: All APIs and resources carrying a financial cost should be successfully identified in the codebase.
  - **7.1/V01/S01 source requirements:** Tool:10.1.1.
- **7.1/V02 — ADVISORY:** SHOULD: The implementation of the $100 limit should be explicitly confirmed, along with proper documentation for any higher justified limits.
  - **7.1/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The implementation of the $100 limit should be explicitly confirmed, along with proper documentation for any higher justified limits.
  - **7.1/V02/S01 source requirements:** Tool:10.1.1.
- **7.1/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Require valid user/resource authority for protected operations; metering alone does not convert a genuine public-safe route into protected access. SHOULD: Authenticate every cost-incurring resource regardless of its protected/public status.
  - **7.1/V03/M01 exercise:** Call a protected paid operation without authority and a genuine public-safe metered route anonymously.
  - **7.1/V03/M01 source requirements:** Tool:10.1.1.
  - **7.1/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Authenticate every cost-incurring resource regardless of its protected/public status.
  - **7.1/V03/S01 source requirements:** Tool:10.1.1.
- **7.1/V04 — ADVISORY:** SHOULD: The real-time cost tracking method should accurately monitor the metered resources during an active session.
  - **7.1/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The real-time cost tracking method should accurately monitor the metered resources during an active session.
  - **7.1/V04/S01 source requirements:** Tool:10.1.1.
- **7.1/V05 — ADVISORY:** SHOULD: The tool should successfully trigger a rate limit or explicit confirmation prompt exactly when the cumulative session cost reaches the defined $100 limit (or justified limit) during high-volume simulation.
  - **7.1/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The tool should successfully trigger a rate limit or explicit confirmation prompt exactly when the cumulative session cost reaches the defined $100 limit (or justified limit) during high-volume simulation.
  - **7.1/V05/S01 source requirements:** Tool:10.1.1.

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

<!-- assessment-context:7.2 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool authorization/anti-automation and optional rate-limit component
- **Applicability:** Resource authorization independent of rate; applicable published authentication alternatives/OOB conditions remain independently assessed.
- **Setup and positive/negative controls:** Seed users A/B and protected resource identifiers. Attempt unauthorized access before any limit and at high volume; for implemented quotas, aggregate concurrent sessions and unrelated-user requests.
- **Observe:** Observe denial and existence confidentiality at the first request and after thresholds; record selected published anti-automation alternative rather than forcing rate limiting.
<!-- /assessment-context:7.2 -->

- **7.2/V01 — ADVISORY:** SHOULD: The codebase should contain functional logic that aggregates limits across all concurrent sessions belonging to the same authenticated user.
  - **7.2/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The codebase should contain functional logic that aggregates limits across all concurrent sessions belonging to the same authenticated user.
  - **7.2/V01/S01 source requirements:** Tool:10.3.1.
- **7.2/V02 — ADVISORY:** SHOULD: Functions susceptible to enumeration or consequential-action abuse should enforce documented action-, resource-, target-, or aggregate-level thresholds with a stated rationale.
  - **7.2/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Functions susceptible to enumeration or consequential-action abuse should enforce documented action-, resource-, target-, or aggregate-level thresholds with a stated rationale.
  - **7.2/V02/S01 source requirements:** Tool:10.3.1.
- **7.2/V03 — BASELINE_GATE:** MUST: Deny unauthorized access and protect existence-sensitive metadata from the first request, independent of reaching a threshold.
  - **7.2/V03/M01 exercise:** Attempt unauthorized resource/existence queries before any rate limit and after high-volume requests.
  - **7.2/V03/M01 source requirements:** Tool:10.3.1.
- **7.2/V04 — ADVISORY:** SHOULD: The rate limiting constraints should be explicitly configurable by the administrator or system.
  - **7.2/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The rate limiting constraints should be explicitly configurable by the administrator or system.
  - **7.2/V04/S01 source requirements:** Tool:10.3.1.
- **7.2/V05 — ADVISORY:** SHOULD: The system should successfully throttle, block, or limit actions when an individual user's aggregate request volume or applicable enumeration threshold is exceeded.
  - **7.2/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The system should successfully throttle, block, or limit actions when an individual user's aggregate request volume or applicable enumeration threshold is exceeded.
  - **7.2/V05/S01 source requirements:** Tool:10.3.1.
- **7.2/V06 — ADVISORY:** SHOULD: The enforcement of rate limits on one user should not impact the availability or performance of the system for other users.
  - **7.2/V06/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The enforcement of rate limits on one user should not impact the availability or performance of the system for other users.
  - **7.2/V06/S01 source requirements:** Tool:10.3.1.

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

<!-- assessment-context:7.3 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool payload/depth component, when implemented
- **Applicability:** Optional declared byte/depth/recursion bounds; injection and access controls apply independently.
- **Setup and positive/negative controls:** Exercise benign payloads and nested requests below, at and above declared byte/depth/recursive-call limits, including an admitted language-runtime bound.
- **Observe:** Observe size/depth decisions, safe errors and process behavior; no new universal numeric baseline is introduced.
<!-- /assessment-context:7.3 -->

- **7.3/V01 — ADVISORY:** SHOULD: Payload size limits should be explicitly implemented and verified in the code, or acceptable language-provided limits should be in place.
  - **7.3/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Payload size limits should be explicitly implemented and verified in the code, or acceptable language-provided limits should be in place.
  - **7.3/V01/S01 source requirements:** Tool:10.2.1.
- **7.3/V02 — ADVISORY:** SHOULD: Recursion limits should be applied and enforced during the processing of nested tool calls or nested JSON structures.
  - **7.3/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Recursion limits should be applied and enforced during the processing of nested tool calls or nested JSON structures.
  - **7.3/V02/S01 source requirements:** Tool:10.2.1.
- **7.3/V03 — ADVISORY:** SHOULD: The server should successfully reject or drop request payloads that exceed the defined size limit.
  - **7.3/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server should successfully reject or drop request payloads that exceed the defined size limit.
  - **7.3/V03/S01 source requirements:** Tool:10.2.1.
- **7.3/V04 — ADVISORY:** SHOULD: The server should successfully reject requests containing JSON objects with a nesting depth significantly higher than the allowed limit.
  - **7.3/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The server should successfully reject requests containing JSON objects with a nesting depth significantly higher than the allowed limit.
  - **7.3/V04/S01 source requirements:** Tool:10.2.1.

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

<!-- assessment-context:8.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool logging/monitoring component
- **Applicability:** Secret access logged OR monitored and published no-secret/task-content restrictions; broader invocation telemetry is recommended.
- **Setup and positive/negative controls:** Exercise successful/failed mock calls and secret access. Inspect configured monitoring and all applicable log sinks with seeded credential/payment/session/task content.
- **Observe:** Observe evidence of secret access monitoring/logging and prohibited sink content; record structured event fields and invocation coverage separately.
<!-- /assessment-context:8.1 -->

- **8.1/V01 — ADVISORY:** SHOULD: The codebase utilizes a structured format like JSON objects or key-value pairs for all logging statements, avoiding simple string concatenation.
  - **8.1/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The codebase utilizes a structured format like JSON objects or key-value pairs for all logging statements, avoiding simple string concatenation.
  - **8.1/V01/S01 source requirements:** Tool:12.2.1.
- **8.1/V02 — ADVISORY:** SHOULD: All functions that execute external tools or access data resources have been successfully identified.
  - **8.1/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: All functions that execute external tools or access data resources have been successfully identified.
  - **8.1/V02/S01 source requirements:** Tool:12.2.1.
- **8.1/V03 — MIXED_BASELINE_AND_ADVISORY:** MUST: Secret access is logged OR monitored and logs obey published credential/payment/session-hash and task-content limits. SHOULD: Emit per-path invocation events with Agent identity, Tool, safe input summary and outcome.
  - **8.1/V03/M01 exercise:** Exercise secret access and inspect actual monitoring/log sinks for forbidden values and event fields.
  - **8.1/V03/M01 source requirements:** Tool:12.2.1.
  - **8.1/V03/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Emit per-path invocation events with Agent identity, Tool, safe input summary and outcome.
  - **8.1/V03/S01 source requirements:** Tool:12.2.1.
- **8.1/V04 — ADVISORY:** SHOULD: Critical events log relevant metadata, including timestamps and correlation IDs.
  - **8.1/V04/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Critical events log relevant metadata, including timestamps and correlation IDs.
  - **8.1/V04/S01 source requirements:** Tool:12.2.1.
- **8.1/V05 — ADVISORY:** SHOULD: No instances exist where a tool is invoked without telemetry or where error states are handled "silently" without an audit entry.
  - **8.1/V05/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: No instances exist where a tool is invoked without telemetry or where error states are handled "silently" without an audit entry.
  - **8.1/V05/S01 source requirements:** Tool:12.2.1.
- **8.1/V06 — ADVISORY:** SHOULD: No unstructured "print" statements or unstructured logger calls are used for operational data.
  - **8.1/V06/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: No unstructured "print" statements or unstructured logger calls are used for operational data.
  - **8.1/V06/S01 source requirements:** Tool:12.2.1.
- **8.1/V07 — MIXED_BASELINE_AND_ADVISORY:** MUST: Meet secret-access logged-OR-monitored evidence and mandatory log-content restrictions; full interaction transcripts are not required. SHOULD: Provide structured coverage of every invocation and outcome through safe summaries/correlation metadata.
  - **8.1/V07/M01 exercise:** Collect success/error/secret-access evidence and seed prohibited values into exercised paths.
  - **8.1/V07/M01 source requirements:** Tool:12.2.1.
  - **8.1/V07/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Provide structured coverage of every invocation and outcome through safe summaries/correlation metadata.
  - **8.1/V07/S01 source requirements:** Tool:12.2.1.
- **8.1/V08 — ADVISORY:** SHOULD: The output logs are confirmed to be valid structured data (e.g., valid JSON) parsable by automated security tools.
  - **8.1/V08/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The output logs are confirmed to be valid structured data (e.g., valid JSON) parsable by automated security tools.
  - **8.1/V08/S01 source requirements:** Tool:12.2.1.

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

<!-- assessment-context:8.2 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool invocation logging/monitoring component
- **Applicability:** Secret access logged OR monitored and mandatory log-content boundaries; six-field JSON invocation records are enhanced.
- **Setup and positive/negative controls:** Run successful and failed invocations with seeded secret/payment/task values. Inspect audit events and alternative secret-access monitoring; validate JSON and the declared six fields if implemented.
- **Observe:** Observe secret-access evidence and actual log contents independently of JSON formatting or field completeness.
<!-- /assessment-context:8.2 -->

- **8.2/V01 — ADVISORY:** SHOULD: Each function handler generates a log entry with all six should fields.
  - **8.2/V01/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: Each function handler generates a log entry with all six should fields.
  - **8.2/V01/S01 source requirements:** Tool:TG-8.2.
- **8.2/V02 — ADVISORY:** SHOULD: The log entry format is verified to be structured JSON.
  - **8.2/V02/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: The log entry format is verified to be structured JSON.
  - **8.2/V02/S01 source requirements:** Tool:TG-8.2.
- **8.2/V03 — ADVISORY:** SHOULD: All six should fields are present in the inspected logs following the execution of successful and failing tool calls.
  - **8.2/V03/S01 exercise:** If implemented, use the context fixtures and relevant declared configuration to inspect/exercise this original scenario: All six should fields are present in the inspected logs following the execution of successful and failing tool calls.
  - **8.2/V03/S01 source requirements:** Tool:TG-8.2.
- **8.2/V04 — MIXED_BASELINE_AND_ADVISORY:** MUST: Secret access is logged OR monitored; actual logs contain no prohibited credentials/payment or disallowed session representation/task content. SHOULD: Produce valid six-field JSON invocation records.
  - **8.2/V04/M01 exercise:** Inspect successful/failed invocation logs and alternative secret-access monitoring with seeded prohibited values.
  - **8.2/V04/M01 source requirements:** Tool:TG-8.2.
  - **8.2/V04/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Produce valid six-field JSON invocation records.
  - **8.2/V04/S01 source requirements:** Tool:TG-8.2.

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

<!-- assessment-context:7.7.1 -->
**Case assessment context — remote HTTP Tool:**

- **Actor:** Tool HTTP transport/authentication component
- **Applicability:** Selected MCP HTTP profile Origin duties and applicable CSRF/anti-automation; Origin never substitutes for user authority.
- **Setup and positive/negative controls:** Use permitted, missing, forged and unexpected Origin headers with valid/missing user credentials. Perform a controlled DNS-rebinding/CSRF attempt under the selected protocol and declared origin policy.
- **Observe:** Observe origin decisions and unauthorized effects; distinguish required selected-protocol validation from optional additional allowlist hardening.
<!-- /assessment-context:7.7.1 -->

- **7.7.1/V01 — MIXED_BASELINE_AND_ADVISORY:** MUST: Meet selected-profile required Origin validation and applicable CSRF controls; Origin does not replace authentication/authorization. SHOULD: Add origin allowlists/rebinding hardening beyond selected-protocol mandatory duties.
  - **7.7.1/V01/M01 exercise:** Send allowed/unexpected Origins under the selected MCP HTTP profile with valid and missing authority.
  - **7.7.1/V01/M01 source requirements:** Tool:7.7.1.
  - **7.7.1/V01/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Add origin allowlists/rebinding hardening beyond selected-protocol mandatory duties.
  - **7.7.1/V01/S01 source requirements:** Tool:7.7.1.
- **7.7.1/V02 — MIXED_BASELINE_AND_ADVISORY:** MUST: Prevent applicable unauthorized effects and enforce any selected-protocol required Origin checks independently of user authority. SHOULD: Enforce additional strict Origin allowlist/rebinding defenses beyond the selected profile.
  - **7.7.1/V02/M01 exercise:** Attempt controlled forged-Origin/DNS-rebinding/CSRF access under the selected profile.
  - **7.7.1/V02/M01 source requirements:** Tool:7.7.1.
  - **7.7.1/V02/S01 exercise:** If implemented, use the context fixtures to inspect/exercise this original mechanism separately from required authority and effects: Enforce additional strict Origin allowlist/rebinding defenses beyond the selected profile.
  - **7.7.1/V02/S01 source requirements:** Tool:7.7.1.

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
