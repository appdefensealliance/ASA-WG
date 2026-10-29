# AI Tool Security Specification

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

## Definitions

| Term             | Definition |
| :--------------- | :--------- |
| sensitive action | An operation that is irreversible, transfers value or money, mutates or shares user data beyond the scope of the current task, or grants or expands access. Aligned with "Sensitive Action" in the AI Agent–Tool Interface Contract. |
| AI model | A statistical model — such as a large language model (LLM) — trained on data to perform inference (e.g., generating text, classifying inputs, or producing embeddings), that an AI Agent invokes or an AI Tool may use internally. |

## Tool requirements

### 1.1.1 Client/Server Authentication for Protected Access

<!-- ada:requirement Tool:1.1.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | For protected/user-specific remote calls, the Tool MUST validate the selected OAuth credential and user/resource/scope authority before execution; MUST reject missing/invalid credentials on protected operations. Public-safe and discovery operations MAY be unauthenticated only when they expose no protected data or unauthorized action. |
| SHOULD | Dedicated MCP-host identity authentication beyond end-user authorization SHOULD be provided. mTLS client identification and rotated keys SHOULD be defense in depth, not public-directory substitutes for the supported user OAuth profile. |

### 1.2.1 Scoped Authorization and User Context Propagation

<!-- ada:requirement Tool:1.2.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | For protected/user-specific operations, the Tool MUST verify user authority and uniformly enforce resource/object/attribute permissions before returning data, existence-sensitive metadata or causing side effects. Its service credential MUST NOT substitute for user authorization. |
| SHOULD | User context SHOULD be propagated centrally through handlers and downstream clients; a particular middleware architecture is not mandatory. |

### 1.2.2 Validation of User Context

<!-- ada:requirement Tool:1.2.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST authenticate protected user context by valid signed-token verification OR trusted opaque-token introspection, including applicable issuer, audience/resource, expiry and scope checks. Bare unsigned user_id is not authentication. Protected downstream access MUST remain user-authorized. |
| SHOULD | An issuer-minted per-request signed user identity assertion forwarded by the Agent and cryptographic per-action parameter binding SHOULD be supported as stronger mechanisms, not mandatory formats. |

### 1.2.3 No Token Passthrough / Downstream Token Exchange

<!-- ada:requirement Tool:1.2.3 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | On user-behalf downstream access, the Tool MUST NOT pass the inbound MCP access token through to an upstream API for a different audience. It MUST use separately authorized resource-scoped credentials preserving the end-user authorization boundary. RFC8693 exchange or equivalent OBO is acceptable, not the only mandated wire procedure. |
| SHOULD | Shorter downstream token lifetimes and sender constraints/DPoP SHOULD be applied, including remote/high-value deployments. Stronger delegation chains SHOULD be supported where practical. |

### 1.3.1 Externalized Secret Management

<!-- ada:requirement Tool:1.3.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Server-side tokens/API keys/secrets MUST use a documented appropriate access-control policy and cryptographically secure storage; access MUST be logged OR monitored without logging secret values. Secrets MUST remain confidential, including public packages/metadata. |
| SHOULD | Externalized runtime secret retrieval, avoiding embedded secret literals, periodic rotation procedures and breach-revocation playbooks SHOULD be implemented. No specific environment-variable or product is mandatory. |

### 1.3.2 Secure Downstream Transport

<!-- ada:requirement Tool:1.3.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Applicable TLS protection/trust MUST satisfy the full published CASA4.1.1/4.1.2 clauses, including default1.2+, necessary legacy mitigations and Additional Context exceptions. Public MCP/auth exchanges MUST use HTTPS. Bearer credentials MUST NOT appear in URL query strings. Credentials MUST NOT be disclosed to unauthorized redirected destinations. |
| SHOULD | TLS 1.3 SHOULD be preferred. Independently reauthorizing every cross-origin redirect SHOULD be the chosen hardening approach; equivalent enforcement of the mandatory authorized-destination/no-secret-disclosure outcome remains required. |

### 1.4.1 Message Freshness and Session Binding

<!-- ada:requirement Tool:1.4.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Applicable stateful session/refresh logout/expiry invalidation and default-or-option password-change termination MUST be preserved. Only non-revocable STATELESS authentication tokens MUST expire within 24 hours. Stateless-session anti-tampering/replay controls MUST meet CASA 2.3.4. |
| SHOULD | Message-level nonce/timestamp validation, inactivity timers and duplicate JSON-RPC replay caches SHOULD be implemented. Their absence alone is advisory unless it exposes an applicable mandatory authentication/session weakness. |

### 1.4.2 Sensitive Action Idempotency and Ambiguous Outcomes

<!-- ada:requirement Tool:1.4.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | No new business-intent identifier baseline gate is introduced here; ordinary baseline authorization and session/token replay protections still apply. |
| SHOULD | Sensitive side-effect actions SHOULD use stable user-approved intent/idempotency identifiers bound to user/account/operation/material parameters; distinct separately approved actions SHOULD have distinct identifiers. Durable duplicate suppression SHOULD survive restarts for the documented retry/uncertainty window. Ambiguous outcomes SHOULD be reconciled, never blindly retried or represented as authoritative success without evidence. |

### 1.4.3 Connector Lifecycle Revocation

<!-- ada:requirement Tool:1.4.3 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST deny protected activity after applicable authority is revoked/expired and MUST enforce the published stateful session/refresh invalidation events. An Agent logout MUST NOT be invented as revocation of a distinct persistent connector grant; enforce the actual grant lifecycle. |
| SHOULD | Explicit unlink/removal/deactivation propagation, revocation convergence-time documentation, queued-work/callback/retry lifecycle handling and authoritative committed-work reconciliation SHOULD be implemented. No new fixed propagation SLA is mandatory. |

### 1.5.1 Strict Redirect URI and State Validation

<!-- ada:requirement Tool:1.5.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Where OAuth applies, the Tool MUST securely validate redirect_uri AND state to prevent open redirects and CSRF; the supported connector flow MUST validate exact registered vendor redirects, preserving applicable native-loopback port conditions. Secure recommended flows MUST exclude Implicit/ROPC. Actual auth/admin web components MUST retain applicable CASA controls regardless of old WebApp-integrated-Tool comments. |
| SHOULD | An explicit user/session/issuer/client/redirect/PKCE transaction tuple, documented short state expiry, single-use state and authenticated cross-device handoff SHOULD be used. If an omission actually permits CSRF/session substitution, it is a mandatory-outcome failure, not excused by advisory mechanism strength. |

### 1.5.2 S256 PKCE for the Selected Public OAuth Profile

<!-- ada:requirement Tool:1.5.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | For the selected public remote user OAuth authorization-code profile, S256 PKCE MUST be supported/advertised and the authorization code flow MUST generate/use the verifier and reject omitted/altered required verifier. Client-generation and authorization-server-verification duties MUST be allocated to the actor that implements them. |
| SHOULD | PKCE SHOULD be used beyond this demonstrated common public-remote profile where appropriate. |

### 1.6.1 Automated PII and Credential Masking in Logs

<!-- ada:requirement Tool:1.6.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Credentials/payment details MUST NOT be logged; session tokens may appear only as irreversible hashes under the exact published CASA exception. Logging MUST NOT collect extraneous conversation content beyond the task/function. |
| SHOULD | Central automatic interception/redaction across stdout/stderr/files, broad PII/secret detection and masking SHOULD be used. Any method is acceptable only if the mandatory no-secret logging outcome is met. |

### 1.6.2 Secure Session Tokens

<!-- ada:requirement Tool:1.6.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | All applicable published session/URL/cookie/browser-storage/secret-storage/TLS controls MUST remain, with every original exception and criterion. This includes Secure/HttpOnly when cookie sessions apply, legacy static-secret exception, scoped24h expiry, refresh invalidation, browser-store logout deletion and hashed-only session-token logs. |
| SHOULD | Avoiding argv/temp-file exposure and preferential environment/header carriers SHOULD be adopted beyond the mandatory common MCP bearer-header/query rules. |

### 2.1.1 Server-Side Consent Backstop for Sensitive Actions

<!-- ada:requirement Tool:2.1.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST provide truthful applicable MCP readOnlyHint/destructiveHint fields: readOnlyHint:true for read-only operations and destructiveHint:true for applicable irreversible/destructive operations. This does not invent every-tool Boolean presence or uniform additive-write semantics. It MUST NOT misrepresent writes as reads or bypass core Agent consequential-action human confirmation. Authentication/authorization and exposed-admin MFA MUST remain independent. Full valid login OR secondary verification remains the CASA 2.4.1 alternative. |
| SHOULD | Independent Tool-owned server-side confirmation/elicitation or fail-closed consent backstop SHOULD be used. Tool challenges/receipts SHOULD bind user/account/operation/recipient/material parameters/validity/one execution and reject mismatches/replay; explicit bounded-batch enumeration SHOULD be provided. No independent Tool confirmation or cryptographic receipt is a new baseline certification gate. consent_required MAY be emitted. |

### 2.1.2 Out-of-Band Confirmation for High-Risk Actions

<!-- ada:requirement Tool:2.1.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Baseline Agent HITL, Tool honest risk labels, authentication and CASAadmin-MFA/sensitive-account protections remain mandatory where applicable. |
| SHOULD | Independent-channel OOB confirmation SHOULD be used for highest-risk actions, including remote/high-value deployments; a safe server-side fallback SHOULD be provided where infeasible. Pre-registered channel/authenticated provider page and matching/expiry/single-use checks SHOULD preserve the current security content. No absent OOB channel alone fails baseline. |

### 2.2.1 Stateless Request Level Isolation

<!-- ada:requirement Tool:2.2.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST prevent unauthorized cross-user/tenant data access or side effects across reused runtimes, caches and concurrent requests. |
| SHOULD | Stateless request architecture, no user-specific globals, context purge/recycling and unique request-ID correlation SHOULD be used; equivalent safely scoped caches are not categorically forbidden. |

### 2.2.2 User Identity Propagation

<!-- ada:requirement Tool:2.2.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Protected multi-user requests MUST derive verified user/tenant authority from valid credentials or trusted introspection, never an assumed connection or attacker-selected identifier alone; MUST scope access and deny invalid/wrong-user/out-of-scope calls before protected output/side effects. |
| SHOULD | Dedicated short-lived identity JWTs, per-query JWT.sub syntax, centralized propagation and identity-labelled downstream logs SHOULD be used where appropriate. Opaque token validation is equally acceptable. |

### 2.2.3 Ensure Sandbox Protections

<!-- ada:requirement Tool:2.2.3 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST prevent applicable code/OS/file injection, traversal and SSRF while respecting the published necessary-functionality, sanitization/sandboxing and allowlist conditions. It MUST NOT bypass platform or upstream security boundaries. |
| SHOULD | Hardened runtime, unsafe-sink detectors, strict path-canonicalization patterns and sandbox-specific restriction policies SHOULD be applied. Legitimate code execution is not categorically forbidden when CASA exceptions are met. |

### 2.4.1 Principle of Least Privilege and Scoped Permissions

<!-- ada:requirement Tool:2.4.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST enforce least-privilege permissions at a trusted service layer and deny unauthorized operations independent of model promises or annotations. |
| SHOULD | Fine-grained scoped-permission design SHOULD be used; do not invent a fixed scope list. |

### 3.1.1 Parameterized Arguments and Unsafe Sink Blocking

<!-- ada:requirement Tool:3.1.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST validate untrusted arguments server-side and meet each applicable published injection/XSS/SSRF/file control; required rejection/neutralization MUST precede execution. Generic schema validation alone is not full coverage. |
| SHOULD | Parameterized APIs, exhaustive static allowlists at every internal boundary and unsafe-sink blocking SHOULD be used. eval/shell presence alone is not a categorical failure where secure expected functionality satisfies CASA. |

### 3.3.1 Cryptographic Message Integrity Validation

<!-- ada:requirement Tool:3.3.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST validate baseline credential/session signatures or trusted introspection and preserve applicable strong cryptography/key storage. It MUST NOT accept a tampered/invalid baseline credential. |
| SHOULD | End-to-end signatures/MACs across all JSON-RPC messages, descriptors and resources SHOULD be implemented; unsigned ordinary messages alone MUST NOT be a baseline failure when required authentication/TLS/outcome controls pass. |

### 5.1.1 Exfiltration Defense

<!-- ada:requirement Tool:5.1.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST prevent unauthorized secret/resource access and corruption through exposed APIs and MUST limit collected/returned task data to the shared necessary-purpose boundary. |
| SHOULD | Defense-in-depth memory-safe secret buffers, runtime isolation, reflection/taint analysis and layered exfiltration protection SHOULD be retained. |

### 6.1.1 No Embedded Model-Directed Control Directives

<!-- ada:requirement Tool:6.1.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST NOT embed hidden/obfuscated model-directed behavioral steering or unauthorized tool-chain instructions in its metadata/results, and MUST enforce its own authorization/input validation independently of Agent/model. It MUST NOT rely on optional provenance tags as its security boundary. |
| SHOULD | Provenance tags and structured/typed output SHOULD be provided where useful; tags do not establish consumer trust. |

### 6.2.1 Semantic Integrity and Descriptive Accuracy

<!-- ada:requirement Tool:6.2.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Metadata MUST accurately describe purpose, inputs, behavior and material side effects. Truthful applicable MCP readOnlyHint and destructiveHint fields MUST be supplied, including readOnlyHint:true for reads and destructiveHint:true for applicable irreversible/destructive operations; neither every-tool Boolean presence nor one additive-write value is invented. Read/write surfaces MUST be separated, not hidden in mixed generic catch-alls. |
| SHOULD | Human-readable titles, universal openWorldHint, a64-character name target, idempotent hints, every-operation granularity and expanded code/docstring audits SHOULD be used where security-useful; none is falsely claimed shared mandatory. Vendor-specific still-binding publication rules are separate. |

### 7.1.1 Integrated Transport Security and Message Integrity

<!-- ada:requirement Tool:7.1.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Public remote endpoint MUST use HTTPS and meet full applicable CASA TLS/trust/crypto criteria, defaultTLS 1.2+ with exact legacy/internal-CA/Additional Context routes. |
| SHOULD | TLS 1.3, all-message MAC/signatures, secureIPC/OS permissions and local loopback-only binding SHOULD be considered for this public-remote impact model. Existing local/mobile strengths are not automatically changed; held variants require separate assessment. |

### 7.7.1 Validate Origin Header on HTTP Transports

<!-- ada:requirement Tool:7.7.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Applicable anti-CSRF/anti-automation outcomes MUST be preserved. Origin MUST NOT act as an authentication credential or sole access-control basis. Where the implementation selects an MCP HTTP transport profile with normative Origin-validation requirements, the implementing actor MUST meet those applicable profile requirements; an unselected protocol or unspecified hardening rule is not imported. |
| SHOULD | Origin allowlists/DNS-rebinding defenses beyond the selected protocol's normative requirements SHOULD be implemented as additional hardening. This does not demote the selected transport's required Origin validation. Current local/internal variants remain held. |

### 8.2.1 Request-Level Isolation and Recommended Stateless Architecture

<!-- ada:requirement Tool:8.2.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Preventing unauthorized cross-user/tenant access MUST be enforced regardless of runtime reuse. |
| SHOULD | Process/Respond/Purge, context reset or restart SHOULD be implemented; source typo Contest Reset has no new normative meaning. Safely isolated persistent state remains possible. |

### 8.4.1 Detect and Block Unsafe Sinks

<!-- ada:requirement Tool:8.4.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Applicable code/command/path/SSRF vulnerabilities MUST be prevented under full CASA conditions. |
| SHOULD | Hardened runtimes, unsafe-sink scanning, parameterized commands and path canonicalization SHOULD be used as engineering approaches. |

### 8.5.1 Resource Pinning and Signature Verification

<!-- ada:requirement Tool:8.5.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | No-known-exploitable-component requirement MUST remain, including exact published guide CVSS>=7 and documented unused-vulnerable-code/no-update-with-regular-patching exceptions. |
| SHOULD | Dependency/plugin hash pinning, tool/model-weight signatures, SBOMs and authenticated update testing SHOULD remain AI-specific supply-chain recommendations. |

### 9.1.1 Data Minimization

<!-- ada:requirement Tool:9.1.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The Tool MUST collect/process/return only function/task-necessary content and MUST NOT covertly reconstruct full Agent history/hidden memory or persistent conversation profiles. |
| SHOULD | Purpose-shaped output schemas/queries, supplemental PII detectors and heuristic redaction SHOULD implement the mandatory minimization outcome; no categorical legitimate-user-file ban is imported. |

### 10.1.1 Financial Resource & Cost Governance

<!-- ada:requirement Tool:10.1.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Metered operations MUST still meet applicable authorization and core Agent consequential-action HITL; no blanket auth gate is added to demonstrably public-safe resources merely because metered. |
| SHOULD | Cost awareness, cumulative tracking, a$100 advisory guardrail, configurable documented higher thresholds and per-user/per-tool budget limits SHOULD be retained. |

### 10.2.1 Maximum Payload and Recursion Depth Constraints

<!-- ada:requirement Tool:10.2.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | No universal payload/depth numeric baseline is established by the reviewed shared evidence; applicable injection/access controls still apply. |
| SHOULD | Configurable incoming byte/depth/recursive-call limits SHOULD be enforced. Excess-limit safe error/truncation handling SHOULD be tested. |

### 10.3.1 Per User Endpoint Rate Limiting

<!-- ada:requirement Tool:10.3.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Authorization and protected-resource existence confidentiality MUST NOT depend on reaching a rate threshold. Published authentication anti-automation alternatives and low-entropy OOB rate-limiting condition MUST remain exactly scoped; not every app is forced to choose rate limiting from1.1.1 alternatives. |
| SHOULD | Configurable per-user concurrent-session aggregation, target/action/resource aggregate limits, rationale and unrelated-user noninterference SHOULD be retained. |

### 12.2.1 Implement comprehensive logging using structured logging formats

<!-- ada:requirement Tool:12.2.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Secret access MUST be logged OR monitored per CASA 6.7.1, and all logging MUST obey credential/payment/hash and task-content restrictions. |
| SHOULD | Machine-readable significant-event logging, invocation outcome metadata, timestamps/correlation IDs and summaries/hashes SHOULD be provided. Logging all model inputs/outputs is not a mandate or permission for transcript collection. |

### 12.2.2 Protect Sensitive Data in Logs

<!-- ada:requirement Tool:12.2.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | No credentials/payment details in logs and hashed-only session-token representation MUST be enforced; extra conversation collection for logging MUST NOT occur. |
| SHOULD | Automated broad PII/identity/proprietary-output masking, centralized filters and heuristic sensitive-variable tracking SHOULD be retained. |

## Supplemental outcomes and enhancements

These stable IDs reconcile tests that previously lacked Specification mappings. They preserve minimum outcomes independently from recommended mechanisms.

### TG-2.5 Tool Function Allow-listing and Parameter Validation

<!-- ada:requirement Tool:TG-2.5 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | The exposed public remote surface MUST preserve truthful declared behavior and separated read/write controls; untrusted parameters MUST be validated and applicable authorization MUST precede every reachable protected execution path. Declared schema types and constraints MUST be enforced when claimed, including rejecting extra fields when additionalProperties:false is declared; no global extra-field ban applies when the schema permits them. Undeclared mixed read/write catch-alls or bypass routes violating this outcome fail baseline. |
| SHOULD | Exhaustive route manifests, strict rejection of every extra schema field irrespective of declared additionalProperties rules, and codepath parity evidence SHOULD be used. Do not prohibit a legitimate fixed-purpose/freeform read query solely by wholesale executor bans. |

### TG-3.5 PII Detection

<!-- ada:requirement Tool:TG-3.5 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Unauthorized or task-extraneous personal data output MUST be prevented; applicable credential/payment log protections remain. Legitimate purpose-required, authorized data is not categorically prohibited. |
| SHOULD | Detecting all SSN/national ID/email/phone/Luhn-valid-card/high-entropy patterns and redacting via a universal PII detector SHOULD be adopted, not a baseline detector-product/category gate. |

### TG-4.1 Output Sanitization

<!-- ada:requirement Tool:TG-4.1 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Where rendered output/XML parsing is applicable, mandatory contextual XSS/XML protections MUST pass. No optional-widget exclusion waives actual auth/admin rendering controls. |
| SHOULD | Universal structured-output schemas and stripping every HTML/JavaScript/shell/SQL metacharacter in non-executable data SHOULD be considered, not imposed indiscriminately where it destroys legitimate content. |

### TG-4.4 Maximum Response Size

<!-- ada:requirement Tool:TG-4.4 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | No universal 1 MB response gate is established. Mandatory data minimization still applies where relevant. |
| SHOULD | Configurable response truncation/pagination/rejection and a 1 MB suggested default with purpose justification for larger responses SHOULD be retained. |

### TG-5.3 Mandatory Tenant Isolation

<!-- ada:requirement Tool:TG-5.3 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Cross-tenant unauthorized data, existence-sensitive metadata and side effects MUST be denied using verified authority; attacker-selected tenant ID is not sufficient authorization. |
| SHOULD | A tenant-ID filter in every individual database/vector-store query SHOULD be the implementation approach, not the only acceptable correctly enforced isolation design. |

### TG-8.2 Invocation Audit Trail

<!-- ada:requirement Tool:TG-8.2 -->

| Strength | Requirement |
| --- | --- |
| MUST when applicable | Secret access MUST be logged OR monitored; log content MUST meet the unchanged credential/payment/session hash and task-content boundaries. |
| SHOULD | A per-invocation JSON record with all six timestamp/Agent ID/function/version/input-hash-or-summary/outcome fields SHOULD be retained. Absence of one field is advisory unless an independent mandatory security property fails. |

## Supplemental minimum properties

### MIN-S01 Public HTTPS and transport confidentiality

<!-- ada:requirement Tool:MIN-S01 -->

Expose the directory MCP endpoint over public HTTPS; protect the authenticated exchange in transit.

**Applicability:** Public-internet connector endpoint and applicable OAuth endpoints. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S02 OAuth authorization-code integration for protected user access

<!-- ada:requirement Tool:MIN-S02 -->

Use the supported standards-based OAuth authorization-code integration for protected user data/actions, with valid client registration for the selected flow.

**Applicability:** Services requiring end-user/account authentication. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S03 S256 PKCE advertised and enforced

<!-- ada:requirement Tool:MIN-S03 -->

Support S256 PKCE and publish the corresponding discovery capability; do not accept a code-exchange flow that lacks required PKCE.

**Applicability:** OAuth authorization-code connections. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S04 Protected-resource and authorization-server discovery

<!-- ada:requirement Tool:MIN-S04 -->

Serve correct HTTPS protected-resource metadata with canonical resource and authorization-server identity, and standards-compliant reachable OAuth/OIDC authorization-server metadata; use the required401 discovery challenge.

**Applicability:** OAuth-enabled MCP endpoints. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S05 Resource audience binding and no token passthrough

<!-- ada:requirement Tool:MIN-S05 -->

Issue/accept credentials only for the intended MCP resource; reject wrong-audience tokens and do not pass a client token unchanged through to an upstream resource for another audience.

**Applicability:** Protected tool calls and upstream API delegation. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S06 Verify user credentials and enforce access at the server

<!-- ada:requirement Tool:MIN-S06 -->

Validate credentials and authorization before executing protected operations or returning protected data; reject invalid/missing/expired credentials and enforce the user/resource/scope boundary at a trusted service layer.

**Applicability:** Protected/user-specific tools and consequential actions. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S07 Exact redirect validation and OAuth state protection

<!-- ada:requirement Tool:MIN-S07 -->

Validate registered redirect destinations and securely validate OAuth state; do not allow untrusted redirect substitution.

**Applicability:** OAuth redirects/callbacks. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S08 CIMD identity and redirect metadata validation

<!-- ada:requirement Tool:MIN-S08 -->

Validate the client metadata identity against itsHTTPSURL and registered redirect values and accept only supported token-endpoint client-authentication methods.

**Applicability:** Only if the selected connection implements CIMD. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S09 Keep authentication material out of URLs

<!-- ada:requirement Tool:MIN-S09 -->

Do not expose authentication material in URL query strings or published URLs; use protected header/cookie transport as appropriate.

**Applicability:** Secrets/access/session tokens in connector/API/OAuth requests. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S10 Secure token/secret handling and storage

<!-- ada:requirement Tool:MIN-S10 -->

Keep credentials/tokens confidential and securely stored, using appropriate protected authentication channels rather than exposing them publicly.

**Applicability:** Credentials/tokens stored or handled by the connector. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S11 Refresh-token and replay protection

<!-- ada:requirement Tool:MIN-S11 -->

Protect public-client refresh tokens against replay, validate refresh failures/expiry, and apply required rotation or sender constraints under the selectedOAuthprofile.

**Applicability:** Public OAuth clients and token refresh. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S12 Truthful read-only and destructive operation classification

<!-- ada:requirement Tool:MIN-S12 -->

Provide truthful applicable risk annotations: distinguish read-only operations and identify destructive/irreversible operations so safeguards can act on actual behavior.

**Applicability:** Every exposed operation; hints according to operation type. MCP-style interface / corresponding selected MCP or OAuth profile only. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S13 Accurate narrow tool descriptions and transparent side effects

<!-- ada:requirement Tool:MIN-S13 -->

Describe what each tool actually does, when it is invoked and relevant side effects/limits; descriptions must match schema and behavior and not hide functionality.

**Applicability:** Exposed tool metadata. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S14 Separate read-only and state-changing tool surfaces

<!-- ada:requirement Tool:MIN-S14 -->

Separate read-only and state-changing operations; do not expose one catch-all tool that mixes safe and unsafe methods.

**Applicability:** Tools exposing reads and writes. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S15 No hidden behavioral directives or unauthorized tool steering

<!-- ada:requirement Tool:MIN-S15 -->

Do not include hidden/obfuscated/encoded behavior instructions, seek secrets/protected context, cause unrequested external actions, or steer the model to bypass security/user intent.

**Applicability:** Descriptions/schemas and other model-readable connector metadata. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S16 Do not circumvent platform or upstream security boundaries

<!-- ada:requirement Tool:MIN-S16 -->

Do not evade agent safety/system/sandbox controls or upstream API authorization/access restrictions; keep tool execution within authorized operation boundaries.

**Applicability:** Tool behavior and downstream access. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S17 Server-side input validation and injection defenses

<!-- ada:requirement Tool:MIN-S17 -->

Validate arguments server-side and reject invalid/unauthorized inputs; do not trust model-generated data to enforce security.

**Applicability:** Untrusted model/client-supplied arguments. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S18 Minimize inputs, outputs and collected conversation/log content

<!-- ada:requirement Tool:MIN-S18 -->

Collect/process/return only function- and task-necessary content, and do not collect extraneous conversation data even for logging.

**Applicability:** Tool inputs/results and data/logcollection. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S19 No covert reconstruction of Agent memory/history or conversation profiles

<!-- ada:requirement Tool:MIN-S19 -->

Do not pull/reconstruct/infer full Agent conversation history or hidden memory, and do not expand taskscoped inputs into covert persistent conversation profiling.

**Applicability:** Agent memory/chat/history and long-lived connector context. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S20 Informed consent for irreversible/consequential actions

<!-- ada:requirement Tool:MIN-S20 -->

Require informed human confirmation for consequential/irreversible operations and preserve correct sensitivity labels; annotations are not a substitute for authentication/authorization or consent safeguards.

**Applicability:** Sensitive or irreversible actions, not every read or every write. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

### MIN-S21 Legitimate endpoint/domain/API provenance

<!-- ada:requirement Tool:MIN-S21 -->

Own/control declared endpoints/domains or legitimately proxy authorized APIs; do not impersonate another provider or bypass access restrictions.

**Applicability:** Connector endpoint and downstream APIs. Applicable Tool behavior/data/authorization property; any literal MCP field syntax requires MCP-style interface. Public directory reachability applies only when publishing to that directory.

**Actor:** Tool assessment gates only owned/implemented roles. Agent UI or external AS/client requirements are seam dependencies, not claims that Tool certification proves those components. Published CASA integration/third-party-auth scope still applies.

## Assessment and assurance

Detailed tests are in the [Testing Guide](AI%20Tool%20Testing%20Guide.md).
Applicable published injection, file-traversal, SSRF, IDOR, CSRF, transport, secret
and session outcomes remain mandatory even where a specific sandbox, signature,
scanner or replay-cache mechanism is recommended. Recommendations do not permit
credential logging or invalid certificate trust. Threat categories and rationale
are context rather than additional undisclosed gates.

Minimum conformance does not establish universal safe composition, independent
Tool-side human approval, all-message integrity or durable exactly-once effects.
Implemented enhanced capabilities must be declared and assessed separately.

## References

* [CSA Monitoring & Operational Security](https://modelcontextprotocol-security.io/ttps/monitoring-operational-security/)
* [OWASP MCP Top 10](https://github.com/OWASP/www-project-mcp-top-10/tree/main/2025)
* [CoSAI MCP Security](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md)


## Contributors

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

### Application Security Assessment Working Group Leads

* Alex Duff (Meta) \- ASA WG Chair
* Anna Bhirud (Google) \- ASA WG Vice Chair

### AI Profile Leads

* Brad Ree (Google)
* Alex Duff (Meta)

### Contributors

* Debdutta Guha(Google)
* Nic Watson (Google)
* Abhiraman Gcl (Google)
* Daniel Bond (Meta)
* Tony Balkan (Microsoft)
* Dario Freni (Google)
* TBD

## Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
