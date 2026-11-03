# AI Agent–Tool Interface Contract

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

## Residual assurance and retained Agent obligations

Baseline conformance demonstrates concrete required properties, not universal safe-composition-by-construction, independently verified Tool-side human consent, exactly-once effects, or universal message integrity. The Agent Specification MAY retain stricter MUSTs; this minimum interface does not demote them. Existing Agent HITL full noncryptographic binding/fidelity, consumer distrust, session/nonce/state/PKCE, model/memory/sandbox and no-blind-retry/unknown-outcome honesty remain independently required unless the Agent-owner ledger expressly changes an affected clause. No Agent file is edited here.

## C1 Verifiable Identity Propagation

### Required outcome / retained baseline

For protected/user-specific calls, the Agent MUST present and the Tool MUST validate a user-authorized target-resource credential through the implementation's supported validated signed-OAuth-token OR trusted opaque-introspection mechanism; either is admissible baseline assessment evidence, not a dual-format implementation mandate. Unsupported/unverifiable credentials cannot grant protected access. Wrong-user/audience/expired/unverifiable credentials MUST NOT authorize protected data or actions. Bare identifiers/ambient service authority cannot substitute. Demonstrably safe public/discovery calls MAY be unauthenticated. Downstream access MUST preserve user authority and no cross-audience token passthrough.

### Recommended enhancement

Issuer-minted user identity forwarded per request, per-action parameter binding, dedicated D1 claim shapes and additional Tool re-verification SHOULD remain enhanced recommendations.

## C2 Data / Control Separation

### Required outcome / retained baseline

The Tool MUST NOT embed hidden/obfuscated model-directed behavioral steering or unauthorized instructions in returned content/metadata and MUST independently enforce its inputs and authorization. The Agent MUST treat Tool Output as untrusted data, not instructions or authorization for consequential actions, and coreHITL remains mandatory. Producer tags MUST NOT establish trust.

### Recommended enhancement

Structured/typed output and provenance tagging SHOULD be useful defenses, not proof of security or required wire fields.

## C3 Consent for Consequential Actions

### Required outcome / retained baseline

The Agent MUST obtain and enforce informed human confirmation for consequential/irreversible actions and preserve shown-versus-executed fidelity; it MUST NOT allow Tool content or an honest hint alone to authorize action. The Tool MUST provide truthful applicable MCP readOnlyHint/destructiveHint fields (readOnlyHint:true for reads, destructiveHint:true for applicable irreversible/destructive operations), without inventing every-tool Boolean presence or uniform additive-write semantics, and MUST enforce authentication/authorization plus applicable sensitive-account/admin-MFA floor. The existing stronger Agent-side non-cryptographic user/account/operation/recipient/material-parameter/validity/one-execution binding, explicit bounded-batch enumeration and correlation record remain REQUIRED by the Agent Specification; lowering Tool backstop strength does not relax those Agent duties.

### Recommended enhancement

The following are TOOL-side enhancements: independent elicitation or fail-closed confirmation backstop, independent OOB, full Tool-controlled user/account/operation/recipient/parameter/validity/one-execution tuple, Tool-side bounded-batch enumeration and correlation evidence. These SHOULD remain recommended; cryptographic receipts SHOULD be an optional wire enhancement. This does NOT demote the existing Agent non-cryptographic tuple, bounded-batch and correlation obligations retained above. An optional consent_required signal MAY be used; core Agent HITL does not depend on its presence.

## C4 Sensitive-Action Idempotency and Outcome Reconciliation

### Required outcome / retained baseline

Published applicable token/session expiry, revocation and stateless-session anti-replay/integrity remain mandatory; C4 is not their replacement. No new stable business-intent mechanism is a Tool baseline gate. Under the retained Agent requirements, the existing Agent stable-intent/idempotency identifiers and their reuse/binding rules remain MUST. Any relaxation requires a separate Agent policy decision. Independently, the independently stronger Agent MUST NOT blindly retry when the original outcome remains unknown and MUST report an indeterminate outcome rather than falsely represent success; its identity/session/state/PKCE, model/memory/sandbox and consumer protections are not demoted by this Tool proposal.

### Recommended enhancement

The Tool SHOULD use stable action-intent identifiers, parameter/user/account binding, two-phase preparation where useful, reuse on retries, mismatch rejection, durable duplicate-suppression state and richer outcome reconciliation. Agent stable-ID obligations remain MUST under this proposal. Tool-owned outcome reconciliation and avoidance of blind retry or unsupported success claims SHOULD be implemented. Independently, the Agent MUST retain its no-blind-retry and unknown-outcome honesty requirements under this proposal; this Tool-side recommendation does not demote them.

## Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
