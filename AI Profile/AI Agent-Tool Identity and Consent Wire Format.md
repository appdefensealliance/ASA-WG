# AI Agent–Tool Identity and Consent Wire Format

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

## Purpose

### Required outcome / retained baseline

The proposed minimum is all applicable published CASA plus clearly applicable leading security practices. The baseline can be satisfied by the implementation's SUPPORTED validated OAuth JWT OR trusted opaque-token introspection; either is admissible assessment evidence, not a requirement that every Tool support both formats. Unsupported or unverifiable credentials MUST NOT grant protected access. Safe public/discovery unauthenticated access MAY exist.

### Recommended enhancement

D1 issuer-minted user identity, Agent-assembled requests and per-action consent attestations SHOULD remain an enhanced interoperability path.

## Relationship to the mandatory baseline

### Required outcome / retained baseline

Applicable CASA clauses and minimum S01–S21 properties MUST govern, under original scope/strength/actor qualifications. Core Agent HITL and trusted Tool authorization remain required.

### Recommended enhancement

TLS 1.3, specialized PoP, Agent-brokered D1, per-action tuple/receipts, whole-message MAC and durable intent SHOULD be recommendations beyond minimum.

## Conformance tiers *(within this optional profile)*

### Required outcome / retained baseline

Protected access MUST satisfy baseline authentication/authorization regardless of selected tier; missing optional-tier claims MUST NOT on their own fail baseline.

### Recommended enhancement

The optional profile has an Enhanced Identity tier and an Enhanced Action tier. Enhanced Action SHOULD add parameter-bound consent. Partial adoption MAY be reported transparently; neither tier names the certification minimum.

## Relationship to MCP and existing standards

### Required outcome / retained baseline

Applicable selected MCP/OAuth discovery, user-resource binding and verification requirements MUST remain.

### Recommended enhancement

ADA JWS/JWT, RAR/APH/JCS, DPoP, ID-JAG and MCPextension integration SHOULD be reusable enhanced substrates rather than a required universal wire.

## Carrier: `_meta` canonical, `Authorization` header conformant on HTTP

### Required outcome / retained baseline

A carrier used for baseline authentication MUST preserve and validate credentials and MUST NOT expose secrets as ordinary model tool arguments. Conflicting identity claims MUST NOT be used to grant unauthorized access.

### Recommended enhancement

Canonical params._meta and HTTPAuthorization D1 carriers, exact dual-carrier equality, preservation keys and failure-on-stripping SHOULD be the enhanced profile behavior.

### Recommended enhanced carriers

D1 SHOULD use `params._meta["org.appdefensealliance/identity"]` for identity and `params._meta["org.appdefensealliance/consent"]` for consent. On HTTP, `Authorization: Bearer <D1 identity JWT>` MAY carry identity instead. Consent MAY remain in `_meta`. D1 SHOULD keep assertions outside `params.arguments`, preserve signed bytes across intermediaries, and reject unequal duplicate carriers. These carrier choices are not universal minimum requirements. A credential carried here and relied upon for protected authorization MUST remain valid and verifiable; silently stripping the only required credential cannot permit protected execution.

## C1 — Enhanced Identity Assertion (optional D1 tier)

### Required outcome / retained baseline

If a presented token is used to authorize protected access, the Tool MUST validate its signature OR trustworthy introspection, applicable trusted issuer/key, audience/resource, expiry/not-before and scopes. It MUST reject unverifiable baseline identity. Applicable CASA stateless-token<=24h/security/strong-crypto requirements remain.

### Recommended enhancement

D1specific typ/kid/act/client_id/jti/short-minute lifetime, asymmetric-only preference, request-level replay-cache and RAR/APH parameter claims SHOULD be used within enhanced D1. RAR support SHOULD be provided; APH MAY be an alternative; ambiguity SHOULD be rejected.

### Recommended enhanced identity schema

D1 SHOULD use the following signed envelope as an enhanced interoperability option, not as the only admissible baseline credential:

| Field | Proposed interpretation |
|---|---|
| `typ` | SHOULD be `application/ada-identity+jwt` to distinguish credential use. |
| `alg` | SHOULD use an asymmetric allowlist such as ES256/EdDSA for D1. Any baseline signed credential MUST use a valid trusted permitted algorithm and signature; unsigned `none` is not valid signed authentication. Standards-valid symmetric OAuth JWTs are not universally rejected merely by this D1 preference. |
| `kid` | SHOULD select the trusted issuer's verification key/cache. |
| `iss` | The issuer MUST be trusted if the assertion is relied upon for baseline authority. |
| `sub` | MUST establish the verified end user when protected access is user-specific; a bare unverified identifier is insufficient. |
| `aud` | MUST identify the intended Tool/resource when used for baseline authority. |
| `client_id` | SHOULD identify the calling Agent. |
| `act` | SHOULD encode the actor/delegation context, e.g. `{ "sub": <agent/workload id> }`. A literal `act` field is not proof of no token passthrough and is not universally mandatory. |
| `iat`, `nbf`, `exp` | SHOULD express a short enhanced lifetime, typically minutes; applicable validity checks MUST succeed when used for baseline authority. The independent CASA maximum is <=24h only for non-revocable stateless authentication tokens. |
| `jti` | SHOULD provide per-request replay identification/cache for enhanced D1. Mandatory CASA stateless-session replay protection remains, but does not require this literal field on every MCP call. |
| `cnf` | SHOULD bind DPoP/JWK thumbprint (`jkt`) or mTLS (`x5t#S256`) for defense in depth. |
| per-action binding | SHOULD be supported for enhanced sensitive actions, not universally required for baseline certification. |

D1 SHOULD support RFC9396 `authorization_details` with action/target/argument details. `aph` MAY be a lightweight alternative: `base64url(SHA-256(JCS({ tool: params.name, args: params.arguments, aud })))`; signed `jti` is not folded into that hash. The implementation SHOULD recompute/match the actual action parameters and reject conflicting simultaneous forms as ambiguous. If a field or proof is the means by which baseline authority is granted, invalid or mismatched authority MUST NOT be accepted. JCS/RAR/APH choices themselves do not create universal minimum gates.

## C3 — Enhanced Consent Assertion (optional D1 action tier)

### Required outcome / retained baseline

Core Agent consequential-action HITL and shown-versus-executed fidelity MUST remain; Tool authentication/authorization cannot be satisfied by an unverified consent claim.

### Recommended enhancement

Signed C3receipt, user/account/operation/recipient/parameter/correlation/expiry/single-use binding and independent verification SHOULD remain enhanced. Tool-side elicitation/OOB SHOULD provide backstops.

### Recommended enhanced consent schema

D1 SHOULD use `typ = application/ada-consent+jwt`, the same verified `sub`, intended `aud` plus operation, `authorization_details` or `aph` for parameters, audit `corr_id`, validity/replay `jti`/`nbf`/`exp`, optional PoP, and actor `act`. It SHOULD reject altered, expired, consumed or cross-user/action receipts when implementing this enhancement. A signed receipt is not required for Tool baseline certification, and Agent-minted claims do not themselves prove that a malicious Agent presented a human approval. Independent Tool OOB confirmation SHOULD provide additional assurance.

Core Agent human confirmation and its independently stronger non-cryptographic binding/fidelity obligations remain required. A Tool confirmation mechanism MAY supplement them; it MUST NOT authorize otherwise invalid baseline access. No receipt absence alone is a baseline failure.

## Trust anchor / key distribution

### Required outcome / retained baseline

Baseline verification keys/issuers MUST be trusted and fetched without unauthorized access/SSRF; baseline secrets MUST meet CASA storage/access controls.

### Recommended enhancement

Pinned issuer allowlist/trust bundle, constrained JWKS bykid, TTLrefresh/rotation overlap, SPIFFE/registry substrates SHOULD be enhanced implementation guidance.

### Issuer roles and assertion meaning

These checks apply when D1 is used to establish protected authority or a claimed
enhanced consent capability. Adopting D1 remains optional.

| Assertion | `iss` and signer role | Meaning |
| --- | --- | --- |
| C1, `application/ada-identity+jwt` | The trusted end-user identity issuer; `kid` selects a key authorized for this identity type and the asserted user/delegation scope. | Authenticated user authority, with intended resource and scope independently verified. The Agent brokers issuer minting or forwards the verified assertion. Its own consent/workload key cannot authenticate an arbitrary user. |
| C3, `application/ada-consent+jwt` | Explicit `iss` identifies the actual consent signer. An Agent issuer/key may be authorized for an Agent consent attestation. | A signature held only by the Agent proves an Agent attestation about a consent event and parameter binding. It does not prove that a human saw or approved those parameters. |
| C3 with a claim of independently verified human approval | A separately authorized user/approval issuer or authenticator over the same action binding, whose approval key is not held by the Agent. | Additional independently verified approval, supported by actual user/step-up evidence and end-to-end parameter verification. |

The trusted key registry MUST record allowed assertion types and signing roles
for each `(iss, kid)` accepted as authority. Verify `typ` against those permissions
before accepting the claims; a valid signature and presence on an issuer list alone
are insufficient. A key authorized only for C3 MUST NOT authorize C1. A Tool MUST
reject a D1 C1 signed solely by a key controlled by the Agent named in `client_id`
or `act.sub`; obtain a separately trusted issuer-signed user assertion instead.
An independently verified upstream user assertion can be checked under its own
declared delegation profile; an Agent wrapper does not expand its authority.

To claim independently verified human consent, verify an approval artifact from
a key the Agent does not hold over the exact action binding, such as a WebAuthn
assertion with an `aph`/JCS-derived challenge or an issuer assertion minted after
step-up. Bind user/account, operation, recipient, parameters, validity and replay
context as declared by that enhanced capability. If only the Agent signature is
present, label the result an Agent attestation. This additional capability is not
a universal Tool certification gate and does not replace the Agent's own HITL.

### Enhanced-profile negative checks

- Present a C1 signed by a consent-only Agent key, including a forged `sub`; reject it as user authority even if its signature is valid.
- Present a valid signature with an unsupported `typ`, issuer/key role or resource/scope; reject protected authority.
- Present an Agent-only C3 and verify it is reported as an Agent attestation; do not credit independently verified human approval.
- Where independent approval is claimed, change the action parameters or remove the independent approval artifact; the claimed capability must not pass. Any attempt to use that failure to bypass mandatory authorization must deny protected execution.

## Tool-side verification algorithm

### Required outcome / retained baseline

First decide whether an operation is protected. On protected operations, validate selected baseline credential and user/resource/scope authority before execution; failures MUST deny protected data/side effects. Noauth MAY be used for demonstrably safe public/discovery operations.

### Recommended enhancement

The original D1algorithm SHOULD validate format, optional jti replaycache, dual carriers, RAR/APH parameters and C3receipt. Report enhancement failures as advisory/optional-profile findings unless they also violate a mandatory auth/data rule.

### Proposed two-stage verification

1. Classify the operation as protected/user-specific or demonstrably safe public/discovery.
2. On protected operations, validate the selected baseline signed token or opaque introspection, trusted issuer/key and permitted assertion role/type, user, intended resource/audience, applicable expiry/not-before and scopes. Required authority failures MUST deny protected output or side effects.
3. If optional D1 is supported, the Tool SHOULD verify its recommended envelope/dual-carrier rules, replay cache, action binding and consent receipt. Missing optional D1 on a route that has valid alternate baseline authority is not a minimum failure.
4. If any optional artifact is relied upon to grant baseline authority, the necessary authority validation MUST succeed. An invalid optional proof cannot bypass mandatory security by being called advisory.
5. Record enhancement/profile findings separately from minimum failures; only an independently identified baseline breach changes the baseline result.

## Mapping to Agent Specification test procedures

### Required outcome / retained baseline

Agent baseline authentication/HITL requirements and CASA floor MUST be assessed by their required properties, not proof that D1 was selected.

### Recommended enhancement

D1 artifacts SHOULD be accepted as one evidence route where implemented; specialized nonce/receipt fields SHOULD be assessed as enhancements.

## Relationship to ID-JAG (why it is upstream, not the wire artifact)

### Required outcome / retained baseline

Resource-scoped downstream credentials MUST preserve the selected baseline no-token-passthrough/user-authority outcome.

### Recommended enhancement

ID-JAG SHOULD remain an optional upstream identity/delegation source; it is not the Tool-facing access-token audience nor an obligatory action-binding format.

## Per-transport placement

### Required outcome / retained baseline

Public remote protected OAuth integrations MUST retain the shared discovery/resource/PKCE/redirect and validation properties under applicable actor roles.

### Recommended enhancement

Transport-specific D1carrier, JCS canonicalization and local process-surviving jti cache SHOULD remain enhanced recommendations within the targeted public-remote model.

## Open WG decisions

### Required outcome / retained baseline

No baseline security outcome may be bypassed by unresolved wire design decisions.

### Recommended enhancement

Carrier/RAR/PoP/claim namespacing/trust-anchor/A2A deferral decisions SHOULD remain design guidance; no automatic ratification/publication occurs.

## Pre-normative verification tasks

### Required outcome / retained baseline

Mandatory baseline tests MUST still be satisfiable using supported valid standardOAuth/opaque authorization mechanisms.

### Recommended enhancement

Pre-normative ext-auth/carrier/key-name/ID-JAG/header compatibility checks SHOULD precede optional wire adoption or any later mandatory elevation.

## Non-normative examples (straw-man)

### Required outcome / retained baseline

Examples do not add baseline requirements.

### Recommended enhancement

Preserve both ordinary identity and sensitive parameter/consent examples as non-normative enhanced examples.

### Preserved non-normative enhanced examples

**Enhanced Identity tier** — routine call, C1 only, HTTP header carrier:

```http

POST /mcp HTTP/1.1

Authorization: Bearer eyJ0eXAiOiJhcHBsaWNhdGlvbi9hZGEtaWRlbnRpdHkrand0...<JWS>

Content-Type: application/json

{ "jsonrpc": "2.0", "id": 7, "method": "tools/call",

  "params": { "name": "search_docs", "arguments": { "q": "retention policy" } } }

```

Decoded C1 payload (illustrative): `{ "iss":"https://idp.example", "sub":"user_123",

"aud":"https://tool.example/mcp", "client_id":"agent_abc", "act":{"sub":"agent_abc"}, "iat":..., "nbf":...,

"exp":..., "jti":"..." }` — no per-action binding at this tier.

**Sensitive Action tier** — C1 with per-action binding + C3 consent receipt, `_meta` carrier (stdio):

```json

{

  "jsonrpc": "2.0", "id": 42, "method": "tools/call",

  "params": {

    "name": "transfer_funds",

    "arguments": { "amount": 500, "to": "acct_998" },

    "_meta": {

      "org.appdefensealliance/identity": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9hZGEtaWRlbnRpdHkrand0...<JWS>",

      "org.appdefensealliance/consent":  "eyJ0eXAiOiJhcHBsaWNhdGlvbi9hZGEtY29uc2VudCtqd3Q...<JWS>"

    }

  }

}

```

Decoded C1 payload (illustrative): as above, plus

`"authorization_details":[{"type":"ada_tool_action","actions":["transfer_funds"],"amount":500,"to":"acct_998"}]`.

Decoded C3 payload (illustrative): same `sub`/`aud`, the same `authorization_details`, plus

`"corr_id":"01JD…"`.

## References

MCP 2025-11-25 (base / tools / authorization / elicitation) · Agent–Tool Interface Contract (C1, C3) ·

AI Agent Specification §2.2.2, §2.2.3, §2.4.1, §6.1.1–§6.1.5 ·

AI Tool Specification §1.1.1, §1.2.2, §1.2.3, §1.4, §2.1.1, §2.2.2 · ID-JAG draft-04 · OIDC Core 1.0 ·

RFC 7515 / 7519 / 7523 / 7638 / 7800 / 8693 / 8705 / 8707 / 9068 / 9396 / 9449 / 9728 / 8785 ·

CoSAI MCP Security §3.2.1–3.2.2 · OWASP Top 10 for Agentic Applications 2026 ASI03 ·

AIUC-1 × OWASP crosswalk (Gap: signed per-action auth artifacts).

- [MCP authorization profile 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- RFCs: [7515](https://www.rfc-editor.org/rfc/rfc7515), [7519](https://www.rfc-editor.org/rfc/rfc7519), [7523](https://www.rfc-editor.org/rfc/rfc7523), [7638](https://www.rfc-editor.org/rfc/rfc7638), [7800](https://www.rfc-editor.org/rfc/rfc7800), [8693](https://www.rfc-editor.org/rfc/rfc8693), [8705](https://www.rfc-editor.org/rfc/rfc8705), [8707](https://www.rfc-editor.org/rfc/rfc8707), [9068](https://www.rfc-editor.org/rfc/rfc9068), [9396](https://www.rfc-editor.org/rfc/rfc9396), [9449](https://www.rfc-editor.org/rfc/rfc9449), [9728](https://www.rfc-editor.org/rfc/rfc9728), [8785](https://www.rfc-editor.org/rfc/rfc8785).

## Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
