# AI Agent–Tool Identity & Consent Wire Format

> **Status: OPTIONAL conformance profile — not required for ADA certification.**
>
> An Agent **MAY** implement this profile. Doing so is **not** a condition of certification in this
> revision, and an Agent that does not implement it is **not** non-conformant. The profile exists for three
> reasons: it is the **reference upgrade path** for deployments that want verifiable agent↔tool identity
> today; it gives the **ADA Malicious Reference Tool/Agent (MRT/MRA)** a concrete artifact to exercise; and
> it is the candidate text for elevation to mandatory in a future revision **once ecosystem support exists**.
>
> **Why optional.** ADA's mandatory bar is deliberately set at what the most responsible, widely adopted
> implementations can meet today — enough to keep irresponsible implementations out, not so far ahead that
> conformance is unattainable. Agent-minted, per-request signed identity assertions verified at the Tool are
> **not shipped by any tier-1 MCP provider** as of this revision, so requiring them would set an
> unattainable bar. The mandatory requirements live in the AI Agent Specification (§2.4.1, §6.1.x); this
> profile is the optional tier above them — see *Relationship to the mandatory baseline*.
>
> Open Decisions **1, 2, 3 and 5** and the **trust-anchor** question are **resolved** in this revision;
> **Open Decisions 4 (stdio) and 6 (claim namespacing)** remain open. The **Pre-Normative Verification**
> checklist must be cleared before any part of this profile is elevated to mandatory. Published with issue
> **#379**.

## Purpose

The Agent–Tool Interface Contract defines two invariants whose enforceable mechanism does not exist in
baseline MCP and is currently undefined in the ADA specifications:

- **C1 — Verifiable Identity Propagation:** the Agent forwards a per-user identity assertion the Tool can
  cryptographically verify, bound per-action for Sensitive Actions.
- **C3 — Consent for Consequential Actions (deferred tier):** a consent assertion bound to the verified
  user identity and operation parameters (see AI Tool Specification §2.1.1, which defers this tier here).

This profile defines that assertion format ("**D1**") so that the ADA Malicious Reference Tool (MRT) and
Malicious Reference Agent (MRA) have a concrete artifact to exercise, and so that a Tool certified in
isolation can verify identity/consent from any conformant Agent.

## Relationship to the mandatory baseline

ADA's **mandatory** agent↔tool security bar is set in the AI Agent Specification and is calibrated to what
responsible, widely adopted implementations can meet today:

| Layer | Where it lives | Status |
|-------|----------------|--------|
| Transport authentication (OAuth 2.1 / mTLS / rotated keys), PKCE, redirect-URI + state validation | Agent Spec §6.1.1, §6.1.4, §6.1.5 | **Mandatory** — universally implemented |
| A user-scoped, audience-bound credential per tool call; no bare plain-text identifiers; no cross-user reuse; no token passthrough | Agent Spec §6.1.2, §2.4.1; Tool Spec §1.2.3 | **Mandatory** — achievable with standard OAuth 2.1 today |
| Human-in-the-loop consent gate for Sensitive Actions, with shown-vs-executed fidelity | Agent Spec §2.2.2 | **Mandatory** — behavioural, no cryptographic artifact required |
| **Agent-minted, per-request signed identity assertion verified by the Tool; per-action cryptographic binding; signed consent receipt** | **This profile (D1)** | **OPTIONAL** — not shipped by tier-1 providers; reference upgrade path |

The dividing line is deliberate: the mandatory tier requires *behaviours and properties* that keep
irresponsible implementations out — ambient or shared credentials, plain-text user IDs, forwarded tokens,
cross-user contamination, ungated destructive actions. This optional profile adds the *cryptographic
artifact* that makes those properties independently verifiable by the Tool. An Agent that meets the
mandatory tier is conformant; an Agent that also implements D1 is verifiably stronger.

## Conformance tiers *(within this optional profile)*

An Agent that elects to implement D1 implements it in **two tiers**, mirroring the Agent Specification's own
distinction between routine tool calls and Sensitive Actions:

| Tier | Applies to | Artifact | Verifies |
|------|-----------|----------|----------|
| **Baseline** | Every tool request | C1 identity assertion (signed JWT, tool-audience-bound). **No** per-action parameter binding. | Tool-side verification of the user context that Agent Spec §6.1.2 requires the Agent to propagate |
| **Sensitive Action** | Actions the Agent classifies as Sensitive | Baseline **+** per-action binding **+** C3 consent assertion carrying `corr_id` | Tool-side verification of the consent binding that Agent Spec §2.2.2 requires the Agent to enforce |

A routine `search_docs` call therefore needs only a validated, audience-bound JWT. A `transfer_funds` call
needs the full per-action binding and a consent receipt. Tiering keeps the entry cost low for ordinary tool
traffic while reserving the expensive guarantees for the actions that warrant them.

An Agent implementing D1 **partially** — Baseline only, without the Sensitive-Action tier — is a valid
deployment choice and still satisfies the mandatory baseline, but MUST NOT claim D1 conformance for
Sensitive Actions.

**Classification is the Agent's.** Which operations are Sensitive Actions is determined by the Agent on its
own criteria (irreversible; transfers value or money; mutates or shares user data beyond the current task;
grants or expands access), per the Interface Contract and Agent Spec §2.2. It does **not** depend on the
Tool emitting the optional `consent_required` signal — see *C3* below.

## Relationship to MCP and existing standards

- **Target revision: MCP 2025-11-25.** MCP has **no native message-signing/integrity mechanism** and (as of
  2025-11-25) **no native per-user identity, consent, or scope field** on tools — confirmed against the core
  base, tools, authorization, and elicitation specifications (extensions such as `modelcontextprotocol/ext-auth`
  and SEPs are **not yet reviewed** — see *Pre-Normative Verification*). Identity/consent must therefore be
  conveyed **in-band in the JSON-RPC message but outside the tool's `arguments`/`inputSchema`, as an
  ADA-defined signed artifact.**
- **Reuse over invention.** This profile reuses: OIDC (identity claim semantics), **IETF OAuth
  Identity Assertion JWT Authorization Grant (ID-JAG), draft-04** (optional upstream identity source — see
  below), RFC 8693 (token exchange / delegation), RFC 8707 + RFC 9068 + RFC 9728 (audience binding &
  resource-server behaviour on HTTP), RFC 9396 (Rich Authorization Requests, per-action binding),
  RFC 9449 (DPoP), RFC 7638 (JWK thumbprint), RFC 8785 (JCS canonicalization), and RFC 7515/7519 (JWS/JWT).

## Carrier: `_meta` canonical, `Authorization` header conformant on HTTP

***Resolves Open Decision #1.*** The profile is **multi-modal**: one canonical placement that works
everywhere, plus a header path that is conformant on the transport where headers exist.

- **`params._meta` is canonical.** The assertions travel in the `tools/call` request's **`params._meta`**
  object. `_meta` is MCP's reserved extension point and rides in the JSON-RPC message body, so it is carried
  **identically over stdio and Streamable HTTP** — the only transport-agnostic placement.
- **`Authorization: Bearer <C1 JWT>` is equally conformant for Streamable HTTP.** Agent Spec §6.1.2's own
  test procedure inspects "the intercepted request's payload, **metadata, or headers**," and its verification
  criterion accepts the token attached "to the **metadata or headers** of every downstream tool invocation."
  A `_meta`-only rule would therefore be *narrower than the specification it implements*. On HTTP the header
  is the natural carrier, is already intercepted by the §6.1.1/§6.1.2 test procedures, and sidesteps the
  `_meta` proxy-preservation concern entirely for the security-critical remote transport. The **C3 consent
  assertion**, having no standard header, travels in `_meta` on both transports.
- **Precedence.** If both are present, the Tool MUST verify both and MUST reject the request when they are
  not identical assertions. A Tool MUST accept at least the canonical `_meta` placement.
- **Keys (reverse-DNS, per MCP's SHOULD):** `org.appdefensealliance/identity` (C1) and
  `org.appdefensealliance/consent` (C3). Prefixes whose second label is `mcp`/`modelcontextprotocol` are
  reserved for MCP; `org.appdefensealliance` is not. *(Verification task: confirm these sub-keys are not
  reserved in `schema/2025-11-25/schema.ts`.)*
- **Not in `arguments`.** The assertion MUST NOT be placed in `params.arguments`: it would collide with the
  tool's `inputSchema`, be visible to the model, and risk being stripped by `additionalProperties:false`.
- **Preservation requirement (ADA-defined).** MCP's base spec is **silent** on whether `_meta` is preserved
  end-to-end through servers/gateways/proxies. Where `_meta` is the carrier, this profile REQUIRES that
  intermediaries forward the `org.appdefensealliance/*` keys **unchanged**. Because C1/C3 are **compact
  JWS/JWT (embedded payload)**, tampering with the **assertion itself** is cryptographically detectable at the
  verifier. Note the signature covers only the assertion's claims: the `tools/call` `name`/`arguments` are
  integrity-bound **only** via the per-action binding, which is REQUIRED for Sensitive Actions — so for
  **Baseline-tier** calls the arguments are **not** integrity-protected against a malicious intermediary. This
  residual risk is **accepted at the Baseline tier**: it is the same exposure any bearer-token API has, and the
  actions that would make argument tampering consequential are precisely those that require the Sensitive-Action
  tier. The remaining risk is *silent stripping* (availability), in which case the Tool MUST **fail closed**.
  *(Verification task: re-check the MCP 2025-11-25 transports/lifecycle pages for any preservation guarantee.)*

## C1 — Identity Assertion (Baseline tier, every Tool request)

An ADA-defined, **tool-audience-bound** compact JWS/JWT.

| Field | Tier | Value / meaning |
|-------|------|-----------------|
| `typ` (header) | Baseline | `application/ada-identity+jwt` (distinct `typ` prevents cross-use) |
| `alg` (header) | Baseline | asymmetric allowlist only (e.g. `ES256`/`EdDSA`); `none` and `HS*` MUST be rejected |
| `kid` (header) | Baseline | key id into the issuer's JWKS/trust bundle |
| `iss` | Baseline | trusted IdP/issuer that authenticated the end user (on the Tool's pinned allowlist) |
| `sub` | Baseline | stable end-user identifier (used as `{JWT.sub}` for downstream scoping per Tool Spec §2.2.2) |
| `aud` | Baseline | **the specific target Tool / canonical MCP-server identifier** (defeats confused-deputy/redirection) |
| `client_id` | Baseline | the calling Agent |
| `act` | Baseline | `{ "sub": <agent/workload id> }` — RFC 8693 delegation (subject = user, actor = agent). This is the wire-level expression of **no token passthrough**, the rule now normative in Tool Spec §1.2.3. |
| `iat`, `nbf`, `exp` | Baseline | short lifetime (minutes); per-request freshness |
| `jti` | Baseline | unique id; Tool de-dupes for replay defense (pairs with Tool Spec §1.4 and Agent Spec §6.1.3) |
| `cnf` | **SHOULD** | *(RFC 7800)* PoP binding: `jkt` (JWK thumbprint, RFC 7638) for **DPoP** (RFC 9449), or `x5t#S256` for **mTLS** (RFC 8705) — see *Proof-of-possession* |
| **per-action binding** | **Sensitive Actions — REQUIRED** | see below |

### Per-action binding (Sensitive Actions)

***Resolves Open Decision #2 — both forms permitted, RAR canonical.***

- **RFC 9396 `authorization_details` (canonical).** Structured (`type`/`actions`/`locations`/`identifier` +
  fields pinning the actual arguments, e.g. amount, destination); auditable; the Tool re-verifies each field.
  Favoured for alignment with ID-JAG's RAR endorsement and because an auditor can read the binding.
- **`aph` (action-parameter hash) — OPTIONAL lightweight alternative.**
  `base64url(SHA-256(JCS(bind_object)))` where `bind_object = { tool: params.name, args: params.arguments, aud }`
  (`jti` is already a signed claim and is **not** folded into `aph`); opaque, simple (DPoP-`ath` style). Suitable
  where arguments are large or the Agent cannot enumerate them structurally.

A Tool MUST support `authorization_details` and MAY additionally support `aph`. An assertion carrying both
MUST be rejected as ambiguous.

### Proof-of-possession

***Resolves Open Decision #3 — `SHOULD`, at both tiers.***

`cnf`-based PoP (DPoP, RFC 9449, or mTLS, RFC 8705) is **RECOMMENDED (SHOULD)** and is **not** elevated to MUST
for Sensitive Actions. Rationale: Agent Spec §6.1.3's freshness criteria are satisfied by the combination of a
short-lived assertion, a Tool-enforced `jti` replay cache, and TLS — so within the lab-testable scope of this
profile PoP adds defense in depth rather than a distinct testable property. PoP also has effectively no
production adoption across tier-1 MCP providers today, and a MUST would make the profile unimplementable rather
than merely demanding. Deployments handling irreversible or high-value actions are strongly encouraged to
enable it, and a future revision may elevate it once ecosystem support exists.

## C3 — Consent Assertion (Sensitive Actions; fills Tool Spec §2.1.1)

Same envelope, `typ = application/ada-consent+jwt`. Binds the four things C3 requires:

| Field | Meaning |
|-------|---------|
| `sub` | the SAME verified end user as C1 (consent tied to identity) |
| `aud` + operation | the specific Tool + operation (consent bound to one action) |
| per-action binding | `authorization_details` (or `aph`) — Tool recomputes and rejects on mismatch (defeats "consent to X, execute Y") |
| `corr_id` | correlation ID for audit (satisfies the C3 Agent obligation to record, and Agent Spec §2.2.2's correlation-ID criterion) |
| `jti`, `nbf`, `exp`, optional `cnf.jkt` | anti-replay |
| `act` | agent as actor (RFC 8693) |

**The receipt is Agent-minted and does not depend on the Tool's `consent_required` signal.** The Agent
classifies the action as Sensitive on its own criteria, obtains user consent, mints the C3 assertion, and the
Tool verifies it. This keeps consent agent-side per Contract **C3** and removes the dependency identified in
issue **#399** — where the Agent-side consent test was keyed to a Tool signal that the Tool Specification
defines only as a MAY. Where a Tool *does* emit `consent_required`, the Agent MUST honour it; its absence MUST
NOT prevent the Agent from gating an action it independently classifies as Sensitive.

**Relationship to MCP elicitation:** elicitation is the interactive *moment-of-consent trigger* only; its
response carries **no signature or identity binding** (client-provided identity is forgeable), so it is
**not** an acceptable consent receipt. The verifiable artifact is this signed C3 JWT. (Agent-side conformance
to the elicitation protocol itself is tested separately by Agent Spec §2.2.3.)

## Trust anchor / key distribution

***Resolved — pinned allowlist, bootstrapped from existing OAuth metadata.***

The Tool holds a **pinned issuer allowlist / trust bundle**; open `iss`-based discovery is forbidden. The
verification key is resolved by `kid` via the issuer's **OIDC Discovery `jwks_uri`, constrained by that
allowlist** — a key is only ever fetched from an issuer already on the list.

Bootstrapping reuses infrastructure the profile already assumes rather than introducing a parallel trust
system: the Agent↔Tool relationship is pre-configured (the Agent maintains a tool registry with pinned
identities, per the agent-side provenance control proposed in issue **#401**), and on HTTP the Tool already
advertises itself via **RFC 9728** protected-resource metadata as part of the OAuth flow that Agent Spec
§6.1.4/§6.1.5 require. Trust anchors are therefore established at configuration time, in the same step that
pins the tool identity.

Key rotation via `kid` + JWKS cache TTL with refresh-on-unknown-`kid` and an overlap window. **SPIFFE** trust
bundles (JWT-SVID for the agent/actor) and an **ADA-run/endorsed registry or CA** (OWASP ANS-style PKI) remain
permissible deployment substrates for the allowlist, but neither is required by this profile.

## Tool-side verification algorithm

1. Reject if `alg` not on the asymmetric allowlist (`none`/`HS*` → fail).
2. Resolve key by `kid`; **`iss` MUST be on the pinned allowlist**; verify signature.
3. Validate `aud` == this Tool, `exp`/`nbf`, and `jti` not previously seen (replay). If both a header and a
   `_meta` assertion are present, verify both and reject on any mismatch.
4. **Baseline tier ends here.** For a Sensitive Action, additionally recompute the per-action binding — for
   `authorization_details`, match each field against the **actual** `params.name`/`params.arguments`; for `aph`,
   JCS-hash the full `bind_object` (`{ tool: params.name, args: params.arguments, aud }`) — and reject on mismatch.
5. For a Sensitive Action: additionally require a valid C3 Consent Assertion bound to the same `sub` +
   operation + parameters, carrying `corr_id`.
6. Any failure → **hard-fail (`401`/`403`)**, fail closed. (MRA exercises forged/missing/mismatched/replayed
   assertions against these steps.)

## Mapping to Agent Specification test procedures

D1 is **one sufficient way — not the only way — to satisfy** the mandatory test procedures below. A lab
assessing an Agent that implements D1 may accept these artifacts as evidence; an Agent that satisfies the
same procedures by other conformant means (e.g. a standard OAuth 2.1 JWT access token scoped to the user
and audience-bound to the Tool) is equally conformant. The Agent Specification therefore does **not**
reference this profile normatively.

| Agent Spec test | What it requires | Artifact D1 supplies (if implemented) |
|-----------------|------------------|----------------------------------------|
| §6.1.2 Cryptographic Validation of User Context | "user context is passed as a cryptographically signed token (e.g., a JWT)" in payload, metadata, or headers | **Baseline C1** assertion (either carrier) |
| §2.4.1 Verifiable Identity Forwarding | a user-scoped, audience-bound credential per request; per-action binding is the optional tier | **Baseline C1**; **per-action binding** at the Sensitive tier |
| §2.2.2 Human in the Loop | consent bound to the user identity and operation parameters, recorded with a correlation ID | **C3** assertion (`sub` + binding + `corr_id`) |
| §6.1.3 Message Freshness | "unique nonce or accurate timestamp" per request | `jti` + short `exp`, with Tool-side replay cache |

## Relationship to ID-JAG (why it is upstream, not the wire artifact)

ID-JAG (draft-04, IETF-WG-adopted) is a strong per-user OBO primitive, but its **`aud` is the receiving
Authorization Server, not the Tool** — it is consumed by the app's AS, which then mints an ordinary access
token for the Tool. It therefore satisfies "the Agent forwards a verifiable per-user identity the app's AS
can verify," **not** "the Tool verifies it at the resource endpoint," and it defines **no** per-action
primitive (deferring to RFC 9396). Hence **C1 is ADA-defined and tool-audience-bound**, and ID-JAG is an
**optional upstream source** of verified user identity that an issuer MAY use to mint the C1 assertion.
(Exact ID-JAG identifiers, for reference: token type `urn:ietf:params:oauth:token-type:id-jag`, header
`typ: oauth-id-jag+jwt`, minted via RFC 8693 token-exchange, redeemed via RFC 7523 `jwt-bearer`.)

## Per-transport placement

- **Streamable HTTP (remote):** C1 travels in **either** `params._meta` **or** the `Authorization` header
  (both conformant — see *Carrier*); C3 travels in `params._meta`. **Additionally** the Tool acts as an
  OAuth 2.1 Resource Server — advertising its audience via RFC 9728 protected-resource metadata, requiring
  RFC 8707 resource-indicator audience binding, and optionally validating DPoP. (PKCE/S256 applies to the
  Agent↔authorization-server code flow, not to the Resource Server.)
- **stdio (local):** *(pending Open Decision #4)* if applied, C1/C3 travel **only** in `params._meta` (OAuth
  does not apply — MCP: stdio servers SHOULD obtain credentials from the environment). Anti-replay = `jti`
  de-dup, for which the Tool MUST retain a replay cache for at least the maximum token `exp` and across process
  recycling (note the tension with the statelessness guidance in Tool Spec §2.2.1); any server nonce is bound at
  the DPoP/PoP layer (signed by the Agent at request time), **not** inside the pre-minted identity JWT.

Both transports MUST use identical **JCS (RFC 8785)** canonicalization so Agent and Tool compute the same
per-action binding.

## Open WG decisions

**Resolved in this revision** (proposed by the Chair following the industry-bar review; WG ratification still
required): **#1 carrier** — multi-modal, `_meta` canonical + `Authorization` conformant on HTTP · **#2
per-action binding** — RFC 9396 canonical, `aph` optional · **#3 proof-of-possession** — `SHOULD`, not MUST ·
**#5 delegation chains & headless agents** — multi-hop `act` chains **deferred to a future revision**,
consistent with the agent-to-agent (A2A) / multi-agent composition deferral already recorded in the Agent
Specification's scoping section · **trust anchor** — pinned allowlist bootstrapped from existing OAuth metadata.

**Still open:**

4. **stdio scope** — does ADA identity/consent apply over stdio, or does local trust rest on the parent
   process (Tool Spec §1.1.1's "authorized parent process")? **Blocked on issue #452:** §6.1.1 carries the
   note *"This requirement only applies to agents which support remote tools,"* but **§6.1.2 (cryptographic
   user context) and §6.1.3 (message freshness) carry no such note**, so as written they apply to *all*
   agents — including stdio-only ones. This profile therefore **cannot** declare stdio out of scope without
   contradicting §6.1.2. Resolve the Specification's applicability first, then settle this decision to match.
6. **Claim namespacing** — reuse registered claims / `authorization_details` vs. mint ADA-private claims
   (`aph`, `corr_id`); register any new claims with IANA.

## Pre-normative verification tasks

- [ ] Re-check `_meta` end-to-end preservation in the MCP 2025-11-25 **transports** and **lifecycle** pages
      (base protocol is silent). Now lower-severity for HTTP (the header carrier is conformant), but still
      decisive for stdio and for C3 on both transports.
- [ ] Examine the external `modelcontextprotocol/ext-auth` extensions repo (and any SEP, e.g. SEP-835) for a
      per-user identity/consent extension that could overlap or supersede this `_meta` approach.
- [ ] Confirm the `org.appdefensealliance/identity` and `.../consent` sub-keys are not reserved in
      `schema/2025-11-25/schema.ts`, and confirm `CallToolRequest` `additionalProperties` behaviour.
- [ ] Confirm ID-JAG remains at draft-04 (pin) and track for RFC/claim changes.
- [ ] Confirm no conflict between the `Authorization: Bearer <C1>` carrier and a Tool's own OAuth 2.1
      resource-server access token on Streamable HTTP; if a deployment needs both, specify which header
      carries which (candidate: C1 in `Authorization`, tool access token via the established OAuth flow, or a
      dedicated `ADA-Identity` header).

## Non-normative examples (straw-man)

**Baseline tier** — routine call, C1 only, HTTP header carrier:

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

## Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
