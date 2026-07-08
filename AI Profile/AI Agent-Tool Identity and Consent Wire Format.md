# AI Agent–Tool Identity & Consent Wire Format

> **Status: DRAFT / RFC — for Working Group feedback.** This document is a design proposal, not
> ratified normative text. Sections marked **[OPEN DECISION]** require a WG determination, and the
> **Pre-Normative Verification** checklist must be cleared before any requirement here becomes binding.
> It is published together with issue **#379** to solicit feedback.

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

## Carrier: `params._meta`

- The assertions travel in the `tools/call` request's **`params._meta`** object. `_meta` is MCP's reserved
  extension point and rides in the JSON-RPC message body, so it is carried **identically over stdio and
  Streamable HTTP** — the only transport-agnostic placement. (OAuth/`Authorization` headers exist on
  Streamable HTTP only; stdio has no headers.)
- **Keys (reverse-DNS, per MCP's SHOULD):** `org.appdefensealliance/identity` (C1) and
  `org.appdefensealliance/consent` (C3). Prefixes whose second label is `mcp`/`modelcontextprotocol` are
  reserved for MCP; `org.appdefensealliance` is not. *(Verification task: confirm these sub-keys are not
  reserved in `schema/2025-11-25/schema.ts`.)*
- **Not in `arguments`.** The assertion MUST NOT be placed in `params.arguments`: it would collide with the
  tool's `inputSchema`, be visible to the model, and risk being stripped by `additionalProperties:false`.
- **Preservation requirement (ADA-defined).** MCP's base spec is **silent** on whether `_meta` is preserved
  end-to-end through servers/gateways/proxies. This profile therefore REQUIRES that intermediaries forward
  the `org.appdefensealliance/*` `_meta` keys **unchanged**. Because C1/C3 are **compact JWS/JWT (embedded
  payload)**, tampering with the **assertion itself** is cryptographically detectable at the verifier. Note the
  signature covers only the assertion's claims: the `tools/call` `name`/`arguments` are integrity-bound **only**
  via the per-action binding, which is REQUIRED for Sensitive Actions — so for **non-Sensitive** calls the
  arguments are **not** integrity-protected against a malicious intermediary (accept this residual risk, or
  extend per-action binding to all calls — **[OPEN DECISION]**). The remaining risk is *silent stripping*
  (availability), in which case the Tool MUST **fail closed**. *(Verification task: re-check the MCP
  2025-11-25 transports/lifecycle pages for any preservation guarantee.)*

## C1 — Identity Assertion (baseline, every Tool request)

An ADA-defined, **tool-audience-bound** compact JWS/JWT.

| Field | Value / meaning |
|-------|-----------------|
| `typ` (header) | `application/ada-identity+jwt` (distinct `typ` prevents cross-use) |
| `alg` (header) | asymmetric allowlist only (e.g. `ES256`/`EdDSA`); `none` and `HS*` MUST be rejected |
| `kid` (header) | key id into the issuer's JWKS/trust bundle |
| `iss` | trusted IdP/issuer that authenticated the end user (on the Tool's pinned allowlist) |
| `sub` | stable end-user identifier (used as `{JWT.sub}` for downstream scoping per Tool Spec §2.2.2) |
| `aud` | **the specific target Tool / canonical MCP-server identifier** (defeats confused-deputy/redirection) |
| `client_id` | the calling Agent |
| `act` | `{ "sub": <agent/workload id> }` — RFC 8693 delegation (subject = user, actor = agent; no token passthrough) |
| `iat`, `nbf`, `exp` | short lifetime (minutes); per-request freshness |
| `jti` | unique id; Tool de-dupes for replay defense (pairs with Tool Spec §1.4) |
| `cnf` | *(optional, RFC 7800)* PoP binding: `jkt` (JWK thumbprint, RFC 7638) for **DPoP** (RFC 9449), or `x5t#S256` for **mTLS** (RFC 8705) |
| **per-action binding** | **REQUIRED for Sensitive Actions** — see below |

**Per-action binding** (for Sensitive Actions), one of **[OPEN DECISION]**:
- **RFC 9396 `authorization_details`** — structured (`type`/`actions`/`locations`/`identifier` + fields
  pinning the actual arguments, e.g. amount, destination); auditable; Tool re-verifies each field. *(Favoured
  for alignment with ID-JAG's RAR endorsement.)*
- **`aph` (action-parameter hash)** — `base64url(SHA-256(JCS(bind_object)))` where
  `bind_object = { tool: params.name, args: params.arguments, aud }` (`jti` is already a signed claim and is **not** folded into `aph`); opaque, simple (DPoP-`ath` style).

## C3 — Consent Assertion (deferred tier; fills Tool Spec §2.1.1)

Same envelope, `typ = application/ada-consent+jwt`. Binds the four things C3 requires:

| Field | Meaning |
|-------|---------|
| `sub` | the SAME verified end user as C1 (consent tied to identity) |
| `aud` + operation | the specific Tool + operation (consent bound to one action) |
| per-action binding | `authorization_details` or `aph` — Tool recomputes and rejects on mismatch (defeats "consent to X, execute Y") |
| `corr_id` | correlation ID for audit (satisfies the C3 Agent obligation to record) |
| `jti`, `nbf`, `exp`, optional `cnf.jkt` | anti-replay |
| `act` | agent as actor (RFC 8693) |

**Relationship to MCP elicitation:** elicitation is the interactive *moment-of-consent trigger* only; its
response carries **no signature or identity binding** (client-provided identity is forgeable), so it is
**not** an acceptable consent receipt. The verifiable artifact is this signed C3 JWT.

## Trust anchor / key distribution **[OPEN DECISION]**

The Tool holds a **pinned issuer allowlist / trust bundle** (open `iss`-based discovery is forbidden).
Verification key resolved by `kid`. Distribution options for WG choice:
1. OIDC Discovery `jwks_uri` **constrained by the allowlist**;
2. **SPIFFE** trust bundle + Federation (JWT-SVID for the agent/actor);
3. an **ADA-run/endorsed registry or CA** (OWASP ANS-style PKI).
Key rotation via `kid` + JWKS cache TTL with refresh-on-unknown-`kid` and an overlap window.

## Tool-side verification algorithm

1. Reject if `alg` not on the asymmetric allowlist (`none`/`HS*` → fail).
2. Resolve key by `kid`; **`iss` MUST be on the pinned allowlist**; verify signature.
3. Validate `aud` == this Tool, `exp`/`nbf`, and `jti` not previously seen (replay).
4. For a Sensitive Action: recompute the per-action binding — for `aph`, JCS-hash the full
   `bind_object` (`{ tool: params.name, args: params.arguments, aud }`); for `authorization_details`, match each
   field against the **actual** `params.name`/`params.arguments` — and reject on mismatch.
5. For C3: additionally require a valid Consent Assertion bound to the same `sub` + operation + parameters.
6. Any failure → **hard-fail (`401`/`403`)**, fail closed. (MRA exercises forged/missing/mismatched/replayed
   assertions against these steps.)

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

- **stdio (local):** *(pending Open decision #4)* if applied, C1/C3 travel **only** in `params._meta` (OAuth
  does not apply — MCP: stdio servers SHOULD obtain credentials from the environment). Anti-replay = `jti`
  de-dup, for which the Tool MUST retain a replay cache for at least the maximum token `exp` and across process
  recycling (note the tension with the statelessness guidance in Tool Spec §2.2.1); any server nonce is bound at
  the DPoP/PoP layer (signed by the Agent at request time), **not** inside the pre-minted identity JWT. **[OPEN
  DECISION]** whether ADA identity/consent is REQUIRED over stdio at all, given Tool Spec §1.1.1 treats local
  transport as "authorized parent process."
- **Streamable HTTP (remote):** the SAME `params._meta` carrier is normative *(pending Open decision #1)*;
  **additionally** the Tool acts as an OAuth 2.1 Resource Server — advertising its audience via RFC 9728
  protected-resource metadata, requiring RFC 8707 resource-indicator audience binding, and optionally validating
  DPoP. (PKCE/S256 applies to the Agent↔authorization-server code flow, not to the Resource Server.) The header
  path is an HTTP-only optimization and cannot be the sole mechanism.

Both transports MUST use identical **JCS (RFC 8785)** canonicalization so Agent and Tool compute the same
per-action binding.

## Open WG decisions

1. **C1 model** — ADA tool-audience-bound JWT (this draft) vs. deferring identity to the receiving AS's
   downstream token.
2. **Per-action binding** — RFC 9396 `authorization_details` vs. `aph` hash vs. allow both.
3. **Proof-of-possession** — DPoP/`cnf` as MUST / SHOULD / MAY.
4. **stdio scope** — does ADA identity/consent apply over stdio, or does local trust rest on the parent process?
5. **Delegation chains & headless agents** — multi-tool `act` chains (ID-JAG-04 gives `act` no normative
   processing) and public/headless agents (ID-JAG is confidential-clients-SHOULD).
6. **Claim namespacing** — reuse registered claims / `authorization_details` vs. mint ADA-private claims
   (`aph`, `corr_id`); register any new claims with IANA.

## Pre-normative verification tasks

- [ ] Re-check `_meta` end-to-end preservation in the MCP 2025-11-25 **transports** and **lifecycle** pages
      (base protocol is silent); if unguaranteed, keep the ADA forwarding requirement above.
- [ ] Examine the external `modelcontextprotocol/ext-auth` extensions repo (and any SEP, e.g. SEP-835) for a
      per-user identity/consent extension that could overlap or supersede this `_meta` approach.
- [ ] Confirm the `org.appdefensealliance/identity` and `.../consent` sub-keys are not reserved in
      `schema/2025-11-25/schema.ts`, and confirm `CallToolRequest` `additionalProperties` behaviour.
- [ ] Confirm ID-JAG remains at draft-04 (pin) and track for RFC/claim changes.

## Non-normative example (straw-man, C1 over stdio)

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
Decoded C1 payload (illustrative): `{ "iss":"https://idp.example", "sub":"user_123",
"aud":"https://tool.example/mcp", "client_id":"agent_abc", "act":{"sub":"agent_abc"}, "iat":..., "nbf":..., "exp":...,
"jti":"...", "authorization_details":[{"type":"ada_tool_action","actions":["transfer_funds"],
"amount":500,"to":"acct_998"}] }`.

## References

MCP 2025-11-25 (base / tools / authorization / elicitation) · Agent–Tool Interface Contract (C1, C3) ·
AI Tool Specification §1.1.1, §1.2.2, §1.4, §2.1.1, §2.2.2 · ID-JAG draft-04 · OIDC Core 1.0 ·
RFC 7515 / 7519 / 7638 / 7800 / 8693 / 8705 / 8707 / 9068 / 9396 / 9449 / 9728 / 8785 · CoSAI MCP Security §3.2.1–3.2.2 ·
OWASP Top 10 for Agentic Applications 2026 ASI03 · AIUC-1 × OWASP crosswalk (Gap: signed per-action auth artifacts).

## Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
