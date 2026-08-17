# AI Agent–Tool Interface Contract

# Introduction

The Agent-Tool Contract defines the normative contract governing the boundary between an AI Agent (MCP host) and an AI Tool (MCP server / App Function). It is referenced by both the **AI Agent Specification** and the **AI Tool Specification**. Its purpose is to ensure that a component certified in isolation composes safely with any other conformant component, **without** requiring the certification of concrete Agent × Model × Tool combinations.

# Purpose and Approach

The most severe agentic risks — indirect prompt injection delivered through tool content, confused-deputy privilege escalation across the agent↔tool boundary, and execution of consequential actions without informed user consent — are **emergent from the interaction** between an Agent and a Tool, not from either component alone. Certifying each component in isolation therefore leaves these risks in the seam between the two specifications.

This contract closes that seam using a **conformance** model rather than combinatorial integration testing:

* Each component is assessed **once** against a standardized adversarial counterparty (see *Reference Adversaries* below), not against every real counterparty it may encounter.  
* The safety invariants are expressed as **per-component obligations at the interface**. Two components that each conform to this contract compose safely **by construction** — the same principle that allows any TLS-conforming client to interoperate securely with any TLS-conforming server without testing the cross-product.  
* Assessment cost is therefore **linear** in the number of certified Agents and Tools, not multiplicative across their model and tool combinations.

Conformance to this contract is a **mandatory condition** of any AI Agent or AI Tool certification claim. Where a requirement in either specification defers a threat to "the other specification," that deferral is satisfied only if the corresponding obligation in this contract is met by the counterparty.

# Definitions

| Term | Definition |
| :---- | :---- |
| Agent (MCP Host) | The component that orchestrates one or more models and invokes AI Tools on behalf of a user. |
| Tool (MCP Server / App Function) | The component that exposes operations (functions, resources) to an Agent and executes them against downstream resources. |
| Identity Assertion | A user-scoped, audience-bound credential a Tool can verify to establish the end user on whose behalf a request is made — for example, an OAuth 2.1 access token issued for that user and audience-bound to the Tool (a signed JWT the Tool validates directly, or an opaque token it validates by introspection). A cryptographically verifiable, per-request assertion that *additionally* binds the specific operation parameters for Sensitive Actions is the stronger form defined by the optional *Agent–Tool Identity & Consent Wire Format* profile. |
| Sensitive Action | An operation that is irreversible, transfers value or money, mutates or shares user data beyond the scope of the current task, or grants or expands access. |
| Tool Output | Any data returned by a Tool to an Agent, including operation results, retrieved resource content, and tool/function descriptions and schemas. |

# Normative Invariants

## C1 — Verifiable Identity Propagation

* **Agent obligation:** The Agent MUST present, with every Tool request, a user-scoped credential that is audience-bound to the target Tool and bound to the authenticated end user. The Agent MUST NOT invoke a Tool with an ambient, shared, or application-level service credential in place of a user-scoped one; MUST NOT forward a bare, unsigned identifier (e.g., a plain `user_id`), nor a token it received from its own client or one issued for a different audience (no passthrough); and MUST fail closed — not escalating to a Sensitive Action — when it cannot produce the credential the Tool requires. The Agent SHOULD additionally forward a cryptographically verifiable, per-request identity assertion bound per action for Sensitive Actions (the optional wire-format profile); this is a documented upgrade path and is **not** required for certification in this revision.  
* **Tool obligation:** The Tool MUST verify the presented credential — cryptographically for a signed token, or by introspection for an opaque token — establish the end user, and scope all downstream access to that identity (On-Behalf-Of). A request bearing a missing, unverifiable, or non-user-scoped credential MUST hard-fail (`401`), and for any Sensitive Action verification is **mandatory**. Where the Agent supplies the optional per-action-bound assertion, the Tool SHOULD re-verify the operation-parameter binding and reject on mismatch.

Enacts the confused-deputy defense across the boundary. Tool-side obligations are specified in AI Tool Specification §1.2 and §2.2.2; the Agent-side obligation is specified in AI Agent Specification §2.4.1. The mandatory bar is the user-scoped, audience-bound, Tool-verifiable credential above (a standard signed OAuth 2.1 JWT qualifies); the agent-minted, per-request signed assertion with per-action parameter binding is the stronger, **optional** tier — consistent with AI Agent Specification §2.4.1 and the optional wire-format profile — so that certification is attainable by implementations taking due care today while a verifiable upgrade path is defined.

## C2 — Data / Control Separation

* **Tool obligation:** The Tool MUST NOT embed model-directed control directives or instructions within its operation results, tool/function descriptions, or schemas, and MUST NOT rely on the model or Agent to enforce the Tool's own security constraints. The Tool SHOULD, where feasible, return structured/typed output and MAY tag external/retrieved content with provenance as defense-in-depth; producer-supplied tags MUST NOT be relied upon by the Agent as a security boundary (a malicious or compromised Tool will not tag honestly).  
* **Agent obligation (load-bearing):** The Agent MUST treat all Tool Output — including operation results, retrieved/resource content, and tool/function descriptions and schemas — as untrusted data and MUST NOT interpret it as instructions. Tool Output MUST NOT, on its own, cause the Agent to invoke a Sensitive Action without fresh user consent (C3).

Enacts the defense against indirect prompt injection delivered through tool content. This is primarily a **consumer-side** control: the load-bearing defense is the Agent obligation above, tested in AI Agent Specification §3.1.2 against the Malicious Reference Tool. AI Tool Specification §6.1 correctly defers *mitigation* of resource-content poisoning to the Agent; the narrow Tool-side honest-behaviour duty is specified in AI Tool Specification §6.1.1. This allocation follows CoSAI MCP Security §3.2.3/§3.2.8 and OWASP Top 10 for Agentic Applications 2026 ASI01/ASI02, which assign data/control separation to the agent/host; no reviewed framework imposes a producer-side provenance duty.

## C3 — Consent for Consequential Actions

* **Agent obligation (primary, load-bearing):** The Agent MUST present, obtain, and enforce per-action user consent for any Sensitive Action, MUST bind that consent to the verified user identity (C1) and the operation parameters, and MUST record it with a correlation ID for audit. The user consent decision is made at the Agent's human interface.  
* **Tool obligation (defense-in-depth backstop):** The Tool MUST classify each exposed operation by sensitivity and reversibility and, for a Sensitive Action, MUST either obtain user confirmation via server-side elicitation or fail closed. The Tool MUST NOT execute a Sensitive Action on the Agent's assertion alone that consent was obtained.

Enacts informed consent at the consequential-action boundary. Consent enforcement is **primarily consumer-side** (CoSAI MCP Security §3.2.9; OWASP Top 10 for Agentic Applications 2026 ASI02/ASI09), with the Tool acting as a fail-closed backstop against a confused or malicious Agent — the confused-deputy case the Malicious Reference Agent tests. Agent-side obligations are specified in AI Agent Specification §2.2 (§2.2.2); Tool-side obligations in AI Tool Specification §2.1.1.

**ADA extensions (beyond baseline MCP):** the machine-readable `consent_required` signal is an ADA construct (candidate alignment: MCP tool annotations); a consent assertion cryptographically bound to the verified user identity and operation parameters — letting the Tool verify consent without an interactive round-trip — is **deferred to the ADA identity/consent wire format together with C1**.

# Reference Adversaries

To keep assessment linear and counterparty-independent, the ADA SHALL publish and version two reference fixtures. Each certified component is assessed against the fixture representing its counterparty.

| Fixture | Used to assess | Behavior |
| :---- | :---- | :---- |
| **ADA Malicious Reference Tool (MRT)** | AI Agents | Emits poisoned resource content, deceptive tool/function descriptions, schema poisoning, forged or withheld identity challenges, and replays. Used to verify C2 (data/control separation) and the Agent half of C1. |
| **ADA Malicious Reference Agent (MRA)** | AI Tools | Forwards forged, mismatched, or missing identity; replays tokens and consent assertions; smuggles injection into tool arguments. Used to verify the Tool half of C1 and C3. |

The dynamic test procedures already present in the AI Tool Specification (e.g., §1.2.2, §2.2.2, §2.4.1) are instances of MRA behavior and SHALL be consolidated into the MRA fixture.

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).  
