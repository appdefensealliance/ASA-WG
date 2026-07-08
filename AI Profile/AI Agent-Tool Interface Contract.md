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
| Identity Assertion | A cryptographically verifiable token (e.g., a signed JWT from a trusted IdP) that binds a request to a specific end user, and — for sensitive actions — to specific operation parameters. |
| Sensitive Action | An operation that is irreversible, transfers value or money, mutates or shares user data beyond the scope of the current task, or grants or expands access. |
| Tool Output | Any data returned by a Tool to an Agent, including operation results, retrieved resource content, and tool/function descriptions and schemas. |

# Normative Invariants

## C1 — Verifiable Identity Propagation

* **Agent obligation:** The Agent MUST forward a verifiable Identity Assertion (C1) with every Tool request, scoped per request and — for Sensitive Actions — bound per action to the operation parameters. The Agent MUST NOT forward a bare, unsigned identifier (e.g., a plain `user_id`). The Agent MUST NOT escalate to a Sensitive Action when it cannot produce the identity the Tool requires; it MUST fail closed.  
* **Tool obligation:** The Tool MUST cryptographically verify the Identity Assertion and scope all downstream access to it (On-Behalf-Of). For any Sensitive Action, verification is **mandatory**; a missing or unverifiable assertion MUST hard-fail (`401`).

Enacts the confused-deputy defense across the boundary. Tool-side obligations are specified in AI Tool Specification §1.2 and §2.2.2; the Agent-side obligation is specified in AI Agent Specification §2.4.

## C2 — Data / Control Separation

* **Tool obligation:** The Tool MUST return external/retrieved content tagged with provenance and segregated from tool-control fields, so that the Agent can distinguish data from instructions. The Tool MUST NOT embed control directives intended for the model within operation results.  
* **Agent obligation:** The Agent MUST treat all Tool Output as untrusted data and MUST NOT interpret it as instructions. Tool Output MUST NOT, on its own, cause the Agent to invoke a Sensitive Action without fresh user consent (C3).

Enacts the defense against indirect prompt injection delivered through tool content. Tool-side provenance tagging is specified in AI Tool Specification §6.1; Agent-side handling is tested in AI Agent Specification §3.1.2 against the Malicious Reference Tool.

## C3 — Consent for Consequential Actions

* **Tool obligation:** The Tool MUST classify each exposed operation by sensitivity and reversibility, and MUST emit a machine-readable `consent_required` signal for any Sensitive Action. The Tool MUST NOT execute a Sensitive Action without a consent assertion bound to the verified identity (C1) and the operation parameters.  
* **Agent obligation:** The Agent MUST obtain and enforce per-action user consent for any operation flagged `consent_required`, MUST bind that consent to identity and parameters, and MUST record it with a correlation ID for audit.

Enacts informed consent at the consequential-action boundary. Tool-side obligations are specified in AI Tool Specification §2.1; Agent-side obligations in AI Agent Specification §2.2.

# Reference Adversaries

To keep assessment linear and counterparty-independent, the ADA SHALL publish and version two reference fixtures. Each certified component is assessed against the fixture representing its counterparty.

| Fixture | Used to assess | Behavior |
| :---- | :---- | :---- |
| **ADA Malicious Reference Tool (MRT)** | AI Agents | Emits poisoned resource content, deceptive tool/function descriptions, schema poisoning, forged or withheld identity challenges, and replays. Used to verify C2 (data/control separation) and the Agent half of C1. |
| **ADA Malicious Reference Agent (MRA)** | AI Tools | Forwards forged, mismatched, or missing identity; replays tokens and consent assertions; smuggles injection into tool arguments. Used to verify the Tool half of C1 and C3. |

The dynamic test procedures already present in the AI Tool Specification (e.g., §1.2.2, §2.2.2, §2.4.1) are instances of MRA behavior and SHALL be consolidated into the MRA fixture.

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).  
