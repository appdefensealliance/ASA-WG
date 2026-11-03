# AI Agent Assessment Applicability

<!-- ai-profile-version: AI-profiles-0.1.0-alpha.1 -->
Version 0.1.0-alpha.1 — 2026-11-03

This alpha defines AI security requirements and assessment procedures within the [AI-only publication scope](AI%20Alpha%20Publication%20Scope.md). A document version alone does not grant assessor authorization or authority to issue ADA certificates.

**AI Agent assessment applicability — 0.1.0-alpha.1.** Apply this companion with the [protocol](AI%20Agent%20Assessment%20Protocol.md), Specification and Guide. The [JSON matrix](AI%20Agent%20Assessment%20Applicability.json) inventories all **37 Agent audit IDs**, with stable companion verification selectors, concrete cases/outcomes and conditional evidence routes. Selectors identify the Guide's acceptance assertions; they are not additional audit IDs or an alternative evidence ontology. The versioned source bundle governs acceptance and evidence.

## 1. Deriving an assessment plan

1. Bind the plan to a verified product build/configuration and immutable profile/procedure references. Record actors, components, deployment, invocation boundaries, protocol versions/roles, negotiated and actually consumed capabilities, admission paths, model versions/routes/modalities/tasks, and evidence verifying those facts. An interface hint or developer declaration alone is not evidence of absence.
2. Apply each of the 37 audit entries and **every verification** to each relevant component/interface/model/security context. The matrix's conditions are conjunctive. `always` means the Agent duty cannot be excluded because its protection or observation mechanism is missing. Feature conditions refer to offered/consumed capabilities, **not whether a protection was implemented**. Never turn a required control into a feature flag to make it N/A.
3. Assign per-verification applicability and evidence disposition separately. A parent audit summarizes its child records; it cannot hide an applicable child behind an overall N/A. Plan records are pending, not passes. An implemented interface with unsupported optional elicitation retains the safe-unsupported-request case. A missing implementation of a required protection is a breach when established; insufficient observations remain unresolved under #543.
4. Execute the prescribed case or an approved equivalent preserving its acceptance assertion. Explicitly record all substitutions, source procedure and fixture versions, case inputs/controls, repetitions, producing systems/originals, responsible component, visibility limits and verdict. Share observations only with explicit assertion mappings and without claiming extra repetitions.

The 0.2 matrix/record remediation makes these derivations explicit:

* Each prescribed primary/additional case binds its `procedure_id`, case ID, pinned source revision, target classification and evidence to the reviewed catalog. LLM-mediated decisions/output default to ten independent target executions regardless of global flags, seeds or temperature. Source-prescribed direct protocol and configuration/document checks are not unnecessarily repeated ten times. A different population must match specifically applicable explicit source/case guidance already in the known catalog; a lab/developer budget or approval does not supply that guidance. Upstream admission and optional benchmark routes retain their own populations/strength.
* False high-stakes/reference/code-output flags cannot alone produce N/A for a generative Agent. A source-bound `feature_exclusions` record must establish actual exposure and a supported production refusal boundary with original observations; pending, unexposed or ambiguous probes keep the assertion applicable/unresolved. Actual emission contradicts an absence claim. Missing a protection is not an absent feature. This is an applicability evidence check, not a claim that schema validation authenticates observations or proves universal absence.
* Typed `findings`/`prior_findings` retain owning verification/context, model/configuration, case, original reference and the existing #543 result. Actual adaptive effort and cross-boundary cases link those findings. A confirmed current-configuration mandatory breach is sticky despite later clean regression runs; a remediated configuration is separately assessed with the original finding retained. Eight actual qualified hours are a total allocation across the assessed models/configurations, not eight hours each.

Dispositions (using #543 verdict semantics):

* **Applicable + pending/satisfied/observed breach/insufficient evidence:** the protection is required under its condition. Missing exposure/evidence blocks mandatory acceptance; a confirmed mandatory breach fails. Lack of source/backend access does not exempt supported behavior.
* **Justified non-applicability:** a genuinely absent optional capability, excluded actor/interface role, or explicit published source exclusion, supported by verified configuration evidence. Other independent protections remain applicable. An optional benchmark can instead be applicable/advisory-not-performed; absence of a benchmark run is not an absent Agent capability.
* **Unsupported architecture:** identify the unsupported certification scope, not a passing product. A v1 A2A-only claim cannot be certified by inventing delegation-chain tests; exposed multi-agent channel/memory isolation remains covered.

A certificate requires all applicable mandatory underlying and AI assertions to be satisfied. The validator below checks record structure/declared consistency; it cannot verify production equivalence, evidence authenticity/completeness, security, calibration, or human work.

## 2. Boundary and strength rules

The Agent Developer remains responsible for Agent/model behavior and integration even when model evidence is inherited. The Agent is assessed **independently of remote Tools**; no Tool certificate or certified Agent×Model×Tool combination is a prerequisite. Remote dependencies are hostile/malfunctioning fixtures, not assumed honest runtimes. Agent-owned managed execution containment remains mandatory where applicable, whether local or hosted; external provider internals are not allocated to the Agent. Inspect admission, authorization, consent, untrusted data, user isolation, lifecycle, logging and safe failure at the Agent boundary.

Underlying released **MASA (mobile), DASA (desktop), CASA (web)** are evaluated with the AI extension at **AL2**, preserving their complete applicable requirements, alternatives, exceptions and evidence obligations. Hybrid components receive their actual profiles. Remote inference does not independently require CASA certification of the external model backend. Public remote MCP retains all applicable published CASA and shared mandatory interface controls; an anonymous public-safe call does not exempt protected access or untrusted-content handling. D1, stronger TLS recommendations and optional benchmarks keep their own strength.

The matrix's #539/#540/#542/#544 amendments are paired with the current source and recorded in AI Agent Policy Alignment.json. Its remote-boundary cases preserve mandatory Agent-side file/request/callback scope and logging without certifying the remote provider's runtime; its consent fidelity is shown-versus-dispatched, not a claim of honest downstream execution. In particular, optional stable-ID use is separate from mandatory required-interface compliance, preservation of IDs in use and safe unknown-outcome handling. No unpublished option selector is adopted. Routine authorized reversible operations do not need fresh consent merely because the Tool is powerful; Sensitive Actions and explicit product/Tool gates do. Authorized private processing is distinct from separately allowed persistence, secret handling and withdrawal/deletion.

## 3. Production-equivalent fixture approval

Lab approval MUST name the approving assessor, source procedure/acceptance reference and fixture revision; list changed endpoint/identity/data/clock settings; and demonstrate unchanged **admission, authentication/authorization, consent, untrusted-input handling, isolation, lifecycle, logging and outcome reconciliation** for the tested assertions. Use paired benign and adverse production-path observations and targeted originals. An approval label alone is insufficient. Security-control disablement, test-only permission bypass, alternate prompt/gating paths or fixture-enforced denial cannot establish Agent enforcement. Never weaken acceptance to fit a fixture.

Approved fixture classes (approval is required per product/record, not granted globally here):

* **MCP HTTP:** controlled public/protected endpoints and authoritative JWT/introspection verifier; record negotiated MCP revision and HTTP role. Observe authorization, callback/session/TTL/replay paths, valid-schema metadata, outputs/errors and downstream effects. HTTP-only products exclude nonexistent stdio procedures; unsupported server requests still receive safe handling.
* **MCP stdio:** local reference child process on the actual parent launch/admission path; record executable/package pin, parent-process identity, pipes, user/process context and supported MCP capabilities. Use local traces instead of demanding HTTP headers or OAuth solely for a local case. Preserve applicable local process isolation and identity requirements.
* **Android AppFunctions:** assessor-controlled function provider using the production package/caller admission and OS permission path; record Android/API and AppFunctions version, package/signing/caller identity, function schema, user/profile boundary and OS-mediated permission/effect observations. No invented MCP registration, elicitation or HTTP OAuth requirement. Retain independent consent, authorization, lifecycle, data isolation and applicable Android platform controls.
* **Desktop local:** controlled executable/plugin in the actual launcher and Agent-owned sandbox, with allowed/denied synthetic files, process actions and canary destinations. DASA applies; local identity and containment cannot be inferred from a safe UI sentence.
* **Fixed private REST:** provider-approved controlled endpoint/tenant, replay/synthetic response channel or test record in the real integration, preserving admission/TLS/credential source and all gates. A fixed integration need not add dynamic MCP discovery. Test immutable API/schema provenance and wrong/revoked endpoints through its actual admission mechanism; missing ability to observe a required property remains unresolved.
* **Generative/multimodal:** preserve the actual route, modality ingestion, prompt/security settings and downstream dispatch. §1.1.1 task outcomes use the **task-appropriate evasion criterion**, not a fictional classifier fixture or an exact-prose comparator. Record meaning-preserving perturbations and rubric approval.
* **Hybrid:** combine component plans and test the real crossing boundaries: local→remote credential/identity propagation, untrusted content→local action, shared user/state isolation, lifecycle termination, aggregate bounds and observability. Do not infer cross-boundary protection from isolated component passes.

## 4. Android Agent planning versus Tool requirements

Android stdio/AppFunctions Agent plans use their actual mobile/local invocation boundary and retain the independently applicable MASA/AI Agent authority, containment, consent, lifecycle and data duties. They do not require a Tool certificate or certify Tool internals.

The corresponding retained **Tool** Spec/Guide planning labels and exclusions belong to [AI Tool Local Android Applicability](AI%20Tool%20Local%20Android%20Applicability.md), not this Agent matrix. That companion preserves original local Tool strength and explicit conditions without selecting a weaker historical column. A remote transport overlay cannot demote local Android requirements.

## 5. Local validation and review

[Plans and worked examples](AI%20Agent%20Assessment%20Plans.md) explain the [schema](AI%20Agent%20Assessment%20Plan.schema.json) and [examples](AI%20Agent%20Assessment%20Examples.json). Run from the repository root:

```sh
python3 scripts/agent_assessment_policy_validate.py
python3 -m unittest discover -s scripts/tests -p test_agent_assessment_policy.py
```

No real Agent is run and no external service is mutated by these checks. The matrix is paired with the versioned Spec/Guide requirements, assessment records and validation entry points. Apply its assertion mappings and Android dispositions to the assessed configuration. Passing structural validation is not product security evidence, a governance decision or authority to issue an ADA certificate.
