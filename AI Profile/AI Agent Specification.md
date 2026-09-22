# AI Agent Specification

#  Contributors

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

**Application Security Assessment Working Group Leads**

* Alex Duff (Meta) \- ASA WG Chair  
* Anna Bhirud (Google) \- ASA WG Vice Chair

**AI Profile Leads**

* Brad Ree (Google)  
* Alex Duff (Meta)

**Contributors**
* Debdutta Guha(Google)  
* Nic Watson (Google)  
* Abhiraman Gcl (Google)  
* Daniel Bond (Meta)  
* Tony Balkan (Microsoft)  
* Dario Freni (Google)
* TBD

# Table of Contents

1 [Model & Data Integrity](#1-model--data-integrity)

1.1 [Adversarial Training and Testing](#11-adversarial-training-and-testing)

1.2 [Model and Data Access Controls](#12-model-and-data-access-controls)

1.3 [Memory and Retrieval Store Integrity](#13-memory-and-retrieval-store-integrity)

2 [Agent Governance](#2-agent-governance)

2.1 [Agent Permissions](#21-agent-permissions)

2.2 [Agent User Control](#22-agent-user-control)

2.3 [Agent Observability](#23-agent-observability)

2.4 [Agent-Tool Interface Conformance](#24-agent-tool-interface-conformance)

3 [Input/Output Security](#3-inputoutput-security)

3.1 [Input Validation and Sanitization](#31-input-validation-and-sanitization)

3.2 [Output Validation and Sanitization](#32-output-validation-and-sanitization)

3.3 [Orchestrator and Route Integrity](#33-orchestrator-and-route-integrity)

4 [Infrastructure & Resource Management](#4-infrastructure--resource-management)

4.1 [Application Access and Resource Management](#41-application-access-and-resource-management)

4.2 [Incident Response Management](#42-incident-response-management)

5 [Privacy & User Trust](#5-privacy--user-trust)

5.1 [Privacy Enhancing Technologies for Inference](#51-privacy-enhancing-technologies-for-inference)

5.2 [User Transparency, Control and Data Management](#52-user-transparency-control-and-data-management)

6 [AI Tool Interface](#6-ai-tool-interface)

6.1 [AI Tool Authentication and Session Security](#61-ai-tool-authentication-and-session-security)

6.2 [Tool Use Sanitization](#62-tool-use-sanitization)


# Introduction

The rapid evolution of Artificial Intelligence has marked a transition from static, conversational Large Language Models (LLMs) to highly autonomous AI Agents. While traditional LLMs excel at text prediction and generation, an AI Agent possesses the orchestrational logic to reason, plan, and critically, invoke and manage external AI tools to interact with real-world data and third-party systems. This advanced autonomy unlocks massive business potential but simultaneously introduces unique, high-impact security vulnerabilities—such as prompt injection, runtime data poisoning, and excessive agency—that conventional cybersecurity frameworks are poorly equipped to defend.

The App Defense Alliance (ADA) AI Agent Specification establishes a definitive, standardized testing matrix to validate the security, integrity, and trustworthiness of these autonomous systems. Derived from the Consortium for Secure AI (CoSAI) risk taxonomy and integrated with the tactical methodologies of the OWASP AI Testing Guide and MLCommons, this specification bridges the gap between conventional security practices and offensive AI engineering.

# Scoping and Compliance

## Defining the Boundaries

To ensure clarity, this specification distinguishes between the core engine and the autonomous system:

* **Large Language Model (LLM):** A statistical model trained on vast datasets to predict and generate text.  
* **AI Agent:** An autonomous system built upon one or more models, possessing the logic to reason, plan, and execute actions. The AI Agent also maintains the memory of the AI System.

The primary differentiator for an agent in this context is the **ability to invoke and manage AI tools** to interact with external data or systems. AI-enabled applications that lack this external interaction are considered out of scope. These agents may utilize a single model or a complex orchestration of multiple models, hosted on-device, in the cloud, or via hybrid architectures.

## Agent-Level Compliance

The **AI Agent** serves as the primary entity for certification. Compliance is determined at the agent level, meaning the Agentic Provider is responsible for ensuring the entire system meets the specification requirements. However, because an agent’s security posture is intrinsically linked to its intelligence source, the certification process accounts for three types of control implementation:

* **Agent-Provided Controls:** Security logic implemented within the application code or orchestration layer (e.g., input sanitization or tool-call gating).  
* **Model-Provided Controls:** Security features inherent to the LLM (e.g., built-in safety alignment and adversarial robustness).  
* **Agent/Model Controls:** Requirements that are only satisfied through the combined interaction of the agent's logic and the model's response characteristics.

Where the Agent Developer does not control the underlying model (for example, a third-party foundation model consumed via API), the model-behaviour requirements (§1.1.x) and Model-Provided Controls still attach to the Agent Developer as the responsible party. These obligations may be satisfied by inheriting upstream model-safety artifacts as evidence — such as the model provider's system/model card, published safety and adversarial-robustness evaluations, or an applicable model component certification — provided the artifacts cover the specific model version(s) and configuration the Agent supports. Where such artifacts are unavailable or do not cover the deployed configuration, the Agent Developer must re-run the model-level tests through the Agent to demonstrate compliance.

## Multi-Model Compliance Requirements

For agents that utilize a complex orchestration of multiple models, compliance is not a "one-and-done" verification. To achieve a certified status, the agent must demonstrate that it maintains the required security standards across its entire ecosystem:

**The Multi-Model Rule:** If an agent supports or interacts with more than one LLM, the agent must demonstrate compliance for **every** model in its catalog.

The requirements in this specification will explicitly indicate which test cases apply generally to the **agent** and which test cases must be repeated for each supported **model**. This ensures that an agent remains secure regardless of which model the orchestrator selects to execute a specific task.

## Out of scope for v1: Agent-to-Agent (A2A) / Multi-Agent Composition

Agent-to-agent (A2A) protocols and multi-agent orchestration — where an Agent delegates tasks to, or composes with, one or more *separate, independent* Agents across a delegation chain — are **out of scope for v1** of this specification. This is distinct from the **Multi-Model Compliance Requirements** above, which govern a single Agent that internally selects among multiple LLMs; that case remains **in scope**. What is deferred here is the composition of an Agent with other Agents.

Concretely, v1 does not assess the security of inter-agent delegation chains, cross-agent identity and consent propagation, or the discovery and trust of peer/third-party Agents. The single defensive expectation that still applies in v1 is that an Agent must **isolate any multi-agent channels and shared memories** it exposes (see §2.1.1); beyond that isolation requirement, v1 does not certify any claim about safe multi-agent composition.

Certification, and any resulting certificate, therefore makes **no assertion** about the security of A2A or multi-agent composition. Buyers should not infer that delegation-chain risks have been assessed. The corresponding CoSAI delegation-chain threats are listed explicitly under *Out of Scope CoSAI Threats*.

**Roadmap:** Explicit A2A / multi-agent composition requirements — including delegation-chain identity and consent propagation, peer-agent discovery and trust, and the delegation-chain threats currently listed as out of scope — are targeted for a future revision.

## Integration with Conventional Security

This specification focuses exclusively on the unique threats introduced by AI models and agentic controls. It does not replace traditional security requirements.

Every agentic application must comply with this specification **in addition to** the relevant standard for its deployment platform. For example:

* **Mobile Agents:** Must comply with this spec \+ **MASA** (Mobile Application Security Assessment).  
* **Web Agents:** Must comply with this spec \+ **CASA** (Cloud App Security Assessment).  
* **Desktop Agents:** Must comply with this spec \+ **DASA** (Desktop App Security Assessment).

## Conformance with the Agent–Tool Interface Contract

Because an Agent's security posture depends on how it composes with the AI Tools it invokes, every certified Agent must additionally conform to the [Agent–Tool Interface Contract](AI%20Agent-Tool%20Interface%20Contract.md). The contract defines the Agent-side obligations at the agent↔tool boundary (verifiable identity propagation, data/control separation, and consent for consequential actions) and is assessed against the **ADA Malicious Reference Tool (MRT)** rather than against concrete tools. Conformance to the contract is a mandatory condition of certification.

## Testing Methodology

The current version of the AI Agent specification only contains testing guidance and acceptance criteria of Assurance Level 2 (AL2 Lab Assessment). Future revisions of the specification may include AL1 (Verified Self Assessment) and/or AL0 (Self Assessment). 

Authorized labs must rely primarily on functional testing, ensuring that assessors do not require access to underlying source code or internal backend systems, though specific test cases may necessitate developers to supply targeted log file samples as evidence. Organizational audits and business process reviews fall entirely out of scope for this certification. To remain adaptable across a wide variety of implementation architectures, the testing procedures are designed to provide high-level, flexible guidance, while the corresponding acceptance criteria are strictly defined to guarantee definitive, objective pass/fail compliance decisions. The testing must be on the final (Production) version of the app. However, the developer may have special modes which help with testing the application in the ADA test harness.

### Evidence Taxonomy

Every AL2 test case in this specification is satisfied by one or more of three evidence types. Each requirement's **Evidence** block identifies the type(s) it relies on; where a requirement can be satisfied purely by exercising the running application, it is Functional Observation by default.

| Evidence Type | Definition | Assessor Action | Access Required |
| :---- | :---- | :---- | :---- |
| **Functional Observation** | Evidence the assessor produces and observes directly by exercising the final (Production) Agent through its user interface and tool interface, treating the system as a black box. This is the default and preferred evidence type. | Drive the application and observe its externally visible behaviour, responses, and traffic. | User interface and tool interface only. No source-code or backend access. |
| **Attestation** | Evidence that is not externally observable and is therefore supplied by the developer at the assessor's targeted request — for example, specific log-file samples, consent records, or the configuration of an automated retention job. The assessor verifies the supplied artifact against the acceptance criteria; it does not grant the assessor standing access to backend systems. | Request a specific, named artifact and verify it against the acceptance criteria. | Developer-supplied artifacts only. |
| **Document Review** | Evidence in the form of developer-provided documentation of a policy, procedure, or process control that cannot be exercised functionally — for example, a secret-rotation and revocation policy. The assessor confirms the documented control exists and meets the stated criteria. | Read the supplied documentation and confirm it satisfies the requirement. | Developer-supplied documentation only. |

Attestation and Document Review are deliberately narrow, targeted exceptions to the functional-testing default: they cover only the specific artifacts named in a requirement's Evidence block. They do not constitute a full organizational audit or business-process review, which remain out of scope. Any requirement whose acceptance criteria cannot be met by Functional Observation alone should name, in its Evidence block, the specific Attestation artifact or document required, and tag the applicable evidence type(s).

# Relationship To CoSAI

The AI Agent specification is derived from the **Consortium for Secure AI (CoSAI)** Secure AI Tooling Risk Map. Utilizing the CoSAI threat model and its corresponding security controls, this specification maps requirements to specific personas within the agentic ecosystem. While this document encompasses all controls relevant to the AI Agent and its underlying models, it excludes model training, internal development lifecycles, and model hosting infrastructure from its scope. These controls are organized into five primary categories, with certain requirements consolidated to allow for unified testing procedures.

| CoSAI Persona | ADA Scope |
| :---- | :---- |
| AI System Users | Out of scope |
| Agentic Platform and Framework Providers | In scope |
| Application Developer | In scope  |
| AI Platform Provider | Mostly out of scope.  ADA focuses on the functional security of the external interfaces, not the underlying infrastructure or internal policies. |
| AI Model Serving | Out of scope |
| Model Provider | Mostly out of scope **as an actor**. ADA does not assess the Model Provider's internal processes — model training, evaluation, or the securing of model parameters and hosting infrastructure. Model *behaviour* is in scope, but is assessed indirectly through the Agent: the Agent Developer inherits and, where required, re-runs the model-level requirements (§1.1.x) for every supported model and remains the party responsible for compliance. |
| Data Provider | Out of scope |
| AI System Governance | Out of scope |

# Relationship To OWASP

This specification integrates core methodologies from the **OWASP AI Testing Guide**, mapping individual OWASP tests directly to CoSAI security controls. To maintain focus on external validation, tests regarding source code, internal organizational processes, and model training have been omitted. The ADA AI Agent specification builds upon the OWASP framework by establishing definitive, measurable acceptance criteria that must be satisfied for compliance. Additionally, traditional OWASP approaches to prompt injection, model safety, and jailbreak testing have been superseded by the MLCommons testing standard.

| OWASP AI Testing Guide Framework | ADA Scope |
| :---- | :---- |
| AI Application Testing | In scope |
| AI model Testing | In scope |
| AI Infrastructure Testing | Out of scope |
| AI Data Testing | Out of scope |

**Test selection rule.** ADA adopts individual OWASP tests wherever they map to an in-scope CoSAI control, even when the parent OWASP test *family* is otherwise out of scope. Accordingly, specific AI Data tests (e.g., AITG-DAT-02, AITG-DAT-05) and AI Infrastructure tests (e.g., AITG-INF-02, AITG-INF-03, AITG-INF-04) are adopted where they validate an in-scope agent behaviour or interface, while the remainder of those families — source-code, training-pipeline, and hosting-infrastructure tests — remain out of scope. The scope entries above therefore describe the *default* disposition of each family, not a prohibition on adopting a specific mapped test.

# Relationship To MLCommons

To address the critical risks of prompt injection, jailbreaking, and model safety, this specification adopts the **MLCommons** framework. Compliance is verified using the official MLCommons test harness and datasets. To achieve ADA certification, the agent and its integrated models must meet or exceed the minimum performance and safety thresholds defined within the ADA acceptance criteria.

# References

* [CoSAI Secure AI Tooling](https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map/tables)  
* [OWASP AI Testing Guide](https://github.com/OWASP/www-project-ai-testing-guide/blob/main/Document/README.md)  
* [MLCommons AILuminate Safety](https://mlcommons.org/ailuminate/safety/)  
* [MLCommons AILuminate Jailbreak](https://mlcommons.org/ailuminate/jailbreak/)


# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

# Definitions

| Term | Definition |
| :---- | :---- |
| Large Language Model | A statistical model trained on vast datasets to predict and generate text. |
| AI Agent | An autonomous system built upon one or more models, possessing the logic to reason, plan, and execute actions. The AI Agent also maintains the memory of the AI System. The primary differentiator for an agent is its ability to invoke and manage AI tools. |
| AI Tool | A mechanism or external interface invoked and managed by an AI Agent to interact with external data or systems. |
| End User | The **End User** uses AI-powered applications or services without developing or deploying the AI components themselves. Users rely on application developers and providers for AI security controls.  **The EndUser actor is out of scope for the AI Agent specification.** |
| Agent Developer | The **Agent Developer** serves as the primary architect of the user-facing experience, delivering the final mobile, web, or desktop applications with which end users interact. This role encompasses the entire orchestration layer—including the software frameworks and runtimes necessary for agentic reasoning, planning, and tool execution—as well as the integration of AI models via APIs or embedding. By consolidating the CoSAI Agentic Platform and Framework Providers and Application Developer personas, the Agent Developer manages both the application’s core logic and the light customization of models through techniques such as prompt engineering and Retrieval-Augmented Generation (RAG). **The Agent Developer is in scope for the AI Agent specification.** |
| Model Provider | The **Model Provider** is a comprehensive entity responsible for the entire lifecycle of an AI model, from initial development, training, and evaluation to the management of the infrastructure and secure runtime environments required for inference. This persona develops foundation and specialized models, configures the necessary compute resources and APIs for hosting, and secures the model-serving application layer to ensure the integrity, confidentiality, and availability of predictions at scale. By consolidating the CoSAI Model Provider, AI Model Serving and AI Platform Provider personas, the Model Provider provides the essential intelligence and delivery framework that powers both AI applications and AI Agents. **The Model Provider is mostly out of scope for the AI Agent specification as a certified actor: ADA does not assess the Model Provider's internal processes (model training, evaluation, parameter security, or hosting infrastructure). The model's *behaviour* is in scope but is assessed indirectly, through the Agent — the Agent Developer inherits and, where required, re-runs the model-level requirements (§1.1.x) for every supported model and is the party responsible for compliance.** |
| Data Provider | The **Data Provider** supplies training data, evaluation datasets, or inference data to model providers or application developers. This includes data aggregators, data marketplaces, and those licensing datasets. **The Data Provider is out of scope for the AI Agent specification.** |
| Agent-Provided Controls | Security logic implemented within the application code or orchestration layer (e.g., input sanitization or tool-call gating). |
| Model-Provided Controls | Security features inherent to the underlying Large Language Model (e.g., built-in safety alignment and adversarial robustness) |
| Agent/Model Controls | Compliance requirements that are only satisfied through the combined interaction of the agent's logic and the model's response characteristics. |
| Orchestrator (Orchestration Layer) | The central framework responsible for mediating all interactions, enforcing security policies, managing plugin calls as independent transactions, and ensuring that the output of one plugin is never interpreted as a command to execute another.  |
| Vector Database / Retrieval System | Storage systems used in Retrieval-Augmented Generation (RAG) that require protection against poisoning attacks via provenance tracking, deduplication, and anomaly detection.  |
| Harmful Action | A Harmful Action refers to any autonomous or agent-initiated operation that results in unauthorized modification, destruction, or exfiltration of user data, or causes significant financial or operational damage to connected infrastructure. It includes executing unapproved system commands, bypassing established platform permissions, or interacting with malicious external utilities without explicit human consent. |
| High Risk Tool | A High Risk Tool is an external interface or utility capable of executing non-reversible actions, modifying stateful user data, or accessing sensitive systems and APIs. Because its invocation can lead to severe data loss, financial liabilities, or systemic privilege escalation, its execution strictly mandates isolation sandboxing and explicit per-action user consent. |
| Sensitive Action | As defined in the [Agent–Tool Interface Contract](AI%20Agent-Tool%20Interface%20Contract.md): an operation that is irreversible, transfers value or money, mutates or shares user data beyond the scope of the current task, or grants or expands access. The Contract is the canonical source for this term. |
| High-stakes queries | High-stakes queries are user prompts or requests that involve critical domains—such as medical, financial, legal, or physical safety—where an incorrect or hallucinated response could lead to severe real-world harm. Due to the elevated risk to the user's well-being or assets, these queries strictly require the system to deliver prominent safety disclaimers, avoid prescriptive language, and strongly recommend professional human consultation. |

# Threat Model

The following threat model is significantly based on the CoSAI Agent threat model, with the primary adjustment being the focus on mitigations which are under the control of the Agentic Provider and Application Developer.

| CoSAI Threat | Description | Audit |
| ----- | ----- | ----- |
| Denial of ML Service | Reducing ML availability via resource-heavy queries or energy-latency "sponge examples". | 4.1.1 Testing for Resource Exhaustion |
| Excessive Data Handling During Inference | Excessively collecting/retaining user inputs and session data during runtime. | 5.2.1 Testing for Data Minimization & Consent |
| Economic Denial of Wallet | Causing excessive financial or computational costs by exploiting billing or token consumption. | 2.1.1 Testing for Agentic Behavior Limits  |
|  |  | 4.1.1 Testing for Resource Exhaustion |
| Insecure Integrated Component | Vulnerabilities in software interacting with models (plugins, libraries) leveraged by attackers. | 2.1.1 Testing for Agentic Behavior Limits |
|  |  | 3.3.1 Testing for Plugin Boundary Violations |
| Insecure Model Output | Model output that is not validated or sanitized before passing to downstream systems or users. | 3.2.1 Testing for Unsafe Outputs |
|  |  | 3.2.3 Testing for Hallucinated References |
| Inferred Sensitive Data | Models inferring true sensitive information about individuals not in the training data. | 2.2.1 Testing for Over-Reliance on AI |
| Model Evasion | Causing a model to produce incorrect inferences via slightly perturbed inputs. | 1.1.1 Testing for Evasion Attacks |
| Prompt/Response Cache Poisoning | Malicious manipulation of shared caches resulting in cross-user contamination. | 1.2.1 Testing for Runtime Exfiltration |
| Prompt Injection | Causing a model to execute unauthorized commands injected inside a prompt (direct or indirect). | 1.1.2 Jailbreak Resistance Testing |
|  |  | 3.1.1 Testing for Prompt Injection |
|  |  | 3.1.2 Testing for Indirect Prompt Injection |
|  |  | 3.1.3 Adversarial / Red-Team Testing |
|  |  | 6.2.1 Testing for Tool Description Metadata Sanitization |
|  |  | 6.2.2 Testing for LLM Control Tokens and Metadata Sanitization |
| Rogue Actions | Unintended or malicious actions executed by a model-based agent via extensions. | 2.1.1 Testing for Agentic Behavior Limits |
|  |  | 2.1.2 Testing for Sandbox Containment |
|  |  | 2.2.2 Human in the Loop controls for AI Tools |
|  |  | 2.2.3 Testing for Tool-Initiated Elicitation Conformance (MCP) |
| Runaway Agent/Tool Loops | Unbounded or self-reinforcing tool-invocation loops (including tool-to-tool chains) that consume resources without progress and can cascade into failures across integrated components. | 2.1.3 Testing for Loop Termination and Execution Bounds |
|  |  | 4.1.1 Testing for Resource Exhaustion |
| Retrieval/Vector Store Poisoning | Malicious modification of retrieval corpora, vector databases, or knowledge bases in RAG systems. | 3.1.2 Testing for Indirect Prompt Injection |
|  |  | 1.3.2 Retrieval / Vector Store Integrity |
| Memory / Context Poisoning | Persistence of malicious instructions or contaminated content in conversational or long-term memory, surviving across turns or sessions. | 1.3.1 Memory Poisoning Resistance |
| Sensitive Data Disclosure | Disclosure of confidential data (memorized training data, logs, prompts) via querying. | 1.2.1 Testing for Runtime Exfiltration |
|  |  | 2.3.2 Testing for Capability Misuse |
|  |  | 5.1.1 Testing for Sensitive Data Leak |
|  |  | 5.1.2 Testing for Input Leakage |

## Out of Scope CoSAI Threats

Model training, protection of model weights and internal hosting infrastructure is out of scope for the ADA Agent certification, as is agent-to-agent (A2A) / multi-agent composition (see *Out of scope for v1: Agent-to-Agent (A2A) / Multi-Agent Composition*). The following CoSAI threats are not addressed in the ADA Agent Specification.

| CoSAI Threat | Description | Rationale for Exclusion |
| ----- | ----- | ----- |
| Adapter/PEFT Injection | Malicious injection of compromised adapters or PEFT components containing backdoors/trojans. | Concerns the model fine-tuning/adaptation pipeline; model training and customization are out of ADA scope. |
| Accelerator and System Side-channels | Shared hardware vulnerabilities (e.g., timing, cache, Spectre) used to infer sensitive assets. | Hosting-infrastructure and hardware concern; AI Infrastructure Testing is out of scope. |
| Covert Channels in Model Outputs | Exploitation of model behavior patterns to establish hidden communication/exfiltration channels. | Mitigation requires model-training and serving-layer controls outside ADA's external-interface scope. |
| Data Poisoning | Altering training/retraining data to degrade performance or create hidden backdoors. | Training-time data manipulation is out of ADA's runtime scope (model training is excluded). The runtime analogue — Retrieval/Vector Store Poisoning — remains in scope (see §3.1.2). |
| Evaluation/Benchmark Manipulation | Compromising evaluation datasets, benchmarks, or infrastructure to generate false quality signals. | Part of the model development and evaluation lifecycle, which is out of scope. |
| Excessive Data Handling | Collection, retention, or processing of training data that violates policies, copyright, or PII rules. | Training-data governance concern; AI Data Testing is out of scope. Excessive data handling *during inference* is covered in scope (§5.2.1). |
| Federated/Distributed Training Privacy | Privacy breaches where participants extract sensitive info from gradient updates or parameters. | Training-time (federated learning) concern; model training is out of scope. |
| Model Deployment Tampering | Unauthorized modification of deployment components or model serving infrastructure. | Model-serving infrastructure concern; model hosting is out of scope. |
| Malicious Loader/Deserialization | Exploiting unsafe deserialization (e.g., pickle) to execute remote code during model loading. | Model-loading/hosting infrastructure concern; out of scope. |
| Model Reverse Engineering | Cloning or recreating a model by analyzing its inputs, outputs, and behaviors. | Attack on model intellectual property; a Model Provider concern, out of ADA scope. |
| Model Source Tampering | Tampering with source code, dependencies, weights, or embedding network backdoors. | Model development and supply-chain concern; out of scope. |
| Model Exfiltration | Unauthorized appropriation or theft of an AI model, its weights, or intellectual property. | Model-weight/IP protection is a Model Provider and hosting concern; out of scope. |
| Orchestrator/Route Hijack | Manipulating orchestration systems or configuration to redirect requests to unauthorized models. | Full route-hijack mitigation depends on model-serving and deployment infrastructure that is out of scope; ADA tests the in-scope subset — plugin-boundary isolation — via §3.3.1. |
| Unauthorized Training Data | Training or fine-tuning a model using data that violates policies, contracts, or regulations. | Training-data provenance/governance concern; model training is out of scope. |
| Agent Delegation-Chain Opacity | Loss of traceability and accountability across a chain of delegating agents, such that an action cannot be attributed to the originating user or agent. | Agent-to-agent (A2A) / multi-agent composition is out of scope for v1 (see Scoping). |
| Agentic Delegation Confused Deputy | A downstream agent is induced to act using a delegating agent's privileges without re-verifying the original user's identity/consent, escalating authority across the chain. | Cross-agent identity/consent propagation (A2A) is out of scope for v1. |
| Shadow / Unknown Agents | Unregistered or unauthorized agents joining an orchestration and participating in delegation without vetting or trust establishment. | Peer-agent discovery and trust establishment (A2A) is out of scope for v1. |

# Controls and Audit Summary

| Category | Control | Audit |
| ----- | ----- | ----- |
| 1. Model & Data Integrity | 1.1 Adversarial Training and Testing | 1.1.1 Testing for Evasion Attacks  (AITG-MOD-01) |
|  |  | 1.1.2 Jailbreak Resistance Testing |
|  |  | 1.1.3 Minimize hazardous responses |
|  | 1.2 Model and Data Access Controls | 1.2.1 Testing for Runtime Exfiltration (AITG-DAT-02) |
|  | 1.3 Memory and Retrieval Store Integrity | 1.3.1 Memory Poisoning Resistance |
|  |  | 1.3.2 Retrieval / Vector Store Integrity (AITG-APP-08) |
| 2. Agent Governance | 2.1 Agent Permissions | 2.1.1 Testing for Agentic Behavior Limits (AITG-APP-06) |
|  |  | 2.1.2 Testing for Sandbox Containment |
|  |  | 2.1.3 Testing for Loop Termination and Execution Bounds |
|  | 2.2 Agent User Control | 2.2.1 Testing for Over-Reliance on AI (AITG-APP-13) |
|  |  | 2.2.2 Human in the Loop controls for AI Tools |
|  |  | 2.2.3 Testing for Tool-Initiated Elicitation Conformance (MCP) |
|  | 2.3 Agent Observability | 2.3.1 Testing for Explainability and Interpretability (AITG-APP-14) |
|  |  | 2.3.2 Testing for Capability Misuse  (AITG-INF-04) |
|  | 2.4 Agent–Tool Interface Conformance | 2.4.1 Verifiable Identity Forwarding |
| 3. Input/Output Security | 3.1 Input Validation and Sanitization | 3.1.1 Testing for Prompt Injection  (AITG-APP-01) |
|  |  | 3.1.2 Testing for Indirect Prompt Injection (AITG-APP-02) |
|  |  | 3.1.3 Adversarial / Red-Team Testing |
|  | 3.2 Output Validation and Sanitization | 3.2.1 Testing for Unsafe Outputs  (AITG-APP-05) |
|  |  | 3.2.2 Testing for Prompt Disclosure (AITG-APP-07) |
|  |  | 3.2.3 Testing for Hallucinated References (AITG-APP-11) |
|  | 3.3 Orchestrator and Route Integrity | 3.3.1 Testing for Plugin Boundary Violations (AITG-INF-03) |
| 4. Infrastructure & Resource Management | 4.1 Application Access and Resource Management | 4.1.1 Testing for Resource Exhaustion (AITG-INF-02) |
|  | 4.2 Incident Response Management | 4.2.1 Security Reporting Routing |
|  |  | 4.2.2 User Reporting Mechanism for AI Responses |
| 5. Privacy & User Trust | 5.1 Privacy Enhancing Technologies for Inference | 5.1.1 Testing for Sensitive Data Leak (AITG-APP-03) |
|  |  | 5.1.2 Testing for Input Leakage  (AITG-APP-04) |
|  | 5.2 User Transparency, Control and Data Management | 5.2.1 Testing for Data Minimization & Consent (AITG-DAT-05) |
|  |  | 5.2.2 Model and Agent Transparency (Model Card) |
| 6. AI Tool Interface | 6.1 AI Tool Authentication and Session Security | 6.1.1 Mandatory Client-Server Transport Authentication |
|  |  | 6.1.2 Mandatory Cryptographic Validation of User Context |
|  |  | 6.1.3 Message Freshness and Session Binding |
|  |  | 6.1.4 Strict Redirect URI and State Validation |
|  |  | 6.1.5 Mandatory Proof Key for Code Exchange (PKCE) |
|  | 6.2 Tool Use Sanitization | 6.2.1 Testing for Tool Description Metadata Sanitization |
|  |  | 6.2.2 Testing for LLM Control Tokens and Metadata Sanitization |

# 1. Model & Data Integrity

---
## 1.1 Adversarial Training and Testing

### Description

Use techniques to make AI models robust to adversarial inputs (i.e. prompts) in the context of their use in applications.

### Rationale

Models must be resilient against prompt injection and jailbreaks to prevent the execution of unauthorized actions, the bypass of safety guardrails, and the generation of insecure outputs. The model shall minimize hazardous responses.

### Audit
| Spec | Description |
| --- | ------|
| [1.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#111-testing-for-evasion-attacks-aitg-mod-01) | Testing for Evasion Attacks (AITG-MOD-01) |
| [1.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#112-jailbreak-resistance-testing) | Jailbreak Resistance Testing |
| [1.1.3](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#113-minimize-hazardous-responses) | Minimize hazardous responses |

---
## 1.2 Model and Data Access Controls

### Description

Minimize internal access to models, weights, datasets, etc. in storage and in production use.

### Rationale

The integrity of an AI Agent hinges on protecting its underlying model weights and training data, which represent both high-value intellectual property and a primary target for adversarial exploitation. Implementing rigorous access controls serves as a critical defense against model theft, unauthorized "cloning" of capabilities, and the accidental exposure of sensitive multi-tenant data.

### Audit
| Spec | Description |
| --- | ------|
| [1.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#121-testing-for-runtime-exfiltration-aitg-dat-02) | Testing for Runtime Exfiltration (AITG-DAT-02) |

---
## 1.3 Memory and Retrieval Store Integrity

### Description

Where an Agent persists state across turns or sessions (conversational or long-term memory) or retrieves from a corpus (RAG / vector / knowledge stores), that store is an attack surface: untrusted content written to it can be replayed later as if it were trusted, defeating single-session controls. The Agent shall protect the integrity of these stores.

### Rationale

An injected instruction that survives a session reset defeats every single-session input/output control in this specification (OWASP ASI06 Memory & Context Poisoning; CoSAI Retrieval/Vector Store and cache-poisoning risks). Because retrieved and persisted content is frequently derived from untrusted sources (tool output, other users, external corpora), it must be treated as untrusted data on write and on read, scoped to the user, and never replayed as instructions.

### Audit
| Spec | Description |
| --- | ------|
| [1.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#131-memory-poisoning-resistance) | Memory Poisoning Resistance |
| [1.3.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#132-retrieval--vector-store-integrity-aitg-app-08) | Retrieval / Vector Store Integrity (AITG-APP-08) |

# 2. Agent Governance

---
## 2.1 Agent Permissions

### Description

Use least-privilege principle as the upper bound on agentic system permissions to minimize the number of tools that an agent is permitted to interact with and the actions it is allowed to take. An agentic system's use of privileges should be contextual and dynamic, adapting to the specific user query and trusted contextual information. This design also applies to agents that have access to user information. For example, an agent asked to fill out a form or answer questions should share only contextually appropriate information and can be designed to dynamically minimize exposed data using reference monitors.

### Rationale

Restricting agents to the least-privilege principle minimizes the blast radius if an agent goes rogue or is hijacked, preventing unauthorized access to sensitive user data or 3rd-party systems.

### Audit
| Spec | Description |
| --- | ------|
| [2.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#211-testing-for-agentic-behavior-limits-aitg-app-06) | Testing for Agentic Behavior Limits (AITG-APP-06) |
| [2.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#212-testing-for-sandbox-containment) | Testing for Sandbox Containment |
| [2.1.3](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#213-testing-for-loop-termination-and-execution-bounds) | Testing for Loop Termination and Execution Bounds |

---
## 2.2 Agent User Control

### Description

The Agent shall ensure user approval for any non-reversable actions performed by agents/plugins that alter user data.

### Rationale

Ensuring human-in-the-loop approval mitigates the risk of rogue actions, preventing the agent from autonomously executing destructive or unauthorized commands.

Consent prompting must also be managed to avoid **consent/approval fatigue** — habituation from an excessive volume of prompts that leads users to approve reflexively (the concern deferred from AI Tool Specification §9.2). Because per-action consent for Sensitive Actions necessarily increases prompt frequency, the Agent limits fatigue by (a) reserving mandatory consent for Sensitive Actions rather than routine tool calls, and (b) making each prompt specific and distinguishable — clearly stating the action and its exact parameters — so users can tell consequential requests apart from routine ones. This is a deliberate trade-off: per-action consent is retained for its security value, and fatigue is mitigated by bounding prompt volume and improving prompt quality rather than by weakening the per-action guarantee.

An alternative fatigue control — **risk-tiered consent**, which batches or suppresses prompts for lower-risk actions — was considered and is **not adopted** for Sensitive Actions in this revision: tiering re-introduces the possibility of a consequential action executing without a fresh, specific approval, which is exactly the guarantee §2.2.2 exists to provide. Developers MAY apply risk tiering to *non-Sensitive* actions (which already require no consent); Sensitive Actions retain the strict per-action gate. This disposition may be revisited if a tiering scheme can be shown to preserve the per-action guarantee for irreversible and high-value actions.

### Audit
| Spec | Description |
| --- | ------|
| [2.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#221-testing-for-over-reliance-on-ai-aitg-app-13) | Testing for Over-Reliance on AI (AITG-APP-13) |
| [2.2.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#222-human-in-the-loop-controls-for-ai-tools) | Human in the Loop controls for AI Tools |
| [2.2.3](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#223-testing-for-tool-initiated-elicitation-conformance-mcp) | Testing for Tool-Initiated Elicitation Conformance (MCP) |

---
## 2.3 Agent Observability

### Description

Ensure an agent's actions, tool use, and reasoning are transparent and auditable through logging, allowing for debugging, security oversight, and user insights into agent activity.

### Rationale

Transparent logging is critical for incident response and user trust, ensuring that all tool invocations and data access events are traceable.

### Audit
| Spec | Description |
| --- | ------|
| [2.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#231-testing-for-explainability-and-interpretability-aitg-app-14) | Testing for Explainability and Interpretability (AITG-APP-14) |
| [2.3.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#232-testing-for-capability-misuse-aitg-inf-04) | Testing for Capability Misuse (AITG-INF-04) |

---
## 2.4 Agent-Tool Interface Conformance

### Description

The Agent shall satisfy its obligations under the [Agent–Tool Interface Contract](AI%20Agent-Tool%20Interface%20Contract.md), presenting a user-scoped, audience-bound credential to every AI Tool it invokes. This closes the confused-deputy boundary between the Agent and the Tool: the Tool's identity-verification controls (AI Tool Specification §1.2, §2.2.2) can only function if the Agent supplies a credential that is genuinely tied to the end user and to that Tool.

### Rationale

An AI Tool that scrupulously verifies user identity provides no protection if the Agent never forwards a verifiable identity, or forwards a bare, unsigned identifier that any compromised or confused component could fabricate. Requiring the Agent to mint and forward a cryptographically verifiable identity assertion ensures the end-to-end authorization chain is intact, preventing privilege escalation across the agent↔tool boundary.

### Audit
| Spec | Description |
| --- | ------|
| [2.4.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#241-verifiable-identity-forwarding) | Verifiable Identity Forwarding |

# 3. Input/Output Security

---
## 3.1 Input Validation and Sanitization

### Description

Block or restrict adversarial queries to AI models.

### Rationale

Filtering inputs at the application layer prevents known malicious payloads, malformed data, and excessive token strings from reaching and potentially destabilizing the inference engine.

### Audit
| Spec | Description |
| --- | ------|
| [3.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#311-testing-for-prompt-injection-aitg-app-01) | Testing for Prompt Injection (AITG-APP-01) |
| [3.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#312-testing-for-indirect-prompt-injection-aitg-app-02) | Testing for Indirect Prompt Injection (AITG-APP-02) |
| [3.1.3](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#313-adversarial--red-team-testing) | Adversarial / Red-Team Testing |

---
## 3.2 Output Validation and Sanitization

### Description

Block, nullify, or sanitize insecure output from AI models before passing it to applications, extensions or users.

### Rationale

Sanitizing outputs protects downstream systems and users from insecure model outputs, such as rendered malware links, hallucinated API calls, or Cross-Site Scripting (XSS) payloads.

### Audit
| Spec | Description |
| --- | ------|
| [3.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#321-testing-for-unsafe-outputs-aitg-app-05) | Testing for Unsafe Outputs (AITG-APP-05) |
| [3.2.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#322-testing-for-prompt-disclosure-aitg-app-07) | Testing for Prompt Disclosure (AITG-APP-07) |
| [3.2.3](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#323-testing-for-hallucinated-references-aitg-app-11) | Testing for Hallucinated References (AITG-APP-11) |

---
## 3.3 Orchestrator and Route Integrity

### Description

Enforce plugin-boundary isolation within the orchestration layer so that each tool or plugin invocation is handled as an independent, isolated transaction and the output of one plugin can never be interpreted as a command that drives another. This is the in-scope subset of route integrity, verified by §3.3.1. Stronger orchestration controls — cryptographically signed route manifests, configuration-integrity verification, and response-provenance tracking — are recognized as valuable but are deferred to a future revision; full mitigation of orchestrator/route hijack additionally depends on model-serving and deployment infrastructure that is out of ADA scope (see *Out of Scope CoSAI Threats*).

### Rationale

Attackers may attempt to manipulate orchestration and routing logic to redirect traffic to malicious or compromised models or to chain plugins into unintended actions. Treating every plugin call as an isolated, permission-checked transaction contains this blast radius at the layer the Agent Developer controls, even where deeper route-signing and provenance guarantees are not yet in scope.

### Audit
| Spec | Description |
| --- | ------|
| [3.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#331-testing-for-plugin-boundary-violations-aitg-inf-03) | Testing for Plugin Boundary Violations (AITG-INF-03) |

# 4. Infrastructure & Resource Management

---
## 4.1 Application Access and Resource Management

### Description

Ensure comprehensive access governance through:

Identity and authorization controls that restrict resources to authorized users and endpoints for authorized actions.

Resource governance controls including usage quotas, rate limiting, cost monitoring, and anomaly detection to prevent resource exhaustion and economic denial of wallet attacks.

### Rationale

Enforcing rate limits and usage quotas prevents attackers from executing Economic Denial of Wallet attacks or exhausting compute resources through automated abuse.

### Audit
| Spec | Description |
| --- | ------|
| [4.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#411-testing-for-resource-exhaustion-aitg-inf-02) | Testing for Resource Exhaustion (AITG-INF-02) |

---
## 4.2 Incident Response Management

### Description

Manage response to AI security and privacy incidents.

### Rationale

Establishing clear reporting and response mechanisms ensures swift mitigation of vulnerabilities and active attacks.

### Audit
| Spec | Description |
| --- | ------|
| [4.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#421-security-reporting-routing) | Security Reporting Routing |
| [4.2.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#422-user-reporting-mechanism-for-ai-responses) | User Reporting Mechanism for AI Responses |

# 5. Privacy & User Trust

---
## 5.1 Privacy Enhancing Technologies for Inference

### Description

Use technologies that minimize, de-identify, or restrict use of PII data during model deployment and inference, including secure multi-party computation, homomorphic encryption, inference log de-identification, on-device processing, and privacy-preserving query mechanisms.

### Rationale

Protecting PII during runtime limits the risk of sensitive data disclosure and ensures compliance with global privacy regulations.

### Audit
| Spec | Description |
| --- | ------|
| [5.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#511-testing-for-sensitive-data-leak-aitg-app-03) | Testing for Sensitive Data Leak (AITG-APP-03) |
| [5.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#512-testing-for-input-leakage-aitg-app-04) | Testing for Input Leakage (AITG-APP-04) |

---
## 5.2 User Transparency, Control and Data Management

### Description

Inform users of relevant AI risks with disclosures, and provide transparency and control experiences for use of their data in AI applications. Then store, process, and use all user data (e.g. prompts and logs) from AI applications in compliance with user consent.

### Rationale

Clear transparency empowers users to understand how their data is used, mitigating risks associated with unauthorized training data and building user trust. Enforcing strict data retention and deletion policies protects users against excessive data handling and long-term exposure of their private interactions.

### Audit
| Spec | Description |
| --- | ------|
| [5.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#521-testing-for-data-minimization--consent-aitg-dat-05) | Testing for Data Minimization & Consent (AITG-DAT-05) |
| [5.2.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#522-model-and-agent-transparency-model-card) | Model and Agent Transparency (Model Card) |

# 6. AI Tool Interface

---
## 6.1 AI Tool Authentication and Session Security

### Description

Ensure that all communications between the AI Agent and external AI tools are secured using modern, strong transport authentication and session management protocols. This includes the mandatory use of cryptographic identity propagation, message freshness indicators, and secure authorization flows (such as OAuth 2.0 with PKCE and strict state validation).

### Rationale

Because AI Agents frequently act autonomously on behalf of users—interacting with external systems, APIs, and sensitive data—the transport and session layers represent a critical attack surface. If authentication and session mechanisms are weak, adversaries can intercept traffic, replay commands, spoof user identities, or hijack authorization flows (e.g., via Cross-Site Request Forgery or intercepted authorization codes). Implementing stringent cryptographic validation and session binding ensures that every tool invocation is legitimate, securely tied to the active user's context, and protected against unauthorized execution or transport-layer tampering.

### Audit
| Spec | Description |
| --- | ------|
| [6.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#611-mandatory-client-server-transport-authentication) | Mandatory Client-Server Transport Authentication |
| [6.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#612-mandatory-cryptographic-validation-of-user-context) | Mandatory Cryptographic Validation of User Context |
| [6.1.3](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#613-message-freshness-and-session-binding) | Message Freshness and Session Binding |
| [6.1.4](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#614-strict-redirect-uri-and-state-validation) | Strict Redirect URI and State Validation |
| [6.1.5](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#615-mandatory-proof-key-for-code-exchange-pkce) | Mandatory Proof Key for Code Exchange (PKCE) |

---
## 6.2 Tool Use Sanitization

### Description

Tool Use Sanitization requires the AI Agent orchestration layer to inspect, filter, and cleanse all metadata associated with external tool descriptions as well as the data payloads returned from tool executions before they are evaluated by the underlying model. This application-layer defense actively strips out direct or indirect prompt injections and raw LLM control tokens (such as structural role turn markers or stop sequences) that may be embedded within third-party utilities. By intercepting and neutralizing these malicious structural elements at the agent-tool boundary, the system enforces a strict isolation barrier that forces the engine to treat external payloads strictly as untrusted, passive data.

### Rationale

Because autonomous agents dynamically compose and invoke external tools to fulfill user prompts, the data returned from these interfaces serves as a high-impact attack surface for context hijacking and privilege escalation. If tool description metadata or invocation outputs are passed to the model unescaped, an adversary can exploit the blurry boundary between instructions and data to prematurely terminate text generation, spoof system identities, or force unauthorized command execution without user consent. Implementing stringent sanitization at this perimeter closes the critical "confused deputy" vulnerability, ensuring that poisoned third-party data cannot manipulate the agent's core routing logic or trigger destructive, downstream actions.

### Audit
| Spec | Description |
| --- | ------|
| [6.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#621-testing-for-tool-description-metadata-sanitization) | Testing for Tool Description Metadata Sanitization |
| [6.2.2](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Agent%20Test%20Guide.md#622-testing-for-llm-control-tokens-and-metadata-sanitization) | Testing for LLM Control Tokens and Metadata Sanitization |
