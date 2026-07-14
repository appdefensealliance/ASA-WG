# App Defense Alliance AI Tool Testing Guide 
# Contributors

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

# Table of Contents

* [1\. Authentication, Identity, & Session Management](#1.-authentication,-identity,-&-session-management)

   * [1.1 Mandatory Client-Server Transport Authentication](#1.1-mandatory-client-server-transport-authentication)

   * [1.2 Message Freshness and Session Binding](#1.2-message-freshness-and-session-binding)

   * [1.3 Strict Redirect URI and State Validation](#1.3-strict-redirect-uri-and-state-validation)

   * [1.4 Mandatory Proof Key for Code Exchange (PKCE)](#1.4-mandatory-proof-key-for-code-exchange-\(pkce\))

   * [1.5 User Identity Propagation](#1.5-user-identity-propagation)

   * [1.6 Secure Downstream Transport](#1.6-secure-downstream-transport)

   * [1.7 Integrated Transport Security and Message Integrity](#1.7-integrated-transport-security-and-message-integrity)

* [2\. Authorization, Consent, & Access Control](#2.-authorization,-consent,-&-access-control)

   * [2.1 Scoped Authorization and User Context Propagation](#2.1-scoped-authorization-and-user-context-propagation)

   * [2.2 Mandatory Cryptographic Validation of User Context](#2.2-mandatory-cryptographic-validation-of-user-context)

   * [2.3 Mandatory Explicit Consent](#2.3-mandatory-explicit-consent)

   * [2.4 Principle of Least Privilege and Scoped Permissions](#2.4-principle-of-least-privilege-and-scoped-permissions)

   * [2.5 Tool Function Allow-listing and Parameter Validation](#2.5-tool-function-allow-listing-and-parameter-validation)

* [3\. Secret Management & Data Protection](#3.-secret-management-&-data-protection)

   * [3.1 Externalized Secret Management](#3.1-externalized-secret-management)

   * [3.2 Automated PII and Credential Masking in Logs](#3.2-automated-pii-and-credential-masking-in-logs)

   * [3.3 Secure Session Tokens](#3.3-secure-session-tokens)

   * [3.4 Sensitive Output Defense in Depth](#3.4-sensitive-output-defense-in-depth)

   * [3.5 PII Detection](#3.5-pii-detection)

   * [3.6 Data Minimization](#3.6-data-minimization)

   * [3.7 Protect Sensitive Data in Logs](#3.7-protect-sensitive-data-in-logs)

* [4\. Input/Output Sanitization](#4.-input/output-sanitization)

   * [4.1 Output Sanitization](#4.1-output-sanitization)

   * [4.2 Parameterized Arguments and Unsafe Sink Blocking](#4.2-parameterized-arguments-and-unsafe-sink-blocking)

   * [4.3 Detect and Block Unsafe Sinks](#4.3-detect-and-block-unsafe-sinks)

   * [4.4 Maximum Response Size](#4.4-maximum-response-size)

* [5\. Multi-Tenancy & Isolation](#5.-multi-tenancy-&-isolation)

   * [5.1 Stateless Request Level Isolation](#5.1-stateless-request-level-isolation)

   * [5.2 Ensure Sandbox Protections](#5.2-ensure-sandbox-protections)

   * [5.3 Mandatory Tenant Isolation](#5.3-mandatory-tenant-isolation)

* [6\. System Integrity & Supply Chain](#6.-system-integrity-&-supply-chain)

   * [6.1 Cryptographic Message Integrity Validation](#6.1-cryptographic-message-integrity-validation)

   * [6.2 Semantic Integrity and Descriptive Accuracy](#6.2-semantic-integrity-and-descriptive-accuracy)

   * [6.3 Resource Pinning and Signature Verification](#6.3-resource-pinning-and-signature-verification)

* [7\. Resource Constraints & Denial of Service (DoS) Prevention](#7.-resource-constraints-&-denial-of-service-\(dos\)-prevention)

   * [7.1 Financial Resource & Cost Governance](#7.1-financial-resource-&-cost-governance)

   * [7.2 Per User Endpoint Rate Limiting](#7.2-per-user-endpoint-rate-limiting)

   * [7.3 Maximum Payload and Recursion Depth Constraints](#7.3-maximum-payload-and-recursion-depth-constraints)

* [8\. Logging, Auditing, & Monitoring](#8.-logging,-auditing,-&-monitoring)

   * [8.1 Implement comprehensive logging using structured logging formats](#8.1-implement-comprehensive-logging-using-structured-logging-formats)

   * [8.2 Invocation Audit Trail](#8.2-invocation-audit-trail)

# Introduction

This AI Tool security certification provides a comprehensive framework for evaluating the security posture of the interface layer between AI Agents and AI Tools. The scope encompasses a diverse range of integration architectures, including Model Context Protocol (MCP) Servers—serving as bridges for web-based or local host applications—and Mobile AI Tools that implement AI-driven interfaces within mobile application environments. By standardizing security requirements across these platforms, this guide ensures the integrity and confidentiality of the conduits through which sensitive AI interactions flow.

Certification boundaries are strictly defined to focus on components under the direct operational control of the AI Tool developer. Consequently, the underlying hosting platforms and the external AI Agents themselves are considered out of scope. While the tool is required to perform specific security functions—such as generating structured interaction logs—the security of the persistent storage or centralized logging infrastructure provided by the host platform is excluded. This approach ensures that assessments remain focused on the tool’s internal logic, communication protocols, and data handling practices, decoupled from the infrastructure in which they are deployed.

![][image1]

AI Tools may be deployed in several different environments and provide connectivity to local resources, remote resources, or any combination of these. Furthermore, an AI tool may be a stand alone application (Such as a AI Tool running locally on a user’s machine), or embedded into a monolithic application (such as App Functions added to a mobile application). In all cases, this specification shall cover the AI Tool portion of the application. Other specifications, such as the Mobile Application Profile or the Web Application Profile shall apply to the remainder of the developer’s application.

![][image2]

# Relationship To CoSAI Model Context Protocol (MCP) Security 

The App Defense Alliance (ADA) developed this security specification and testing guide by performing a rigorous review of the Model Context Protocol (MCP) Security threat model defined by CoSAI. This underlying threat model encompasses both AI Tool Specific threats and conventional security vulnerabilities. ADA translated these threats into the specific controls and audit test cases detailed throughout this guide.  
The certification boundary is focused exclusively on security controls within the direct operational scope of the AI Tool developer. Consequently, it does not impose requirements on the AI Agent itself or on infrastructure under the end-user's control. While this specification is organized into logical control categories to improve clarity and readability, every requirement is explicitly mapped back to the original CoSAI threat model to ensure comprehensive coverage of identified risks.  
Both static code inspection and dynamic application test cases are defined. Sample prompts are provided for each static test case, which could be used for automated testing. However, detailed testing requirements and acceptance criteria are defined in the AI Tool Testing Guide.

## CoSAI MCP Threat Model 

| Threat Category | AI Tool Specific Threat | Conventional Security Threat |
| :---- | :---- | :---- |
| [MCP-T1](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t1-improper-authentication-and-identity-management): Improper Authentication and Identity Management | [1:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#identity-spoofing) Identity Spoofing<br><br> [8:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#privilege-escalation) Confused Deputy (OAuth Proxy) | [16:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#credential-theft) Credential Theft/Token Theft <br><br>[17:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#replay-attacks) Replay Attacks/Session Hijacking <br><br>[18:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#auth-weakness) OAuth/Legacy Auth Weaknesses <br><br>[19:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#token-leakage) Session Token Leakage |
| [MCP-T2](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t2-missing-or-improper-access-control): Missing or Improper Access Control | [9:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#hil) Insecure Human-in-the-Loop  <br><br>[10:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#improper-multitenancy) Improper Multitenancy | [8:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#privilege-escalation) Privilege Escalation <br><br>[20:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#excessive-permissions) Excessive Permissions/Overexposure |
| [MCP-T3](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t3-input-validationsanitization-failures): Input Validation/Sanitization Failures |  | [21:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#command-injection) Command Injection <br><br>[22:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#path-traversal) File System Exposure/Path Traversal **(Out of ADA AI Tool Scope)**  <br><br>[23:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#insufficient-integrity-checks) Insufficient Integrity Checks |
| [MCP-T4](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t4-inputinstruction-boundary-distinction-failure): Data/Control Boundary Distinction Failure | [2:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#tool-poisoning) Tool Poisoning **(Out of ADA AI Tool Scope)**  <br><br>[3:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#fsp) Full Schema Poisoning **(Out of ADA AI Tool Scope)**  <br><br>[4:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#resource-content-poisoning) Resource Content Poisoning **(Out of ADA AI Tool Scope)**  <br><br>[11:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#prompt-injection) Prompt Injection **(Out of ADA AI Tool Scope)** | [21:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#command-injection) Command Injection **(Out of ADA AI Tool Scope)** |
| [MCP-T5](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t5-inadequate-data-protection-and-confidentiality-controls): Inadequate Data Protection and Confidentiality Controls |  | [24:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#data-exfiltration) Data Exfiltration & Corruption <br><br>[22:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#path-traversal) File System Exposure/Path Traversal **(Out of ADA AI Tool Scope)** |
| [MCP-T6](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t6-missing-integrityverification-controls): Missing Integrity/Verification Controls | [4:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#resource-content-poisoning) Resource Content Poisoning **(Out of ADA AI Tool Scope)** <br><br>[5:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#typosquatting) Typosquatting/Confusion Attacks <br><br>[6:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#shadow-mcp) Shadow AI Tools **(Out of ADA AI Tool Scope)** | [25:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#supply-chain) Supply Chain Compromise and Privileged host-base Attacks **(Out of ADA AI Tool Scope)** |
| [MCP-T7](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t7-session-and-transport-security-failures): Session and Transport Security Failures | [12:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mitm) Man-in-the-Middle (MITM) | [26:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#unrestricted-network) Unrestricted Network Access **(Out of ADA AI Tool Scope)** <br><br>[27:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#protocol-security) Protocol Security Gaps **(Out of ADA AI Tool Scope)** <br><br>[28:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#insecure-descriptor) Insecure Descriptor Handling **(Out of ADA AI Tool Scope)** <br><br>[23:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#insufficient-integrity-checks) Insufficient Integrity Checks <br><br>[29:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#csrf) CSRF Protection Missing **(Mitigated through CASA)** <br><br>[30:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#cors) CORS/Origin Policy Bypass |
| [MCP-T8](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t8-network-bindingisolation-failures): Network Binding/Isolation Failures | [6:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#shadow-mcp) Shadow AI Tools <br><br>[10:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#improper-multitenancy) Improper Multitenancy | [31:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#malicious-command-execution) Malicious Command Execution <br><br>[32:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#dependency-update-attack) Dependency/Update Attack <br><br>[26:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#unrestricted-network) Unrestricted Network Access **(Out of ADA AI Tool Scope)** |
| [MCP-T9](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t9-trust-boundary-and-privilege-design-failures): Trust Boundary and Privilege Design Failures | [7:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#overreliance) Overreliance on the LLM <br><br>[13:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#user-fagitue) Consent/User Approval Fatigue **(Out of ADA AI Tool Scope)**  |  |
| [MCP-T10](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t10-resource-managementrate-limiting-absence): Resource Management/Rate Limiting Absence | [14:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#resource-exhaustion) Resource exhaustion and denial of wallet | [33:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#payload-limit) Payload Limit/DoS |
| [MCP-T11](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t11-supply-chain-and-lifecycle-security-failures): Supply Chain and Lifecycle Security Failures | [6:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#shadow-mcp) Shadow AI Tools **(Out of ADA AI Tool Scope)** | [25](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#supply-chain): Supply Chain Compromise **(Out of ADA AI Tool Scope)** |
| [MCP-T12](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t12-insufficient-logging-monitoring-and-auditability): Insufficient Logging, Monitoring, and Auditability | [15:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#invisible-agent) Invisible Agent Activity | [34:](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#lack-of-observability) Lack of Observability |

# Applicability

This document is intended for AI tool developers, end-users, network administrators responsible for enterprise deployments, and security assessors who plan to build, operate, host, or evaluate AI tools.

# References

* [CoSAI MCP Security](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md)

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License.](https://creativecommons.org/licenses/by-sa/4.0/)

# Definitions

| Term | Definition |
| :---- | :---- |
| **AI Tool** | An application or integration that encompasses the interface layer between an AI Agent and the tool itself, as well as between the tool and a Web/Mobile Application. This includes Model Context Protocol (MCP) Servers and Mobile AI Tools. |
| **Model Context Protocol (MCP) Servers** | Servers that act as bridges to web-based applications, or function as local interfaces residing on host machines. The MCP Client is often embedded in the AI Agent. |
| **Mobile AI Tools** | Mobile applications that implement AI-driven interfaces similar to MCP architectures, such as mobile applications with App Functions. The App Function portion of the code would be considered the AI Tool. |
| **Confused Deputy** | A vulnerability that occurs when an AI Tool uses a global admin key or its own service-level credentials to fulfill a request from a low-privilege user, allowing the user to escalate privileges via the AI tool. |
| **Session Bleed** | A flaw where data from a previous request persists in memory or global variables and is inadvertently accessed by a subsequent request from a different tenant. |
| **Cross-Tenant Data Leakage (CTDL)** | The unauthorized exposure of one tenant's data to another, which can be mitigated by enforcing mandatory statelessness. |
| **Mandatory Statelessness** | A technical control requiring a "Process, Respond, Purge" lifecycle so that every request is treated as an independent atomic unit. This ensures no user-specific data or internal reasoning traces linger in memory for subsequent requests. |
| **Prompt Injection** | A class of vulnerabilities where an attacker intentionally crafts malicious inputs to manipulate a model into ignoring its original system instructions and executing unauthorized actions. |
| **Indirect Prompt Injection (IPI)** | A subversion technique where a compromised Agent attempts to instruct a tool to read its own internal configuration or leak supplementary backend data. |
| **Resource Content Poisoning** | An attack where hidden malicious instructions are embedded within backend data sources (like databases or documents) that AI Tools retrieve and provide to LLMs. |
| **Typosquatting / Confusion Attacks** | Attacks where malicious actors create tools or AI Tools with names and descriptions similar to legitimate ones, tricking clients or agents into invoking harmful tools. |
| **Shadow AI Tools** | Unauthorized, unmonitored, or hidden AI Tool instances that create blind spots and increase the risk of covert data exfiltration. |
| **Denial of Wallet (DoW) Attack** | An attack that triggers an excessive number of API or tool calls, leading to unexpected financial costs that impact the viability of a business. |
| **Rug Pull Attack** | A supply chain attack where a dependency is automatically updated to a compromised version, which is mitigated by strict version pinning. |
| **Proof Key for Code Exchange (PKCE)** | A challenge-response mechanism providing a dynamic, cryptographically bound secret that ensures only the entity that initiated an OAuth authorization request can successfully exchange the resulting code for a token. |

# Static Application Security Testing (SAST) Guidance

Assurance level 0 (self assessment) and Assurance level 1 (Verified Self Assessment) are based on evidence generated based on source code inspection. For AL0 (Self Assessment), the developer attests that the evidence complies with the audit verification requirements. For AL1 (Verified Self Assessment), the developer submits the evidence to an ADA Authorized Lab, who will then verify the evidence complies with the audit verification requirements. It is expected that the gathering of evidence will be performed by the ADA AI Tool certification tool.

# Specification Summary

| Category | Requirement |
| :---- | :---- |
| 1\. Authentication, Identity, & Session Management | 1.1 Mandatory Client-Server Transport Authentication |
|  | 1.2 Message Freshness and Session Binding |
|  | 1.3 Strict Redirect URI and State Validation |
|  | 1.4 Mandatory Proof Key for Code Exchange (PKCE) |
|  | 1.5 User Identity Propagation |
|  | 1.6 Secure Downstream Transport |
|  | 1.7 Integrated Transport Security and Message Integrity |
| 2\. Authorization, Consent, & Access Control | 2.1 Scoped Authorization and User Context Propagation |
|  | 2.2 Mandatory Cryptographic Validation of User Context |
|  | 2.3 Mandatory Explicit Consent |
|  | 2.4 Principle of Least Privilege and Scoped Permissions |
|  | 2.5 Tool Function Allow-listing and Parameter Validation |
| 3\. Secret Management & Data Protection | 3.1 Externalized Secret Management |
|  | 3.2 Automated PII and Credential Masking in Logs |
|  | 3.3 Secure Session Tokens |
|  | 3.4 Sensitive Output Defense in Depth |
|  | 3.5 PII Detection |
|  | 3.6 Data Minimization |
|  | 3.7 Protect Sensitive Data in Logs |
| 4\. Input/Output Sanitization | 4.1 Output Sanitization |
|  | 4.2 Parameterized Arguments and Unsafe Sink Blocking |
|  | 4.3 Detect and Block Unsafe Sinks |
|  | 4.4 Maximum Response Size |
| 5\. Multi-Tenancy & Isolation | 5.1 Ensure Sandbox Protections |
|  | 5.2 Stateless Request Level Isolation |
|  | 5.3 Mandatory Stateless Request-Level Isolation |
|  | 5.4 Mandatory Tenant Isolation |
| 6\. System Integrity & Supply Chain | 6.1 Cryptographic Message Integrity Validation |
|  | 6.2 Semantic Integrity and Descriptive Accuracy |
|  | 6.3 Resource Pinning and Signature Verification |
| 7\. Resource Constraints & Denial of Service (DoS) Prevention | 7.1 Financial Resource & Cost Governance |
|  | 7.2 Per User Endpoint Rate Limiting |
|  | 7.3 Maximum Payload and Recursion Depth Constraints |
| 8\. Logging, Auditing, & Monitoring | 8.1 Implement comprehensive logging using structured logging formats |
|  | 8.2 Invocation Audit Trail |

# 1. Authentication, Identity, & Session Management

## 1.1 Mandatory Client-Server Transport Authentication

### Description

The AI Tool must verify the identity of the client before executing any tools or providing resources. For remote connections (SSE), this must involve strong authentication (e.g., OAuth2, dynamically rotated API Keys, or mTLS). For local connections (Stdio), the server must ensure it is only accepting input from the authorized parent process.

**This requirement only applies to remote servers. Local and mobile servers are out of scope.**

### Rationale

Without identity verification, an attacker could impersonate a legitimate AI agent or host to trigger sensitive tools (e.g., "delete\_database") or extract proprietary data.

### Audit

**Evidence**  
**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with valid credentials.

**Test Procedure**  
**AL0, AL1:**

1. **Identify Transport Setup:** Search the AI Tool initialization and transport setup code to determine the communication method (e.g., SSE, Stdio).  
2. **Verify Identity Validation:** Identify where the server validates the 'Authorization' header or client certificates during the handshake or request phase.  
3. **Check Cryptographic Binding:** Verify that there is a cryptographic binding between the validated identity and the established session to prevent hijacking.  
4. **Flag Authentication Gaps:** Flag any server implementation that executes tool calls or provides resources without an explicit, successful authentication check.

**AL2:**

1. **Attempt Unauthenticated Access:** Try to connect to the AI Tool or trigger a tool call without providing any authentication credentials to ensure the request is rejected.  
2. **Test Invalid Credentials:** Provide expired, malformed, or incorrect tokens/keys to verify that the server correctly denies access.  
3. **Verify Session Persistence:** Ensure that once a session is authenticated, the identity remains consistent and cannot be swapped mid-session.

**Verification**  
**AL0, AL1:**

1. **Identity Validation:** The server shall validate the 'Authorization' header or client certificates during the handshake or request phase.  
2. **Cryptographic Binding:** There shall be cryptographic binding between the validated identity and the established session.  
3. **Authentication Gaps:** There shall not be any server implementation that executes tool calls or provides resources without an explicit, successful authentication check.

**AL2:**

1. **Unauthenticated Access:** Unauthenticated access shall be rejected.  
2. **Invalid Credentials:** Expired, malformed, or incorrect tokens/keys shall be rejected.  
3. **Session Persistence:** Once a session is authenticated, the identity remains consistent and cannot be swapped mid-session.

## 1.2 Message Freshness and Session Binding

### Description

For persistent or stateful transports (e.g., SSE, WebSockets), the AI Tool must implement session timeouts and validate message timestamps or nonces if provided by the client. The server must terminate sessions that exceed a defined period of inactivity.

### Rationale

If an attacker captures a valid AI Tool tool-call request, they could "replay" it later to trigger the tool again (e.g., a "pay_invoice" tool) even if the original session has ended.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with valid credentials.

**Test Procedure**

**AL0, AL1:**

1. **Examine Session Management:** Review the session management logic within the AI Tool transport layer (e.g., SSE, WebSockets).  
2. **Identify Expiration Timers:** Verify the implementation of an expiration timer (TTL) for active sessions to ensure they are terminated after a defined period of inactivity.  
3. **Check Freshness Validation:** Confirm the server validates 'timestamp' or 'nonce' fields within incoming JSON-RPC objects to prevent processing stale or duplicate requests.

**AL2:**

1. **Verify Inactivity Timeouts:** Establish a session and remain inactive to verify the server automatically terminates the connection after the defined timeout period.  
2. **Test Replay Resistance:** Attempt to capture and resend a previously successful JSON-RPC tool-call request to ensure the server rejects the duplicate based on an expired timestamp or used nonce.  
3. **Validate Session Termination:** Ensure that once a session is terminated or timed out, any subsequent requests using that session identifier are strictly rejected.

**Verification**

**AL0, AL1:**

1. **Session Management:** The session management logic within the AI Tool transport layer is present and properly implemented.  
2. **Expiration Timers:** There is a verified implementation of an expiration timer (TTL) that ensures active sessions are terminated after a defined period of inactivity.  
3. **Freshness Validation:** The server enforces validation of 'timestamp' or 'nonce' fields within incoming JSON-RPC objects to block stale or duplicate requests.

**AL2:**

1. **Inactivity Timeouts:** The server automatically terminates the connection after the defined timeout period of inactivity.  
2. **Replay Resistance:** Duplicate JSON-RPC requests are successfully rejected by the server based on an expired timestamp or used nonce.  
3. **Session Termination:** Any subsequent requests attempting to use a terminated or timed-out session identifier are strictly rejected.

## 1.3 Strict Redirect URI and State Validation

### Description

If the AI Tool facilitates OAuth flows for tool access, it must strictly validate Redirect URIs against a pre-defined allowlist and enforce the use of the state parameter to prevent Cross-Site Request Forgery (CSRF). Legacy authentication methods (Basic Auth over HTTP) are strictly prohibited.

### Rationale

AI tools often need to connect to 3rd party SaaS (GitHub, Jira). Weaknesses in the OAuth flow can allow attackers to intercept authorization codes and hijack the tool's access to those services.

**This requirement is out of scope for mobile AI Tools, or remote servers in which the AI Tool is integrated into a WebApp.**

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with valid credentials and configured OAuth flows.

**Test Procedure**

**AL0, AL1:**

1. **Locate OAuth Logic:** Identify the OAuth callback or authorization URL construction logic within the server codebase.  
2. **Verify State Generation:** Ensure that the state parameter is generated using a cryptographically secure random generator.  
3. **Verify State Validation:** Confirm that the state parameter is strictly validated upon return to prevent Cross-Site Request Forgery (CSRF).  
4. **Check Redirect URI Construction:** Verify that the redirect\_uri is not dynamically constructed from user-controlled input.  
5. **Confirm Allowlist Enforcement:** Ensure the redirect\_uri is checked against a hardcoded or configuration-based allowlist.  
6. **Flag Legacy Methods:** Identify and flag any use of legacy authentication methods, such as Basic Auth over HTTP, which are strictly prohibited.

**AL2:**

1. **Verify Redirect URI Validation:** Attempt to use a redirect\_uri that is not on the pre-defined allowlist to confirm the authorization request fails.  
2. **Confirm Secure Transport:** Verify that all authentication flows occur over secure channels (HTTPS) and that legacy unencrypted methods are rejected.

**Verification**

**AL0, AL1:**

1. **OAuth Logic:** OAuth callback and authorization URL construction logic is present and properly implemented.  
2. **State Generation:** A cryptographically secure random generator is verified to be in use for generating the state parameter.  
3. **State Validation:** The server enforces strict validation of the state parameter upon return to prevent CSRF.  
4. **Redirect URI Construction:** The redirect\_uri is structurally secure and isolated from dynamic, user-controlled input.  
5. **Allowlist Enforcement:** The redirect\_uri successfully validates against a hardcoded or configuration-based allowlist.  
6. **Legacy Methods:** There is no presence or permitted use of legacy authentication methods (e.g., Basic Auth over HTTP).

**AL2:**

1. **Redirect URI Validation:** The authorization request successfully fails when attempting to use a redirect\_uri not on the pre-defined allowlist.  
2. **Secure Transport:** Authentication flows are confirmed to be strictly bound to secure channels (HTTPS), and any requests via legacy unencrypted methods are rejected.

## 1.4 Mandatory Proof Key for Code Exchange (PKCE)

### Description

When the AI Tool initiates an OAuth 2.0 authorization code flow to obtain user credentials for a tool, it must implement and enforce Proof Key for Code Exchange (PKCE) as defined in RFC 7636\. The server must generate a unique, high-entropy code\_verifier for every authorization request, send the code\_challenge (derived via the S256 method) to the authorization endpoint, and provide the original code\_verifier during the token exchange step. This requirement applies regardless of whether the client is classified as public or confidential.

### Rationale

Authorization codes are vulnerable to interception via custom URI scheme hijacking (on mobile/local hosts) or log leakage. PKCE provides a dynamic, cryptographically bound secret that ensures only the entity that initiated the authorization request can successfully exchange the resulting code for a token. This effectively mitigates "Authorization Code Injection" and "Interception" attacks by rendering a stolen code useless to an attacker.

**Mobile AI Tools are out of scope for this requirement.**

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with valid credentials and configured OAuth flows.

**Test Procedure**

**AL0, AL1:**

1. **Identify OAuth Initiation Logic:** Locate the code responsible for constructing the initial authorization URL. Verify that it generates a cryptographically secure `code_verifier` and includes a `code_challenge` and `code_challenge_method=S256` in the request parameters.  
2. **Verify Token Exchange:** Locate the function that exchanges the authorization code for an access token. Ensure that the original `code_verifier` is retrieved from secure session storage and included in the POST body to the token endpoint.  
3. **Flag Vulnerabilities:** Flag any OAuth 2.0 implementation that relies solely on a static `client_secret` or state parameter without incorporating the PKCE challenge-response mechanism.

**AL2:**

1. **Attempt PKCE Bypass:** Initiate an OAuth authorization flow and attempt to complete the token exchange without providing the `code_verifier`, or by providing an invalid `code_verifier`. Verify that the server correctly rejects the token exchange request.

**Verification**

**AL0, AL1:**

1. **OAuth Initiation Logic:** The codebase must generate a cryptographically secure `code_verifier` and explicitly include `code_challenge` and `code_challenge_method=S256` in the authorization request.  
2. **Token Exchange:** The token exchange function must successfully retrieve the original `code_verifier` from secure session storage and include it in the POST body to the token endpoint.  
3. **Vulnerabilities:** There must be no instances of OAuth 2.0 implementations relying solely on a static `client_secret` or state parameter without PKCE.

**AL2:**

1. **PKCE Bypass:** The server must successfully reject token exchange requests that omit or alter a valid `code_verifier`.  
   

## 1.5 User Identity Propagation

### Description

If more than one user is supported, the AI Tool must not "assume" which user it is acting for based on the connection alone.

* **Token Validation:** Every request must include a short-lived Identity Token that identifies the specific user.

* **Scoped Access:** The server’s internal logic must use this token to scope all database queries (e.g., SELECT \* FROM docs WHERE owner\_id \= {JWT.sub}), or access to other user specific data or APIs.

* **Hard Fail on Missing Identity:** If a request arrives without a valid, verifiable identity token, the server must return a 401 Unauthorized and terminate the execution thread immediately.

#### 

### Rationale

Identity Propagation is the cornerstone of Multi-Tenant Data Isolation, ensuring that every action performed by an AI Tool is explicitly tied to a verified user or organization through short-lived, cryptographically signed identity tokens. By mandating that the server validate these tokens for every incoming request, we eliminate "Implicit Authorization" and prevent Direct Object Reference (IDOR) attacks where one tenant might attempt to access another's data by guessing a resource ID. This requirement forces the third-party server to operate within a "Zero Trust" framework, where access to any underlying data or tool is strictly scoped to the identity contained within the request payload, providing a verifiable and auditable cryptographic link between the user's intent and the server's execution.

**Mobile AI Tools are out of scope for this requirement.**

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool configured with multiple user accounts and downstream resource access.

**Test Procedure**

**AL0, AL1:**

1. **Identify Token Handling:** Search the codebase for the point where incoming requests are received. Verify that the user’s identity (e.g., JWT, OAuth token, or User ID) is extracted and explicitly passed into the tool execution context.  
2. **Verify Downstream Authentication:** Inspect the client initialization for downstream services (e.g., a Database client or GitHub API client). Ensure that these clients are instantiated using the propagated user token rather than a hardcoded administrative or "app-level" API key.  
3. **Check Middleware Injection:** If using a framework, verify that the identity propagation is enforced via middleware and cannot be bypassed by individual tool implementations.

**AL2:**

1. **Verify Permission Enforcement:** Attempt to call a tool (e.g., read\_file) targeting a resource that "User A" owns but "User B" does not. Authenticate as "User B" and verify that the tool returns a 403 Forbidden or 401 Unauthorized error from the downstream resource.  
2. **Inspect Downstream Logs:** Execute a tool call and then inspect the audit logs of the downstream service (e.g., AWS CloudTrail or GitHub Audit Logs). Confirm that the action was recorded under the end-user's identity and not the AI Tool’s service account name.  
3. **Token Scoping Test:** Provide the AI Tool with a scoped or "limited" token for a user. Attempt to execute a tool that requires permissions outside of that scope. Verify that the tool execution fails at the resource level, proving that the server is respecting the specific token's limitations.

**Verification**

**AL0, AL1:**

1. **Token Handling:** User identity must be successfully extracted from incoming requests and explicitly passed into the tool execution context.  
2. **Downstream Authentication:** Downstream service clients must be instantiated using the propagated user token rather than a hardcoded administrative key.  
3. **Middleware Injection:** Identity propagation must be enforced centrally (e.g., via middleware) and cannot be bypassed by individual tool implementations.

**AL2:**

1. **Permission Enforcement:** The server must reject cross-user resource access attempts with a 403 Forbidden or 401 Unauthorized error.  
2. **Downstream Logs:** Downstream audit logs must correctly record the action under the end-user's identity, not a service account.  
3. **Token Scoping:** The server must respect scoped token limitations and fail execution at the resource level when permissions are exceeded.

## 1.6 Secure Downstream Transport

### Description

The AI Tool must ensure that all communications with downstream resources (e.g., internal APIs, databases, or third-party services) that involve the transmission of secrets are conducted over encrypted channels (TLS 1.3 or higher). All security sensitive data shall be protected when in flight. For example, tokens shall not be sent in HTTP headers.

### Rationale

Credential theft often occurs during transit or through the reuse of intercepted long-lived keys. Ensuring encrypted transport mitigates interception risks during the "handling" phase.

**Mobile AI Tools and AI Tools integrated into Web Applications are out of scope for this requirement.** 

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool and downstream resources with network interception tools (e.g., Wireshark, proxy).

**Test Procedure**

**AL0, AL1:**

1. **Identify Downstream Clients:** Search the codebase for all outgoing network clients (e.g., axios, fetch, requests, pg-client).  
2. **Verify TLS Enforcement:** Confirm that connection strings and URL constructions strictly use https:// or equivalent secure protocols (e.g., sslmode=require for databases).  
3. **Protect Data in Transit:** Audit the codebase for any transmission of sensitive information (e.g., auth tokens) and confirm robust encryption is enforced.

**AL2:**

1. **Monitor Outbound Traffic:** Use a network interception tool (e.g., Wireshark or a service mesh proxy) to verify that secrets (Authorization headers, API keys) are never sent over unencrypted (HTTP) connections.

**Verification**

**AL0, AL1:**

1. **Downstream Clients Identification:** All outgoing network clients are successfully identified in the codebase.  
2. **TLS Enforcement:** All connection strings and URL constructions strictly enforce secure protocols (https:// or equivalent).  
3. **Data in Transit Protection:** Robust encryption is enforced for the transmission of all sensitive information.

**AL2:**

1. **Secure Outbound Traffic:** Network interception confirms that no secrets or sensitive authentication data are transmitted over unencrypted connections.  
   

## 1.7 Integrated Transport Security and Message Integrity

### Description

To mitigate Man-in-the-Middle (MitM) and message integrity risks, the system must enforce a unified secure transport layer and message-level protection. For remote connections, communication must be encrypted using TLS 1.3+ with strict X.509 certificate and trust chain validation (rejecting plaintext, expired, or untrusted endpoints). For local connections, the system must bypass the network stack in favor of secure Inter-Process Communication (IPC)—such as Unix domain sockets or Windows Named Pipes—protected by strict OS-level permissions. 

### Rationale

This requirement establishes a multi-layered defense. High-grade encryption and secure IPC prevent unauthorized eavesdropping on the wire or within the host. Strict certificate validation ensures the client is communicating with the legitimate server, rather than an attacker's proxy. Lastly, message-level signing guarantees that even if a transport-level vulnerability exists, the underlying tool calls and responses remain immutable and can only be executed once.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool and client setups with valid credentials, network interception proxy, or manipulation tools.

**Test Procedure**

**AL0, AL1:**

1. **Protocol Check:** Inspect configuration files (e.g., server\_config.json) to ensure the minimum TLS version is pinned to 1.3 and that legacy ciphers are disabled.  
2. **Validation Check:** Verify that the client implementation does not include flags that bypass certificate validation (e.g., NODE\_TLS\_REJECT\_UNAUTHORIZED=0 or verify=False).  
3. **IPC Check:** Review the transport initialization code to ensure local deployments use socket paths or named pipes rather than localhost or 127.0.0.1.

**AL2:**

1. **Downgrade Attack Test:** Attempt to initiate a connection using TLS 1.2 or lower; verify the server refuses the handshake.  
2. **Trust Chain Test:** Point the AI Tool client to a server with a self-signed or expired certificate; verify the client terminates the connection immediately.  
3. **Replay Attack Test:** Intercept a valid tool call and attempt to resend it to the server; verify the server rejects the message as a duplicate based on the nonce/timestamp.  
4. **Local Isolation Test:** Attempt to read from the IPC socket or pipe using a secondary, non-privileged system user; verify the operating system denies access based on the file permissions.

**Verification**

**AL0, AL1:**

1. **Protocol Check:** The codebase strictly enforces a minimum TLS version of 1.3 with legacy ciphers disabled.  
2. **Validation Check:** The implementation does not include or permit flags that bypass X.509 certificate validation.  
3. **IPC Check:** Local deployments successfully bypass the network stack in favor of secure Inter-Process Communication (e.g., Unix domain sockets or Windows Named Pipes).

**AL2:**

1. **Downgrade Attack:** The server refuses any handshake attempting to use TLS 1.2 or lower.  
2. **Trust Chain Validation:** Connections to servers with self-signed or expired certificates are immediately terminated by the client.  
3. **Replay Attack Resistance:** Duplicate messages are successfully rejected by the server based on an expired timestamp or used nonce.  
4. **Local Isolation:** Secondary, non-privileged system users are successfully denied access to the IPC socket or pipe based on OS-level permissions.

# 2. Authorization, Consent, & Access Control

## 2.1 Scoped Authorization and User Context Propagation

### Description

The AI Tool must not rely solely on its own service-level credentials to access downstream resources. It must require and validate "User-in-the-loop" context or scoped tokens passed through the AI Tool request metadata to ensure the end-user has the authority to perform the requested action.

### Rationale

An AI Tool acts as a deputy. If it uses a global admin key to fulfill a request from a low-privilege user, it becomes a 'confused deputy,' allowing the user to escalate privileges via the AI tool.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool configured with multiple user accounts and downstream resource access.

**Test Procedure**

**AL0, AL1:**

1. **Analyze Tool Handlers:** Identify and examine all `callTool` handler functions within the codebase.  
2. **Verify Token Usage:** Check if the tool logic relies on a hardcoded "Global Admin" or service-level token to access external APIs.  
3. **Verify Context Extraction:** Confirm the code extracts a user-specific identifier or session token from the metadata or parameters of the AI Tool request.  
4. **Check Authorization Logic:** Verify that the extracted user context is used to authorize access to specific downstream resources.

**AL2:**

1. **Test Privilege Separation:** Attempt to access a resource belonging to User A while authenticated as User B to ensure the request is denied.  
2. **Verify Scoped Execution:** Trigger a tool call and inspect the downstream API request to confirm it uses a scoped user token rather than a global administrative key.  
3. **Validate Metadata Propagation:** Ensure that user-in-the-loop context passed through AI Tool request metadata is correctly honored by the server before executing sensitive actions.

**Verification**

**AL0, AL1:**

1. **Tool Handlers:** `callTool` handlers must be identified and explicitly examined for authorization checks.  
2. **Token Usage:** Tool logic must not rely on hardcoded "Global Admin" or service-level tokens to access external APIs.  
3. **Context Extraction:** Code must successfully extract a user-specific identifier or session token from AI Tool request metadata or parameters.  
4. **Authorization Logic:** The extracted user context must be strictly used to authorize access to specific downstream resources.

**AL2:**

1. **Privilege Separation:** The server must deny requests attempting to access resources belonging to a different user.  
2. **Scoped Execution:** Downstream API requests must use a scoped user token rather than a global administrative key.  
3. **Metadata Propagation:** The server must correctly honor user-in-the-loop context passed through AI Tool request metadata before sensitive execution.

## 2.2 Mandatory Cryptographic Validation of User Context

### Description 

The AI Tool must verify the cryptographic signature of identity tokens or user context metadata provided by the AI Tool host (Agent) (when possible). If the tool interacts with external third-party APIs (downstream resources), it must utilize an "On-Behalf-Of" flow or exchange the validated user token for a scoped access token. The server shall reject any request where the user context is provided as a simple, unverified string (e.g., a plain `user_id` field).

### Rationale 

If a developer's tool simply trusts a `user_id` passed by the Agent, a compromised or "confused" Agent could provide "User A's" ID while executing "User B's" request. By requiring cryptographic validation (e.g., verifying a JWT signed by a trusted IdP), the Developer ensures that the user context is authentic and that the Agent cannot escalate privileges by misrepresenting the user.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with valid credentials and network interception tools.

**Test Procedure**

**AL0, AL1:**

1. **Identify Token Validation Logic:** Search the codebase for JWT or identity token parsing logic. Verify that the implementation uses a library to check signatures (e.g., `jwt.verify()`) against a trusted public key or JWKS endpoint.  
2. **Check Downstream Flow:** Inspect outbound API calls to ensure they utilize the validated user context to acquire "On-Behalf-Of" tokens rather than using the server's own administrative credentials.  
3. **Flag Unverified Identifiers:** Identify and flag any tool handlers that accept user identifiers (like email or uuid) as plain parameters without verifying an accompanying cryptographic signature.

**AL2:**

1. **Submit Unsigned/Malformed Tokens:** Attempt to trigger a tool call using a token with the signature removed or a header set to "alg": "none". Verify the server returns an authentication error.  
2. **Payload Tampering:** Provide a validly signed token but modify the `user_id` within the payload. Verify the cryptographic check fails and the request is rejected.  
3. **Verify Token Exchange:** Intercept downstream traffic to confirm that the AI Tool is passing a scoped user-specific token to the final resource, rather than its own service-level key.

**Verification**

**AL0, AL1:**

1. **Token Validation Logic:** The implementation must securely use a cryptographic library to check signatures against a trusted public key or JWKS endpoint.  
2. **Downstream Flow:** Outbound API calls must correctly utilize validated user context for "On-Behalf-Of" token acquisition.  
3. **Unverified Identifiers:** The server must flag and not process tool handlers accepting plain user identifiers without cryptographic signature verification.

**AL2:**

1. **Unsigned/Malformed Tokens:** The server must return an authentication error for tokens missing signatures or with "alg" set to "none".  
2. **Payload Tampering:** The server must reject requests and fail cryptographic checks for tokens with tampered payloads.  
3. **Token Exchange:** Downstream traffic must explicitly show the server passing a scoped user-specific token instead of a service-level key.

## 2.3 Mandatory Explicit Consent

### Description

The AI tool implementation must utilize elicitation or confirmation message on the server side to request user confirmation of actions, or enforce the use of clients with configurations that unprivileged users cannot change to keep confirmation prompts enabled. Security-relevant messages and elicitations must be clear, indicating the implications of the request, and unambiguous about what is being requested.

### Rationale

Missing or insufficient human-in-the-loop consent checks can allow an AI Tool to take risky actions not authorized by the user. A large language model, whether legitimate or poisoned, may decide to execute a tool in a dangerous way, making user confirmation crucial for mitigating this risk.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with defined high-risk tools and unprivileged user accounts.

**Test Procedure**

**AL0, AL1:**

1. **Review Elicitation Logic:** Identify tool execution logic handling sensitive or state-changing actions. Verify that the code mandates an elicitation or confirmation flow prior to execution.  
2. **Check Configuration Enforcement:** Inspect client and server configuration files to ensure confirmation prompts are locked and cannot be disabled by unprivileged users.  
3. **Assess Prompt Clarity:** Review the UI/UX strings or schema definitions associated with the prompts to ensure they clearly articulate the security implications of the requested action.

**AL2:**

1. **Attempt Unauthorized Execution:** Try to trigger a high-risk tool via the AI Tool using an automated script or prompt injection payload without providing out-of-band consent. Verify that the action halts and requests explicit authorization.  
2. **Test Configuration Bypass:** Log in as an unprivileged user and attempt to modify the application settings to disable the confirmation prompt configuration; verify the system rejects this change.

**Verification**

**AL0, AL1:**

1. **Elicitation Logic:** The code must consistently enforce an elicitation or confirmation flow prior to executing sensitive or state-changing actions.  
2. **Configuration Enforcement:** Configuration logic must lock confirmation prompts, preventing unprivileged users from disabling them.  
3. **Prompt Clarity:** UI/UX strings and schema definitions must clearly and accurately articulate the security implications of the intended action.

**AL2:**

1. **Unauthorized Execution:** The server must automatically halt execution and request explicit authorization when high-risk tools are triggered without out-of-band consent.  
2. **Configuration Bypass:** The system must explicitly reject unprivileged user attempts to disable confirmation prompt settings.

## 2.4 Principle of Least Privilege and Scoped Permissions

### Description

AI Tools must operate with the minimum privileges necessary. Implementations must reduce scopes to least privilege, such as removing write scopes when only read access is required.

### Rationale

AI agents, AI Tools, or tools granted more privileges than necessary drastically increase the blast radius in the event of an attack or misconfiguration. Without strict least privilege by design, a compromised agent can easily escalate privileges, move laterally, or corrupt sensitive data.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection and IAM/RBAC configuration reviews to show compliance.

**AL2:** Functional AI Tool with varying scoped tokens (e.g., read-only).

**Test Procedure**

**AL0, AL1:**

1. **Review IAM and RBAC:** Audit role-based access control (RBAC) configurations, Identity and Access Management (IAM) policies, and OAuth token exchanges to ensure requested scopes match the exact operational requirements of the tools.  
2. **Analyze Scope Definitions:** Inspect tool definition files and server configurations to ensure they explicitly reduce scopes for least privilege, such as not requesting write scopes when only read access is required. Flag any tools requesting broad administrative rights or wildcard (\*) access.

**AL2:**

1. **Test Scope Boundaries:** Authenticate a session using a properly scoped "read-only" token. Attempt to invoke an AI Tool that performs a "write," "update," or "delete" operation.  
2. **Verify Rejection:** Confirm that the server explicitly rejects the action at the resource level and returns an unauthorized/forbidden error, proving the server respects the specific token's limitations.

**Verification**

**AL0, AL1:**

1. **IAM and RBAC:** Requested scopes in RBAC, IAM, and OAuth exchanges must strictly match documented operational requirements.  
2. **Scope Definitions:** Tool definitions and configurations must explicitly reduce scopes for least privilege and must not request broad administrative rights or wildcard access.

**AL2:**

1. **Scope Boundaries:** The system must reliably enforce the limitations of scoped tokens (e.g., preventing write actions with read-only tokens).  
2. **Rejection:** The server must explicitly reject unauthorized resource-level actions, responding with a forbidden or unauthorized error.

## 2.5 Tool Function Allow-listing and Parameter Validation

### Description

The AI Tool SHALL expose only an explicitly defined set of functions to the AI Agent. Functions not included in the tool's published manifest SHALL NOT be invocable via the agent interface. All function parameters SHALL be validated against their declared types and constraints before execution. The tool SHALL reject requests containing undeclared parameters or parameters that fail type/constraint validation.

### Rationale

Because AI agents are inherently probabilistic and vulnerable to prompt injection, strict function allow-listing ensures that only explicitly authorized capabilities are exposed to minimize the system's overall attack surface. Additionally, rigorous parameter validation prevents malicious payloads or model hallucinations from executing unauthorized commands, accessing unintended data, or causing downstream system instability.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection and manifest review to show compliance.

**AL2:** Functional AI Tool to test API constraints and invalid parameters.

**Test Procedure**

**AL0, AL1:**

1. **Manifest and Export Review:** Compare the tool's published manifest against actual exported function handlers. Flag any function executable but not declared.  
2. **Parameter Validation Check:** Inspect parameter handling for type and constraint validation before execution.

**AL2:**

1. **Test Undeclared Functions:** Attempt to invoke a function that is not declared in the tool's published manifest.  
2. **Test Parameter Constraints:** Submit calls with wrong parameter types, out-of-range values, and extra parameters. Verify each is rejected.

**Verification**

**AL0, AL1:**

1. **Manifest and Export Match:** All executable functions must be explicitly and correctly declared in the published manifest.  
2. **Parameter Handling:** The code must implement strict type and constraint validation for all declared function parameters.

**AL2:**

1. **Undeclared Functions:** The server must explicitly reject any invocation of an undeclared function.  
2. **Parameter Rejection:** The server must successfully reject tool calls containing incorrect parameter types, out-of-range values, or extra parameters.

# 3. Secret Management & Data Protection

## 3.1 Externalized Secret Management

### Description

AI Tools must never contain hardcoded credentials, API keys, or private keys within the source code or configuration files. All sensitive secrets must be retrieved at runtime from an environment variable or a dedicated Secret Management Service (e.g., AWS Secrets Manager, HashiCorp Vault). Developers shall have a policy and procedure in place to periodically rotate sensitive secrets and have revocation protocols in place if a breach is detected.

### Rationale

AI Tools are often lightweight and distributed; hardcoded secrets are easily leaked through version control or container image inspection, leading to full compromise of the connected tools.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with valid credentials and network interception tools.

**Test Procedure**

**AL0, AL1:**

1. **Scan for Hardcoded Secrets:** Scan the codebase for regex patterns matching high-entropy strings, API keys (e.g., sk-, ghp\_), and hardcoded passwords.  
2. **Verify Client Initialization:** Check that all external service clients (e.g., OpenAI, Database, Slack) are initialized using process.env or a specific configuration provider.  
3. **Flag String Literals:** Identify and flag any string literals used directly as credentials within the source code or configuration files.  
4. **Review Rotation Policies:** Verify the existence of documented policies and procedures for periodically rotating sensitive secrets.  
5. **Confirm Revocation Protocols:** Ensure there are established protocols for immediate secret revocation if a breach is detected.

**AL2:**

1. **Verify Runtime Retrieval:** Confirm that the AI Tool successfully retrieves sensitive secrets from an environment variable or a dedicated Secret Management Service at runtime.  
2. **Validate Secret Isolation:** Ensure that sensitive credentials are not exposed in the process environment beyond what is necessary for execution.

**Verification**

**AL0, AL1:**

1. **Hardcoded Secrets:** The codebase must be free of hardcoded passwords, API keys, or high-entropy strings.  
2. **Client Initialization:** External service clients must exclusively initialize using environment variables or dedicated configuration providers.  
3. **String Literals:** No credentials should be supplied as string literals.  
4. **Rotation Policies:** Documented policies for secret rotation must be present and verified.  
5. **Revocation Protocols:** Breach response protocols for immediate secret revocation must be defined.

**AL2:**

1. **Runtime Retrieval:** The server successfully accesses sensitive secrets from authorized environment variables or Secret Management Services.  
2. **Secret Isolation:** Process environments must properly isolate sensitive credentials from unnecessary exposure.

## 3.2 Automated PII and Credential Masking in Logs

### Description

The AI Tool must implement an interception layer for all logging (stdout/stderr/files) that automatically redacts sensitive information, specifically the Authorization headers, session tokens, and sensitive fields within the tool params (e.g., "password", "api\_key").

### Rationale

Developers often log full JSON-RPC requests for debugging. If these logs are sent to a centralized logging system, any user with log access can steal active session tokens or sensitive tool inputs.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool generating logs with valid inputs.

**Test Procedure**

**AL0, AL1:**

1. **Review Logging Calls:** Identify all logging calls (e.g., console.log, logger.info, winston) throughout the codebase.  
2. **Detect Full Object Logging:** Search for instances where the entire AI Tool request or headers object is logged directly.  
3. **Verify Redaction Middleware:** Confirm that a redaction utility or middleware is applied to these objects before they are passed to the logging function.  
4. **Check Sensitive Key Masking:** Ensure the redaction utility specifically masks sensitive keys such as token, authorization, secret, and sensitive tool parameters like password or api\_key.

**AL2:**

1. **Generate Sensitive Requests:** Trigger JSON-RPC requests containing sensitive information in the headers (e.g., Authorization tokens) or tool parameters (e.g., api\_key).  
2. **Verify Output Redaction:** Inspect the resulting logs to ensure that all sensitive fields have been successfully masked or redacted before being written to the log sink.

**Verification**

**AL0, AL1:**

1. **Logging Calls:** All logging functions must be identified.  
2. **Full Object Logging:** Full objects and headers must not be directly passed to logging mechanisms without processing.  
3. **Redaction Middleware:** A dedicated redaction utility or middleware must intercept objects prior to logging.  
4. **Sensitive Key Masking:** Redaction utilities must explicitly mask sensitive keys and tool parameters.

**AL2:**

1. **Output Redaction:** The server must successfully mask or redact all submitted sensitive tokens or parameters from resulting logs.

## 3.3 Secure Session Tokens

### Description

Developers must ensure that session identifiers and authentication tokens used within the AI Tool ecosystem (between Hosts, Servers, and any intermediate transport layers) are handled as highly sensitive secrets. This includes:

* **Encrypted Transport:** Using secure channels for all token exchanges.  
* **Secure Storage:** Avoiding the use of local, unencrypted persistent storage for session state.  
* **Log Redaction:** Ensuring tokens are never written to standard output (stdout), standard error (stderr), or debug log files.  
* **Minimal Exposure:** Passing tokens through standardized headers or environment variables rather than command-line arguments or URL query parameters.

### Rationale

In the AI Tool architecture, the session token is the "keys to the kingdom." If a developer accidentally leaks a token—for instance, by logging the full JSON-RPC initialization message—an attacker with access to those logs can impersonate the Host and execute arbitrary tools on the Server. Because AI Tools often have access to sensitive local files or internal APIs, a leaked session token can lead to immediate and total system compromise.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with a network interception proxy and verbose logging enabled.

**Test Procedure**

**AL0, AL1:**

1. **Hardocoded Tokens:** Scan the codebase for hardcoded strings that match common token formats (e.g., UUIDs, JWTs, or high-entropy strings).  
2. **Logging:** Review all logging statements (e.g., console.log, logging.debug, fprintf) that output the Session or Context objects.  
3. **Initialization:** Verify that the AI Tool implementation does not accept credentials via argv (command-line arguments), as these are visible to other users on the system via process listing (ps aux).

**AL2:**

1. **Traffic Analysis:** Intercept the AI Tool transport layer (e.g., stdio streams or WebSockets) and verify that session tokens are not transmitted in "cleartext" over insecure channels (if remote) or exposed in side-channels.  
2. **Log Inspection:** Execute a full AI Tool session lifecycle (Connect \-\> Tool Call \-\> Disconnect) with "Verbose" logging enabled. Search the resulting log files for the session token string.  
3. **Environment Check:** Inspect the process environment and temporary directories during execution to ensure tokens are not written to world-readable files or .env files that lack proper permissions.

**Verification**

**AL0, AL1:**

1. **Hardcoded Tokens:** The codebase must not contain hardcoded strings matching token formats.  
2. **Logging:** Session or Context objects must not expose tokens in logging statements.  
3. **Initialization:** The server must not accept credentials via command-line arguments (argv).

**AL2:**

1. **Traffic Analysis:** Session tokens must only be transmitted over secure, encrypted channels.  
2. **Log Inspection:** Verbose session logs must not contain plain-text session token strings.  
3. **Environment Check:** Tokens must not be exposed in temporary directories, world-readable files, or improperly permitted .env files.

## 3.4 Sensitive Output Defense in Depth

### Description

The system SHALL implement a defense-in-depth architecture to prevent sensitive data leakage. It should also prevent the transmission of any data in transit, at rest, and during processing to the Agent that was not explicitly intended for the current task. AI Tool implementations must treat the AI Agent as an untrusted principal. 

The AI tool (e.g., AI Tool) MUST implement strict access controls, memory isolation, and input validation to ensure that any confidential material held internally—including internal API keys, service credentials, local configuration files, and private caching states—cannot be exfiltrated, exposed, modified, or corrupted through the tool’s exposed execution pathways or APIs. The tool MUST enforce a rigid boundary between its internal operational secrets and the execution context handling agent requests.

### Rationale

AI tools often require highly privileged credentials (e.g., database passwords, OAuth tokens) to function. If an Agent is subverted via Indirect Prompt Injection (IPI), it may attempt to instruct the tool to read its own internal configuration or "leak" supplementary data retrieved from a backend. By isolating internal secrets and enforcing strict output schemas, the "blast radius" of a compromised agent is contained; the request simply becomes technically impossible to fulfill.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with the capability to submit complex traversal payloads and stress tests.

**Test Procedure**

**AL0, AL1:**

1. **Secret Lifecycle Mapping:** Identify all points where the tool loads (Get), refreshes (Update), or clears (Delete) internal credentials.  
2. **Automated Secret Hunting:** Execute high-entropy scans (e.g., TruffleHog, Gitleaks) to find hardcoded "sk-", "ghp\_", or mock credentials in source code and config snippets.  
3. **Secrets Management:** Verify secrets are retrieved into memory-safe buffers.  
4. **Path & Reflection Verification:** Confirm zero code paths exist where agent input can dynamically dictate file paths targeting local secret files.  
5. **Taint & Reflection Analysis:** Trace Agent-controlled inputs to ensure they cannot reach sinks that allow dynamic file system access or memory reflection (e.g., eval(), unsafe-load).

**AL2:**

1. **Internal Exfiltration Probe:** Submit traversal payloads (e.g., /etc/secrets/, ../../../../etc/secrets) and commands to dump environment variables.  
2. **Exfiltration Stress Test:** Command the AI Tool to output internally held secrets data.  
3. **Corruption & Integrity Test:** Submit payloads attempting to overwrite local configuration or exhaust memory.

**Verification**

**AL0, AL1:**

1. **Secret Lifecycle Mapping:** All paths loading or mutating internal credentials must be identified and secured.  
2. **Automated Secret Hunting:** No hardcoded or mock credentials must exist within source code and config snippets.  
3. **Secrets Management:** Secrets must be isolated within memory-safe buffers.  
4. **Path & Reflection:** Agent inputs must not have dynamic control over file paths targeting local secrets.  
5. **Taint & Reflection Analysis:** Agent-controlled inputs must not reach unsafe sinks enabling memory reflection or dynamic file system access.

**AL2:**

1. **Internal Exfiltration Probe:** The tool must block or drop all requests attempting to dump environment variables or traverse to sensitive paths; mock keys must never appear in responses.  
2. **Exfiltration Stress Test:** The tool must successfully prevent the output of any internally held secret data.  
3. **Corruption & Integrity:** The tool's internal configuration must remain uncorrupted and operational for subsequent benign requests despite overwrite or exhaustion attempts.

## 3.5 PII Detection

### Description

When the AI Tool accesses data stores that may contain PII, the tool SHALL detect the following patterns in responses: (1) SSN/national ID numbers, (2) email addresses, (3) phone numbers, (4) credit card numbers (Luhn-valid), (5) high-entropy credential patterns. Detected PII SHALL be redacted before inclusion in responses, unless the tool's documented purpose requires returning PII and the requesting agent has appropriate authorization scope.

### Rationale

PII Detection is fundamentally used to prevent PII leakage. It serves as a critical defense-in-depth mechanism against the unauthorized exposure or exfiltration of sensitive user data by compromised or hallucinating AI agents interacting with backend data stores. By mandating the automated detection and redaction of sensitive patterns—such as Social Security Numbers, email addresses, phone numbers, credit card numbers, and high-entropy credentials—the tool neutralizes Personally Identifiable Information before it reaches the agent. This strict redaction policy limits the blast radius of potential vulnerabilities, ensuring sensitive data is only returned when strictly necessary for the tool's documented purpose and when the requesting agent possesses the explicitly authorized scope to handle it.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool integrated with a seeded test data source containing PII.

**Test Procedure**

**AL0, AL1:**

1. **Inspect Response Handling:** Inspect response handling for PII detection logic covering five categories (SSN/national ID numbers, email addresses, phone numbers, credit card numbers, high-entropy credential patterns). Verify redaction before response return.

**AL2:**

1. **Seed Data Testing:** Seed data source with test PII records. Query the data and verify redaction behavior.  
2. **Authorization Scopes:** For authorized PII tools, verify that the authorization scope check allows PII return only for explicitly scoped agents.

**Verification**

**AL0, AL1:**

1. **Response Handling:** Output response handlers must utilize robust detection logic for all required PII categories and apply redaction before returning data.

**AL2:**

1. **Seed Data Redaction:** Output containing seeded test PII records must be successfully redacted.  
2. **Authorization Scopes:** Return of PII must strictly succeed only if the requesting agent possesses the appropriate authorization scope for the tool's documented purpose.

## 3.6 Data Minimization

### Description

The AI Tool shall minimize the data being exposed to align with the use case the tool supports. The tool’s output schema and database queries shall be limited to necessary fields to support the functions stated need.For example, a tool which provides the current travel rewards points balance should not return the user’s credit card number and social security number.

### Rationale

Overly permissive tools may expose the user’s data, or result in actions which the user never intended an agent to be able to perform.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection and schema reviews to show compliance.

**AL2:** Functional AI Tool responding to various agent function calls.

**Test Procedure**

**AL0, AL1:**

1. **Schema Review:** Verify the function inputs and outputs only include the necessary data to fulfill the tool’s description and function’s stated need.

**AL2:**

1. **Functional Execution:** Execute each of the tool’s functions and verify the function inputs and outputs only include the necessary data to fulfill the tool’s description and function’s stated need.

**Verification**

**AL0, AL1:**

1. **Schema Review:** Function interfaces and queries must be strictly constrained to only request and return fields actively required by the tool's use case.

**AL2:**

1. **Functional Execution:** The AI Tool must not expose broader data scopes (e.g., returning social security numbers when only rewards points were requested) during active execution.

## 3.7 Protect Sensitive Data in Logs

### Description

All logging mechanisms must include automated redaction or masking for sensitive information. This includes, but is not limited to, Personally Identifiable Information (PII), authentication tokens, API keys, passwords, and sensitive model outputs that may contain proprietary or private data.

### Rationale

Logs are frequently replicated across multiple systems, stored in centralized repositories, and accessed by various personnel, making them a high-value target for attackers. According to OWASP and COSAI standards, failure to scrub sensitive data from telemetry can lead to accidental data breaches and compliance violations. Because LLMs and agents may process sensitive data as part of their prompt context, it is vital to ensure that this data does not leak into the persistent logging layer during the monitoring process.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with an agent interface designed to generate sensitive data inputs.

**Test Procedure**

**AL0, AL1:**

1. **Identify Sensitive Variables:** Search the codebase for variables and keys that typically contain sensitive information, such as password, token, apiKey, secret, email, ssn, authorization, or bearer.  
2. **Trace Logging Sinks:** Identify all locations where logging functions (e.g., console.log, logger.info, winston) are called. Verify if the sensitive variables identified above are passed directly into these functions.  
3. **Verify Redaction Middleware:** Confirm the application utilizes a centralized redaction middleware or a dedicated sanitization helper function designed to scrub or mask inputs before they reach the logging layer.  
4. **Check Raw Data Logging:** Inspect code to ensure that raw user prompts or raw API responses—which may contain PII or proprietary data—are not logged without an explicit filtering mechanism.  
5. **Verify Identity Masking:** Confirm that specific User IDs or unique PII identifiers are not written to the logs in plain text.

**AL2:**

1. **Generate Sensitive Telemetry:** Interact with the AI Tool through the agent and perform actions designed to generate sensitive data (e.g., entering a mock password, providing an API key, or sharing PII).  
2. **Inspect Log Output:** Access the generated logs and verify that any sensitive data entered during the interaction has been successfully redacted, masked, or filtered out.

**Verification**

**AL0, AL1:**

1. **Sensitive Variables:** Variables indicating sensitive data must be clearly identifiable within the codebase.  
2. **Trace Logging Sinks:** Sensitive variables must not bypass sanitation structures to be passed directly into logging sinks.  
3. **Redaction Middleware:** Centralized redaction middleware must be present and capable of masking inputs destined for the logging layer.  
4. **Raw Data Logging:** Code must forbid the direct logging of raw user prompts or API responses without explicitly applied filters.  
5. **Identity Masking:** Specific User IDs or unique PII identifiers must not be written to logs in plain text formats.

AL2:

1. **Sensitive Telemetry & Log Output:** Generating sensitive data during interaction must result in safely redacted, masked, or completely filtered values inside the persistent log outputs.

# 4. Input/Output Sanitization

## 4.1 Output Sanitization

### Description

The AI Tool SHALL sanitize all outputs returned to the AI Agent. Structured outputs (JSON, YAML, XML) SHALL be validated against a defined schema before transmission. String outputs that may be rendered in a user interface SHALL be encoded to neutralize HTML, JavaScript, and shell metacharacters.

### Rationale

Output Sanitization helps to prevent output vulnerabilities by ensuring that malicious payloads cannot be executed or improperly rendered by downstream systems. By mandating that structured outputs—such as JSON, YAML, and XML—are strictly validated against a defined schema before transmission, the system guarantees data integrity and prevents malformed or poisoned responses from compromising the AI Agent. Furthermore, requiring the encoding of string outputs neutralizes hazardous elements, specifically HTML, JavaScript, and shell metacharacters. This comprehensive sanitization process acts as a critical safeguard, protecting the final user interface from injection attacks disguised as legitimate AI tool responses and maintaining the overall security of the data flowing from the tool to the agent.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool responding to various agent function calls.

**Test Procedure**

**AL0, AL1:**

1. **Inspect Output Handlers:** Inspect tool output handlers for encoding/escaping functions.  
2. **Verify Schema Validation:** Verify structured outputs are validated against a defined schema.  
3. **Flag Raw Strings:** Flag code paths returning raw, unvalidated strings.

**AL2:**

1. **Test Malicious Inputs:** Submit inputs designed to produce outputs containing HTML tags, JavaScript, shell metacharacters, and SQL. Verify the tool's response encodes or strips these.  
2. **Test Malformed JSON:** Submit inputs producing malformed JSON and verify the tool returns a schema-compliant error.

**Verification**

**AL0, AL1:**

1. **Output Handlers:** Tool output handlers must implement proper encoding and escaping functions.  
2. **Schema Validation:** Structured outputs must be successfully validated against a schema before transmission.  
3. **Raw Strings:** There must be no code paths returning raw, unvalidated strings.

**AL2:**

1. **Malicious Inputs:** The tool's response must successfully encode or strip HTML tags, JavaScript, shell metacharacters, and SQL from its outputs.  
2. **Malformed JSON:** The tool must successfully return a schema-compliant error when provided inputs producing malformed JSON.

## 4.2 Parameterized Arguments and Unsafe Sink Blocking

### Description 

The AI Tool must enforce strict input validation, sanitization, and parameterization across all execution contexts. It must actively identify and block the use of unsafe execution sinks (such as eval(), os.system(), or subprocess.Popen(shell=True)) and mandate the use of parameterized arguments for any underlying system calls or queries. All inputs must be validated using strict allowlists at every trust boundary.

### Rationale

Developers incorrectly assume that user input processed through an LLM is inherently safe, bypassing established secure coding practices. In reality, the LLM transforms but does not sanitize malicious payloads. Without strict parameterized boundaries, an attacker can manipulate tool arguments to execute arbitrary shell commands, leading to total system compromise and sandbox escapes.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with an interface to test command injection payloads.

**Test Procedure**

**AL0, AL1:**

1. **Identify Unsafe Execution Sinks:** Scan the server codebase for high-risk functions that evaluate strings as code or execute shell commands directly (e.g., os.system, eval()).  
2. **Verify Parameterization:** Inspect database queries and system calls to ensure they utilize parameterized execution methods rather than dynamic string concatenation.  
3. **Check Validation Logic:** Confirm that all tool parameters are strictly validated against predefined allowlists before being processed.

**AL2:**

1. **Fuzz Tool Parameters:** Submit crafted command injection payloads (e.g., ; rm \-rf /, $(whoami), or & ping https://www.google.com/url?sa=E\&source=gmail\&q=attacker.com) via the LLM prompt or directly into the AI Tool arguments.  
2. **Verify Safe Rejection:** Confirm that the AI Tool neutralizes the payload, treats it as a literal string parameter, or explicitly rejects the request with an error, preventing the underlying command from executing.

**Verification**

**AL0, AL1:**

1. **Unsafe Execution Sinks:** The codebase must not contain high-risk functions that evaluate strings as code or execute shell commands directly.  
2. **Parameterization:** Database queries and system calls must successfully utilize parameterized execution methods instead of dynamic string concatenation.  
3. **Validation Logic:** The server must enforce strict validation of all tool parameters against predefined allowlists before processing.

**AL2:**

1. **Fuzz Tool Parameters / Safe Rejection:** The AI Tool must successfully neutralize crafted command injection payloads, treat them as literal string parameters, or explicitly reject the request with an error, preventing the underlying command from executing.

## 4.3 Detect and Block Unsafe Sinks

### Description

The AI Tool must operate within a hardened runtime that identifies and blocks code patterns facilitating sandbox escapes, such as os.system(), subprocess.Popen(shell=True), or eval(). Any tool that passes arguments to system-level calls must utilize parameterized arguments and path canonicalization

### Rationale

Proactively identifying insecure coding patterns during development mitigates the risk of Command Injection and Directory Traversal, which serve as primary vectors for bypassing tool sandboxes.

**Note: Mobile AI Tools are out of scope for this requirement.**

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool or AI Tool environment.

**Test Procedure**

**AL0, AL1:**

1. **Pattern Scan:** Identify the use of unsafe functions like eval() or shell-enabled subprocess calls (e.g., subprocess.Popen(shell=True)).  
2. **URL Generation Check:** Identify and flag any dynamic URL generation that is not securely checked against an allowlist.

**AL2:**

1. **Sandbox Escape Probing:** Attempt to use an Attacker LLM to generate tool-call JSON designed to execute a shell command (e.g., ls ; rm \-rf).

**Verification**

**AL0, AL1:**

1. **Pattern Scan:** The codebase must not utilize unsafe execution functions or shell-enabled subprocess calls to prevent command injection.  
2. **URL Generation Check:** All dynamic URL generation must be successfully checked against a predefined static allowlist.

**AL2:**

1. **Sandbox Escape Probing:** The runtime must successfully detect and block the execution of the injected shell command, preventing any sandbox escapes.

## 4.4 Maximum Response Size

### Description

The AI Tool SHALL enforce a configurable maximum size for all responses returned to the AI Agent. Responses exceeding this limit SHALL be truncated, paginated, or rejected with an error indicating the limit. The default limit SHALL NOT exceed 1 MB unless the tool's documented use case requires larger responses.

### Rationale

Enforcing a strict ceiling on outbound payloads serves as a vital safeguard to limit output over-exposure and minimize the blast radius of potential system compromises. Because AI tools act as functional bridges to robust backend databases and external APIs , an untrusted or manipulated AI agent—subverted via indirect prompt injection—may attempt to execute commands designed to harvest or leak extensive volumes of corporate or user data.

By mandating a tight default maximum response limit of 1 MB and requiring oversized payloads to be truncated, paginated, or explicitly rejected , the tool enforces strict data minimization at the output boundary. Furthermore, this restriction protects the calling AI host from client-side parsing latency, memory consumption spikes, or systemic Denial-of-Service (DoS) vulnerabilities that arise when trying to process unconstrained natural language or deeply nested JSON structures.

### Audit

**Evidence**  
**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool or AI Tool environment.

**Test Procedure**  
**AL0, AL1:**

1. **Identify Output Serialization:** Search the codebase for response generation and serialization handlers where data is prepared for transmission back to the AI Agent.  
2. **Verify Size Limit Configuration:** Review configuration files or initialization logic to verify the presence of a configurable maximum response size limit, ensuring the default setup does not exceed 1 MB.  
3. **Check Oversized Handling Logic:** Inspect code paths to ensure that payloads exceeding the threshold trigger a defined remediation mechanism—specifically truncation, pagination, or explicit error generation.

**AL2:**

1. **Request Large Payload:** Trigger a tool or function call designed to fetch or construct an outbound response payload larger than the configured maximum size constraint (e.g., testing with a \> 1 MB payload response).  
2. **Verify Boundary Enforcement:** Intercept the outbound message stream or review the client-side agent response to confirm that the tool correctly handles the payload via truncation, pagination, or a clear size-limit error response.

**Verification**  
**AL0, AL1:**

1. **Output Serialization:** The codebase must systematically intercept outbound responses to evaluate data size bounds before serialization or transmission.  
2. **Size Limit Configuration:** A maximum size constraint must be explicitly configurable, defaulting to 1 MB or less unless a larger threshold is documented and justified by the tool's specific use case.  
3. **Oversized Handling Logic:** The implementation must contain valid code blocks that safely truncate, paginate, or reject data when a payload exceeds the defined threshold.

**AL2:**

1. **Boundary Enforcement:** The active system must successfully prevent oversized natural language or structured outputs from reaching the host by returning a validly truncated, paginated, or size-limit rejected error payload

# 5. Multi-Tenancy & Isolation

## 5.1 Stateless Request Level Isolation

### Description

To prevent "Session Bleed" (where data from a previous request persists in memory and affects the next), the server must treat every request as an independent atomic unit.

* **No Global State:** The server must not store user-specific data in global variables or static caches.  
    
* **Memory Clearing:** If the runtime environment (e.g., Python/Node.js) is reused across requests for different tenants, the server must perform a "Context Reset" or be forcibly restarted between different tenant contexts.

* **Unique Request IDs:** Every incoming request from the Agent must be tagged with a unique Request ID. All logs and internal traces must use this ID to ensure auditability of data boundaries

### Rationale

Mandatory Statelessness is the primary technical control against Cross-Tenant Data Leakage (CTDL), ensuring that a third-party AI Tool maintains a strict isolation boundary between independent user sessions. By requiring a "Process, Respond, Purge" lifecycle, we eliminate "session bleed"—where data from one user lingers in memory or global variables and is inadvertently accessed by a subsequent request from a different tenant. This architecture shifts the security boundary away from potentially flawed application logic and onto Google’s hardened infrastructure, removing the possibility of state-based side-channel attacks and ensuring that every transaction is a self-contained, auditable event with no memory of prior sensitive contexts.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement. 

**AL2:** Functional AI Tool in a multi-tenant test environment.

**Test Procedure**

**AL0, AL1:**

1. **Identify Global State:** Search the codebase for global variables, static caches, or singleton patterns used to store user-specific data or session metadata. Verify that all user-specific data is confined to the local scope of the request handler.  
2. **Verify Context Reset:** If the server uses a persistent runtime (e.g., Node.js or Python) across different requests, identify the mechanism used to clear in-memory state between executions. Flag any implementation that lacks an explicit "Context Reset" or process recycling logic for different tenant contexts.  
3. **Check Request ID Propagation:** Verify that the server initializes a unique Request ID for every incoming JSON-RPC object. Ensure this ID is passed to all internal sub-functions and included in every structured log entry generated during that request's lifecycle.

**AL2:**

1. **Test for Session Bleed:** Execute a sequence of tool calls using "User A" credentials containing unique, identifiable data (e.g., a "search\_files" tool with a specific keyword). Immediately follow with a tool call from "User B." Inspect the response for User B and the server logs to ensure no fragments of User A's data or keywords appear in User B's execution context.  
2. **Verify Log Correlation:** Trigger multiple concurrent tool calls. Inspect the generated logs to confirm that every log line is tagged with a unique Request ID and that logs for different requests do not intermingle data under the same identifier.  
3. **Check Memory Isolation:** In a multi-tenant test environment, observe the memory footprint or process lifecycle to verify that the server either restarts or explicitly purges tenant-specific heap data after the completion of a request.

**Verification**

**AL0, AL1:**

1. **Global State:** All user-specific data must be confined to the local scope of the request handler.  
2. **Context Reset:** There must be an explicit "Context Reset" or process recycling logic for different tenant contexts.  
3. **Request ID Propagation:** A unique Request ID must be initialized, passed to all internal sub-functions, and included in every structured log entry.

**AL2:**

1. **Session Bleed:** No fragments of User A's data or keywords shall appear in User B's execution context or logs.  
2. **Log Correlation:** Every log line must be tagged with a unique Request ID, and logs for different requests must not intermingle data.  
3. **Memory Isolation:** The server must either restart or explicitly purge tenant-specific heap data after the completion of a request.

## 5.2 Ensure Sandbox Protections

### Description

Identify and block code patterns that facilitate sandbox escapes or multi-tenant data leakage. Mandating the detection of "unsafe sinks"—such as direct shell execution, unvalidated file system operations, and unrestricted network sockets—ensures that the AI Tool remains isolated. Any code that passes user-supplied tool arguments to system-level calls must undergo rigorous path canonicalization and validation against a pre-defined allowlist to prevent build-breaking security violations.

### Rationale

Enforcing these programmatic constraints aligns the AI Tool architecture with the principle of "Least Privilege," ensuring inherent compatibility with hardened runtimes. Proactively identifying and remediating insecure coding patterns during the development phase mitigates the risk of Directory Traversal and Command Injection vulnerabilities, which serve as primary vectors for bypassing execution sandboxes. Such a stance is critical in multi-tenant environments to ensure that even a compromised or manipulated model cannot programmatically execute unauthorized actions on the host system or access data belonging to other users.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool environment.

**Test Procedure**

**AL0, AL1:**

1. **Detect Unsafe Execution:** Identify use of os.system(), subprocess.Popen(shell=True), or eval(). Flag implementations that do not use parameterized arguments or avoid shell execution.  
2. **Detect Missing Path Validation:** Identify file I/O operations (e.g., open(), fs.readFile()) where the input path is concatenated with user-provided strings without a call to a normalization function (e.g., os.path.abspath() or path.resolve()).  
3. **Detect Hardcoded Network Requests:** Identify HTTP/Socket libraries (e.g., requests.get, http.request) where the destination URL is dynamically generated from LLM-provided tool arguments without being checked against a static Allowlist.

**AL2:**

1. **Sandbox Escape & Command Fuzzing:** Submit crafted command injection payloads (e.g., ; rm \-rf /, $(whoami), or & ping attacker.com) via the LLM prompt or inject them directly into the AI Tool arguments to attempt to trigger execution outside the intended tool logic.  
2. **Path Traversal Probing:** Submit payload strings containing directory traversal sequences (e.g., /etc/secrets/, ../../../../etc/secrets, or Windows equivalents) to file system execution blocks to attempt to read or modify files outside the tool's designated sandbox directory boundaries.  
3. **Server-Side Request Forgery (SSRF) Fuzzing:** Inject tool arguments containing local loopback addresses (e.g., http://127.0.0.1, http://localhost) or unexpected remote infrastructure domains to evaluate if the tool executes unrestricted outbound network connections.

**Verification**

**AL0, AL1:**

1. **Unsafe Execution:** AI tools must use parameterized arguments and avoid shell execution to prevent command injection leading to sandbox escapes.  
2. **Missing Path Validation:** File I/O operations must use normalization functions to prevent directory traversal attacks that bypass sandbox directory restrictions.  
3. **Hardcoded Network Requests:** Dynamic destination URLs must be checked against a static Allowlist to prevent Server-Side Request Forgery (SSRF) from the sandbox to the internal network.

**AL2:**

1. **Sandbox Escape Prevention:** The runtime must successfully detect, neutralize, or explicitly reject the injected shell commands with an error, treating malicious configurations as literal string parameters and preventing any underlying system command execution.  
2. **Directory Traversal Mitigation:** The tool must completely block or drop all requests attempting to traverse out of bounds or read unauthorized host files, ensuring internal operational contexts and local configurations remain isolated.  
3. **SSRF and Network Blocking:** The AI Tool must abort or fail the execution sequence whenever a dynamic network argument attempts to target an internal asset or any destination domain missing from the predefined static allowlist.

## 5.3 Mandatory Tenant Isolation

### Description

For multi-tenant deployments, the AI Tool SHALL enforce logical isolation of tenant data. All data storage operations SHALL include a tenant identifier as a mandatory filter condition. The tenant identifier SHALL be derived from the authenticated session context, not from user-supplied parameters. The tool SHALL reject any request where the authenticated tenant context does not match the requested data's tenant identifier.

### Rationale

Prevent Cross-Tenant Data Leakage

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement. 

**AL2:** Functional AI tool deployed in a multi-tenant environment.

**Test Procedure**

**AL0, AL1:**

1. **Query Inspection:** Inspect database/vector store queries for mandatory tenant ID filtering.  
2. **Context Verification:** Verify tenant ID is extracted from session context, not request parameters.

**AL2:**

1. **Cross-Tenant Access Attempt:** Authenticate as Tenant A. Attempt to retrieve Tenant B's data by manipulating request parameters.

**Verification**

**AL0, AL1:**

1. **Query Inspection:** All database/vector store queries must enforce mandatory tenant ID filtering.  
2. **Context Verification:** Tenant IDs must strictly be extracted from the authenticated session context, not from user-supplied parameters.

**AL2:**

1. **Cross-Tenant Access:** Verify only Tenant A's data is returned. The server must successfully reject attempts to retrieve Tenant B's data by manipulating request parameters.

# 6. System Integrity & Supply Chain

## 6.1 Cryptographic Message Integrity Validation

### Description 

AI Tool implementations must require and enforce cryptographic integrity checks on all messages, tool definitions, and resource responses. Tool developers must include mechanisms such as message authentication codes (MACs) or digital signatures to ensure end-to-end integrity and prevent the undetected modification of critical system components or payloads during transit.

### Rationale

Without integrity verification, malicious actors or compromised intermediaries can intercept and modify tool definitions, forge messages, or inject poisoned data into resource responses. Because the AI model implicitly trusts the context and data returned by connected tools, tampered payloads can seamlessly trigger prompt injections or execute unauthorized behavior .

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool setup with a network interception proxy or manipulation tools.

**Test Procedure**

**AL0, AL1:**

1. **Review Integrity Mechanisms**: Inspect the message handling and transport layer code to verify the implementation of cryptographic signatures or HMAC validation for incoming JSON-RPC payloads.  
2. **Verify Key Management**: Ensure that the public keys or shared secrets used for signature validation are stored securely and retrieved safely at runtime.  
3. **Check Enforcement Logic**: Confirm that the server explicitly drops or rejects messages that lack a signature or fail the integrity validation check.

**AL2:**

1. **Attempt Payload Tampering**: Intercept a legitimate, signed AI Tool invocation or resource response using a proxy. Modify the data payload (e.g., change a tool argument or alter a schema description) without recalculating the cryptographic signature.  
2. **Verify Mismatch Rejection**: Submit the tampered message to the client or server. Verify that the receiving component detects the integrity mismatch and immediately drops the connection or rejects the payload.

**Verification**

**AL0, AL1:**

1. **Integrity Mechanisms**: The codebase must properly implement cryptographic signatures or HMAC validation for all incoming JSON-RPC payloads within the message handling and transport layer.  
2. **Key Management**: The public keys or shared secrets used for signature validation must be securely stored and safely retrieved at runtime.  
3. **Enforcement Logic**: The server must explicitly drop or reject any messages that lack a valid signature or fail the integrity validation check.

**AL2:**

1. **Payload Tampering and Mismatch Rejection**: The receiving component must successfully detect the integrity mismatch of a tampered payload and immediately drop the connection or reject the message.

## 6.2 Semantic Integrity and Descriptive Accuracy

### Description

The tool's metadata—including its name, description, and the definitions of its functions/APIs—must accurately reflect its actual behavior and internal logic. Developers must ensure that:

* The **natural language description** provided to the AI agent matches the functional capabilities of the code.  
* **API parameters** are named and described according to their actual use (e.g., a parameter named `zip_code` should not be used to smuggle an `api_key`).  
* The tool does not contain **undocumented "easter egg" functions** or side effects that deviate significantly from the stated purpose.

### Rationale

In the context of AI Agents (like those using the Model Context Protocol), the agent relies almost entirely on the tool's description to decide *when* and *how* to call it.

* **Deceptive Mapping:** If a tool is named `fetch_weather` but actually executes `delete_database`, the AI agent can be tricked into performing malicious actions under the guise of a benign request.  
* **Prompt Injection via Metadata:** Misleading descriptions can be used as a "Trojan Horse" to influence the LLM’s reasoning, leading it to ignore system instructions or exfiltrate data to the tool's backend.  
* **Trust Erosion:** Users must be able to audit a tool’s intent by reading its manifest without needing to reverse-engineer the entire codebase.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with network and system monitoring tools.

**Test Procedure**

**AL0, AL1:**

1. **Manifest Review:** Compare the description fields in the tool’s configuration (e.g., mcp.json or similar) against the function names and variable types.  
2. **Code-to-Metadata Mapping:** Verify that for every exported function, the docstring and metadata capture the primary purpose of the logic. Check for "Dead Code" or "Shadow Parameters" that are defined in the code but omitted or misrepresented in the tool’s public description.  
3. **Heuristic Analysis:** Flag tools that use generic or intentionally vague descriptions (e.g., "Run utility") for complex or high-privilege code blocks.

**AL2:**

1. **Functional Verification:** Execute the tool with a series of standard inputs and verify that the output and side effects (file changes, network calls, etc.) align with the tool’s description.  
2. **I/O Monitoring:** Monitor network traffic during execution to ensure it does not initiate unexpected outbound requests (e.g., a "Calculator" tool initiating an HTTPS request to an unknown domain). Inspect system calls to ensure the tool is only accessing resources relevant to its description (e.g., a "Word Counter" should not read SSH keys).  
3. **Agent-Simulated Testing:** Provide the tool to a "clean" AI Agent and ask it to describe what the tool does based on its metadata. Compare the agent's understanding against the developer’s actual code implementation to identify semantic gaps.

**Verification**

**AL0, AL1:**

1. **Manifest Review:** Configuration description fields must accurately match the declared function names and variable types.  
2. **Code-to-Metadata Mapping:** All exported functions must have docstrings and metadata that accurately capture their logic, completely free of hidden "Dead Code" or "Shadow Parameters".  
3. **Heuristic Analysis:** Tools containing complex or high-privilege code blocks must not possess generic or intentionally vague descriptions.

**AL2:**

1. **Functional Verification:** Execution outputs and side effects must strictly align with the documented tool's description.  
2. **I/O Monitoring:** The tool must be verified to only access resources relevant to its description and successfully fail integrity checks if initiating unrelated outbound requests or system calls.  
3. **Agent-Simulated Testing:** The AI Agent's interpretation of the metadata must accurately align with the actual code implementation without semantic gaps.  
   

## 6.3 Resource Pinning and Signature Verification

### Description

The AI Tool must implement strict version pinning for all third-party plugins and dependencies using strict equality (e.g., "1.4.0" rather than "\>=1.4.0"). All model weights and tool packages must have valid digital signatures and be verified against known cryptographic hashes.

### Rationale

Resource pinning ensures that updates are a deliberate developer decision, preventing "Rug Pull" attacks where a dependency is automatically updated to a compromised version. This forces a "temporal delay" that eliminates a major class of common ecosystem vulnerabilities

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection and dependency manifest review to show compliance to the requirement.

**AL2:** Functional AI Tool configured with a mocked update repository.

**Test Procedure**

**AL0, AL1:**

1. **Check Dependency Files:** Verify that package files (e.g., package.json or requirements.txt) use strict version pinning.  
2. **Review SBOM:** Review the Software Bill of Materials (SBOM) for unmitigated vulnerabilities.

**AL2:**

1. **Update Verification:** Attempt to point the tool to a mocked update repository with a mismatched signature to confirm the update is rejected.

**Verification**

**AL0, AL1:**

1. **Check Dependency Files:** Dependency files must be verified to use strict version pinning (e.g., "1.4.0" rather than "\>=1.4.0").  
2. **Review SBOM:** The SBOM must be completely free of unmitigated vulnerabilities.

**AL2:**

1. **Update Verification:** The tool must successfully reject the update when provided with a mocked update repository presenting a mismatched digital signature.

# 7. Resource Constraints & Denial of Service (DoS) Prevention

## 7.1  Financial Resource & Cost Governance

### Description

The AI Tool must be inherently **cost-aware**. It must identify whether a specific resource (e.g. a premium search API or a paid data scraper) carries a direct financial cost to the user or organization. For these metered resources, the tool must implement the following:

* **Session-Based Cost Tracking:** The tool must calculate and track the cumulative cost of all API calls made during an active session.  
* **The $100 Guardrail:** By default, if the cumulative session cost reaches **$100**, the tool must automatically intervene by either enforcing a strict rate limit or pausing execution to request explicit user confirmation.  
* **Justified Overrides:** Developers may set a higher dollar threshold only if they provide a documented business justification within the configuration metadata.  
* **Governance Layers:** Enforce mandatory authentication for all tool access and implement per-user/per-tool rate limiting to prevent unauthorized or runaway consumption.

### Rationale

AI Tools are "force multipliers" for LLMs. Because these tools often bridge the gap to paid APIs (e.g., GPT-4o, Claude 3.5 Sonnet, or search engines), they represent a direct financial vulnerability. A logic loop or a malicious actor could trigger thousands of dollars in costs in seconds. Unlike traditional DoS, which impacts availability, a DoW attack impacts the viability of the business.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with metered resources and an automated test harness capable of high-volume call simulation.

**Test Procedure**

**AL0, AL1:**

1. **Identify Paid Assets:** Verify that all APIs/resources carrying a financial cost are identified in the codebase.  
2. **Threshold Verification:** Confirm the implementation of the $100 limit and review documentation for any higher justified limits.  
3. **Auth Check:** Ensure all cost-incurring resources require a valid, authenticated user context.

**AL2:**

1. **Cost Tracking Validation:** Request the list of metered resources and the specific method used to track costs in real-time during a session.  
2. **Stress Testing:** Using an automated test harness, simulate high-volume calls to verify that the tool triggers a rate limit or confirmation prompt exactly when the $100 (or justified) limit is hit.

**Verification**

**AL0, AL1:**

1. **Paid Assets Identification:** All APIs and resources carrying a financial cost must be successfully identified in the codebase.  
2. **Threshold Verification:** The implementation of the $100 limit must be explicitly confirmed, along with proper documentation for any higher justified limits.  
3. **Authentication Check:** All cost-incurring resources must successfully enforce a valid, authenticated user context.

**AL2:**

1. **Cost Tracking Validation:** The real-time cost tracking method must accurately monitor the metered resources during an active session.  
2. **Stress Testing:** The tool must successfully trigger a rate limit or explicit confirmation prompt exactly when the cumulative session cost reaches the defined $100 limit (or justified limit) during high-volume simulation.  
   

## 7.2  Per User Endpoint Rate Limiting

### Description

For remote deployments, the AI Tool SHALL enforce per-user or per-session rate limits. The tool SHALL implement at least one of: (1) max requests per time window per authenticated user, (2) progressive throttling, (3) temporary blocking after threshold. Limits SHALL be configurable. Rate limiting for one user SHALL NOT affect other users.

### Rationale

TBD

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with multiple user accounts configured.

**Test Procedure**

**AL0, AL1:**

1. **Inspect Request Handling:** Review the request handling logic in the codebase to identify the implementation of per-user or per-session rate limits (e.g., max requests per time window, progressive throttling, or temporary blocking).  
2. **Verify Configurability:** Confirm that the implemented rate limiting thresholds and parameters are configurable.

**AL2:**

1. **Exceed Rate Limit:** Authenticate as "User A" and generate a volume of requests that exceeds the configured rate limit.  
2. **Verify Enforcement:** Confirm that the system actively enforces the limit on "User A" (e.g., by throttling or temporarily blocking).  
3. **Verify User Isolation:** Authenticate as "User B" and verify that "User B" is completely unaffected by the rate limiting applied to "User A".

**Verification**

**AL0, AL1:**

1. **Request Handling:** The codebase must contain functional logic that enforces per-user or per-session rate limits.  
2. **Configurability:** The rate limiting constraints must be explicitly configurable by the administrator or system.

**AL2:**

1. **Enforcement:** The system must successfully throttle, block, or limit actions when an individual user's request volume exceeds the threshold.  
2. **Isolation:** The enforcement of rate limits on one user shall not impact the availability or performance of the system for other users.

## 7.3 Maximum Payload and Recursion Depth Constraints

### Description

The server must strictly enforce configurable limits on the maximum size of incoming request payloads (in bytes) and the maximum depth of nested structures (e.g., JSON objects, arrays, or recursive tool calls).

### Rationale

Unbounded inputs allow attackers to trigger Denial-of-Service (DoS). Large payloads exhaust RAM/bandwidth, while deep recursion can lead to stack overflow errors or CPU spikes during parsing, rendering the server unavailable to legitimate users.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool capable of receiving test payloads.

**Test Procedure**

**AL0, AL1:**

1. **Payload Size Limits:** Inspect the code to verify that payload size limits are implemented. The preferred method is explicit limits, but language provided limits are acceptable.  
2. **Recursion Depth Limits:** Inspect the code to verify recursion limits are applied during the processing of nested tool calls or nested JSON structures.

**AL2:**

1. **Payload Size Limits:** Using a tool like curl or Postman, attempt to send a payload that exceeds the defined limit (e.g., a 100MB JSON string when the limit is 5MB).  
2. **Recursion Depth Limits:** Send a JSON object with nesting depth significantly higher than the limit (e.g., 1,000 levels of nested arrays: \[\[\[\[...\]\]\]\]).

**Verification**

**AL0, AL1:**

1. **Payload Size Limits:** Payload size limits must be explicitly implemented and verified in the code, or acceptable language-provided limits must be in place.  
2. **Recursion Depth Limits:** Recursion limits must be applied and enforced during the processing of nested tool calls or nested JSON structures.

**AL2:**

1. **Payload Size Limits:** The server must successfully reject or drop request payloads that exceed the defined size limit.  
2. **Recursion Depth Limits:** The server must successfully reject requests containing JSON objects with a nesting depth significantly higher than the allowed limit.

# 8. Logging, Auditing, & Monitoring

## 8.1 Implement comprehensive logging using structured logging formats

### Description

The system must capture all significant security and operational events—including authentication attempts, authorization decisions, tool/function calls, AI model inputs/outputs, and system state changes. These logs must be generated in a machine-readable, structured format (such as JSON) rather than unstructured plain text.

### Rationale

In agentic and MCP-based architectures, the complexity of interactions between users, hosts, and servers makes traditional grep-based log analysis insufficient. Structured logging allows automated security orchestration, automation, and response (SOAR) tools and SIEMs to parse and correlate events in real-time. This visibility is critical for detecting anomalous patterns, such as indirect prompt injection, which are often only visible when analyzing the metadata of model interactions and tool execution.

### Audit

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with the ability to generate agent activity and access to the generated logs.

**Test Procedure**

**AL0, AL1:**

1. **Verify Structured Format:** Identify all logging statements (e.g., console.log, logger.info, winston) and confirm they utilize a structured format like JSON objects or key-value pairs rather than simple string concatenation.  
2. **Identify External Tool Execution Paths:** Review the code for AI tool integration and AI Tool implementations to identify all functions that execute external tools or access data resources.  
3. **Check Telemetry Coverage:** Verify that each execution path includes a logging call capturing the identity of the calling agent, the specific tool requested, the input parameters, and the success/failure status.  
4. **Inspect Metadata and Correlation:** Confirm that critical events (tool execution, API requests, and authentication logic) are logged with relevant metadata, including timestamps and correlation IDs.  
5. **Flag Silent Failures:** Identify and flag any instances where a tool is invoked without telemetry or where error states are handled "silently" without an audit entry.  
6. **Flag Unstructured Calls:** Identify and flag any instances of "print" statements or unstructured logger calls used for operational data.

**AL2:**

1. **Generate Agent Activity:** Interact with the system through the AI agent to trigger various tool calls, API requests, and authentication events.  
2. **Validate Log Capture:** Inspect the generated logs to confirm that the interaction was captured in its entirety.  
3. **Confirm Machine-Readability:** Verify that the output logs are valid structured data (e.g., valid JSON) that can be parsed by automated security tools.

**Verification**

**AL0, AL1:**

1. **Structured Format:** The codebase utilizes a structured format like JSON objects or key-value pairs for all logging statements, avoiding simple string concatenation.  
2. **External Tool Execution Paths:** All functions that execute external tools or access data resources have been successfully identified.  
3. **Telemetry Coverage:** Each execution path includes a logging call capturing the identity of the calling agent, specific tool requested, input parameters, and success/failure status.  
4. **Metadata and Correlation:** Critical events log relevant metadata, including timestamps and correlation IDs.  
5. **Silent Failures:** No instances exist where a tool is invoked without telemetry or where error states are handled "silently" without an audit entry.  
6. **Unstructured Calls:** No unstructured "print" statements or unstructured logger calls are used for operational data.

**AL2:**

1. **Log Capture Validation:** The generated logs successfully confirm that the entire interaction was fully captured.  
2. **Machine-Readability:** The output logs are confirmed to be valid structured data (e.g., valid JSON) parsable by automated security tools.

## 8.2 Invocation Audit Trail

### Description

The AI Tool SHALL generate a structured log entry for every function invocation containing at minimum: (1) timestamp, (2) identity of the calling agent or AI Tool host, (3) function name, (4) tool version, (5) hash or summary of input parameters (sensitive values redacted per 12.2.2), (6) execution outcome (success/failure/error code). Entries SHALL be in a machine-parseable structured format (e.g., JSON).

### Rationale

**Evidence**

**AL0, AL1:** Supporting evidence from static code inspection to show compliance to the requirement.

**AL2:** Functional AI Tool with the ability to execute tool calls and access to the generated logs.

**Test Procedure**

**AL0, AL1:**

1. **Verify Log Generation:** Inspect the codebase to ensure each function handler generates a log entry containing all six required fields.  
2. **Verify Structured Format:** Check that the format of the generated log entry is structured JSON.

**AL2:**

1. **Execute Tool Calls:** Execute both successful and failing tool calls.  
2. **Inspect Logs:** Inspect the generated logs for all six required fields.  
3. **Verify Format and Content:** Verify that the logs are valid JSON and ensure no sensitive values are present in plaintext.

**Verification**

**AL0, AL1:**

1. **Log Generation:** Each function handler generates a log entry with all six required fields.  
2. **Structured Format:** The log entry format is verified to be structured JSON.

**AL2:**

1. **Log Inspection:** All six required fields are present in the inspected logs following the execution of successful and failing tool calls.  
2. **Format and Content Validation:** The logs are valid JSON and contain no sensitive values in plaintext.

## 7.7.1 Validate Origin Header on HTTP Transports
### Description
The AI Tool must validate the `Origin` header on all incoming HTTP connections to prevent DNS rebinding attacks and unauthorized cross-origin access.
### Rationale
DNS rebinding allows an attacker's webpage to interact with local or internal MCP servers. Validating the `Origin` header is a mandatory requirement of the MCP transport specification to prevent these attacks.
### Audit
**Evidence**
**AL0, AL1:** Supporting evidence from static code inspection of the HTTP server configuration.
**AL2:** Functional AI Tool tested with forged Origin headers.
**Test Procedure**
**AL0, AL1:**
1. **Origin Check:** Verify that the HTTP server configuration explicitly validates the `Origin` header against an approved allowlist and rejects mismatched requests.
**AL2:**
1. **Rebinding Test:** Attempt to connect to the server using an unexpected or forged `Origin` header (e.g., `Origin: https://attacker.com`); the server must reject the connection.
**Verification**
**AL0, AL1:**
1. **Origin Check:** The server configuration explicitly validates the `Origin` header and rejects mismatched requests.
**AL2:**
1. **Rebinding Test:** The server rejects connections containing unexpected or forged `Origin` headers.
