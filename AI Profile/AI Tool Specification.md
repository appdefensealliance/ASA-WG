# App Defense Alliance AI Tool Specification

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

1 [Authentication, Identity, & Session Management](#1-authentication-identity--session-management)

1.1 [Mandatory Client-Server Transport Authentication](#11-mandatory-client-server-transport-authentication)

1.2 [Message Freshness and Session Binding](#12-message-freshness-and-session-binding)

1.3 [Strict Redirect URI and State Validation](#13-strict-redirect-uri-and-state-validation)

1.4 [Mandatory Proof Key for Code Exchange (PKCE)](#14-mandatory-proof-key-for-code-exchange-pkce)

1.5 [User Identity Propagation](#15-user-identity-propagation)

1.6 [Secure Downstream Transport](#16-secure-downstream-transport)

1.7 [Integrated Transport Security and Message Integrity](#17-integrated-transport-security-and-message-integrity)

2 [Authorization, Consent, & Access Control](#2-authorization-consent--access-control)

2.1 [Scoped Authorization and User Context Propagation](#21-scoped-authorization-and-user-context-propagation)

2.2 [Mandatory Cryptographic Validation of User Context](#22-mandatory-cryptographic-validation-of-user-context)

2.3 [Server-Side Consent Backstop for Sensitive Actions](#23-server-side-consent-backstop-for-sensitive-actions)

2.4 [Principle of Least Privilege and Scoped Permissions](#24-principle-of-least-privilege-and-scoped-permissions)

2.5 [Tool Function Allow-listing and Parameter Validation](#25-tool-function-allow-listing-and-parameter-validation)

2.6 [No Token Passthrough / Downstream Token Exchange](#26-no-token-passthrough--downstream-token-exchange)

2.7 [Out-of-Band Confirmation for High-Risk Actions](#27-out-of-band-confirmation-for-high-risk-actions)

3 [Secret Management & Data Protection](#3-secret-management--data-protection)

3.1 [Externalized Secret Management](#31-externalized-secret-management)

3.2 [Automated PII and Credential Masking in Logs](#32-automated-pii-and-credential-masking-in-logs)

3.3 [Secure Session Tokens](#33-secure-session-tokens)

3.4 [Exfiltration Defense](#34-exfiltration-defense)

3.5 [PII Detection](#35-pii-detection)

3.6 [Data Minimization](#36-data-minimization)

3.7 [Protect Sensitive Data in Logs](#37-protect-sensitive-data-in-logs)

4 [Input/Output Sanitization](#4-inputoutput-sanitization)

4.1 [Output Sanitization](#41-output-sanitization)

4.2 [Parameterized Arguments and Unsafe Sink Blocking](#42-parameterized-arguments-and-unsafe-sink-blocking)

4.3 [Detect and Block Unsafe Sinks](#43-detect-and-block-unsafe-sinks)

4.4 [Maximum Response Size](#44-maximum-response-size)

5 [Multi-Tenancy & Isolation](#5-multi-tenancy--isolation)

5.1 [Stateless Request Level Isolation](#51-stateless-request-level-isolation)

5.2 [Ensure Sandbox Protections](#52-ensure-sandbox-protections)

5.3 [Mandatory Tenant Isolation](#53-mandatory-tenant-isolation)

6 [System Integrity & Supply Chain](#6-system-integrity--supply-chain)

6.1 [Cryptographic Message Integrity Validation](#61-cryptographic-message-integrity-validation)

6.2 [Semantic Integrity and Descriptive Accuracy](#62-semantic-integrity-and-descriptive-accuracy)

6.3 [Resource Pinning and Signature Verification](#63-resource-pinning-and-signature-verification)

6.4 [No Embedded Model-Directed Control Directives](#64-no-embedded-model-directed-control-directives)

7 [Resource Constraints & Denial of Service (DoS) Prevention](#7-resource-constraints--denial-of-service-dos-prevention)

7.1 [Financial Resource & Cost Governance](#71-financial-resource--cost-governance)

7.2 [Per User Endpoint Rate Limiting](#72-per-user-endpoint-rate-limiting)

7.3 [Maximum Payload and Recursion Depth Constraints](#73-maximum-payload-and-recursion-depth-constraints)

8 [Logging, Auditing, & Monitoring](#8-logging-auditing--monitoring)

8.1 [Implement comprehensive logging using structured logging formats](#81-implement-comprehensive-logging-using-structured-logging-formats)

8.2 [Invocation Audit Trail](#82-invocation-audit-trail)

7.7.1 [Validate Origin Header on HTTP Transports](#771-validate-origin-header-on-http-transports)

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
| **Rug Pull Attack** | A supply chain attack where a dependency is automatically updated to a compromised version, which is mitigated by hash-based dependency pinning. |
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
|  | 2.6 No Token Passthrough / Downstream Token Exchange |
|  | 2.7 Out-of-Band Confirmation for High-Risk Actions |
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

---
## 1.1 Mandatory Client-Server Transport Authentication

### Description

The AI Tool must verify the identity of the client before executing any tools or providing resources. For remote connections (Streamable HTTP), this must involve strong authentication (e.g., OAuth2, dynamically rotated API Keys, or mTLS). For local connections (Stdio), the server must ensure it is only accepting input from the authorized parent process.

**This requirement only applies to remote servers. Local and mobile servers are out of scope.**

### Rationale

Without identity verification, an attacker could impersonate a legitimate AI agent or host to trigger sensitive tools (e.g., "delete\_database") or extract proprietary data.

### Audit

| Spec | Description |
| --- | ------|
| [1.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#111-mandatory-client-server-transport-authentication) | Mandatory Client-Server Transport Authentication |

---
## 1.2 Message Freshness and Session Binding

### Description

For persistent or stateful transports (e.g., Streamable HTTP), the AI Tool must implement session timeouts and validate message timestamps or nonces if provided by the client. The server must terminate sessions that exceed a defined period of inactivity.

### Rationale

If an attacker captures a valid AI Tool tool-call request, they could "replay" it later to trigger the tool again (e.g., a "pay_invoice" tool) even if the original session has ended.

### Audit

| Spec | Description |
| --- | ------|
| [1.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#121-message-freshness-and-session-binding) | Message Freshness and Session Binding |

---
## 1.3 Strict Redirect URI and State Validation

### Description

If the AI Tool facilitates OAuth flows for tool access, it must strictly validate Redirect URIs against a pre-defined allowlist and enforce the use of the state parameter to prevent Cross-Site Request Forgery (CSRF). Legacy authentication methods (Basic Auth over HTTP) are strictly prohibited.

### Rationale

AI tools often need to connect to 3rd party SaaS (GitHub, Jira). Weaknesses in the OAuth flow can allow attackers to intercept authorization codes and hijack the tool's access to those services.

**This requirement is out of scope for mobile AI Tools, or remote servers in which the AI Tool is integrated into a WebApp.**

### Audit

| Spec | Description |
| --- | ------|
| [1.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#131-strict-redirect-uri-and-state-validation) | Strict Redirect URI and State Validation |

---
## 1.4 Mandatory Proof Key for Code Exchange (PKCE)

### Description

When the AI Tool initiates an OAuth 2.0 authorization code flow to obtain user credentials for a tool, it must implement and enforce Proof Key for Code Exchange (PKCE) as defined in RFC 7636\. The server must generate a unique, high-entropy code\_verifier for every authorization request, send the code\_challenge (derived via the S256 method) to the authorization endpoint, and provide the original code\_verifier during the token exchange step. This requirement applies regardless of whether the client is classified as public or confidential.

### Rationale

Authorization codes are vulnerable to interception via custom URI scheme hijacking (on mobile/local hosts) or log leakage. PKCE provides a dynamic, cryptographically bound secret that ensures only the entity that initiated the authorization request can successfully exchange the resulting code for a token. This effectively mitigates "Authorization Code Injection" and "Interception" attacks by rendering a stolen code useless to an attacker.

**Mobile AI Tools are out of scope for this requirement.**

### Audit

| Spec | Description |
| --- | ------|
| [1.4.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#141-mandatory-proof-key-for-code-exchange-pkce) | Mandatory Proof Key for Code Exchange (PKCE) |

---
## 1.5 User Identity Propagation

### Description

If more than one user is supported, the AI Tool must not "assume" which user it is acting for based on the connection alone.

* **Token Validation:** Every request must include a short-lived Identity Token that identifies the specific user.

* **Scoped Access:** The server’s internal logic must use this token to scope all database queries (e.g., SELECT \* FROM docs WHERE owner\_id \= {JWT.sub}), or access to other user specific data or APIs.

* **Hard Fail on Missing Identity:** If a request arrives without a valid, verifiable identity token, the server must return a 401 Unauthorized and terminate the execution thread immediately.

### Rationale

Identity Propagation is the cornerstone of Multi-Tenant Data Isolation, ensuring that every action performed by an AI Tool is explicitly tied to a verified user or organization through short-lived, cryptographically signed identity tokens. By mandating that the server validate these tokens for every incoming request, we eliminate "Implicit Authorization" and prevent Direct Object Reference (IDOR) attacks where one tenant might attempt to access another's data by guessing a resource ID. This requirement forces the third-party server to operate within a "Zero Trust" framework, where access to any underlying data or tool is strictly scoped to the identity contained within the request payload, providing a verifiable and auditable cryptographic link between the user's intent and the server's execution.

**Mobile AI Tools are out of scope for this requirement.**

### Audit

| Spec | Description |
| --- | ------|
| [1.5.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#151-user-identity-propagation) | User Identity Propagation |

---
## 1.6 Secure Downstream Transport

### Description

The AI Tool must ensure that all communications with downstream resources (e.g., internal APIs, databases, or third-party services) that involve the transmission of secrets are conducted over encrypted channels (TLS 1.3 or higher). All security sensitive data shall be protected when in flight. For example, tokens shall not be sent in HTTP headers.

### Rationale

Credential theft often occurs during transit or through the reuse of intercepted long-lived keys. Ensuring encrypted transport mitigates interception risks during the "handling" phase.

**Mobile AI Tools and AI Tools integrated into Web Applications are out of scope for this requirement.**

### Audit

| Spec | Description |
| --- | ------|
| [1.6.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#161-secure-downstream-transport) | Secure Downstream Transport |

---
## 1.7 Integrated Transport Security and Message Integrity

### Description

To mitigate Man-in-the-Middle (MitM) and message integrity risks, the system must enforce a unified secure transport layer and message-level protection. For remote connections, communication must be encrypted using TLS 1.3+ with strict X.509 certificate and trust chain validation (rejecting plaintext, expired, or untrusted endpoints). For local connections, the system must bypass the network stack in favor of secure Inter-Process Communication (IPC)—such as Unix domain sockets or Windows Named Pipes—protected by strict OS-level permissions.

### Rationale

This requirement establishes a multi-layered defense. High-grade encryption and secure IPC prevent unauthorized eavesdropping on the wire or within the host. Strict certificate validation ensures the client is communicating with the legitimate server, rather than an attacker's proxy. Lastly, message-level signing guarantees that even if a transport-level vulnerability exists, the underlying tool calls and responses remain immutable and can only be executed once.

### Audit

| Spec | Description |
| --- | ------|
| [1.7.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#171-integrated-transport-security-and-message-integrity) | Integrated Transport Security and Message Integrity |

# 2. Authorization, Consent, & Access Control

---
## 2.1 Scoped Authorization and User Context Propagation

### Description

The AI Tool must not rely solely on its own service-level credentials to access downstream resources. It must require and validate "User-in-the-loop" context or scoped tokens passed through the AI Tool request metadata to ensure the end-user has the authority to perform the requested action.

### Rationale

An AI Tool acts as a deputy. If it uses a global admin key to fulfill a request from a low-privilege user, it becomes a 'confused deputy,' allowing the user to escalate privileges via the AI tool.

### Audit

| Spec | Description |
| --- | ------|
| [2.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#211-scoped-authorization-and-user-context-propagation) | Scoped Authorization and User Context Propagation |

---
## 2.2 Mandatory Cryptographic Validation of User Context

### Description

The AI Tool must verify the cryptographic signature of identity tokens or user context metadata provided by the AI Tool host (Agent) (when possible). If the tool interacts with external third-party APIs (downstream resources), it must utilize an "On-Behalf-Of" flow or exchange the validated user token for a scoped access token. The server shall reject any request where the user context is provided as a simple, unverified string (e.g., a plain `user_id` field).

### Rationale

If a developer's tool simply trusts a `user_id` passed by the Agent, a compromised or "confused" Agent could provide "User A's" ID while executing "User B's" request. By requiring cryptographic validation (e.g., verifying a JWT signed by a trusted IdP), the Developer ensures that the user context is authentic and that the Agent cannot escalate privileges by misrepresenting the user.

### Audit

| Spec | Description |
| --- | ------|
| [2.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#221-mandatory-cryptographic-validation-of-user-context) | Mandatory Cryptographic Validation of User Context |

---
## 2.3 Server-Side Consent Backstop for Sensitive Actions

### Description

The AI tool implementation must utilize elicitation or confirmation message on the server side to request user confirmation of actions, or enforce the use of clients with configurations that unprivileged users cannot change to keep confirmation prompts enabled. Security-relevant messages and elicitations must be clear, indicating the implications of the request, and unambiguous about what is being requested. The AI Tool must not treat an Agent-supplied claim that consent was obtained as sufficient; it must fail closed when it cannot establish that the user confirmed the specific action.

### Rationale

Missing or insufficient human-in-the-loop consent checks can allow an AI Tool to take risky actions not authorized by the user. A large language model, whether legitimate or poisoned, may decide to execute a tool in a dangerous way, making user confirmation crucial for mitigating this risk.

### Audit

| Spec | Description |
| --- | ------|
| [2.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#231-server-side-consent-backstop-for-sensitive-actions) | Server-Side Consent Backstop for Sensitive Actions |

---
## 2.4 Principle of Least Privilege and Scoped Permissions

### Description

AI Tools must operate with the minimum privileges necessary. Implementations must reduce scopes to least privilege, such as removing write scopes when only read access is required.

### Rationale

AI agents, AI Tools, or tools granted more privileges than necessary drastically increase the blast radius in the event of an attack or misconfiguration. Without strict least privilege by design, a compromised agent can easily escalate privileges, move laterally, or corrupt sensitive data.

### Audit

| Spec | Description |
| --- | ------|
| [2.4.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#241-principle-of-least-privilege-and-scoped-permissions) | Principle of Least Privilege and Scoped Permissions |

---
## 2.5 Tool Function Allow-listing and Parameter Validation

### Description

The AI Tool SHALL expose only an explicitly defined set of functions to the AI Agent. Functions not included in the tool's published manifest SHALL NOT be invocable via the agent interface. All function parameters SHALL be validated against their declared types and constraints before execution. The tool SHALL reject requests containing undeclared parameters or parameters that fail type/constraint validation.

### Rationale

Because AI agents are inherently probabilistic and vulnerable to prompt injection, strict function allow-listing ensures that only explicitly authorized capabilities are exposed to minimize the system's overall attack surface. Additionally, rigorous parameter validation prevents malicious payloads or model hallucinations from executing unauthorized commands, accessing unintended data, or causing downstream system instability.

### Audit

| Spec | Description |
| --- | ------|
| [2.5.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#251-tool-function-allow-listing-and-parameter-validation) | Tool Function Allow-listing and Parameter Validation |

---
## 2.6 No Token Passthrough / Downstream Token Exchange

### Description

When the AI Tool calls a downstream/upstream API on the user's behalf, it must not forward the client-supplied token; it must obtain a separate, audience-scoped token via OAuth 2.0 Token Exchange (RFC 8693) or an equivalent on-behalf-of flow, and should sender-constrain downstream tokens (DPoP, RFC 9449) — required for remote/high-value deployments.

### Rationale

Forwarding the inbound token downstream is the classic confused-deputy / audience-confusion vector. Token exchange preserves the user's identity and least-privilege scope while binding each hop's credential to its audience; proof-of-possession stops a stolen bearer token from being replayed.

### Audit

| Spec | Description |
| --- | ------|
| [2.6.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#261-no-token-passthrough--downstream-token-exchange) | No Token Passthrough / Downstream Token Exchange |

---
## 2.7 Out-of-Band Confirmation for High-Risk Actions

### Description

For the highest-risk operations — irreversible actions, transfers of value or money, or the granting/expansion of access — the AI Tool SHOULD require user confirmation over a channel independent of the AI Agent (out-of-band), so that approval cannot be forged by the Agent in the request path. Out-of-band confirmation is REQUIRED for remote and other high-value deployments. Where it is not feasible for a given action, the Tool MUST fall back to the server-side elicitation backstop (§2.3) and MUST NOT downgrade to Agent-relayed consent.

### Rationale

Server-side elicitation transits the Agent, so a malicious Agent can fabricate an affirmative response without ever showing the user. An independent confirmation channel — for example a link or one-time code delivered to a pre-registered email/SMS/authenticator, or a provider-hosted approval page authenticated directly to the user — lets the user approve the specific action directly, closing the malicious-Agent gap for the actions where a forged approval is most costly.

### Audit

| Spec | Description |
| --- | ------|
| [2.7.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#271-out-of-band-confirmation-for-high-risk-actions) | Out-of-Band Confirmation for High-Risk Actions |

# 3. Secret Management & Data Protection

---
## 3.1 Externalized Secret Management

### Description

AI Tools must never contain hardcoded credentials, API keys, or private keys within the source code or configuration files. All sensitive secrets must be retrieved at runtime from an environment variable or a dedicated Secret Management Service (e.g., AWS Secrets Manager, HashiCorp Vault). Developers shall have a policy and procedure in place to periodically rotate sensitive secrets and have revocation protocols in place if a breach is detected.

### Rationale

AI Tools are often lightweight and distributed; hardcoded secrets are easily leaked through version control or container image inspection, leading to full compromise of the connected tools.

### Audit

| Spec | Description |
| --- | ------|
| [3.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#311-externalized-secret-management) | Externalized Secret Management |

---
## 3.2 Automated PII and Credential Masking in Logs

### Description

The AI Tool must implement an interception layer for all logging (stdout/stderr/files) that automatically redacts sensitive information, specifically the Authorization headers, session tokens, and sensitive fields within the tool params (e.g., "password", "api\_key").

### Rationale

Developers often log full JSON-RPC requests for debugging. If these logs are sent to a centralized logging system, any user with log access can steal active session tokens or sensitive tool inputs.

### Audit

| Spec | Description |
| --- | ------|
| [3.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#321-automated-pii-and-credential-masking-in-logs) | Automated PII and Credential Masking in Logs |

---
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

| Spec | Description |
| --- | ------|
| [3.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#331-secure-session-tokens) | Secure Session Tokens |

---
## 3.4 Exfiltration Defense

### Description

The system SHALL implement a defense-in-depth architecture to prevent sensitive data leakage. It should also prevent the transmission of any data in transit, at rest, and during processing to the Agent that was not explicitly intended for the current task. AI Tool implementations must treat the AI Agent as an untrusted principal. 

The AI tool (e.g., AI Tool) MUST implement strict access controls, memory isolation, and input validation to ensure that any confidential material held internally—including internal API keys, service credentials, local configuration files, and private caching states—cannot be exfiltrated, exposed, modified, or corrupted through the tool’s exposed execution pathways or APIs. The tool MUST enforce a rigid boundary between its internal operational secrets and the execution context handling agent requests.

### Rationale

AI tools often require highly privileged credentials (e.g., database passwords, OAuth tokens) to function. If an Agent is subverted via Indirect Prompt Injection (IPI), it may attempt to instruct the tool to read its own internal configuration or "leak" supplementary data retrieved from a backend. By isolating internal secrets and enforcing strict output schemas, the "blast radius" of a compromised agent is contained; the request simply becomes technically impossible to fulfill.

### Audit

| Spec | Description |
| --- | ------|
| [3.4.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#341-exfiltration-defense) | Exfiltration Defense |

---
## 3.5 PII Detection

### Description

When the AI Tool accesses data stores that may contain PII, the tool SHALL detect the following patterns in responses: (1) SSN/national ID numbers, (2) email addresses, (3) phone numbers, (4) credit card numbers (Luhn-valid), (5) high-entropy credential patterns. Detected PII SHALL be redacted before inclusion in responses, unless the tool's documented purpose requires returning PII and the requesting agent has appropriate authorization scope.

### Rationale

PII Detection is fundamentally used to prevent PII leakage. It serves as a critical defense-in-depth mechanism against the unauthorized exposure or exfiltration of sensitive user data by compromised or hallucinating AI agents interacting with backend data stores. By mandating the automated detection and redaction of sensitive patterns—such as Social Security Numbers, email addresses, phone numbers, credit card numbers, and high-entropy credentials—the tool neutralizes Personally Identifiable Information before it reaches the agent. This strict redaction policy limits the blast radius of potential vulnerabilities, ensuring sensitive data is only returned when strictly necessary for the tool's documented purpose and when the requesting agent possesses the explicitly authorized scope to handle it.

### Audit

| Spec | Description |
| --- | ------|
| [3.5.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#351-pii-detection) | PII Detection |

---
## 3.6 Data Minimization

### Description

The AI Tool shall minimize the data being exposed to align with the use case the tool supports. The tool’s output schema and database queries shall be limited to necessary fields to support the functions stated need.For example, a tool which provides the current travel rewards points balance should not return the user’s credit card number and social security number.

### Rationale

Overly permissive tools may expose the user’s data, or result in actions which the user never intended an agent to be able to perform.

### Audit

| Spec | Description |
| --- | ------|
| [3.6.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#361-data-minimization) | Data Minimization |

---
## 3.7 Protect Sensitive Data in Logs

### Description

All logging mechanisms must include automated redaction or masking for sensitive information. This includes, but is not limited to, Personally Identifiable Information (PII), authentication tokens, API keys, passwords, and sensitive model outputs that may contain proprietary or private data.

### Rationale

Logs are frequently replicated across multiple systems, stored in centralized repositories, and accessed by various personnel, making them a high-value target for attackers. According to OWASP and COSAI standards, failure to scrub sensitive data from telemetry can lead to accidental data breaches and compliance violations. Because LLMs and agents may process sensitive data as part of their prompt context, it is vital to ensure that this data does not leak into the persistent logging layer during the monitoring process.

### Audit

| Spec | Description |
| --- | ------|
| [3.7.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#371-protect-sensitive-data-in-logs) | Protect Sensitive Data in Logs |

# 4. Input/Output Sanitization

---
## 4.1 Output Sanitization

### Description

The AI Tool SHALL sanitize all outputs returned to the AI Agent. Structured outputs (JSON, YAML, XML) SHALL be validated against a defined schema before transmission. String outputs that may be rendered in a user interface SHALL be encoded to neutralize HTML, JavaScript, and shell metacharacters.

### Rationale

Output Sanitization helps to prevent output vulnerabilities by ensuring that malicious payloads cannot be executed or improperly rendered by downstream systems. By mandating that structured outputs—such as JSON, YAML, and XML—are strictly validated against a defined schema before transmission, the system guarantees data integrity and prevents malformed or poisoned responses from compromising the AI Agent. Furthermore, requiring the encoding of string outputs neutralizes hazardous elements, specifically HTML, JavaScript, and shell metacharacters. This comprehensive sanitization process acts as a critical safeguard, protecting the final user interface from injection attacks disguised as legitimate AI tool responses and maintaining the overall security of the data flowing from the tool to the agent.

### Audit

| Spec | Description |
| --- | ------|
| [4.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#411-output-sanitization) | Output Sanitization |

---
## 4.2 Parameterized Arguments and Unsafe Sink Blocking

### Description

The AI Tool must enforce strict input validation, sanitization, and parameterization across all execution contexts. It must actively identify and block the use of unsafe execution sinks (such as eval(), os.system(), or subprocess.Popen(shell=True)) and mandate the use of parameterized arguments for any underlying system calls or queries. All inputs must be validated using strict allowlists at every trust boundary.

### Rationale

Developers incorrectly assume that user input processed through an LLM is inherently safe, bypassing established secure coding practices. In reality, the LLM transforms but does not sanitize malicious payloads. Without strict parameterized boundaries, an attacker can manipulate tool arguments to execute arbitrary shell commands, leading to total system compromise and sandbox escapes.

### Audit

| Spec | Description |
| --- | ------|
| [4.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#421-parameterized-arguments-and-unsafe-sink-blocking) | Parameterized Arguments and Unsafe Sink Blocking |

---
## 4.3 Detect and Block Unsafe Sinks

### Description

The AI Tool must operate within a hardened runtime that identifies and blocks code patterns facilitating sandbox escapes, such as os.system(), subprocess.Popen(shell=True), or eval(). Any tool that passes arguments to system-level calls must utilize parameterized arguments and path canonicalization

### Rationale

Proactively identifying insecure coding patterns during development mitigates the risk of Command Injection and Directory Traversal, which serve as primary vectors for bypassing tool sandboxes.

**Note: Mobile AI Tools are out of scope for this requirement.**

### Audit

| Spec | Description |
| --- | ------|
| [4.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#431-detect-and-block-unsafe-sinks) | Detect and Block Unsafe Sinks |

---
## 4.4 Maximum Response Size

### Description

The AI Tool SHALL enforce a configurable maximum size for all responses returned to the AI Agent. Responses exceeding this limit SHALL be truncated, paginated, or rejected with an error indicating the limit. The default limit SHALL NOT exceed 1 MB unless the tool's documented use case requires larger responses.

### Rationale

Enforcing a strict ceiling on outbound payloads serves as a vital safeguard to limit output over-exposure and minimize the blast radius of potential system compromises. Because AI tools act as functional bridges to robust backend databases and external APIs , an untrusted or manipulated AI agent—subverted via indirect prompt injection—may attempt to execute commands designed to harvest or leak extensive volumes of corporate or user data.

By mandating a tight default maximum response limit of 1 MB and requiring oversized payloads to be truncated, paginated, or explicitly rejected , the tool enforces strict data minimization at the output boundary. Furthermore, this restriction protects the calling AI host from client-side parsing latency, memory consumption spikes, or systemic Denial-of-Service (DoS) vulnerabilities that arise when trying to process unconstrained natural language or deeply nested JSON structures.

### Audit

| Spec | Description |
| --- | ------|
| [4.4.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#441-maximum-response-size) | Maximum Response Size |

# 5. Multi-Tenancy & Isolation

---
## 5.1 Stateless Request Level Isolation

### Description

To prevent "Session Bleed" (where data from a previous request persists in memory and affects the next), the server must treat every request as an independent atomic unit.

* **No Global State:** The server must not store user-specific data in global variables or static caches.  
    
* **Memory Clearing:** If the runtime environment (e.g., Python/Node.js) is reused across requests for different tenants, the server must perform a "Context Reset" or be forcibly restarted between different tenant contexts.

* **Unique Request IDs:** Every incoming request from the Agent must be tagged with a unique Request ID. All logs and internal traces must use this ID to ensure auditability of data boundaries

### Rationale

Mandatory Statelessness is the primary technical control against Cross-Tenant Data Leakage (CTDL), ensuring that a third-party AI Tool maintains a strict isolation boundary between independent user sessions. By requiring a "Process, Respond, Purge" lifecycle, we eliminate "session bleed"—where data from one user lingers in memory or global variables and is inadvertently accessed by a subsequent request from a different tenant. This architecture shifts the security boundary away from potentially flawed application logic and onto a deterministic, stateless execution model, removing the possibility of state-based side-channel attacks and ensuring that every transaction is a self-contained, auditable event with no memory of prior sensitive contexts.

### Audit

| Spec | Description |
| --- | ------|
| [5.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#511-stateless-request-level-isolation) | Stateless Request Level Isolation |

---
## 5.2 Ensure Sandbox Protections

### Description

Identify and block code patterns that facilitate sandbox escapes or multi-tenant data leakage. Mandating the detection of "unsafe sinks"—such as direct shell execution, unvalidated file system operations, and unrestricted network sockets—ensures that the AI Tool remains isolated. Any code that passes user-supplied tool arguments to system-level calls must undergo rigorous path canonicalization and validation against a pre-defined allowlist to prevent build-breaking security violations.

### Rationale

Enforcing these programmatic constraints aligns the AI Tool architecture with the principle of "Least Privilege," ensuring inherent compatibility with hardened runtimes. Proactively identifying and remediating insecure coding patterns during the development phase mitigates the risk of Directory Traversal and Command Injection vulnerabilities, which serve as primary vectors for bypassing execution sandboxes. Such a stance is critical in multi-tenant environments to ensure that even a compromised or manipulated model cannot programmatically execute unauthorized actions on the host system or access data belonging to other users.

### Audit

| Spec | Description |
| --- | ------|
| [5.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#521-ensure-sandbox-protections) | Ensure Sandbox Protections |

---
## 5.3 Mandatory Tenant Isolation

### Description

For multi-tenant deployments, the AI Tool SHALL enforce logical isolation of tenant data. All data storage operations SHALL include a tenant identifier as a mandatory filter condition. The tenant identifier SHALL be derived from the authenticated session context, not from user-supplied parameters. The tool SHALL reject any request where the authenticated tenant context does not match the requested data's tenant identifier.

### Rationale

Prevent Cross-Tenant Data Leakage

### Audit

| Spec | Description |
| --- | ------|
| [5.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#531-mandatory-tenant-isolation) | Mandatory Tenant Isolation |

# 6. System Integrity & Supply Chain

---
## 6.1 Cryptographic Message Integrity Validation

### Description

AI Tool implementations must require and enforce cryptographic integrity checks on all messages, tool definitions, and resource responses. Tool developers must include mechanisms such as message authentication codes (MACs) or digital signatures to ensure end-to-end integrity and prevent the undetected modification of critical system components or payloads during transit.

### Rationale

Without integrity verification, malicious actors or compromised intermediaries can intercept and modify tool definitions, forge messages, or inject poisoned data into resource responses. Because the AI model implicitly trusts the context and data returned by connected tools, tampered payloads can seamlessly trigger prompt injections or execute unauthorized behavior .

### Audit

| Spec | Description |
| --- | ------|
| [6.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#611-cryptographic-message-integrity-validation) | Cryptographic Message Integrity Validation |

---
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

| Spec | Description |
| --- | ------|
| [6.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#621-semantic-integrity-and-descriptive-accuracy) | Semantic Integrity and Descriptive Accuracy |

---
## 6.3 Resource Pinning and Signature Verification

### Description

The AI Tool must implement strict dependency pinning with hash-based verification for all third-party plugins and dependencies, rather than relying solely on version ranges or strict equality. All model weights and tool packages must have valid digital signatures and be verified against known cryptographic hashes.

### Rationale

Resource pinning ensures that updates are a deliberate developer decision, preventing "Rug Pull" attacks where a dependency is automatically updated to a compromised version. This forces a "temporal delay" that eliminates a major class of common ecosystem vulnerabilities

### Audit

| Spec | Description |
| --- | ------|
| [6.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#631-resource-pinning-and-signature-verification) | Resource Pinning and Signature Verification |

---
## 6.4 No Embedded Model-Directed Control Directives

### Description

The AI Tool must not embed model-directed control directives or instructions within the content it returns to the Agent — including operation results, retrieved/resource content, and its own tool/function descriptions and schemas. The AI Tool must not rely on the model or Agent to enforce the Tool's own security constraints; it must validate its own inputs and enforce its own authorization independently of the model. Provenance or "data vs. control" tags may be provided as defense-in-depth but must not be relied upon as a security boundary.

### Rationale

Indirect prompt injection cannot be prevented by the producer marking its output, so the load-bearing defense is the Agent treating all Tool Output as untrusted (Agent–Tool Interface Contract C2; mitigation is tested consumer-side in AI Agent Specification §3.1.2). The Tool's residual, testable duty is narrow: not to be an injection vector itself, and not to delegate its own security to the model (CoSAI MCP Security §3.2.8: "Tool implementations should not rely on the LLM to perform security-critical operations, validate inputs, or enforce constraints").

### Audit

| Spec | Description |
| --- | ------|
| [6.4.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#641-no-embedded-model-directed-control-directives) | No Embedded Model-Directed Control Directives |

# 7. Resource Constraints & Denial of Service (DoS) Prevention

---
## 7.1 Financial Resource & Cost Governance

### Description

The AI Tool must be inherently **cost-aware**. It must identify whether a specific resource (e.g. a premium search API or a paid data scraper) carries a direct financial cost to the user or organization. For these metered resources, the tool must implement the following:

* **Session-Based Cost Tracking:** The tool must calculate and track the cumulative cost of all API calls made during an active session.  
* **The $100 Guardrail:** By default, if the cumulative session cost reaches **$100**, the tool must automatically intervene by either enforcing a strict rate limit or pausing execution to request explicit user confirmation.  
* **Justified Overrides:** Developers may set a higher dollar threshold only if they provide a documented business justification within the configuration metadata.  
* **Governance Layers:** Enforce mandatory authentication for all tool access and implement per-user/per-tool rate limiting to prevent unauthorized or runaway consumption.

### Rationale

AI Tools are "force multipliers" for LLMs. Because these tools often bridge the gap to paid APIs (e.g., GPT-4o, Claude 3.5 Sonnet, or search engines), they represent a direct financial vulnerability. A logic loop or a malicious actor could trigger thousands of dollars in costs in seconds. Unlike traditional DoS, which impacts availability, a DoW attack impacts the viability of the business.

### Audit

| Spec | Description |
| --- | ------|
| [7.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#711-financial-resource--cost-governance) | Financial Resource & Cost Governance |

---
## 7.2 Per User Endpoint Rate Limiting

### Description

For remote deployments, the AI Tool SHALL enforce per-user or per-session rate limits. The tool SHALL implement at least one of: (1) max requests per time window per authenticated user, (2) progressive throttling, (3) temporary blocking after threshold. Limits SHALL be configurable. Rate limiting for one user SHALL NOT affect other users.

### Rationale

TBD

### Audit

| Spec | Description |
| --- | ------|
| [7.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#721-per-user-endpoint-rate-limiting) | Per User Endpoint Rate Limiting |

---
## 7.3 Maximum Payload and Recursion Depth Constraints

### Description

The server must strictly enforce configurable limits on the maximum size of incoming request payloads (in bytes) and the maximum depth of nested structures (e.g., JSON objects, arrays, or recursive tool calls).

### Rationale

Unbounded inputs allow attackers to trigger Denial-of-Service (DoS). Large payloads exhaust RAM/bandwidth, while deep recursion can lead to stack overflow errors or CPU spikes during parsing, rendering the server unavailable to legitimate users.

### Audit

| Spec | Description |
| --- | ------|
| [7.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#731-maximum-payload-and-recursion-depth-constraints) | Maximum Payload and Recursion Depth Constraints |

# 8. Logging, Auditing, & Monitoring

---
## 8.1 Implement comprehensive logging using structured logging formats

### Description

The system must capture all significant security and operational events—including authentication attempts, authorization decisions, tool/function calls, AI model inputs/outputs, and system state changes. These logs must be generated in a machine-readable, structured format (such as JSON) rather than unstructured plain text.

### Rationale

In agentic and MCP-based architectures, the complexity of interactions between users, hosts, and servers makes traditional grep-based log analysis insufficient. Structured logging allows automated security orchestration, automation, and response (SOAR) tools and SIEMs to parse and correlate events in real-time. This visibility is critical for detecting anomalous patterns, such as indirect prompt injection, which are often only visible when analyzing the metadata of model interactions and tool execution.

### Audit

| Spec | Description |
| --- | ------|
| [8.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#811-implement-comprehensive-logging-using-structured-logging-formats) | Implement comprehensive logging using structured logging formats |

---
## 8.2 Invocation Audit Trail

### Description

The AI Tool SHALL generate a structured log entry for every function invocation containing at minimum: (1) timestamp, (2) identity of the calling agent or AI Tool host, (3) function name, (4) tool version, (5) hash or summary of input parameters (sensitive values redacted per 12.2.2), (6) execution outcome (success/failure/error code). Entries SHALL be in a machine-parseable structured format (e.g., JSON).

### Rationale

Detailed audit trails allow security teams to reconstruct anomalous agent sessions, verify non-repudiation, and detect subtle privilege escalation attempts or unauthorized actions executed via tools.

### Audit

| Spec | Description |
| --- | ------|
| [8.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#821-invocation-audit-trail) | Invocation Audit Trail |

---
## 7.7.1 Validate Origin Header on HTTP Transports

### Description

The AI Tool must validate the `Origin` header on all incoming HTTP connections to prevent DNS rebinding attacks and unauthorized cross-origin access.

### Rationale

DNS rebinding allows an attacker's webpage to interact with local or internal MCP servers. Validating the `Origin` header is a mandatory requirement of the MCP transport specification to prevent these attacks.

### Audit

| Spec | Description |
| --- | ------|
| [7.7.1](https://github.com/appdefensealliance/ASA-WG/blob/main/AI%20Profile/AI%20Tool%20Testing%20Guide.md#771-validate-origin-header-on-http-transports) | Validate Origin Header on HTTP Transports |

