# AI Tool Security Specification

Version 0.1 3/9/26

# Revision History

| Version | Date   | Description                                                        |
| :------ | :----- | :----------------------------------------------------------------- |
| 0.1     | 3/9/26 | Initial document outline based on CoSAI MCP security paper threats |
|         |        |                                                                    |

# Contributors

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

### Application Security Assessment Working Group Leads

* Alex Duff (Meta) \- ASA WG Chair  
* Anna Bhirud (Google) \- ASA WG Vice Chair

### AI Profile Leads

* Brad Ree (Google)  
* Alex Duff (Meta)

### Contributors

* Summer Yue (Meta)  
* Deb Dhuttaguha (Google)  
* Nic Watson (Google)  
* Abhiraman Gcl (Google)  
* Daniel Bond (Meta)  
* Tony Balkin (Microsoft)  
* Dario Freni (Google)
* TBD

# Table of Contents

[**Revision History	1**](#revision-history)

[**Contributors	1**](#contributors)

[Application Security Assessment Working Group Leads	1](#application-security-assessment-working-group-leads)

[AI Profile Leads	1](#ai-profile-leads)

[Contributors	1](#contributors-1)

[**Table of Contents	2**](#table-of-contents)

[Introduction	5](#introduction)

[Scope	5](#scope)

[Relationship To CoSAI Model Context Protocol (MCP) Security	7](#relationship-to-cosai-model-context-protocol-\(mcp\)-security)

[References	9](#references)

[Licensing	9](#licensing)

[Definitions	9](#definitions)

[1 Improper Authentication and Identity Management	9](#1-improper-authentication-and-identity-management)

[1.1 Identity Spoofing	9](#1.1-identity-spoofing)

[1.2 Confused Deputy (OAuth Proxy)	11](#1.2-confused-deputy-\(oauth-proxy\))

[1.3 Credential Theft/Token Theft	13](#1.3-credential-theft/token-theft)

[1.4 Replay Attacks/Session Hijacking	15](#1.4-replay-attacks/session-hijacking)

[1.5 OAuth/Legacy Auth Weaknesses	17](#1.5-oauth/legacy-auth-weaknesses)

[1.6 Session Token Leakage	19](#1.6-session-token-leakage)

[2 Missing or Improper Access Control	21](#2-missing-or-improper-access-control)

[2.1 Insecure Human-in-the-Loop	21](#2.1-insecure-human-in-the-loop)

[2.2 Improper Multitenancy	22](#2.2-improper-multitenancy)

[2.3 Confused Deputy (OAuth Proxy) (Duplicate)	27](#2.3-confused-deputy-\(oauth-proxy\)-\(duplicate\))

[2.4 Excessive Permissions/Overexposure	27](#2.4-excessive-permissions/overexposure)

[3 Input Validation/Sanitization Failures	28](#3-input-validation/sanitization-failures)

[3.1 Command Injection	28](#3.1-command-injection)

[3.2 File System Exposure/Path Traversal (Duplicate)	29](#3.2-file-system-exposure/path-traversal-\(duplicate\))

[3.3 Insufficient Integrity Checks	30](#3.3-insufficient-integrity-checks)

[4 Data/Control Boundary Distinction Failure	31](#4-data/control-boundary-distinction-failure)

[4.1 Tool Definition Poisoning	31](#4.1-tool-definition-poisoning)

[4.2 Full Schema Poisoning	34](#4.2-full-schema-poisoning)

[4.3 Resource Content Poisoning	35](#4.3-resource-content-poisoning)

[4.4 Prompt Injection	36](#4.4-prompt-injection)

[5 Inadequate Data Protection and Confidentiality Controls	38](#5-inadequate-data-protection-and-confidentiality-controls)

[5.1 Data Exfiltration & Corruption	38](#5.1-data-exfiltration-&-corruption)

[5.2 File System Exposure/Path Traversal (Duplicate)	38](#5.2-file-system-exposure/path-traversal-\(duplicate\))

[6 Missing Integrity/Verification Controls	39](#6-missing-integrity/verification-controls)

[6.1 Resource Content Poisoning	39](#6.1-resource-content-poisoning)

[6.2 Typosquatting/Confusion Attacks	40](#6.2-typosquatting/confusion-attacks)

[6.3 Shadow MCP Servers	41](#6.3-shadow-mcp-servers)

[6.4 Supply Chain Compromise and Privileged host-base Attacks	42](#6.4-supply-chain-compromise-and-privileged-host-base-attacks)

[7 Session and Transport Security Failures	43](#7-session-and-transport-security-failures)

[7.1 Man-in-the-Middle (MITM)	43](#7.1-man-in-the-middle-\(mitm\))

[7.2 Insufficient Integrity Checks (Duplicate)	43](#7.2-insufficient-integrity-checks-\(duplicate\))

[7.3 Unrestricted Network Access	44](#7.3-unrestricted-network-access)

[7.4 Protocol Security Gaps	45](#7.4-protocol-security-gaps)

[7.5 Insecure Descriptor Handling	46](#7.5-insecure-descriptor-handling)

[7.6 CSRF Protection Missing	47](#7.6-csrf-protection-missing)

[7.7 CORS/Origin Policy Bypass	47](#7.7-cors/origin-policy-bypass)

[8 Network Binding/Isolation Failures	48](#8-network-binding/isolation-failures)

[8.1 Shadow MCP Servers (Duplicate)	48](#8.1-shadow-mcp-servers-\(duplicate\))

[8.2 Improper Multitenancy	49](#8.2-improper-multitenancy)

[8.3 Unrestricted Network Access (Duplicate)	50](#8.3-unrestricted-network-access-\(duplicate\))

[8.4 Malicious Command Execution	51](#8.4-malicious-command-execution)

[8.5 Dependency/Update Attack	51](#8.5-dependency/update-attack)

[9 Trust Boundary and Privilege Design Failures	52](#9-trust-boundary-and-privilege-design-failures)

[9.1 Overreliance on the LLM	52](#9.1-overreliance-on-the-llm)

[9.2 Consent/User Approval Fatigue	53](#9.2-consent/user-approval-fatigue)

[10 Resource Management/Rate Limiting Absence	54](#10-resource-management/rate-limiting-absence)

[10.1 Resource exhaustion and denial of wallet	54](#10.1-resource-exhaustion-and-denial-of-wallet)

[10.2 Payload Limit/DoS	55](#10.2-payload-limit/dos)

[11 Supply Chain and Lifecycle Security Failures	56](#11-supply-chain-and-lifecycle-security-failures)

[11.1 Shadow MCP Servers (Duplicate)	56](#11.1-shadow-mcp-servers-\(duplicate\))

[11.2 Supply Chain Compromise (Duplicate)	58](#11.2-supply-chain-compromise-\(duplicate\))

[12 Insufficient Logging, Monitoring, and Auditability	60](#12-insufficient-logging,-monitoring,-and-auditability)

[12.1 Invisible Agent Activity	60](#12.1-invisible-agent-activity)

[12.2 Lack of Observability	60](#12.2-lack-of-observability)

# Introduction

TBD

# Scope

This AI Tool security certification encompasses a diverse range of integration methods, focusing on the security posture of the interface layer between the AI Agent and AI Tool, along with the AI Tool and the Web/Mobile Application. The scope includes Model Context Protocol (MCP) Servers, which act as bridges to web-based applications, as well as local interfaces residing on host machines. Furthermore, Mobile AI Tools—specifically mobile applications that implement AI-driven interfaces similar to MCP architectures—are explicitly included. This multi-platform approach ensures that regardless of whether the tool is web-based, local, or mobile, the certification validates the security of the specific conduit through which AI interactions flow.

To maintain a rigorous and fair evaluation, the certification boundaries are strictly confined to the components under the direct control of the AI Tool developer. Consequently, the underlying platform hosting the tool and the external AI Agent itself are considered out of scope. For instance, while a requirement might mandate that an AI Tool generates comprehensive logs of all agent interactions, the security of the persistent storage or the centralized logging infrastructure is excluded, as these are managed by the host platform. All testing and compliance criteria are directed solely at the tool’s logic, its communication protocols, and its internal handling of data, ensuring the assessment remains decoupled from the infrastructure it inhabits.

![][image1]

AI Tools may be deployed in several different environments and provide connectivity to local resources, remote resources, or any combination of these. Furthermore, an AI tool may be a stand alone application (Such as a MCP server running locally on a user’s machine), or embedded into a monolithic application (such as App Functions added to a mobile application). In all cases, this specification shall cover the AI Tool portion of the application. Other specifications, such as the Mobile Application Profile or the Web Application Profile shall apply to the remainder of the developer’s application.

![][image2]

# Relationship To CoSAI Model Context Protocol (MCP) Security

The following security specification and testing guide is based upon the Model Context Protocol (MCP) Security paper published by CoSAI. Each threat category includes one or more MCP or conventional security (CS) threats. All threats follow the same numbering convention as the MCP security paper, thus MCP-1 references either the MCP specific or MCP contextualized threat \#1. CS-16 refers to the Conventional Security threat 16\. For each threat, the App Defense Alliance created a set of requirements and audit test cases. For some conventional security threats, the existing Mobile Application Security profile or the Web Application Security Profile may be referenced.

Both static code inspection and dynamic application test cases are defined. Sample prompts are provided for each static test case, which could be used for automated testing. However, detailed testing requirements and acceptance criteria are defined in the AI Tool Testing Guide.

| Threat Category                                                                                                          | AI Tool Specific Threat                                                                                                                                                                                                                    | Conventional Security Threat                                                                                                                                                                                                                                                                                                                                                                                                                    |
| :----------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [1](#1-improper-authentication-and-identity-management): Improper Authentication and Identity Management                 | [1.1](#1.1-identity-spoofing): Identity Spoofing <br>[1.2](#1.2-confused-deputy-\(oauth-proxy\)): Confused Deputy (OAuth Proxy)                                                                                                            | [1.3](#1.3-credential-theft/token-theft): Credential Theft/Token Theft <br>[1.4](#1.4-replay-attacks/session-hijacking): Replay Attacks/Session Hijacking<br>[1.5](#1.5-oauth/legacy-auth-weaknesses): OAuth/Legacy Auth Weaknesses <br>[1.6](#1.6-session-token-leakage): Session Token Leakage                                                                                                                                                |
| [2](#2-missing-or-improper-access-control): Missing or Improper Access Control                                           | [2.1](#2.1-insecure-human-in-the-loop): Insecure Human-in-the-Loop  <br>[2.2](#2.2-improper-multitenancy): Improper Multitenancy                                                                                                           | CS-8: Privilege Escalation<br>[2.4](#2.4-excessive-permissions/overexposure): Excessive Permissions/Overexposure                                                                                                                                                                                                                                                                                                                                |
| [3](#3-input-validation/sanitization-failures): Input Validation/Sanitization Failures                                   |                                                                                                                                                                                                                                            | [3.1](#3.1-command-injection): Command Injection <br>[3.2](#3.2-file-system-exposure/path-traversal-\(duplicate\)): File System Exposure/Path Traversal <br>[3.3](#3.3-insufficient-integrity-checks): Insufficient Integrity Checks                                                                                                                                                                                                            |
| [4](#4-data/control-boundary-distinction-failure): Data/Control Boundary Distinction Failure                             | [4.1](#4.1-tool-definition-poisoning): Tool Poisoning <br>[4.2](#4.2-full-schema-poisoning): Full Schema Poisoning<br>[4.3](#4.3-resource-content-poisoning): Resource Content Poisoning<br>[4.4](#4.4-prompt-injection): Prompt Injection | [4.5](#heading=h.eqisat9des8o): Command Injection                                                                                                                                                                                                                                                                                                                                                                                               |
| [5](#5-inadequate-data-protection-and-confidentiality-controls): Inadequate Data Protection and Confidentiality Controls |                                                                                                                                                                                                                                            | [5.1](#5.1-data-exfiltration-&-corruption): Data Exfiltration & Corruption <br>[5.2](#5.2-file-system-exposure/path-traversal-\(duplicate\)): File System Exposure/Path Traversal                                                                                                                                                                                                                                                               |
| [6](#6-missing-integrity/verification-controls): Missing Integrity/Verification Controls                                 | [6.1](#6.1-resource-content-poisoning): Resource Content Poisoning <br>[6.2](#6.2-typosquatting/confusion-attacks): Typosquatting / Confusion Attacks <br>[6.3](#6.3-shadow-mcp-servers): Shadow MCP Servers                               | [6.4](#6.4-supply-chain-compromise-and-privileged-host-base-attacks): Supply Chain Compromise and Privileged host-base Attacks                                                                                                                                                                                                                                                                                                                  |
| [7](#7-session-and-transport-security-failures): Session and Transport Security Failures                                 | [7.1](#7.1-man-in-the-middle-\(mitm\)): Man-in-the-Middle (MITM)                                                                                                                                                                           | [7.3](#7.3-unrestricted-network-access): Unrestricted Network Access <br>[7.4](#7.4-protocol-security-gaps): Protocol Security Gaps <br>[7.5](#7.5-insecure-descriptor-handling): Insecure Descriptor Handling <br>[7.2](#7.2-insufficient-integrity-checks-\(duplicate\)): Insufficient Integrity Checks <br>[7.6](#7.6-csrf-protection-missing): CSRF Protection Missing <br>[7.7](#7.7-cors/origin-policy-bypass): CORS/Origin Policy Bypass |
| [8](#8-network-binding/isolation-failures): Network Binding/Isolation Failures                                           | [8.1](#8.1-shadow-mcp-servers-\(duplicate\)): Shadow MCP Servers <br>[8.2](#8.2-improper-multitenancy): Improper Multitenancy                                                                                                              | [8.4](#8.4-malicious-command-execution): Malicious Command Execution <br>[8.5](#8.5-dependency/update-attack): Dependency/Update Attack <br>[8.3](#8.3-unrestricted-network-access-\(duplicate\)): Unrestricted Network Access                                                                                                                                                                                                                  |
| [9](#9-trust-boundary-and-privilege-design-failures): Trust Boundary and Privilege Design Failures                       | [9.1](#9.1-overreliance-on-the-llm): Overreliance on the LLM <br>[9.2](#9.2-consent/user-approval-fatigue): Consent/User Approval Fatigue                                                                                                  |                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [10](#10-resource-management/rate-limiting-absence): Resource Management/Rate Limiting Absence                           | [10.1](#10.1-resource-exhaustion-and-denial-of-wallet): Resource exhaustion and denial of wallet                                                                                                                                           | [10.2](#10.2-payload-limit/dos): Payload Limit/DoS                                                                                                                                                                                                                                                                                                                                                                                              |
| [11](#11-supply-chain-and-lifecycle-security-failures): Supply Chain and Lifecycle Security Failures                     | [11.1](#11.1-shadow-mcp-servers-\(duplicate\)): Shadow MCP Servers                                                                                                                                                                         | [11.2](#11.2-supply-chain-compromise-\(duplicate\)): Supply Chain Compromise                                                                                                                                                                                                                                                                                                                                                                    |
| [12](#12-insufficient-logging,-monitoring,-and-auditability): Insufficient Logging, Monitoring, and Auditability         | [12.1](#12.1-invisible-agent-activity): Invisible Agent Activity                                                                                                                                                                           | [21.2](#12.2-lack-of-observability): Lack of Observability                                                                                                                                                                                                                                                                                                                                                                                      |

# References

* [CSA Monitoring & Operational Security](https://modelcontextprotocol-security.io/ttps/monitoring-operational-security/)  
* [OWASP MCP Top 10](https://github.com/OWASP/www-project-mcp-top-10/tree/main/2025)  
* [CoSAI MCP Security](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md)  
* 

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

# Definitions

| Term             | Definition |
| :--------------- | :--------- |
| sensitive action |            |
| AI model         |            |

# 1 Improper Authentication and Identity Management
## 1.1 Identity Spoofing

Weak or misconfigured authentication in MCP deployments could allow attackers to impersonate legitimate clients or the agents acting on their behalf, corrupting audit trails or gaining unauthorized access to server resources.


## 1.2 Confused Deputy (OAuth Proxy)

Attackers exploit misconfigured roles, credentials, ACLs, trust relationships, or flawed delegation logic to gain elevated permissions and access unauthorized resources. In MCP deployments, this includes privilege escalation, as well as attacks that leverage the MCP server's intermediary role in multi-user token delegation. For example, confused deputy attacks can occur when an MCP server acting as an OAuth proxy fails to properly validate authorization context—allowing attackers to manipulate the server into using another user's credentials to perform privileged operations.

## 1.3 Credential Theft/Token Theft

Attackers exploit insecure storage, handling, or transmission of secrets (OAuth tokens, API keys, credentials), enabling impersonation, unauthorized access, or privilege escalation.

## 1.4 Replay Attacks/Session Hijacking 

Attackers intercept, reuse, or hijack authentication tokens or session identifiers, impersonating legitimate users or agents and executing unauthorized actions.


## 1.5 OAuth/Legacy Auth Weaknesses

Use of outdated, weak, or pass-through authentication and authorization (e.g., basic auth, static API keys) exposes systems to impersonation, privilege misuse, and poor accountability.

## 1.6 Session Token Leakage

Exposure or insecure handling of session tokens across MCP components leads to unauthorized access, impersonation, or session hijacking.


# 2 Missing or Improper Access Control 

## 2.1 Insecure Human-in-the-Loop

Missing or insufficient human-in-the-loop consent checks can allow an MCP server to take risky actions not authorized by the user.

Discussion Points:

1. I believe most agents will provide tool approvals as they also control the user interface.  
2. It would be nice to require approval for sensitive (or non-routine) operations, but I am not sure if the agents will implement these controls  
3. The MCP protocol does support [elicitations](https://modelcontextprotocol.io/specification/draft/client/elicitation), but it is unclear if this will pop up every time a user hits a function with the elicitation and thus could lead to fatigue.  
   

### 2.1.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method  | Description |
| :------ | :---------- |
| Static  |             |
| Dynamic |             |

#### Comments

| Scope  | Comment |
| :----- | :------ |
| Local  |         |
| Mobile |         |
| Remote |         |

## 2.2 Improper Multitenancy

An attacker may exploit weak isolation between tenants or users, such as shared memory between processes, sessions, or secrets and credentials, to access or manipulate unauthorized data.


## 2.3 Confused Deputy (OAuth Proxy) (Duplicate)

Attackers exploit misconfigured roles, credentials, ACLs, trust relationships, or flawed delegation logic to gain elevated permissions and access unauthorized resources. In MCP deployments, this includes privilege escalation, as well as attacks that leverage the MCP server's intermediary role in multi-user token delegation. For example, confused deputy attacks can occur when an MCP server acting as an OAuth proxy fails to properly validate authorization context—allowing attackers to manipulate the server into using another user's credentials to perform privileged operations.

### 2.3.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method  | Description |
| :------ | :---------- |
| Static  |             |
| Dynamic |             |

#### Comments

| Scope  | Comment |
| :----- | :------ |
| Local  |         |
| Mobile |         |
| Remote |         |

## 2.4 Excessive Permissions/Overexposure 

AI agents, MCP servers, or tools are granted more privileges than necessary, increasing risk of abuse or compromise in case of attack or misconfiguration.

### 2.4.1 Req TBD

#### Description

TBD

#### 

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 3 Input Validation/Sanitization Failures 

## 3.1 Command Injection

Unvalidated or unsanitized user inputs, prompts, or tool arguments lead to execution of unauthorized system commands, resulting in data compromise or system takeover.

### 3.1.1 Req TBD

#### Description

#### Rationale

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 3.2 File System Exposure/Path Traversal (Duplicate)

Improper validation of file paths or tool arguments enables access to or exfiltration of files outside intended directories, exposing credentials and sensitive data

### 3.2.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 3.3 Insufficient Integrity Checks

Absence of signature or integrity validation on MCP messages and responses enables replay, spoofing, or delivery of poisoned results.

### 3.3.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 4 Data/Control Boundary Distinction Failure

## 4.1 Tool Definition Poisoning

*Tool poisoning* is an indirect form of Prompt Injection (MCP-T4-05) in which [Tool](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#protocol-messages) metadata, configuration, or descriptors have been modified in order to provide new instructions or other manipulation to make an AI model act in an unintended fashion. Because the AI model implicitly trusts the context and data returned by its connected tools, the attacker can inject malicious payloads or hidden instructions (a form of Indirect Prompt Injection) into the tool's response. When the AI ingests this compromised data, it processes the Tool metadata as legitimate instructions.

#### Framework Mapping

* [OWASP MCP03:2025 Tool Poisoning](https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning)  
* [CoSAI WS4: Designing Agentic Systems: Input/Instruction Boundary Distinction Failures](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md#mcp-t4-inputinstruction-boundary-distinction-failure)

### 4.1.1 TBD

#### Description

TBD
#### Rationale

TBD
#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope  | Comment |
| :----- | :------ |
| Local  |         |
| Mobile |         |
| Remote |         |


## 4.2 Full Schema Poisoning

Attackers compromise entire tool schema definitions at the structural level, injecting hidden parameters, altered return types, or malicious default values that affect all subsequent tool invocations while maintaining apparent compatibility and evading detection by appearing legitimate to monitoring systems.

Unlike Tool Poisoning (MCP-2): Goes beyond poisoning individual tool metadata to compromise the entire structural definition and type system of tools.

### TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method  | Description |
| :------ | :---------- |
| Static  |             |
| Dynamic |             |

#### Comments

| Scope  | Comment |
| :----- | :------ |
| Local  |         |
| Mobile |         |
| Remote |         |


## 4.3 Resource Content Poisoning

Attackers embed hidden malicious instructions within data sources (databases, documents, API responses) that MCP servers retrieve and provide to LLMs, causing the poisoned content to execute as commands when processed, effectively achieving persistent prompt injection through trusted data channels rather than direct user input. Unlike Prompt Injection (MCP-12): Malicious instructions are embedded in backend data sources, not user-provided prompts. Unlike Tool Poisoning (MCP-2): Poisons the actual data/content retrieved by tools, not the tool definitions themselves. This attack surface may be expanded with transitive or composed MCP server calls.

### 4.3.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 4.4 Prompt Injection

LLMs have insufficient boundaries between input data and instructions. Attackers craft malicious inputs to manipulate LLMs or MCP components to perform unintended or harmful actions such as data exfiltration, privilege escalation, or unauthorized command execution. These malicious instructions can be sent directly to the LLM (e.g., via Sampling or when the MCP tool uses its own LLM) or indirectly by embedding instructions in prompts, resources, or tool metadata. This threat exists whenever untrusted input can reach the LLM's context window.

### 4.4.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 5 Inadequate Data Protection and Confidentiality Controls 

## 5.1 Data Exfiltration & Corruption

Attackers leverage MCP components to steal or corrupt sensitive data, reroute messages, or manipulate outputs, often via compromised servers or poisoned tools.

### 5.1.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 5.2 File System Exposure/Path Traversal (Duplicate)

Improper validation of file paths or tool arguments enables access to or exfiltration of files outside intended directories, exposing credentials and sensitive data.

### 5.2.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### 

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 6 Missing Integrity/Verification Controls 

## 6.1 Resource Content Poisoning

Attackers embed hidden malicious instructions within data sources (databases, documents, API responses) that MCP servers retrieve and provide to LLMs, causing the poisoned content to execute as commands when processed, effectively achieving persistent prompt injection through trusted data channels rather than direct user input. Unlike Prompt Injection (MCP-12): Malicious instructions are embedded in backend data sources, not user-provided prompts. Unlike Tool Poisoning (MCP-2): Poisons the actual data/content retrieved by tools, not the tool definitions themselves. This attack surface may be expanded with transitive or composed MCP server calls.

### 6.1.1 Req TBD

#### Description

#### Rationale

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### 

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 6.2 Typosquatting/Confusion Attacks 

Malicious actors create MCP servers or tools with names/descriptions similar to legitimate ones, tricking clients or AI agents into invoking harmful tools due to naming confusion or LLM hallucination. The MCP specification provides guidance on making tool origins and inputs visible to users and recommends human-in-the-loop approval for tool invocations (User Interaction Model), but consent fatigue—where users reflexively approve prompts without careful review—can significantly undermine these protections.

### 6.2.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 6.3 Shadow MCP Servers

Unauthorized, unmonitored, or hidden MCP server instances create blind spots, increasing risk of undetected compromise and covert data exfiltration. These servers pose governance and compliance risks and may be malicious or easily compromised.

### 6.3.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 6.4 Supply Chain Compromise and Privileged host-base Attacks

Malicious or compromised MCP servers, dependencies, or packages are introduced into the environment, enabling attackers to execute arbitrary code, exfiltrate data, or persist within the infrastructure.

### 6.4.1 Req TBD

#### Description

TBD 

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 7 Session and Transport Security Failures

## 7.1 Man-in-the-Middle (MITM)

Exploiting insecure network transport (lack of TLS, improper certificate validation, or missing mutual authentication) to intercept, modify, or reroute data between MCP components, enabling data theft or manipulation.

### 7.1.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 7.2 Insufficient Integrity Checks (Duplicate) 

Absence of signature or integrity validation on MCP messages and responses enables replay, spoofing, or delivery of poisoned results.

### 7.2.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 7.3 Unrestricted Network Access

MCP servers or clients with open outbound or inbound network access can download malicious payloads, exfiltrate data, or connect to command-and-control infrastructure. Malicious or compromised MCP servers allow attackers to move laterally using stored credentials and exploiting poor network segmentation and isolation.

### 7.3.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### 

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 7.4 Protocol Security Gaps

Weaknesses in MCP protocol/transport layers (e.g., missing payload limits, no TLS, unauthenticated requests) enable DoS, spoofing, or unauthorized command execution.

### 7.4.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 7.5 Insecure Descriptor Handling

Improper management of transport descriptors (e.g., stdio) allows attackers to hijack or interfere with data streams and process communications.

### 7.5.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 7.6 CSRF Protection Missing

Lack of Cross-Site Request Forgery (CSRF) controls on HTTP/SSE transports enables attackers to forge or replay unauthorized requests.

### 7.6.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

### 7.7 CORS/Origin Policy Bypass

Missing or weak cross-origin policies allow unauthorized data leaks via cross-origin resource sharing (CORS) in browser-based or web transports.

### 7.7.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### 

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 8 Network Binding/Isolation Failures

## 8.1 Shadow MCP Servers (Duplicate)

Unauthorized, unmonitored, or hidden MCP server instances create blind spots, increasing risk of undetected compromise and covert data exfiltration. These servers pose governance and compliance risks and may be malicious or easily compromised.

### 8.1.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 8.2 Improper Multitenancy

An attacker may exploit weak isolation between tenants or users, such as shared memory between processes, sessions, or secrets and credentials, to access or manipulate unauthorized data.

### 8.2.1 Req TBD

#### Description

#### Rationale

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 8.3 Unrestricted Network Access (Duplicate)

MCP servers or clients with open outbound or inbound network access can download malicious payloads, exfiltrate data, or connect to command-and-control infrastructure. Malicious or compromised MCP servers allow attackers to move laterally using stored credentials and exploiting poor network segmentation and isolation.

### 8.3.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 8.4 Malicious Command Execution

Compromised or rogue MCP servers execute arbitrary or malicious payloads (ransomware, data manipulation) triggered by crafted prompts or files.

### 

### 8.4.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 8.5 Dependency/Update Attack

Attackers compromise MCP dependencies or update channels (e.g., “rug pull” attacks), swapping benign code for malicious versions after trust is established. MCP servers may also introduce new capabilities (e.g., tools or prompts) that have not been vetted or approved for use.

### 8.5.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 9 Trust Boundary and Privilege Design Failures

## 9.1 Overreliance on the LLM

MCP server developers may implement overly permissive tools, assuming the LLM will invoke them correctly and safely. However, model-level controls (trained refusals, safety classifiers, etc.) are not ironclad—even capable models can be manipulated through prompt injection, make errors in judgment, or be replaced with weaker models that lack equivalent safeguards.

### 9.1.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### 

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 9.2 Consent/User Approval Fatigue

Flooding users with excessive consent or permission prompts, causing habituation and leading to blind approval of potentially dangerous or malicious actions.

### 9.2.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### 

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 10 Resource Management/Rate Limiting Absence

## 10.1 Resource exhaustion and denial of wallet

Attackers trigger an excessive number of LLM, tool, or other API calls leading to unexpected costs or resource exhaustion and denial of service

### 10.1.1. Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

## 10.2 Payload Limit/DoS

Unrestricted payload sizes or recursion depth in protocols enable denial-of-service via resource exhaustion.

### 10.2.1 Req TBD

#### Description

TBD

#### Rationale

TBD

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local |  |
| Mobile |  |
| Remote |  |

# 11 Supply Chain and Lifecycle Security Failures

## 11.1 Shadow MCP Servers (Duplicate) 

Unauthorized, unmonitored, or hidden MCP server instances create blind spots, increasing risk of undetected compromise and covert data exfiltration. These servers pose governance and compliance risks and may be malicious or easily compromised.


## 11.2 Supply Chain Compromise (Duplicate) 

Malicious or compromised MCP servers, dependencies, or packages are introduced into the environment, enabling attackers to execute arbitrary code, exfiltrate data, or persist within the infrastructure.

### 11.2.1 TBD

#### Description

TBD
#### Rationale

TBD
#### Audit


| Audit Component | Verification Method                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| :-------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|                 |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |



#### Comments

| Scope  | Comment  |
| :----- | :------- |
| Local  | In scope |
| Mobile | In scope |
| Remote | In scope |

# 12 Insufficient Logging, Monitoring, and Auditability

## 12.1 Invisible Agent Activity

Agents or servers operate covertly, mimicking valid workflows but executing malicious or unauthorized actions without detection.

Note: The controls for this threat are combined with CS-24: Lack of Observability, MCP-T1: Improper Authentication and Identity Management and the ADA Agent Security Specification.

## 12.2 Lack of Observability

Insufficient logging, monitoring, or attribution across MCP actions hides malicious or unintended activity, hindering detection and response.

### 12.2.1 Implement comprehensive logging using structured logging formats

#### Description

The system must capture all significant security and operational events—including authentication attempts, authorization decisions, tool/function calls, AI model inputs/outputs, and system state changes. These logs must be generated in a machine-readable, structured format (such as JSON) rather than unstructured plain text.

#### Rationale

In agentic and MCP-based architectures, the complexity of interactions between users, hosts, and servers makes traditional grep-based log analysis insufficient. Structured logging allows automated security orchestration, automation, and response (SOAR) tools and SIEMs to parse and correlate events in real-time. This visibility is critical for detecting anomalous patterns, such as indirect prompt injection, which are often only visible when analyzing the metadata of model interactions and tool execution.

#### Audit

| Method  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| :------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Static  | **Verify Structured Format:** Identify all logging statements (e.g., `console.log`, `logger.info`, `winston`) and confirm they utilize a structured format like JSON objects or key-value pairs rather than simple string concatenation. <br><br>**Identify External Tool Execution Paths:** Review the code for AI tool integration and MCP server implementations to identify all functions that execute external tools or access data resources. <br><br>**Check Telemetry Coverage:** Verify that each execution path includes a logging call capturing the identity of the calling agent, the specific tool requested, the input parameters, and the success/failure status. <br><br>**Inspect Metadata and Correlation:** Confirm that critical events (tool execution, API requests, and authentication logic) are logged with relevant metadata, including timestamps and correlation IDs. <br><br>**Audit for Reasoning Traces:** Verify if the "Intent" of the agent is logged to provide an auditable "Reasoning Trace" explaining why an agent took a specific action. <br><br>**Flag Silent Failures:** Identify and flag any instances where a tool is invoked without telemetry or where error states are handled "silently" without an audit entry. <br><br>**Flag Unstructured Calls:** Identify and flag any instances of "print" statements or unstructured logger calls used for operational data. |
| Dynamic | **Generate Agent Activity:** Interact with the system through the AI agent to trigger various tool calls, API requests, and authentication events. <br><br>**Validate Log Capture:** Inspect the generated logs to confirm that the interaction was captured in its entirety. <br><br>**Confirm Machine-Readability:** Verify that the output logs are valid structured data (e.g., valid JSON) that can be parsed by automated security tools.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

#### 

#### Comments

| Scope  | Comment                                                             |
| :----- | :------------------------------------------------------------------ |
| Local  | In scope                                                            |
| Mobile | In scope                                                            |
| Remote | Would this be in scope as the user may not have access to the logs? |

### 12.2.2 Protect Sensitive Data in Logs 

#### Description

All logging mechanisms must include automated redaction or masking for sensitive information. This includes, but is not limited to, Personally Identifiable Information (PII), authentication tokens, API keys, passwords, and sensitive model outputs that may contain proprietary or private data.

#### Rationale

Logs are frequently replicated across multiple systems, stored in centralized repositories, and accessed by various personnel, making them a high-value target for attackers. According to OWASP and COSAI standards, failure to scrub sensitive data from telemetry can lead to accidental data breaches and compliance violations. Because LLMs and agents may process sensitive data as part of their prompt context, it is vital to ensure that this data does not leak into the persistent logging layer during the monitoring process.

#### Audit

| Method  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| :------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Static  | **Identify Sensitive Variables:** Search the codebase for variables and keys that typically contain sensitive information, such as `password`, `token`, `apiKey`, `secret`, `email`, `ssn`, `authorization`, or `bearer`. <br><br>**Trace Logging Sinks:** Identify all locations where logging functions (e.g., `console.log`, `logger.info`, `winston`) are called. Verify if the sensitive variables identified above are passed directly into these functions. <br><br>**Verify Redaction Middleware:** Confirm the application utilizes a centralized redaction middleware or a dedicated sanitization helper function designed to scrub or mask inputs before they reach the logging layer. <br><br>**Check Raw Data Logging:** Inspect code to ensure that raw user prompts or raw API responses—which may contain PII or proprietary data—are not logged without an explicit filtering mechanism. <br><br>**Verify Identity Masking:** Confirm that specific User IDs or unique PII identifiers are not written to the logs in plain text. |
| Dynamic | **Generate Sensitive Telemetry:** Interact with the AI Tool through the agent and perform actions designed to generate sensitive data (e.g., entering a mock password, providing an API key, or sharing PII). <br><br>**Inspect Log Output:** Access the generated logs and verify that any sensitive data entered during the interaction has been successfully redacted, masked, or filtered out.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

#### Comments

| Scope  | Comment                                                             |
| :----- | :------------------------------------------------------------------ |
| Local  | In scope                                                            |
| Mobile | In scope                                                            |
| Remote | Would this be in scope as the user may not have access to the logs? |
|        |                                                                     |
