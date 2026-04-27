# AI Tool Security Specification

Version 0.1 3/9/26

# Revision History

| Version | Date   | Description                                                        |
| :------ | :----- | :----------------------------------------------------------------- |
| 0.1     | 3/9/26 | Initial document outline based on CoSAI MCP security paper threats |
| 0.2     | 3/26/26 | Added requirements for section 1 (Authentication) and updates for section 11 (Supply Chain) |
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

* Debdutta Guha(Google)  
* Nic Watson (Google)  
* Abhiraman Gcl (Google)  
* Daniel Bond (Meta)  
* Tony Balkan (Microsoft)  
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

### 1.1.1 Mandatory Client-Server Transport Authentication

#### Description

The MCP server must verify the identity of the MCP host (client) before executing any tools or providing resources. For remote connections (SSE), this must involve strong authentication (e.g., OAuth2, dynamically rotated API Keys, or mTLS). For local connections (Stdio), the server must ensure it is only accepting input from the authorized parent process.

#### Rationale

Without identity verification, an attacker could impersonate a legitimate AI agent or host to trigger sensitive tools (e.g., "delete\_database") or extract proprietary data.

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  **Identify Transport Setup:** Search the MCP server initialization and transport setup code to determine the communication method (e.g., SSE, Stdio). <br><br>**Verify Identity Validation:** Identify where the server validates the 'Authorization' header or client certificates during the handshake or request phase. <br><br>**Check Cryptographic Binding:** Verify that there is a cryptographic binding between the validated identity and the established session to prevent hijacking. <br><br>**Flag Authentication Gaps:** Flag any server implementation that executes tool calls or provides resources without an explicit, successful authentication check.  |
| Dynamic | **Attempt Unauthenticated Access:** Try to connect to the MCP server or trigger a tool call without providing any authentication credentials to ensure the request is rejected. <br><br>**Test Invalid Credentials:** Provide expired, malformed, or incorrect tokens/keys to verify that the server correctly denies access. <br><br>**Verify Session Persistence:** Ensure that once a session is authenticated, the identity remains consistent and cannot be swapped mid-session.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | Out of scope |
| Mobile | Out of scope |
| Remote | In Scope |

## 1.2 Confused Deputy (OAuth Proxy)

Attackers exploit misconfigured roles, credentials, ACLs, trust relationships, or flawed delegation logic to gain elevated permissions and access unauthorized resources. In MCP deployments, this includes privilege escalation, as well as attacks that leverage the MCP server's intermediary role in multi-user token delegation. For example, confused deputy attacks can occur when an MCP server acting as an OAuth proxy fails to properly validate authorization context—allowing attackers to manipulate the server into using another user's credentials to perform privileged operations.

### 1.2.1 Scoped Authorization and User Context Propagation

#### Description

The MCP server must not rely solely on its own service-level credentials to access downstream resources. It must require and validate "User-in-the-loop" context or scoped tokens passed through the MCP request metadata to ensure the end-user has the authority to perform the requested action.

#### Rationale

An MCP server acts as a deputy. If it uses a global admin key to fulfill a request from a low-privilege user, it becomes a 'confused deputy,' allowing the user to escalate privileges via the AI tool.

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  **Analyze Tool Handlers:** Identify and examine all `callTool` handler functions within the codebase. <br><br>**Verify Token Usage:** Check if the tool logic relies on a hardcoded "Global Admin" or service-level token to access external APIs. <br><br>**Verify Context Extraction:** Confirm the code extracts a user-specific identifier or session token from the metadata or parameters of the MCP request. <br><br>**Check Authorization Logic:** Verify that the extracted user context is used to authorize access to specific downstream resources.  |
| Dynamic | **Test Privilege Separation:** Attempt to access a resource belonging to User A while authenticated as User B to ensure the request is denied. <br><br>**Verify Scoped Execution:** Trigger a tool call and inspect the downstream API request to confirm it uses a scoped user token rather than a global administrative key. <br><br>**Validate Metadata Propagation:** Ensure that user-in-the-loop context passed through MCP request metadata is correctly honored by the server before executing sensitive actions. |

### 1.2.2: Mandatory Cryptographic Validation of User Context

#### Description 

The MCP server must verify the cryptographic signature of identity tokens or user context metadata provided by the MCP host (Agent) (when possible). If the tool interacts with external third-party APIs (downstream resources), it must utilize an "On-Behalf-Of" flow or exchange the validated user token for a scoped access token. The server shall reject any request where the user context is provided as a simple, unverified string (e.g., a plain `user_id` field).

#### Rationale 

If a developer's tool simply trusts a `user_id` passed by the Agent, a compromised or "confused" Agent could provide "User A's" ID while executing "User B's" request. By requiring cryptographic validation (e.g., verifying a JWT signed by a trusted IdP), the Developer ensures that the user context is authentic and that the Agent cannot escalate privileges by misrepresenting the user.

#### Audit

| Method | Description |
| :---- | :---- |
| Static | **Identify Token Validation Logic:** Search the codebase for JWT or identity token parsing logic. Verify that the implementation uses a library to check signatures (e.g., `jwt.verify()`) against a trusted public key or JWKS endpoint. <br><br>**Check Downstream Flow:** Inspect outbound API calls to ensure they utilize the validated user context to acquire "On-Behalf-Of" tokens rather than using the server's own administrative credentials. <br><br>**Flag Unverified Identifiers:** Identify and flag any tool handlers that accept user identifiers (like `email` or `uuid`) as plain parameters without verifying an accompanying cryptographic signature  |
| Dynamic | **Submit Unsigned/Malformed Tokens:** Attempt to trigger a tool call using a token with the signature removed or a header set to `"alg": "none"`. Verify the server returns an authentication error. <br><br>**Payload Tampering:** Provide a validly signed token but modify the `user_id` within the payload. Verify the cryptographic check fails and the request is rejected. <br><br>**Verify Token Exchange:** Intercept downstream traffic to confirm that the MCP server is passing a scoped user-specific token to the final resource, rather than its own service-level key. |

##### Comments {#comments}

| Scope | Comment |
| :---- | :---- |
| Local | In Scope |
| Mobile | In Scope |
| Remote | In Scope |

## 1.3 Credential Theft/Token Theft

Attackers exploit insecure storage, handling, or transmission of secrets (OAuth tokens, API keys, credentials), enabling impersonation, unauthorized access, or privilege escalation.

### 1.3.1 Externalized Secret Management

#### Description

MCP servers must never contain hardcoded credentials, API keys, or private keys within the source code or configuration files. All sensitive secrets must be retrieved at runtime from an environment variable or a dedicated Secret Management Service (e.g., AWS Secrets Manager, HashiCorp Vault). Developers shall have a policy and procedure in place to periodically rotate sensitive secrets and have revocation protocols in place if a breach is detected.

#### Rationale

MCP servers are often lightweight and distributed; hardcoded secrets are easily leaked through version control or container image inspection, leading to full compromise of the connected tools.

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  **Scan for Hardcoded Secrets:** Scan the codebase for regex patterns matching high-entropy strings, API keys (e.g., `sk-`, `ghp_`), and hardcoded passwords. <br><br>**Verify Client Initialization:** Check that all external service clients (e.g., OpenAI, Database, Slack) are initialized using `process.env` or a specific configuration provider. <br><br>**Flag String Literals:** Identify and flag any string literals used directly as credentials within the source code or configuration files. <br><br>**Review Rotation Policies:** Verify the existence of documented policies and procedures for periodically rotating sensitive secrets. <br><br>**Confirm Revocation Protocols:** Ensure there are established protocols for immediate secret revocation if a breach is detected.  |
| Dynamic | **Verify Runtime Retrieval:** Confirm that the MCP server successfully retrieves sensitive secrets from an environment variable or a dedicated Secret Management Service at runtime. <br><br>**Validate Secret Isolation:** Ensure that sensitive credentials are not exposed in the process environment beyond what is necessary for execution.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In scope |
| Mobile | In scope |
| Remote | In scope |

### 1.3.2 Secure Downstream Transport

#### Description

The AI Tool must ensure that all communications with downstream resources (e.g., internal APIs, databases, or third-party services) that involve the transmission of secrets are conducted over encrypted channels (TLS 1.3 or higher). All security sensitive data shall be protected when in flight. For example, tokens shall not be sent in HTTP headers.

#### Rationale

Credential theft often occurs during transit or through the reuse of intercepted long-lived keys. Ensuring encrypted transport mitigates interception risks during the "handling" phase.

#### Audit

| Method | Description |
| :---- | :---- |
| Static | **Identify Downstream Clients:** Search the codebase for all outgoing network clients (e.g., axios, fetch, requests, pg-client). <br><br>**Verify TLS Enforcement:** Confirm that connection strings and URL constructions strictly use https:// or equivalent secure protocols (e.g., sslmode=require for databases). <br><br>**Protect Data in Transit:** Audit the codebase for any transmission of sensitive information (e.g., auth tokens) and confirm robust encryption is enforced. |
| Dynamic | **Monitor Outbound Traffic:** Use a network interception tool (e.g., Wireshark or a service mesh proxy) to verify that secrets (Authorization headers, API keys) are never sent over unencrypted (HTTP) connections. |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In scope |
| Mobile | Out of scope |
| Remote | In scope (When MCP server is not integrated with Web App) |

## 1.4 Replay Attacks/Session Hijacking 

Attackers intercept, reuse, or hijack authentication tokens or session identifiers, impersonating legitimate users or agents and executing unauthorized actions.

### 1.4.1 Message Freshness and Session Binding

#### Description

For persistent or stateful transports (e.g., SSE, WebSockets), the MCP server must implement session timeouts and validate message timestamps or nonces if provided by the client. The server must terminate sessions that exceed a defined period of inactivity.

#### Rationale

If an attacker captures a valid MCP tool-call request, they could "replay" it later to trigger the tool again (e.g., a "pay\_invoice" tool) even if the original session has ended.

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  **Examine Session Management:** Review the session management logic within the MCP transport layer (e.g., SSE, WebSockets). <br><br>**Identify Expiration Timers:** Verify the implementation of an expiration timer (TTL) for active sessions to ensure they are terminated after a defined period of inactivity. <br><br>**Check Freshness Validation:** Confirm the server validates 'timestamp' or 'nonce' fields within incoming JSON-RPC objects to prevent processing stale or duplicate requests.  |
| Dynamic | **Verify Inactivity Timeouts:** Establish a session and remain inactive to verify the server automatically terminates the connection after the defined timeout period. <br><br>**Test Replay Resistance:** Attempt to capture and resend a previously successful JSON-RPC tool-call request to ensure the server rejects the duplicate based on an expired timestamp or used nonce. <br><br>**Validate Session Termination:** Ensure that once a session is terminated or timed out, any subsequent requests using that session identifier are strictly rejected.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In scope |
| Mobile | In scope |
| Remote | In scope |

## 1.5 OAuth/Legacy Auth Weaknesses

Use of outdated, weak, or pass-through authentication and authorization (e.g., basic auth, static API keys) exposes systems to impersonation, privilege misuse, and poor accountability.

### 1.5.1 Strict Redirect URI and State Validation

#### Description

If the MCP server facilitates OAuth flows for tool access, it must strictly validate Redirect URIs against a pre-defined allowlist and enforce the use of the state parameter to prevent Cross-Site Request Forgery (CSRF). Legacy authentication methods (Basic Auth over HTTP) are strictly prohibited.

#### Rationale

AI tools often need to connect to 3rd party SaaS (GitHub, Jira). Weaknesses in the OAuth flow can allow attackers to intercept authorization codes and hijack the tool's access to those services.

#### Audit

| Method | Description |
| :---- | :---- |
| Static | **Locate OAuth Logic:** Identify the OAuth callback or authorization URL construction logic within the server codebase. <br><br>**Verify State Generation:** Ensure that the state parameter is generated using a cryptographically secure random generator. <br><br>**Verify State Validation:** Confirm that the state parameter is strictly validated upon return to prevent Cross-Site Request Forgery (CSRF). <br><br>**Check Redirect URI Construction:** Verify that the redirect\_uri is not dynamically constructed from user-controlled input. **Confirm Allowlist Enforcement:** Ensure the redirect\_uri is checked against a hardcoded or configuration-based allowlist. **Flag Legacy Methods:** Identify and flag any use of legacy authentication methods, such as Basic Auth over HTTP, which are strictly prohibited. |
| Dynamic | **Verify Redirect URI Validation:** Attempt to use a `redirect_uri` that is not on the pre-defined allowlist to confirm the authorization request fails.  <br><br>**Confirm Secure Transport:** Verify that all authentication flows occur over secure channels (HTTPS) and that legacy unencrypted methods are rejected.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In scope |
| Mobile | Out of scope |
| Remote | In scope (When MCP server is not integrated with WebApp) |

### 1.5.2 Mandatory Proof Key for Code Exchange (PKCE)

#### Description

When the MCP server initiates an OAuth 2.0 authorization code flow to obtain user credentials for a tool, it must implement and enforce Proof Key for Code Exchange (PKCE) as defined in RFC 7636. The server must generate a unique, high-entropy code\_verifier for every authorization request, send the code\_challenge (derived via the S256 method) to the authorization endpoint, and provide the original code\_verifier during the token exchange step. This requirement applies regardless of whether the client is classified as public or confidential.

#### Rationale

Authorization codes are vulnerable to interception via custom URI scheme hijacking (on mobile/local hosts) or log leakage. PKCE provides a dynamic, cryptographically bound secret that ensures only the entity that initiated the authorization request can successfully exchange the resulting code for a token. This effectively mitigates "Authorization Code Injection" and "Interception" attacks by rendering a stolen code useless to an attacker.

#### Audit

| Method | Description |
| :---- | :---- |
| Static | Perform the following code inspection.<br>**Identify OAuth Initiation Logic:** Locate the code responsible for constructing the initial authorization URL. Verify that it generates a cryptographically secure code\_verifier and includes a code\_challenge and code\_challenge\_method=S256 in the request parameters. <br><br>**Verify Token Exchange:** Locate the function that exchanges the authorization code for an access token. Ensure that the original code\_verifier is retrieved from secure session storage and included in the POST body to the token endpoint. <br><br>**Flag Vulnerabilities:** Flag any OAuth 2.0 implementation that relies solely on a static client\_secret or state parameter without incorporating the PKCE challenge-response mechanism. |
| Dynamic |  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In scope |
| Mobile | Out of scope |
| Remote | In scope |

## 1.6 Session Token Leakage

Exposure or insecure handling of session tokens across MCP components leads to unauthorized access, impersonation, or session hijacking.

### 1.6.1 Automated PII and Credential Masking in Logs

#### Description

The MCP server must implement an interception layer for all logging (stdout/stderr/files) that automatically redacts sensitive information, specifically the Authorization headers, session tokens, and sensitive fields within the tool params (e.g., "password", "api\_key").

#### Rationale

Developers often log full JSON-RPC requests for debugging. If these logs are sent to a centralized logging system, any user with log access can steal active session tokens or sensitive tool inputs.

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  **Review Logging Calls:** Identify all logging calls (e.g., console.log, logger.info, winston) throughout the codebase. <br><br>**Detect Full Object Logging:** Search for instances where the entire MCP request or headers object is logged directly. <br><br>**Verify Redaction Middleware:** Confirm that a redaction utility or middleware is applied to these objects before they are passed to the logging function. <br><br>**Check Sensitive Key Masking:** Ensure the redaction utility specifically masks sensitive keys such as token, authorization, secret, and sensitive tool parameters like password or api\_key. |
| Dynamic | **Generate Sensitive Requests:** Trigger JSON-RPC requests containing sensitive information in the headers (e.g., Authorization tokens) or tool parameters (e.g., api\_key). <br><br>**Verify Output Redaction:** Inspect the resulting logs to ensure that all sensitive fields have been successfully masked or redacted before being written to the log sink.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In scope |
| Mobile | In scope |
| Remote | In scope |

### 1.6.2 Secure Session Tokens

#### Description

Developers must ensure that session identifiers and authentication tokens used within the MCP ecosystem (between Hosts, Servers, and any intermediate transport layers) are handled as highly sensitive secrets. This includes:

* **Encrypted Transport:** Using secure channels for all token exchanges.  
* **Secure Storage:** Avoiding the use of local, unencrypted persistent storage for session state.  
* **Log Redaction:** Ensuring tokens are never written to standard output (stdout), standard error (stderr), or debug log files.  
* **Minimal Exposure:** Passing tokens through standardized headers or environment variables rather than command-line arguments or URL query parameters.

#### Rationale

In the MCP architecture, the session token is the "keys to the kingdom." If a developer accidentally leaks a token—for instance, by logging the full JSON-RPC initialization message—an attacker with access to those logs can impersonate the Host and execute arbitrary tools on the Server. Because MCP servers often have access to sensitive local files or internal APIs, a leaked session token can lead to immediate and total system compromise.

#### Audit

| Method | Description |
| :---- | :---- |
| Static |  **Hardocoded Tokens:** Scan the codebase for hardcoded strings that match common token formats (e.g., UUIDs, JWTs, or high-entropy strings).  <br><br>**Logging:** Review all logging statements (e.g., `console.log`, `logging.debug`, `fprintf`) that output the `Session` or `Context` objects.  <br><br>**Initialization:** Verify that the MCP Server implementation does not accept credentials via `argv` (command-line arguments), as these are visible to other users on the system via process listing (`ps aux`).  |
| Dynamic | **Traffic Analysis:** Intercept the MCP transport layer (e.g., stdio streams or WebSockets) and verify that session tokens are not transmitted in "cleartext" over insecure channels (if remote) or exposed in side-channels.  <br><br>**Log Inspection:** Execute a full MCP session lifecycle (Connect \-\> Tool Call \-\> Disconnect) with "Verbose" logging enabled. Search the resulting log files for the session token string.   <br><br>**Environment Check:** Inspect the process environment and temporary directories during execution to ensure tokens are not written to world-readable files or `.env` files that lack proper permissions.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In scope |
| Mobile | In scope |
| Remote | In scope |

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

### 5.1.1 Exfiltration Defense
The system SHALL implement a defense-in-depth architecture to prevent sensitive data leakage. It should also prevent the transmission of any data in transit, at rest, and during processing to the Agent that was not explicitly intended for the current task. MCP implementations must treat the AI Agent as an untrusted principal. 


#### Description

The AI tool (e.g., MCP Server) MUST implement strict access controls, memory isolation, and input validation to ensure that any confidential material held internally—including internal API keys, service credentials, local configuration files, and private caching states—cannot be exfiltrated, exposed, modified, or corrupted through the tool’s exposed execution pathways or APIs. The tool MUST enforce a rigid boundary between its internal operational secrets and the execution context handling agent requests.


#### Rationale

AI tools often require highly privileged credentials (e.g., database passwords, OAuth tokens) to function. If an Agent is subverted via Indirect Prompt Injection (IPI), it may attempt to instruct the tool to read its own internal configuration or "leak" supplementary data retrieved from a backend. By isolating internal secrets and enforcing strict output schemas, the "blast radius" of a compromised agent is contained; the request simply becomes technically impossible to fulfill.


#### Audit

| Method | Description |
| :---- | :---- |
| Static |**Secret Lifecycle Mapping:** Identify all points where the tool loads (Get), refreshes (Update), or clears (Delete) internal credentials. <br><br> **Automated Secret Hunting:** Execute high-entropy scans (e.g., TruffleHog, Gitleaks) to find hardcoded "sk-", "ghp_", or mock credentials in source code and config snippets. <br><br> **Secrets management:** Verify secrets are retrieved into memory-safe buffers. <br><br> **Path & Reflection Verification:** Confirm zero code paths exist where agent input can dynamically dictate file paths targeting local secret files. <br><br> **Taint & Reflection Analysis:** Trace Agent-controlled inputs to ensure they cannot reach sinks that allow dynamic file system access or memory reflection (e.g., eval(), unsafe-load).  |
| Dynamic |**Internal Exfiltration Probe:** Submit traversal payloads (e.g., /etc/secrets/, ../../../../etc/secrets) and commands to dump environment variables. <br>  **Pass:** The tool must block or drop all requests; internal mock keys (e.g., test_secret_key_123) must never appear in responses. <br><br> **Exfiltration Stress Test:** Command the AI Tool to output internally held secrets data. <br>   **Pass:** No internally held secret is in the response. <br><br> **Corruption & Integrity Test:** Submit payloads attempting to overwrite local configuration or exhaust memory. <br>   **Pass:** The tool's internal configuration must remain uncorrupted and operational for subsequent benign requests.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In Scope |
| Mobile | In Scope |
| Remote | In Scope |

## 5.2 File System Exposure/Path Traversal (Duplicate)

Improper validation of file paths or tool arguments enables access to or exfiltration of files outside intended directories, exposing credentials and sensitive data.

**Note: This is a duplicate threat**


# 6 Missing Integrity/Verification Controls 

## 6.1 Resource Content Poisoning

Attackers embed hidden malicious instructions within data sources (databases, documents, API responses) that MCP servers retrieve and provide to LLMs, causing the poisoned content to execute as commands when processed, effectively achieving persistent prompt injection through trusted data channels rather than direct user input. Unlike Prompt Injection (MCP-12): Malicious instructions are embedded in backend data sources, not user-provided prompts. Unlike Tool Poisoning (MCP-2): Poisons the actual data/content retrieved by tools, not the tool definitions themselves. This attack surface may be expanded with transitive or composed MCP server calls.

**Note: Mitigations for this risk are out of scope for the AI Tool specification. This threat will be addressed in the AI Agent specification.**

## 6.2 Typosquatting/Confusion Attacks 

Malicious actors create MCP servers or tools with names/descriptions similar to legitimate ones, tricking clients or AI agents into invoking harmful tools due to naming confusion or LLM hallucination. The MCP specification provides guidance on making tool origins and inputs visible to users and recommends human-in-the-loop approval for tool invocations (User Interaction Model), but consent fatigue—where users reflexively approve prompts without careful review—can significantly undermine these protections.

### 6.2.1 Semantic Integrity and Descriptive Accuracy

#### Description

The tool's metadata—including its name, description, and the definitions of its functions/APIs—must accurately reflect its actual behavior and internal logic. Developers must ensure that:

* The **natural language description** provided to the AI agent matches the functional capabilities of the code.  
* **API parameters** are named and described according to their actual use (e.g., a parameter named `zip_code` should not be used to smuggle an `api_key`).  
* The tool does not contain **undocumented "easter egg" functions** or side effects that deviate significantly from the stated purpose.

#### Rationale

In the context of AI Agents (like those using the Model Context Protocol), the agent relies almost entirely on the tool's description to decide *when* and *how* to call it.

* **Deceptive Mapping:** If a tool is named `fetch_weather` but actually executes `delete_database`, the AI agent can be tricked into performing malicious actions under the guise of a benign request.  
* **Prompt Injection via Metadata:** Misleading descriptions can be used as a "Trojan Horse" to influence the LLM’s reasoning, leading it to ignore system instructions or exfiltrate data to the tool's backend.  
* **Trust Erosion:** Users must be able to audit a tool’s intent by reading its manifest without needing to reverse-engineer the entire codebase.

#### Audit

| Method | Description |
| :---- | :---- |
| Static | **Manifest Review:** Compare the `description` fields in the tool’s configuration (e.g., `mcp.json` or similar) against the function names and variable types.  **Code-to-Metadata Mapping:** Verify that for every exported function, the docstring and metadata capture the primary purpose of the logic. Check for "Dead Code" or "Shadow Parameters" that are defined in the code but omitted or misrepresented in the tool’s public description. **Heuristic Analysis:** Flag tools that use generic or intentionally vague descriptions (e.g., "Run utility") for complex or high-privilege code blocks.  |
| Dynamic | **Functional Verification:** Execute the tool with a series of standard inputs and verify that the output and side effects (file changes, network calls, etc.) align with the tool’s description. **I/O Monitoring:** Monitor network traffic during execution. If a "Calculator" tool initiates an outbound HTTPS request to an unknown domain, it fails the integrity check. Inspect system calls to ensure the tool is only accessing resources relevant to its description (e.g., a "Word Counter" should not be reading the user's SSH keys). **Agent-Simulated Testing:** Provide the tool to a "clean" AI Agent and ask it to describe what the tool does based on its metadata. Compare the agent's understanding against the developer’s actual code implementation to identify semantic gaps.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In Scope |
| Mobile | In Scope |
| Remote | In Scope |

## 6.3 Shadow MCP Servers

Unauthorized, unmonitored, or hidden MCP server instances create blind spots, increasing risk of undetected compromise and covert data exfiltration. These servers pose governance and compliance risks and may be malicious or easily compromised.

**Note: This threat is covered by infrastructure security and out of scope for the ADA AI Tool specification.**

## 6.4 Supply Chain Compromise and Privileged host-base Attacks

Malicious or compromised MCP servers, dependencies, or packages are introduced into the environment, enabling attackers to execute arbitrary code, exfiltrate data, or persist within the infrastructure.

**Note: This risk is mitigated through the MASA and CASA certification.**

# 7 Session and Transport Security Failures

## 7.1 Man-in-the-Middle (MITM)

Exploiting insecure network transport (lack of TLS, improper certificate validation, or missing mutual authentication) to intercept, modify, or reroute data between MCP components, enabling data theft or manipulation.

### 7.1.1 Integrated Transport Security and Message Integrity

#### Description

To mitigate Man-in-the-Middle (MitM) and message integrity risks, the system must enforce a unified secure transport layer and message-level protection. For remote connections, communication must be encrypted using TLS 1.3+ with strict X.509 certificate and trust chain validation (rejecting plaintext, expired, or untrusted endpoints). For local connections, the system must bypass the network stack in favor of secure Inter-Process Communication (IPC)—such as Unix domain sockets or Windows Named Pipes—protected by strict OS-level permissions. 

#### Rationale

This requirement establishes a multi-layered defense. High-grade encryption and secure IPC prevent unauthorized eavesdropping on the wire or within the host. Strict certificate validation ensures the client is communicating with the legitimate server, rather than an attacker's proxy. Lastly, message-level signing guarantees that even if a transport-level vulnerability exists, the underlying tool calls and responses remain immutable and can only be executed once.

#### Audit

| Method | Description |
| :---- | :---- |
| Static | **Protocol Check:** Inspect configuration files (e.g., `server_config.json`) to ensure the minimum TLS version is pinned to `1.3` and that legacy ciphers are disabled. **Validation Check:** Verify that the client implementation does not include flags that bypass certificate validation (e.g., `NODE_TLS_REJECT_UNAUTHORIZED=0` or `verify=False`). **IPC Check:** Review the transport initialization code to ensure local deployments use socket paths or named pipes rather than `localhost` or `127.0.0.1`.  |
| Dynamic | **Downgrade Attack Test:** Attempt to initiate a connection using TLS 1.2 or lower; the server must refuse the handshake. **Trust Chain Test:** Point the MCP client to a server with a self-signed or expired certificate; the client must terminate the connection immediately. **Replay Attack Test:** Intercept a valid tool call and attempt to resend it to the server; the server must reject the message as a duplicate based on the nonce/timestamp. **Local Isolation Test:** Attempt to read from the IPC socket or pipe using a secondary, non-privileged system user; the operating system should deny access based on the file permissions.  |

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In Scope |
| Mobile | In Scope |
| Remote | In Scope |

## 7.2 Insufficient Integrity Checks (Duplicate)

Absence of signature or integrity validation on MCP messages and responses enables replay, spoofing, or delivery of poisoned results.

**Note: Message integrity checks are addressed under “7.1.1 Integrated Transport Security and Message Integrity”**

## 7.3 Unrestricted Network Access

MCP servers or clients with open outbound or inbound network access can download malicious payloads, exfiltrate data, or connect to command-and-control infrastructure. Malicious or compromised MCP servers allow attackers to move laterally using stored credentials and exploiting poor network segmentation and isolation.

**Note: User network security is out of scope for the AI Tool specification. Further, malicious behavior is addressed in 6.2.1 Semantic Integrity and Descriptive Accuracy.**

## 7.4 Protocol Security Gaps

Weaknesses in MCP protocol/transport layers (e.g., missing payload limits, no TLS, unauthenticated requests) enable DoS, spoofing, or unauthorized command execution.

**Note: This threat is addressed by the other authentication, session and transport security controls contained in this document and the underlying CASA and MASA specifications.**

## 7.5 Insecure Descriptor Handling

Improper management of transport descriptors (e.g., stdio) allows attackers to hijack or interfere with data streams and process communications.

**Note: This threat is covered by infrastructure security and out of scope for the ADA AI Tool specification.**

## 7.6 CSRF Protection Missing

Lack of Cross-Site Request Forgery (CSRF) controls on HTTP/SSE transports enables attackers to forge or replay unauthorized requests.

**Note: Out of scope for all HTTP APIs.**

### 7.7 CORS/Origin Policy Bypass

Missing or weak cross-origin policies allow unauthorized data leaks via cross-origin resource sharing (CORS) in browser-based or web transports.

**Note: Out of scope for all HTTP APIs.**

## 7.8 Replay Attacks/Session Hijacking (Duplicate)

Attackers intercept, reuse, or hijack authentication tokens or session identifiers, impersonating legitimate users or agents and executing unauthorized actions.

**Note: See section 1.4.1 for security requirements.**

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

### 10.1.1. Financial Resource & Cost Governance

#### Description

The AI Tool must be inherently cost-aware. It must identify whether a specific resource (e.g. a premium search API or a paid data scraper) carries a direct financial cost to the user or organization. For these metered resources, the tool must implement the following:

* **Session-Based Cost Tracking:** The tool must calculate and track the cumulative cost of all API calls made during an active session.
* **The $100 Guardrail:** By default, if the cumulative session cost reaches $100, the tool must automatically intervene by either enforcing a strict rate limit or pausing execution to request explicit user confirmation.
* **Justified Overrides:** Developers may set a higher dollar threshold only if they provide a documented business justification within the configuration metadata.
* **Governance Layers:** Enforce mandatory authentication for all tool access and implement per-user/per-tool rate limiting to prevent unauthorized or runaway consumption.


#### Rationale

AI Tools are "force multipliers" for LLMs. Because these tools often bridge the gap to paid APIs (e.g., GPT-4o, Claude 3.5 Sonnet, or search engines), they represent a direct financial vulnerability. A logic loop or a malicious actor could trigger thousands of dollars in costs in seconds. Unlike traditional DoS, which impacts availability, a DoW attack impacts the viability of the business.


#### Audit

| Method | Description |
| :---- | :---- |
| Static | **Identify Paid Assets:** Verify that all APIs/resources carrying a financial cost are identified in the codebase. <br><br> **Threshold Verification:** Confirm the implementation of the $100 limit and review documentation for any higher justified limits. <br><br> **Auth Check:** Ensure all cost-incurring resources require a valid, authenticated user context.|
| Dynamic | **Cost Tracking Validation:** Request the list of metered resources and the specific method used to track costs in real-time during a session. <br><br> **Stress Testing:** Using an automated test harness, simulate high-volume calls to verify that the tool triggers a rate limit or confirmation prompt exactly when the $100 (or justified) limit is hit.|

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In Scope |
| Mobile | In Scope |
| Remote | In Scope |

## 10.2 Payload Limit/DoS

Unrestricted payload sizes or recursion depth in protocols enable denial-of-service via resource exhaustion.

### 10.2.1 Maximum Payload and Recursion Depth Constraints

#### Description

The server must strictly enforce configurable limits on the maximum size of incoming request payloads (in bytes) and the maximum depth of nested structures (e.g., JSON objects, arrays, or recursive tool calls).

#### Rationale

Unbounded inputs allow attackers to trigger Denial-of-Service (DoS). Large payloads exhaust RAM/bandwidth, while deep recursion can lead to stack overflow errors or CPU spikes during parsing, rendering the server unavailable to legitimate users.


#### Audit

| Method | Description |
| :---- | :---- |
| Static | **Payload Size Limits:** Inspect the code to verify that payload size limits are implemented. The preferred method is explicit limits, but language provided limits are acceptable. <br><br> **Recursion Depth Limits:** Inspect the code to verify recursion limits are applied during the processing of nested tool calls or nested JSON structures. |
| Dynamic | **Payload Size Limits:** Using a tool like curl or Postman, attempt to send a payload that exceeds the defined limit (e.g., a 100MB JSON string when the limit is 5MB). <br><br> **Recursion Depth Limits:** Send a JSON object with nesting depth significantly higher than the limit (e.g., 1,000 levels of nested arrays: [[[[...]]]]).|

#### Comments

| Scope | Comment |
| :---- | :---- |
| Local | In Scope |
| Mobile | In Scope |
| Remote | In Scope |

# 11 Supply Chain and Lifecycle Security Failures

## 11.1 Shadow MCP Servers (Duplicate) 

Unauthorized, unmonitored, or hidden MCP server instances create blind spots, increasing risk of undetected compromise and covert data exfiltration. These servers pose governance and compliance risks and may be malicious or easily compromised.

**Note: This threat is covered by infrastructure security and out of scope for the ADA AI Tool specification.**

## 11.2 Supply Chain Compromise (Duplicate) 

Malicious or compromised MCP servers, dependencies, or packages are introduced into the environment, enabling attackers to execute arbitrary code, exfiltrate data, or persist within the infrastructure.

**Note: This risk is mitigated through the MASA and CASA certification.**

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

| Method  | Description |
| :------ | :--------------------------------------------------------------------- |
| Static  | **Verify Structured Format:** Identify all logging statements (e.g., `console.log`, `logger.info`, `winston`) and confirm they utilize a structured format like JSON objects or key-value pairs rather than simple string concatenation. <br><br>**Identify External Tool Execution Paths:** Review the code for AI tool integration and MCP server implementations to identify all functions that execute external tools or access data resources. <br><br>**Check Telemetry Coverage:** Verify that each execution path includes a logging call capturing the identity of the calling agent, the specific tool requested, the input parameters, and the success/failure status. <br><br>**Inspect Metadata and Correlation:** Confirm that critical events (tool execution, API requests, and authentication logic) are logged with relevant metadata, including timestamps and correlation IDs. <br><br>**Audit for Reasoning Traces:** Verify if the "Intent" of the agent is logged to provide an auditable "Reasoning Trace" explaining why an agent took a specific action. <br><br>**Flag Silent Failures:** Identify and flag any instances where a tool is invoked without telemetry or where error states are handled "silently" without an audit entry. <br><br>**Flag Unstructured Calls:** Identify and flag any instances of "print" statements or unstructured logger calls used for operational data. |
| Dynamic | **Generate Agent Activity:** Interact with the system through the AI agent to trigger various tool calls, API requests, and authentication events. <br><br>**Validate Log Capture:** Inspect the generated logs to confirm that the interaction was captured in its entirety. <br><br>**Confirm Machine-Readability:** Verify that the output logs are valid structured data (e.g., valid JSON) that can be parsed by automated security tools.  |
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
