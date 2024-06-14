# App Defense Alliance Web Application Specification
Version 0.7 - May 25, 2024


# Revision History
| Version | Date  | Description|
|----|----|-----------------|
| 0.5 | 5/25/24 | Initial draft based on Web App Tiger Team review of ASVS specification |
| 0.7 | 5/25/24 | Updates from Tiger Team review of 0.5 spec |

# Contributors
The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification:

* Alex Duff (ASA WG Chair)
* Brooke Davis (ASA WG Vice Chair)
* Brad Ree
* Chilik Tamir
* Christopher Estrada
* Cody Martin
* Gianluca Braga
* John Tidwell
* Juan Manuel Martinez Hernandez
* Jullian Gerhart
* Michael Whiteman
* Viktor Sytnik
* Zach Moreno

# Table of Contents
1 [Authentication](#1-authentication)

1.1 [Implement strong password security measures](#11-implement-strong-password-security-measures)

1.2 [Disable any default accounts for public application access interfaces](#12-disable-any-default-accounts-for-public-application-access-interfaces)

1.3 [Lookup secrets shall be random and not reused](#13-lookup-secrets-shall-be-random-and-not-reused)

1.4 [Out of band verifiers shall be random and not reused](#14-out-of-band-verifiers-shall-be-random-and-not-reused)

2 [Session Management](#2-session-management)

2.1 [URLs shall not expose sensitive information](#21-urls-shall-not-expose-sensitive-information)

2.2 [Implement Session Invalidation on Logout, User Request, and Password Change](#22-implement-session-invalidation-on-logout-user-request-and-password-change)

2.3 [Implement and Secure Application Session Tokens](#23-implement-and-secure-application-session-tokens)

2.4 [Protect Sensitive Account Modifications](#24-protect-sensitive-account-modifications)

3 [Access Control](#3-access-control)

3.1 [Implement access control mechanisms to protect sensitive data and APIs](#31-implement-access-control-mechanisms-to-protect-sensitive-data-and-apis)

3.2 [Implement secure OAuth integrations to protect user data and prevent unauthorized access](#32-implement-secure-oauth-integrations-to-protect-user-data-and-prevent-unauthorized-access)

3.3 [Application exposed administrative interfaces shall use appropriate multi-factor authentication.](#33-application-exposed-administrative-interfaces-shall-use-appropriate-multi-factor-authentication)

4 [Communications](#4-communications)

4.1 [Protect Sensitive Data Through Strong Cryptography](#41-protect-sensitive-data-through-strong-cryptography)

5 [Data Validation and Sanitization](#5-data-validation-and-sanitization)

5.1 [Implement Validation & Input Sanitation](#51-implement-validation--input-sanitation)

5.2 [Securely Handle Untrusted Files](#52-securely-handle-untrusted-files)

6 [Configuration](#6-configuration)

6.1 [Keep all components up to date](#61-keep-all-components-up-to-date)

6.2 [Disable debug modes in production environments](#62-disable-debug-modes-in-production-environments)

6.3 [The origin header shall not be used for authentication of access control decisions](#63-the-origin-header-shall-not-be-used-for-authentication-of-access-control-decisions)

6.4 [Protect Application from Subdomain Takeover](#64-protect-application-from-subdomain-takeover)

6.5 [Do not log credentials or payment details](#65-do-not-log-credentials-or-payment-details)

6.6 [Sensitive user data is either not stored in browser storage or is deleted when the user logs out](#66-sensitive-user-data-is-either-not-stored-in-browser-storage-or-is-deleted-when-the-user-logs-out)

6.7 [Securely store server-side secrets](#67-securely-store-server-side-secrets)


# Introduction
In today's digitally-driven world, web applications are the backbone of countless businesses and organizations. Unfortunately, they are also prime targets for cyberattacks that threaten data confidentiality, service availability, and overall business integrity. To mitigate risks and build a secure web environment, a robust web application security standard and certification program is essential.

**Our Approach: OWASP ASVS as the Foundation**

This program leverages the internationally recognized OWASP Application Security Verification Standard (ASVS) as its core. The OWASP ASVS offers a comprehensive set of security assessment requirements and guidelines covering the entire web application development lifecycle. Building upon this base, the App Defense Alliance (ADA) focused on testable requirements with clear acceptance criteria. Further, the ADA approach emphasizes the use of automation where possible.

# Applicability
This document is intended for system and application administrators, security specialists, auditors, help desk, platform deployment, and/or DevOps personnel who plan to develop, deploy, assess, or secure solutions in the cloud.


# References
1. [OWASP Application Security Verification Standard](https://github.com/OWASP/ASVS?tab=readme-ov-file)

# Licensing
This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License.](https://creativecommons.org/licenses/by-sa/4.0/)

# Definitions
*ASVS*
Application Security Verification Standard

*Sensitive Data*
TBD

*Software Bill Of Material (SBOM)*
A “software bill of materials” (SBOM) has emerged as a key building block in software security and software supply chain risk management. A SBOM is a nested inventory, a list of ingredients that make up software components. 

# 1 Authentication
## 1.1 Implement strong password security measures
### Description
Applications need to have robust mechanisms in place to ensure the security of user passwords. This includes, but is not limited to, enforcing password length requirements, implementing mitigations to prevent automated attacks against authentication systems, and securely storing passwords using strong cryptographic methods.
### Rationale
Weak or compromised passwords are a common attack vector used by adversaries to gain unauthorized access to user accounts. By implementing strong password security measures, organizations can significantly reduce the likelihood of successful password-based attacks.
### Audit
| Spec | Description |
| --- | ------|
| 1.1.1 | Authentication is resistant to brute force attacks |
| 1.1.2 | System generated initial passwords or activation codes shall be securely randomly generated and expire after a short period. |
| 1.1.3 | Passwords shall be stored in a form that is resistant to offline attacks.|


---
## 1.2 Disable any default accounts for public application access interfaces
### Description
Applications should not have any pre-configured or default user accounts that can be used to access its public-facing interfaces. This includes both user and administrative accounts that come with default credentials.
### Rationale
Default accounts can be easily discovered through publicly available documentation, online forums, or other sources, making them an attractive target for attackers. If an attacker is able to gain access to a default account, they may be able to escalate their privileges and move laterally within the application or underlying infrastructure.
### Audit
| Spec | Description |
| --- | ------|
| 1.2.1 | Shared or default accounts shall not present on publicly exposed interfaces.|

---
## 1.3 Lookup secrets shall be random and not reused
### Description
Lookup secrets are pre-generated lists of single-use codes that are often used as a substitute for a user's password when they forget their password or need access to their account. Given the sensitive nature of these codes, it is important that they are resistant to replay, spoofing, and brute force attacks. 

### Rationale
Since lookup secrets often act as a substitute for a user password, it's important that they are securely randomly generated and resistant to replay attacks.
### Audit
| Spec | Description |
| --- | ------|
| 1.3.1 | Lookup secrets shall be used only once.|
| 1.3.2 | Lookup secrets shall have sufficient randomness.|


---
## 1.4 Out of band verifiers shall be random and not reused
### Description
Any verification codes or tokens sent through out-of-band methods (such as SMS or email) should have sufficient entropy along with a suitable expiration duration. Once a verifier has been used or has expired, it should be invalidated and a new one should be generated for each subsequent verification attempt.
### Rationale
By ensuring that out of band verifiers are securely generated and managed, the risk of an adversary intercepting and using these verifiers is significantly reduced.
### Audit
| Spec | Description |
| --- | ------|
| 1.4.1 | Out of band verifier shall expire after 7 days.|
| 1.4.2 | Out of band verifier shall only be used once.|
| 1.4.3 | Out of band verifier shall be securely random|

---
# 2 Session Management
## 2.1 URLs shall not expose sensitive information
### Description
Web applications must never expose sensitive data within URL parameters. Sensitive data should be transmitted securely, such as within HTTP headers or cookies with appropriate security flags.
### Rationale
Exposing sensitive data such as session tokens in URLs significantly increases the risk of data loss and session hijacking. Attackers can easily intercept this data through browser history, network sniffing, or by tricking users into visiting malicious links.  This vulnerability undermines data protection, the security of user sessions and makes the application susceptible to unauthorized access
### Audit
| Spec | Description |
| --- | ------|
| 2.1.1 | The application shall not reveal passwords or session tokens in URL parameters. In cases where the application provides an API, the application shall prevent (or give developers an option) to prevent exposing sensitive information like API keys or session tokens within the URL query strings|

---
## 2.2 Implement Session Invalidation on Logout, User Request, and Password Change
### Description
The application must invalidate session tokens upon logout, expiration, and shall provide the option (or acts by default) to terminate other active sessions after a successful password change (including reset).
### Rationale
These features protect against unauthorized access.  Logouts and expirations prevent lingering sessions, while password-change termination deters attackers who might know an old password.  Session visibility and control let users proactively manage their account, ensuring that only authorized devices are actively associated with their profile.
### Audit
| Spec | Description |
| --- | ------|
| 2.2.1 | Users shall have the ability to logout of the application. Logout or session expiration shall invalidate all stateful session tokens, including refresh tokens.|
| 2.2.2 | The application shall provide the option (or acts by default) to terminate all other active sessions, including stateful refresh tokens, after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties.|
| 2.2.3 | Stateless authentication tokens must expire within 24 hours of being issued|

---
## 2.3 Implement and Secure Application Session Tokens
### Description
When using cookie-based session tokens, the application must enforce the 'Secure' attribute (ensuring transmission only over HTTPS) and the 'HttpOnly' attribute (preventing access by client-side JavaScript).  The application prioritizes session tokens over static API keys, except where legacy systems necessitate static secrets.
### Rationale
Secure' and 'HttpOnly' mitigate risks of token interception and Cross-Site Scripting (XSS) attacks, enhancing session security. Session tokens, being temporary and user-specific, offer better control and auditing compared to long-lived API secrets, making them the preferred approach for modern applications.
### Audit
| Spec | Description |
| --- | ------|
| 2.3.1 | Cookie-based session tokens shall have the 'Secure' attribute set.|
| 2.3.2 | Cookie-based session tokens shall have the 'HttpOnly' attribute set.|
| 2.3.3 | The application shall use session tokens rather than static API secrets and keys, except with legacy implementations.|
| 2.3.4 | Stateless session tokens shall use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.|

---
## 2.4 Protect Sensitive Account Modifications 
### Description
Applications must enforce a complete, valid login session or require re-authentication/secondary verification prior to any sensitive actions, such as sensitive data transactions or changes to account settings.
### Rationale
This requirement prevents unauthorized access to sensitive parts of an application.  Even if an attacker partially compromises a session, re-authentication or secondary checks create an extra barrier. It helps mitigate session hijacking attempts and safeguards user data,  promoting overall account security.
### Audit
| Spec | Description |
| --- | ------|
| 2.4.1 | Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.|

---
# 3 Access Control
## 3.1 Implement access control mechanisms to protect sensitive data and APIs
### Description
Applications shall enforce robust access controls at a trusted service layer, ensuring data integrity and applying the principle of least privilege. This includes protecting user/data attributes, limiting user manipulation, failing securely during exceptions, defending against Insecure Direct Object References (IDOR), and using strong anti-CSRF and multi-factor authentication (MFA) for administrative functions.
### Rationale
*Layered Defense* 
Combining URI and resource-level checks provides multiple layers of protection, enhancing security against unauthorized access.

*Fine-grained Control*
Resource-level permissions allow for precise control over individual objects or data, while URI-level controls offer broader protection of web resources.

*Flexibility*
This approach supports varying access control needs, ensuring security in diverse application architectures.
### Audit
| Spec | Description |
| --- | ------|
| 3.1.1 | The application shall enforce least privilege access control rules on a trusted service layer.|
| 3.1.2 | All user and data attributes and policy information used by access controls shall not be able to be manipulated by end users unless specifically authorized.|
| 3.1.3 | Access controls shall fail securely including when an exception occurs.|
| 3.1.4 | Sensitive resources shall be protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records.|
| 3.1.5 | The application or framework shall enforce a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality.|
| 3.1.6 | Directory browsing shall be disabled unless deliberately desired.|

---
## 3.2 Implement secure OAuth integrations to protect user data and prevent unauthorized access
### Description
Applications which support OAuth integrations shall follow established security guidelines to safeguard user data and prevent unauthorized access.

### Rationale
OAuth is a widely adopted authorization framework that allows users to grant third-party applications limited access to their resources on another service without sharing their login credentials. However, if not implemented securely, OAuth can expose users to various attacks, including account compromises and information disclosure. By securely implementing OAuth integrations, the application minimizes these risks and provides users with a more secure experience.

### Audit
| Spec | Description |
| --- | ------|
| 3.2.1 | Application shall implement only secure and recommended OAuth 2.0 flows, such as the Authorization Code Flow or the Authorization Code Flow with PKCE, while avoiding the use of deprecated flows like the Implicit Flow or the Resource Owner Password Credentials Flow.|
| 3.2.2 | Ensure that the application securely validates the redirect_uri and state parameters during the OAuth 2.0 authorization process to prevent open redirect and CSRF vulnerabilities. |

---
## 3.3 Application exposed administrative interfaces shall use appropriate multi-factor authentication.
### Description
Application exposed administrative interfaces shall implement multi-factor authentication. These interfaces shall be limited to application layer functionality and must not expose the cloud infrastructure.
### Rationale
Infrastructure administrative interfaces shall never be exposed through an internet facing interface. However, there are many cases where application layer administrative tasks may need to be exposed to the internet. It is critical that these interfaces be limited in functionality and always implement multi-factor authentication to prevent attackers from compromising administrative accounts.

### Audit
| Spec | Description |
| --- | ------|
| 3.3.1 | Application administrative interfaces shall use appropriate multi-factor authentication to prevent unauthorized use.|

---
# 4 Communications
## 4.1 Protect Sensitive Data Through Strong Cryptography 
### Description
Applications must enforce strong TLS configurations and cryptographic practices. This includes using up-to-date tools to enable only strong cipher suites (prioritizing the strongest), employing trusted TLS certificates, and ensuring secure failure modes in cryptographic modules to mitigate common cryptographic attacks.
### Rationale
Strong TLS and cipher suites ensure confidentiality and integrity of data in transit by protecting against eavesdropping and modification. Trusted TLS certificates verify authenticity and prevent adversary-in-the-middle attacks, while secure failure modes and robust cryptography deter advanced attacks exploiting weaknesses in cryptographic implementations.

### Audit
| Spec | Description |
| --- | ------|
| 4.1.1 | Application shall enforce the use of TLS for all connections and default to TLS 1.2+. In cases where support for legacy clients is necessary, TLS 1.0 and 1.1 may be supported if mitigations are implemented to minimize the risk of downgrade attacks and known TLS exploits. Regardless of the TLS version in use, the application shall default to secure cipher suites and reject those with known vulnerabilities.|
| 4.1.2 | Connections to and from the server shall use trusted TLS certificates. Where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs and specific self-signed certificates. All others should be rejected.|
| 4.1.3 | No instances of weak cryptography which meaningfully impact the confidentiality or integrity of sensitive data.|
| 4.1.4 | All cryptographic modules shall fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.|

---
# 5 Data Validation and Sanitization
## 5.1 Implement Validation & Input Sanitation
### Description
Web applications must implement robust input validation and output encoding to defend against a wide range of injection attacks. This includes protecting against HTTP Parameter Pollution, XSS (reflected, stored, and DOM-based), SQL injection, OS command injection, file inclusion vulnerabilities, template injection, SSRF, XPath/XML injection, and unsafe use of dynamic code execution features (like eval()).
### Rationale
Robust input validation and output encoding is essential for web applications to effectively defend against multiple injection attack types. Injection attacks pose a significant risk for web applications due to their simplicity and ease of automation, enabling potential attackers to readily target vulnerable sites. By implementing secure input validation, web applications can significantly reduce the risk of attackers exploiting injection vulnerabilities to gain unauthorized access, manipulate data, or compromise systems.
### Audit
| Spec | Description |
| --- | ------|
| 5.1.1 | Protect against HTTP parameter pollution.|
| 5.1.2 | URL redirects and forwards are limited to allowlisted URLs or a warning is displayed when redirecting to untrusted content.|
| 5.1.3 | Avoid the use of eval() or other dynamic code execution features. When there is no alternative, any user input is sanitized and sandboxed before being executed.|
| 5.1.4 | Protect against template injection attacks by ensuring that any user input being included is sanitized or sandboxed.|
| 5.1.5 | Prevent Server-Side Request Forgery (SSRF)|
| 5.1.6 | Sanitize, disable, or sandbox user supplied SVG files|
| 5.1.7 | Protect against XPath or XML injection attacks|
| 5.1.8 | Context-aware output escaping or sanitization protects against reflected, stored, and DOM based XSS.|
| 5.1.9 | Protect against database injection attacks|
| 5.1.10 | Protect against OS command injections|
| 5.1.11 | Protect against local file inclusion or remote file inclusion attacks|

---
## 5.2 Securely Handle Untrusted Files 
### Description
Web applications must safely process and manage files that originate from untrusted or unknown sources. This includes restricting uploads to expected file types and preventing direct execution of uploaded content containing HTML, JavaScript, or dynamic server-side code.
### Rationale
Files from untrusted sources may contain malicious code which could allow compromise of the application. If these files are executed directly, they can compromise the security of the web application, leading to unauthorized access, data breaches, or other harmful actions.
### Audit
| Spec | Description |
| --- | ------|
| 5.2.1 | Protect against malicious file uploads by limiting uploads to expected file types and preventing direct execution of uploaded content.|

---
# 6 Configuration
## 6.1 Keep all components up to date
### Description
Developers must verify that the libraries included in their application do not have any known exploitable vulnerabilities.
### Rationale
Attackers can perform automated scans to identify vulnerable applications based on published vulnerabilities. 
### Audit
| Spec | Description |
| --- | ------|
| 6.1.1 | The app only uses software components without known exploitable vulnerabilities.|

---
## 6.2 Disable debug modes in production environments
### Description
Applications must strictly disable all debug modes before deployment into production environments.
### Rationale
Debug modes often expose sensitive information like stack traces, code internals, and environment variables. This information can aid attackers in understanding the application's structure and identifying vulnerabilities, significantly increasing the risk of targeted attacks and exploitation. Disabling debug modes removes this unnecessary risk in production.
### Audit
| Spec | Description |
| --- | ------|
| 6.2.1 | Disable debug modes in production environments|

---
## 6.3 The origin header shall not be used for authentication of access control decisions
### Description
The application must never rely solely on the Origin HTTP header for authentication or access control decisions.
### Rationale
The Origin header can be easily manipulated by attackers, making it an unreliable indicator of a request's true source. This could lead to unauthorized access if an application mistakenly trusts requests based on a forged  Origin header. Security mechanisms must use more robust and tamper-proof methods for authentication and authorization.
### Audit
| Spec | Description |
| --- | ------|
| 6.3.1 | The origin header shall not be used for authentication of access control decisions|

---
## 6.4 Protect Application from Subdomain Takeover
### Description
The application must implement safeguards to prevent subdomain takeover vulnerabilities. This includes proactive identification and removal of dangling DNS records (e.g., CNAME records pointing to decommissioned services) and regular monitoring of third-party services integrated with the application's domains.
### Rationale
Dangling DNS records and vulnerable third-party services can allow attackers to take control of subdomains. This could enable them to host malicious content on the application's domain, harming reputation and potentially leading to phishing attacks or the compromise of user data.
### Audit
| Spec | Description |
| --- | ------|
| 6.4.1 | The application shall not be susceptible to subdomain takeovers.|

---
## 6.5 Do not log credentials or payment details
### Description
Applications must never log sensitive user data, specifically credentials (e.g., passwords, API keys) and payment details (e.g., credit card numbers, CVVs).
### Rationale
*Data Compromise Prevention*
Logging such sensitive data creates unnecessary copies that are themselves targets for attackers. If logs are compromised, critical user information is exposed, significantly increasing the impact of a breach.

*Regulatory Compliance*
Many data privacy regulations (PCI-DSS, GDPR, etc.) explicitly prohibit the storage of sensitive authentication and financial data, especially in plain text.

*Security Best Practice*
Avoiding logging sensitive information minimizes the overall attack surface and demonstrates a commitment to responsible data handling.
### Audit
| Spec | Description |
| --- | ------|
| 6.5.1 | The application shall not log credentials or payment details. Session tokens shall only be stored in logs in an irreversible, hashed form.|

---
## 6.6 Sensitive user data is either not stored in browser storage or is deleted when the user logs out
### Description
Web applications should never store sensitive user data (e.g., passwords, credit card numbers, session tokens) in browser storage mechanisms like local storage or session storage. However, if data is stored in browser storage it must be deleted when the user logs out.
### Rationale
Browser storage is inherently accessible to client-side JavaScript, making it vulnerable to attacks like Cross-Site Scripting (XSS). Storing sensitive data here exposes it to potential theft or misuse by an attacker if they manage to inject malicious code. Sensitive data must be stored securely on the server-side.
### Audit
| Spec | Description |
| --- | ------|
| 6.6.1 | If data is stored in browser storage it shall not contain sensitive data.|

---
## 6.7 Securely store server-side secrets
### Description
Ensure server-side secrets are stored securely using an appropriate secrets management approach which provides encryption, access controls, and monitoring to prevent unauthorized access and maintain data confidentiality.
### Rationale
Secrets management helps protect API keys, access tokens, and other server-side secrets used by the application from being accessed or stolen by unauthorized parties.
### Audit
| Spec | Description |
| --- | ------|
| 6.7.1 | The application shall securely store access tokens, API keys, and other server-side secrets.|
