# App Defense Alliance Web Application Specification
Version 0.7 - May 25, 2024


# Revision History
| Version | Date  | Description|
|----|----|-----------------|
| 0.5 | 5/25/24 | Initial draft based on Web App Tiger Team review of ASVS specification |
| 0.7 | 5/25/24 | Updates from Tiger Team review of 0.5 spec |

# Contributors
The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

### Application Security Assessment Working Group Leads
* Alex Duff (Meta) - ASA WG Chair
* Brooke Davis (Google) - ASA WG Vice Chair

### Mobile Profile Leads
* Brad Ree (Google)
* Michael Whiteman (Meta)

### Contributors
* Abdullah Albyati (Google)
* Alex Duff (Meta)
* Alexander Cobblah 
* Anushree Shetty  (KPMG)
* Artur Gartvikh
* Bhairavi Mehta (TAC Security)
* Brad Ree (Google)
* Brooke Davis (Google)
* Chilik Tamir
* Chris Cinnamo (Zimperium)
* Christopher Estrada (NCC Group)
* Cody Martin (Leviathan Security)
* Gianluca Braga (Zimperium)
* Joel Scambray (NCC Group)
* John Tidwell (Meta)
* Jorge Wallace Ruiz (Dekra)
* José María Santos López
* Juan Manuel Martinez Hernandez
* Julia McLaughlin (Google)
* Jullian Gerhart (NCC Group)
* Kelly Albrink (Bishop Fox)
* Mamachan Anish (KPMG)
* Manuel Mancera (Dekra)
* Mark Stribling (Leviathan Security)
* Mateo Morales Amador
* Michael Whiteman (Meta)
* Nazariy Haliley (Bishop Fox)
* Nico Chiaraviglio (Zimperium)
* Nicole Weisenbach (NCC Group)
* Noelle Murata (Leviathan Security)
* Pamela Dingle  (Microsoft)
* Rene Guerra (Schellman)
* Richard Harris  (NCC Group)
* Rupesh Nair (Net Sentries)
* Shad Malloy
* Soledad Antelada Toledano (Google)
* Tim Bolton (Meta)
* Viktor Sytnik (Leviathan)
* Zach Moreno (Bishop Fox)
  
# Table of Contents
1 [Authentication](#1-authentication)

1.1 [Implement strong password security measures](#11-implement-strong-password-security-measures)

1.2 [Disable any default accounts for public application access interfaces](#12-disable-any-default-accounts-for-public-application-access-interfaces)

1.3 [Out of band verifiers shall be random and not reused](#13-out-of-band-verifiers-shall-be-random-and-not-reused)

2 [Session Management](#2-session-management)

2.1 [URLs shall not expose sensitive information](#21-urls-shall-not-expose-sensitive-information)

2.2 [Implement session invalidation on logout, user request, and password change](#22-implement-session-invalidation-on-logout-user-request-and-password-change)

2.3 [Implement and secure application session tokens](#23-implement-and-secure-application-session-tokens)

2.4 [Protect sensitive account modifications](#24-protect-sensitive-account-modifications)

3 [Access Control](#3-access-control)

3.1 [Implement access control mechanisms to protect data and APIs](#31-implement-access-control-mechanisms-to-protect-sensitive-data-and-apis)

3.2 [Implement secure OAuth integrations to protect user data and prevent unauthorized access](#32-implement-secure-oauth-integrations-to-protect-user-data-and-prevent-unauthorized-access)

3.3 [Application exposed administrative interfaces shall use appropriate multi-factor authentication.](#33-application-exposed-administrative-interfaces-shall-use-appropriate-multi-factor-authentication)

4 [Communications](#4-communications)

4.1 [Protect data through strong cryptography](#41-protect-sensitive-data-through-strong-cryptography)

5 [Data Validation and Sanitization](#5-data-validation-and-sanitization)

5.1 [Implement validation & input sanitation](#51-implement-validation--input-sanitation)

5.2 [Securely handle untrusted files](#52-securely-handle-untrusted-files)

6 [Configuration](#6-configuration)

6.1 [Keep all components up to date](#61-keep-all-components-up-to-date)

6.2 [Disable debug modes in production environments](#62-disable-debug-modes-in-production-environments)

6.3 [The origin header shall not be used for authentication of access control decisions](#63-the-origin-header-shall-not-be-used-for-authentication-of-access-control-decisions)

6.4 [Protect application from subdomain takeover](#64-protect-application-from-subdomain-takeover)

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

# Specification Scoping Guidance
Scoping a web application test can be a complex and challenging task, as it requires defining the boundaries of the application and determining what needs to be tested. Here is some guidance to help define a reasonable scope while evaluating a web application within the context of this specification.

This specification is designed to be applied to one or more target web application(s) (first party components) and their integrated third-party components, subject to the following considerations:

**First-Party Scoping Considerations**
- Target Web Application(s): Before testing, define the target web application(s) as a group of components that operate together to provide a logical set of services. For example, if a large business platform offers multiple services such as online dating, instant messaging, and investment banking; each can be scoped and evaluated separately using this specification, with all grouped subcomponents considered in-scope for testing & evaluation.
- Shared Backend Components: First party shared backend components or APIs are considered in the scope if they are utilized by the defined target application(s).

**Third-Party API Scoping Considerations**
- Sensitive Operations: Any third-party (3P) product API that supports sensitive operations, such as Authentication, accessing or mutating user data, & account recovery are within the scope of an ADA web assessment. These 3P APIs will only be subject to web assessment requirements defined within the Authentication, Session Management, & Access Control sections.
- Limited Testing: Testing of these 3P APIs will be limited to components and configurations utilized by the tested application. Other 3P API components and ADA web requirements will be out of scope and will not be tested in relation to 3P Product APIs.

**Additional Clarifications**
- Out-of-Scope Components: The following components are explicitly out of scope for this testing:
  - Third-party APIs not utilized by the target application
  - Non-sensitive operations performed by third-party APIs
- Examples and Scenarios: To illustrate the scoping decisions, consider the following examples:
  - A web application uses a third-party authentication API to handle user login. In this case, the authentication API is within scope for testing.
  - A web application uses a third-party analytics gateway to process application performance metrics. As the gateway does not handle sensitive user data, it is out of scope for testing.

# Definitions
| Term | Definition |
| --- | ----- |
| ADA-approved external user authentication service | User authentication / Identity provider which has been reviewed against the ADA authentication requirements. The review may have been done directly against the service or part of an application review. See ADA Approved User Authentication Service. |
| ASVS | Application Security Verification Standard |
| Code snippets | Portion of code (either screenshot or text file), which demonstrates the implementation of the security control defined in the audit test case. The full text file, calling functions or underlying libraries do not need to be included. |
| CVE | Common Vulnerabilities and Exposures. [https://www.cve.org/](https://www.cve.org/)|
| CVSS | Common Vulnerability Scoring System. [https://www.cve.org/](https://www.cve.org/)|
| Default credentials | Default credentials are any predefined user names and passwords combinations. For example, Admin/Admin. However, Admin with a user defined password would not be a default credential. |
| HTTP parameter pollution | HTTP Parameter Pollution (HPP) is a web application vulnerability exploited by injecting encoded query string delimiters in already existing parameters. [https://en.wikipedia.org/wiki/HTTP_parameter_pollution](https://en.wikipedia.org/wiki/HTTP_parameter_pollution)|
| IV (Initialization Vector) | A binary vector used as the input to initialize the algorithm for the encryption of a plaintext block sequence to increase security by introducing additional cryptographic variance and to synchronize cryptographic equipment. The initialization vector need not be secret. [https://csrc.nist.gov/glossary/term/initialization_vector](https://csrc.nist.gov/glossary/term/initialization_vector) |
| Local File Inclusion | The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a “dynamic file inclusion” mechanism implemented in the target application. [https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion) |
| (L1) ADA Assurance Level 1 (Verified Self Assessment) | The developer provides evidence and statements of compliance to each audit test case. The ADA approved lab reviews the evidence against the requirements. The ADA approved lab does not directly assess the application. |
| (L2) ADA Assurance Level 2 (Lab Assessment) |  The ADA approved lab evaluates each audit test case directly against the application. In some cases, the developer may need to provide limited information or code snippets. |
| non-ADA approved authentication service | Any external user authentication service which has not been assessed against the ADA authentication requirements, or a developer’s proprietary authentication service. |
| Padding Oracle | A padding oracle is a function of an application which decrypts encrypted data provided by the client, e.g. internal session state stored on the client, and leaks the state of the validity of the padding after decryption. [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)|
| Principle of least privilege | A security principle that a system should restrict the access privileges of users (or processes acting on behalf of users) to the minimum necessary to accomplish assigned tasks. [https://csrc.nist.gov/glossary/term/least_privilege](https://csrc.nist.gov/glossary/term/least_privilege)|
| Publicly exposed interfaces | Any interface directly accessible on the Internet, either through a URL or IP address. Indirect access, such as access through a VPN or IP whitelisting, are out of scope. |
| Qualys SSL Labs scan | A free online service which performs a deep analysis of the configuration of any SSL web server on the public Internet. [https://www.ssllabs.com/ssltest](https://www.ssllabs.com/ssltest)|
| Scope | Identifies whether a requirement is applicable to web applications, web APIs, or both. Mobile applications that utilize web APIs must comply with both the mobile application and web API specifications. |
| Confidential data | Non-public information including user data and company confidential information which should only be accessible to authorized applications and systems. |
| Authentication material | Sensitive information used to verify the identity of a user or service. These materials can include passwords, API tokens, session cookies, and other types of credentials that are used to authenticate access to a system or application. |
| Remote File Inclusion | Remote File Inclusion (also known as RFI) is the process of including remote files through the exploitation of vulnerable inclusion procedures implemented in the application. [https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion) |
| WSTG | OWASP Web Security Testing Guide |
| 3P library | Any library which was not developed by the developer. These libraries may be open source or commercial libraries or SDKs.|



# 1 Authentication
## 1.1 Implement strong password security measures
### Description
Applications need to have robust mechanisms in place to ensure the security of user passwords. This includes, but is not limited to, enforcing password length requirements, implementing mitigations to prevent automated attacks against authentication systems, and securely storing passwords using strong cryptographic methods.
### Rationale
Weak or compromised passwords are a common attack vector used by adversaries to gain unauthorized access to user accounts. By implementing strong password security measures, organizations can significantly reduce the likelihood of successful password-based attacks.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [1.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#111-authentication-is-resistant-to-brute-force-attacks) | Authentication is resistant to brute force attacks |
| [1.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#112-system-generated-initial-passwords-or-activation-codes-shall-be-securely-randomly-generated-and-expire-after-a-short-period) | System generated initial passwords or activation codes shall be securely randomly generated and expire after a short period. |
| [1.1.3](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#113-passwords-shall-be-stored-in-a-form-that-is-resistant-to-offline-attacks) | Passwords shall be stored in a form that is resistant to offline attacks.|


---
## 1.2 Disable any default accounts for public application access interfaces
### Description
Applications should not have any pre-configured or default user accounts that can be used to access its public-facing interfaces. This includes both user and administrative accounts that come with default credentials.
### Rationale
Default accounts can be easily discovered through publicly available documentation, online forums, or other sources, making them an attractive target for attackers. If an attacker is able to gain access to a default account, they may be able to escalate their privileges and move laterally within the application or underlying infrastructure.
### Scope
- Web application
### Audit
| Spec | Description |
| --- | ------|
| [1.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#121-default-credentials-shall-not-be-present-on-publicly-exposed-interfaces) | Default credentials shall not present on publicly exposed interfaces.|

---
## 1.3 Out of band verifiers shall be random and not reused
### Description
Any verification codes or tokens sent through out-of-band methods (such as SMS or email) should have sufficient entropy along with a suitable expiration duration. Once a verifier has been used or has expired, it should be invalidated and a new one should be generated for each subsequent verification attempt.
### Rationale
By ensuring that out of band verifiers are securely generated and managed, the risk of an adversary intercepting and using these verifiers is significantly reduced.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [1.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#131-out-of-band-verifier-shall-expire-in-a-reasonable-timeframe) | Out of band verifier shall expire in a reasonable timeframe.|
| [1.3.2](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#132-out-of-band-verifier-shall-only-be-used-once) | Out of band verifier shall only be used once.|
| [1.3.3](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#133-out-of-band-verifier-shall-be-securely-random) | Out of band verifier shall be securely random|
| [1.3.4](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#134-out-of-band-verifier-shall-be-resistant-to-brute-force-attacks) | Out of band verifier shall be resistant to brute force attacks|

---
# 2 Session Management
## 2.1 URLs shall not expose authentication material
### Description
Web applications must never expose authentication material, such as passwords or session cookies, within URL parameters. Authentication material should be transmitted securely, such as within HTTP headers or cookies with appropriate security flags.
### Rationale
Exposing authentication material such as session tokens in URLs significantly increases the risk of data loss and session hijacking. Attackers can easily intercept this data through browser history, network sniffing, or by tricking users into visiting malicious links.  This vulnerability undermines data protection, the security of user sessions and makes the application susceptible to unauthorized access
### Scope
- Web application
### Audit
| Spec | Description |
| --- | ------|
| [2.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#211-the-application-shall-not-reveal-passwords-or-session-tokens-in-url-parameters-in-cases-where-the-application-provides-an-api-the-application-shall-prevent-or-give-developers-an-option-to-prevent-exposing-sensitive-information-like-api-keys-or-session-tokens-within-the-url-query-strings) | The application shall not reveal passwords or session tokens in URL parameters. In cases where the application provides an API, the application shall prevent (or give developers an option) to prevent exposing sensitive information like API keys or session tokens within the URL query strings|

---
## 2.2 Implement session invalidation on logout, user request, and password change
### Description
The application must invalidate session tokens upon logout, expiration, and shall provide the option (or acts by default) to terminate other active sessions after a successful password change (including reset).
### Rationale
These features protect against unauthorized access.  Logouts and expirations prevent lingering sessions, while password-change termination deters attackers who might know an old password.  Session visibility and control let users proactively manage their account, ensuring that only authorized devices are actively associated with their profile.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [2.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#221-users-shall-have-the-ability-to-logout-of-the-application-logout-or-session-expiration-shall-invalidate-all-stateful-session-tokens-including-refresh-tokens) | Users shall have the ability to logout of the application. Logout or session expiration shall invalidate all stateful session tokens, including refresh tokens.|
| [2.2.2](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#222-the-application-shall-provide-the-option-or-acts-by-default-to-terminate-all-other-active-sessions-including-stateful-refresh-tokens-after-a-successful-password-change-including-change-via-password-resetrecovery-and-that-this-is-effective-across-the-application-federated-login-if-present-and-any-relying-parties) | The application shall provide the option (or acts by default) to terminate all other active sessions, including stateful refresh tokens, after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties.|
| [2.2.3](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#223-non-revocable-stateless-authentication-tokens-must-expire-within-24-hours-of-being-issued) | Non-revocable sateless authentication tokens must expire within 24 hours of being issued|

---
## 2.3 Implement and secure application session tokens
### Description
When using cookie-based session tokens, the application must enforce the 'Secure' attribute (ensuring transmission only over HTTPS) and the 'HttpOnly' attribute (preventing access by client-side JavaScript).  The application prioritizes session tokens over static API keys, except where legacy systems necessitate static secrets.
### Rationale
Secure' and 'HttpOnly' mitigate risks of token interception and Cross-Site Scripting (XSS) attacks, enhancing session security. Session tokens, being temporary and user-specific, offer better control and auditing compared to long-lived API secrets, making them the preferred approach for modern applications.
### Scope
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [2.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#231-cookie-based-session-tokens-shall-have-the-secure-attribute-set) | Cookie-based session tokens shall have the 'Secure' attribute set.|
| [2.3.2](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#232-cookie-based-session-tokens-shall-have-the-httponly-attribute-set) | Cookie-based session tokens shall have the 'HttpOnly' attribute set.|
| [2.3.3](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#233-the-application-shall-use-session-tokens-rather-than-static-api-secrets-and-keys-except-with-legacy-implementations) | The application shall use session tokens rather than static API secrets and keys, except with legacy implementations.|
| [2.3.4](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#234-stateless-session-tokens-shall-use-digital-signatures-encryption-and-other-countermeasures-to-protect-against-tampering-enveloping-replay-null-cipher-and-key-substitution-attacks) | Stateless session tokens shall use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.|

---
## 2.4 Protect sensitive account modifications
### Description
Applications must enforce a complete, valid login session or require re-authentication/secondary verification prior to any sensitive actions, such as sensitive data transactions or changes to account settings.
### Rationale
This requirement prevents unauthorized access to sensitive parts of an application.  Even if an attacker partially compromises a session, re-authentication or secondary checks create an extra barrier. It helps mitigate session hijacking attempts and safeguards user data,  promoting overall account security.
### Scope
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [2.4.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#241-verify-the-application-ensures-a-full-valid-login-session-or-requires-re-authentication-or-secondary-verification-before-allowing-any-sensitive-transactions-or-account-modifications) | Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.|

---
# 3 Access Control
## 3.1 Implement access control mechanisms to protect data and APIs
### Description
Applications shall enforce robust access controls at a trusted service layer, ensuring data integrity and applying the principle of least privilege. This includes protecting user/data attributes, limiting user manipulation, failing securely during exceptions, defending against Insecure Direct Object References (IDOR), and using strong anti-CSRF and multi-factor authentication (MFA) for administrative functions.
### Rationale
*Layered Defense*
Combining URI and resource-level checks provides multiple layers of protection, enhancing security against unauthorized access.

*Fine-grained Control*
Resource-level permissions allow for precise control over individual objects or data, while URI-level controls offer broader protection of web resources.

*Flexibility*
This approach supports varying access control needs, ensuring security in diverse application architectures.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [3.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#311-the-application-shall-enforce-least-privilege-access-control-rules-on-a-trusted-service-layer) | The application shall enforce least privilege access control rules on a trusted service layer.|
| [3.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#312-all-user-and-data-attributes-and-policy-information-used-by-access-controls-shall-not-be-able-to-be-manipulated-by-end-users-unless-specifically-authorized) | All user and data attributes and policy information used by access controls shall not be able to be manipulated by end users unless specifically authorized.|
| [3.1.3](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#313-access-controls-shall-fail-securely-including-when-an-exception-occurs) | Access controls shall fail securely including when an exception occurs.|
| [3.1.4](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#314-sensitive-resources-shall-be-protected-against-insecure-direct-object-reference-idor-attacks-targeting-creation-reading-updating-and-deletion-of-records-such-as-creating-or-updating-someone-elses-record-viewing-everyones-records-or-deleting-all-records) | Sensitive resources shall be protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records.|
| [3.1.5](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#315-the-application-or-framework-shall-enforce-a-strong-anti-csrf-mechanism-to-protect-authenticated-functionality-and-effective-anti-automation-or-anti-csrf-protects-unauthenticated-functionality) | The application or framework shall enforce a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality.|
| [3.1.6](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#316-directory-browsing-shall-be-disabled-unless-deliberately-desired) | Directory browsing shall be disabled unless deliberately desired.|

---
## 3.2 Implement secure OAuth integrations to protect user data and prevent unauthorized access
### Description
Applications which support OAuth integrations shall follow established security guidelines to safeguard user data and prevent unauthorized access.

### Rationale
OAuth is a widely adopted authorization framework that allows users to grant third-party applications limited access to their resources on another service without sharing their login credentials. However, if not implemented securely, OAuth can expose users to various attacks, including account compromises and information disclosure. By securely implementing OAuth integrations, the application minimizes these risks and provides users with a more secure experience.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [3.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#321-application-shall-implement-only-secure-and-recommended-oauth-20-flows-such-as-the-authorization-code-flow-or-the-authorization-code-flow-with-pkce-while-avoiding-the-use-of-deprecated-flows-like-the-implicit-flow-or-the-resource-owner-password-credentials-flow) | Application shall implement only secure and recommended OAuth 2.0 flows, such as the Authorization Code Flow or the Authorization Code Flow with PKCE, while avoiding the use of deprecated flows like the Implicit Flow or the Resource Owner Password Credentials Flow.|
| [3.2.2](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#322-ensure-that-the-application-securely-validates-the-redirect_uri-and-state-parameters-during-the-oauth-20-authorization-process-to-prevent-open-redirect-and-csrf-vulnerabilities) | Ensure that the application securely validates the redirect_uri and state parameters during the OAuth 2.0 authorization process to prevent open redirect and CSRF vulnerabilities. |

---
## 3.3 Application exposed administrative interfaces shall use appropriate multi-factor authentication.
### Description
Application exposed administrative interfaces shall implement multi-factor authentication. These interfaces shall be limited to application layer functionality and must not expose the cloud infrastructure.
### Rationale
Infrastructure administrative interfaces shall never be exposed through an internet facing interface. However, there are many cases where application layer administrative tasks may need to be exposed to the internet. It is critical that these interfaces be limited in functionality and always implement multi-factor authentication to prevent attackers from compromising administrative accounts.
### Scope
- Web application
### Audit
| Spec | Description |
| --- | ------|
| [3.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#331-application-administrative-interfaces-shall-use-appropriate-multi-factor-authentication-to-prevent-unauthorized-use) | Application administrative interfaces shall use appropriate multi-factor authentication to prevent unauthorized use.|

---
# 4 Communications
## 4.1 Protect data through strong cryptography
### Description
Applications must enforce strong TLS configurations and cryptographic practices. This includes using up-to-date tools to enable only strong cipher suites (prioritizing the strongest), employing trusted TLS certificates, and ensuring secure failure modes in cryptographic modules to mitigate common cryptographic attacks.
### Rationale
Strong TLS and cipher suites ensure confidentiality and integrity of data in transit by protecting against eavesdropping and modification. Trusted TLS certificates verify authenticity and prevent adversary-in-the-middle attacks, while secure failure modes and robust cryptography deter advanced attacks exploiting weaknesses in cryptographic implementations.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [4.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#411-application-shall-enforce-the-use-of-tls-for-all-connections-and-default-to-tls-12-in-cases-where-support-for-legacy-clients-is-necessary-tls-10-and-11-may-be-supported-if-mitigations-are-implemented-to-minimize-the-risk-of-downgrade-attacks-and-known-tls-exploits-regardless-of-the-tls-version-in-use-the-application-shall-default-to-secure-cipher-suites-and-reject-those-with-known-vulnerabilities) | Application shall enforce the use of TLS for all connections and default to TLS 1.2+. In cases where support for legacy clients is necessary, TLS 1.0 and 1.1 may be supported if mitigations are implemented to minimize the risk of downgrade attacks and known TLS exploits. Regardless of the TLS version in use, the application shall default to secure cipher suites and reject those with known vulnerabilities.|
| [4.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#412-connections-to-and-from-the-server-shall-use-trusted-tls-certificates-where-internally-generated-or-self-signed-certificates-are-used-the-server-must-be-configured-to-only-trust-specific-internal-cas-and-specific-self-signed-certificates-all-others-should-be-rejected) | Connections to and from the server shall use trusted TLS certificates. Where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs and specific self-signed certificates. All others should be rejected.|
| [4.1.3](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#413-no-instances-of-weak-cryptography-which-meaningfully-impact-the-confidentiality-or-integrity-of-sensitive-data) | No instances of weak cryptography which meaningfully impact the confidentiality or integrity of confidential data.|
| [4.1.4](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#414-all-cryptographic-modules-shall-fail-securely-and-errors-are-handled-in-a-way-that-does-not-enable-padding-oracle-attacks) | All cryptographic modules shall fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.|

---
# 5 Data Validation and Sanitization
## 5.1 Implement validation & input sanitation
### Description
Web applications must implement robust input validation and output encoding to defend against a wide range of injection attacks. This includes protecting against HTTP Parameter Pollution, XSS (reflected, stored, and DOM-based), SQL injection, OS command injection, file inclusion vulnerabilities, template injection, SSRF, XPath/XML injection, and unsafe use of dynamic code execution features (like eval()).
### Rationale
Robust input validation and output encoding is essential for web applications to effectively defend against multiple injection attack types. Injection attacks pose a significant risk for web applications due to their simplicity and ease of automation, enabling potential attackers to readily target vulnerable sites. By implementing secure input validation, web applications can significantly reduce the risk of attackers exploiting injection vulnerabilities to gain unauthorized access, manipulate data, or compromise systems.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [5.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#511-protect-against-http-parameter-pollution) | Protect against HTTP parameter pollution.|
| [5.1.2](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#512-url-redirects-and-forwards-are-limited-to-allowlisted-urls-or-a-warning-is-displayed-when-redirecting-to-untrusted-content) | URL redirects and forwards are limited to allowlisted URLs or a warning is displayed when redirecting to untrusted content.|
| [5.1.3](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#513-avoid-the-use-of-eval-or-other-dynamic-code-execution-features-when-there-is-no-alternative-any-user-input-is-sanitized-and-sandboxed-before-being-executed) | Avoid the use of eval() or other dynamic code execution features. When there is no alternative, any user input is sanitized and sandboxed before being executed.|
| [5.1.4](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#514-protect-against-template-injection-attacks-by-ensuring-that-any-user-input-being-included-is-sanitized-or-sandboxed) | Protect against template injection attacks by ensuring that any user input being included is sanitized or sandboxed.|
| [5.1.5](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#515-prevent-server-side-request-forgery-ssrf) | Prevent Server-Side Request Forgery (SSRF)|
| [5.1.6](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#516-protect-against-xpath-or-xml-injection-attacks) | Protect against XPath or XML injection attacks|
| [5.1.7](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#517-context-aware-output-escaping-or-sanitization-protects-against-reflected-stored-and-dom-based-xss) | Context-aware output escaping or sanitization protects against reflected, stored, and DOM based XSS.|
| [5.1.8](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#518-protect-against-database-injection-attacks) | Protect against database injection attacks|
| [5.1.9](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#519-protect-against-os-command-injections) | Protect against OS command injections|
| [5.1.10](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#5110-protect-against-local-file-inclusion-or-remote-file-inclusion-attacks) | Protect against local file inclusion or remote file inclusion attacks|

---
## 5.2 Securely Handle Untrusted Files
### Description
Web applications must safely process and manage files that originate from untrusted or unknown sources. This includes restricting uploads to expected file types and preventing direct execution of uploaded content containing HTML, JavaScript, or dynamic server-side code.
### Rationale
Files from untrusted sources may contain malicious code which could allow compromise of the application. If these files are executed directly, they can compromise the security of the web application, leading to unauthorized access, data breaches, or other harmful actions.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [5.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#521-protect-against-malicious-file-uploads-by-limiting-uploads-to-expected-file-types-and-preventing-direct-execution-of-uploaded-content) | Protect against malicious file uploads by limiting uploads to expected file types and preventing direct execution of uploaded content.|

---
# 6 Configuration
## 6.1 Keep all components up to date
### Description
Developers must verify that the libraries included in their application do not have any known exploitable vulnerabilities.
### Rationale
Attackers can perform automated scans to identify vulnerable applications based on published vulnerabilities.
### Scope
- Web application
### Audit
| Spec | Description |
| --- | ------|
| [6.1.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#611-the-application-only-uses-software-components-without-known-exploitable-vulnerabilities) | The app only uses software components without known exploitable vulnerabilities.|

---
## 6.2 Disable debug modes in production environments
### Description
Applications must strictly disable all debug modes before deployment into production environments.
### Rationale
Debug modes often expose sensitive information like stack traces, code internals, and environment variables. This information can aid attackers in understanding the application's structure and identifying vulnerabilities, significantly increasing the risk of targeted attacks and exploitation. Disabling debug modes removes this unnecessary risk in production.
### Scope
- Web application
### Audit
| Spec | Description |
| --- | ------|
| [6.2.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#621-disable-debug-modes-in-production-environments) | Disable debug modes in production environments|

---
## 6.3 The origin header shall not be used for authentication of access control decisions
### Description
The application must never rely solely on the Origin HTTP header for authentication or access control decisions.
### Rationale
The Origin header can be easily manipulated by attackers, making it an unreliable indicator of a request's true source. This could lead to unauthorized access if an application mistakenly trusts requests based on a forged  Origin header. Security mechanisms must use more robust and tamper-proof methods for authentication and authorization.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [6.3.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#631-the-origin-header-shall-not-be-used-for-authentication-of-access-control-decisions) | The origin header shall not be used for authentication of access control decisions|

---
## 6.4 Protect Application from Subdomain Takeover
### Description
The application must implement safeguards to prevent subdomain takeover vulnerabilities. This includes proactive identification and removal of dangling DNS records (e.g., CNAME records pointing to decommissioned services) and regular monitoring of third-party services integrated with the application's domains.
### Rationale
Dangling DNS records and vulnerable third-party services can allow attackers to take control of subdomains. This could enable them to host malicious content on the application's domain, harming reputation and potentially leading to phishing attacks or the compromise of user data.
### Scope
- Web application
### Audit
| Spec | Description |
| --- | ------|
| [6.4.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#641-the-application-shall-not-be-susceptible-to-subdomain-takeovers) | The application shall not be susceptible to subdomain takeovers.|

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
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [6.5.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#651-the-application-shall-not-log-credentials-or-payment-details-session-tokens-shall-only-be-stored-in-logs-in-an-irreversible-hashed-form) | The application shall not log credentials or payment details. Session tokens shall only be stored in logs in an irreversible, hashed form.|

---
## 6.6 Securely clear client storage during logout
### Description
Web applications should ensure that any confidential data or authentication material stored in the browser's local storage is deleted or otherwise rendered inaccessible when the user logs out.
### Rationale
Properly deleting confidential data and authentication material after logout decreases the risk that an attacker with local access to the system will be able to compromise the data. This is particularly relevant in scenarios where users are logging in from shared systems or devices.
### Scope
- Web application
### Audit
| Spec | Description |
| --- | ------|
| [6.6.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#661-browser-storage-is-securely-cleared-during-logout) | Browser storage is securely cleared during logout.|

---
## 6.7 Securely store server-side secrets
### Description
Ensure server-side secrets are stored securely using an appropriate secrets management approach which provides encryption, access controls, and monitoring to prevent unauthorized access and maintain data confidentiality.
### Rationale
Secrets management helps protect API keys, access tokens, and other server-side secrets used by the application from being accessed or stolen by unauthorized parties.
### Scope
- Web application
- Web and mobile APIs
### Audit
| Spec | Description |
| --- | ------|
| [6.7.1](https://github.com/appdefensealliance/ASA-WG/blob/main/Web%20App%20Profile/Web%20App%20Test%20Guide.md#671-the-application-shall-securely-store-access-tokens-api-keys-and-other-server-side-secrets) | The application shall securely store access tokens, API keys, and other server-side secrets.|
