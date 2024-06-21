# App Defense Alliance Web Application Testing Guide 
Version 0.7 - May 25, 2024


# Revision History
| Version | Date  | Description|
|----|----|-----------------|
| 0.5 | 5/25/24 | Initial draft based on Web App Tiger Team review of ASVS specification |
| 0.7 | 5/25/24 | Updates from Tiger Team review of 0.5 spec |


# Table of Contents
1 [Authentication](#1-authentication)

1.1 [Implement strong password security measures](#11-implement-strong-password-security-measures)

1.1.1 [Authentication is resistant to brute force attacks](#111-authentication-is-resistant-to-brute-force-attacks)

1.1.2 [System generated initial passwords or activation codes shall be securely randomly generated and expire after a short period.](#112-system-generated-initial-passwords-or-activation-codes-shall-be-securely-randomly-generated-and-expire-after-a-short-period)

1.1.3 [Passwords shall be stored in a form that is resistant to offline attacks.](#113-passwords-shall-be-stored-in-a-form-that-is-resistant-to-offline-attacks)

1.2 [Disable any default accounts for public application access interfaces](#12-disable-any-default-accounts-for-public-application-access-interfaces)

1.2.1 [Default credentials shall not be present on publicly exposed interfaces.](#121-default-credentials-shall-not-be-present-on-publicly-exposed-interfaces)

1.3 [Out of band verifiers shall be random and not reused](#14-out-of-band-verifiers-shall-be-random-and-not-reused)

1.3.1 [Out of band verifier shall expire after 7 days.](#141-out-of-band-verifier-shall-expire-after-7-days)

1.3.2 [Out of band verifier shall only be used once.](#142-out-of-band-verifier-shall-only-be-used-once)

1.3.3 [Out of band verifier shall be securely random](#143-out-of-band-verifier-shall-be-securely-random)

2 [Session Management](#2-session-management)

2.1 [URLs shall not expose sensitive information](#21-urls-shall-not-expose-sensitive-information)

2.1.1 [The application shall not reveal passwords or session tokens in URL parameters. In cases where the application provides an API, the application shall prevent (or give developers an option to prevent) exposing sensitive information like API keys or session tokens within the URL query strings.](#211-the-application-shall-not-reveal-passwords-or-session-tokens-in-url-parameters-in-cases-where-the-application-provides-an-api-the-application-shall-prevent-or-give-developers-an-option-to-prevent-exposing-sensitive-information-like-api-keys-or-session-tokens-within-the-url-query-strings)

2.2 [Implement Session Invalidation on Logout, User Request, and Password Change](#22-implement-session-invalidation-on-logout-user-request-and-password-change)

2.2.1 [Users shall have the ability to logout of the application. Logout or session expiration shall invalidate all stateful session tokens, including refresh tokens.](#221-users-shall-have-the-ability-to-logout-of-the-application-logout-or-session-expiration-shall-invalidate-all-stateful-session-tokens-including-refresh-tokens)

2.2.2 [The application shall provide the option (or acts by default) to terminate all other active sessions, including stateful refresh tokens, after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties.](#222-the-application-shall-provide-the-option-or-acts-by-default-to-terminate-all-other-active-sessions-including-stateful-refresh-tokens-after-a-successful-password-change-including-change-via-password-resetrecovery-and-that-this-is-effective-across-the-application-federated-login-if-present-and-any-relying-parties)

2.2.3 [Stateless authentication tokens must expire within 24 hours of being issued](#223-stateless-authentication-tokens-must-expire-within-24-hours-of-being-issued)

2.3 [Implement and Secure Application Session Tokens](#23-implement-and-secure-application-session-tokens)

2.3.1 [Cookie-based session tokens shall have the 'Secure' attribute set.](#231-cookie-based-session-tokens-shall-have-the-secure-attribute-set)

2.3.2 [Cookie-based session tokens shall have the 'HttpOnly' attribute set.](#232-cookie-based-session-tokens-shall-have-the-httponly-attribute-set)

2.3.3 [The application shall use session tokens rather than static API secrets and keys, except with legacy implementations.](#233-the-application-shall-use-session-tokens-rather-than-static-api-secrets-and-keys-except-with-legacy-implementations)

2.3.4 [Stateless session tokens shall use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.](#234-stateless-session-tokens-shall-use-digital-signatures-encryption-and-other-countermeasures-to-protect-against-tampering-enveloping-replay-null-cipher-and-key-substitution-attacks)

2.4 [Protect Sensitive Account Modifications](#24-protect-sensitive-account-modifications)

2.4.1 [Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.](#241-verify-the-application-ensures-a-full-valid-login-session-or-requires-re-authentication-or-secondary-verification-before-allowing-any-sensitive-transactions-or-account-modifications)

3 [Access Control](#3-access-control)

3.1 [Implement access control mechanisms to protect sensitive data and APIs](#31-implement-access-control-mechanisms-to-protect-sensitive-data-and-apis)

3.1.1 [The application shall enforce least privilege access control rules on a trusted service layer.](#311-the-application-shall-enforce-least-privilege-access-control-rules-on-a-trusted-service-layer)

3.1.2 [All user and data attributes and policy information used by access controls shall not be able to be manipulated by end users unless specifically authorized.](#312-all-user-and-data-attributes-and-policy-information-used-by-access-controls-shall-not-be-able-to-be-manipulated-by-end-users-unless-specifically-authorized)

3.1.3 [Access controls shall fail securely including when an exception occurs.](#313-access-controls-shall-fail-securely-including-when-an-exception-occurs)

3.1.4 [Sensitive resources shall be protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records.](#314-sensitive-resources-shall-be-protected-against-insecure-direct-object-reference-idor-attacks-targeting-creation-reading-updating-and-deletion-of-records-such-as-creating-or-updating-someone-elses-record-viewing-everyones-records-or-deleting-all-records)

3.1.5 [The application or framework shall enforce a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality.](#315-the-application-or-framework-shall-enforce-a-strong-anti-csrf-mechanism-to-protect-authenticated-functionality-and-effective-anti-automation-or-anti-csrf-protects-unauthenticated-functionality)

3.1.6 [Directory browsing shall be disabled unless deliberately desired.](#316-directory-browsing-shall-be-disabled-unless-deliberately-desired)

3.2 [Implement secure OAuth integrations to protect user data and prevent unauthorized access](#32-implement-secure-oauth-integrations-to-protect-user-data-and-prevent-unauthorized-access)

3.2.1 [Application shall implement only secure and recommended OAuth 2.0 flows, such as the Authorization Code Flow or the Authorization Code Flow with PKCE, while avoiding the use of deprecated flows like the Implicit Flow or the Resource Owner Password Credentials Flow.](#321-application-shall-implement-only-secure-and-recommended-oauth-20-flows-such-as-the-authorization-code-flow-or-the-authorization-code-flow-with-pkce-while-avoiding-the-use-of-deprecated-flows-like-the-implicit-flow-or-the-resource-owner-password-credentials-flow)

3.2.2 [Ensure that the application securely validates the redirect_uri and state parameters during the OAuth 2.0 authorization process to prevent open redirect and CSRF vulnerabilities.](#322-ensure-that-the-application-securely-validates-the-redirect_uri-and-state-parameters-during-the-oauth-20-authorization-process-to-prevent-open-redirect-and-csrf-vulnerabilities)

3.3 [Application exposed administrative interfaces shall use appropriate multi-factor authentication.](#33-application-exposed-administrative-interfaces-shall-use-appropriate-multi-factor-authentication)

3.3.1 [Application administrative interfaces shall use appropriate multi-factor authentication to prevent unauthorized use.](#331-application-administrative-interfaces-shall-use-appropriate-multi-factor-authentication-to-prevent-unauthorized-use)

4 [Communications](#4-communications)

4.1 [Protect Sensitive Data Through Strong Cryptography](#41-protect-sensitive-data-through-strong-cryptography)

4.1.1 [Application shall enforce the use of TLS for all connections and default to TLS 1.2+.](#411-application-shall-enforce-the-use-of-tls-for-all-connections-and-default-to-tls-12-in-cases-where-support-for-legacy-clients-is-necessary-tls-10-and-11-may-be-supported-if-mitigations-are-implemented-to-minimize-the-risk-of-downgrade-attacks-and-known-tls-exploits-regardless-of-the-tls-version-in-use-the-application-shall-default-to-secure-cipher-suites-and-reject-those-with-known-vulnerabilities)

4.1.2 [Connections to and from the server shall use trusted TLS certificates.](#412-connections-to-and-from-the-server-shall-use-trusted-tls-certificates-where-internally-generated-or-self-signed-certificates-are-used-the-server-must-be-configured-to-only-trust-specific-internal-cas-and-specific-self-signed-certificates-all-others-should-be-rejected)

4.1.3 [No instances of weak cryptography which meaningfully impact the confidentiality or integrity of sensitive data.](#413-no-instances-of-weak-cryptography-which-meaningfully-impact-the-confidentiality-or-integrity-of-sensitive-data)

4.1.4 [All cryptographic modules shall fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.](#414-all-cryptographic-modules-shall-fail-securely-and-errors-are-handled-in-a-way-that-does-not-enable-padding-oracle-attacks)

5 [Data Validation and Sanitization](#5-data-validation-and-sanitization)

5.1 [Implement Validation & Input Sanitation](#51-implement-validation--input-sanitation)

5.1.1 [Protect against HTTP parameter pollution.](#511-protect-against-http-parameter-pollution)

5.1.2 [URL redirects and forwards are limited to allowlisted URLs or a warning is displayed when redirecting to untrusted content.](#512-url-redirects-and-forwards-are-limited-to-allowlisted-urls-or-a-warning-is-displayed-when-redirecting-to-untrusted-content)

5.1.3 [Avoid the use of eval() or other dynamic code execution features. When there is no alternative, any user input is sanitized and sandboxed before being executed.](#513-avoid-the-use-of-eval-or-other-dynamic-code-execution-features-when-there-is-no-alternative-any-user-input-is-sanitized-and-sandboxed-before-being-executed)

5.1.4 [Protect against template injection attacks by ensuring that any user input being included is sanitized or sandboxed.](#514-protect-against-template-injection-attacks-by-ensuring-that-any-user-input-being-included-is-sanitized-or-sandboxed)

5.1.5 [Prevent Server-Side Request Forgery SSRF](#515-prevent-server-side-request-forgery-ssrf)

5.1.6 [Sanitize, disable, or sandbox user supplied SVG files](#516-sanitize-disable-or-sandbox-user-supplied-svg-files)

5.1.7 [Protect against XPath or XML injection attacks](#517-protect-against-xpath-or-xml-injection-attacks)

5.1.8 [Context-aware output escaping or sanitization protects against reflected, stored, and DOM based XSS.](#518-context-aware-output-escaping-or-sanitization-protects-against-reflected-stored-and-dom-based-xss)

5.1.9 [Protect against database injection attacks](#519-protect-against-database-injection-attacks)

5.1.10 [Protect against OS command injections](#5110-protect-against-os-command-injections)

5.1.11 [Protect against local file inclusion or remote file inclusion attacks](#5111-protect-against-local-file-inclusion-or-remote-file-inclusion-attacks)

5.2 [Securely Handle Untrusted Files](#52-securely-handle-untrusted-files)

5.2.1 [Protect against malicious file uploads by limiting uploads to expected file types and preventing direct execution of uploaded content.](#521-protect-against-malicious-file-uploads-by-limiting-uploads-to-expected-file-types-and-preventing-direct-execution-of-uploaded-content)

6 [Configuration](#6-configuration)

6.1 [Keep all components up to date](#61-keep-all-components-up-to-date)

6.1.1 [The application only uses software components without known exploitable vulnerabilities.](#611-the-application-only-uses-software-components-without-known-exploitable-vulnerabilities)

6.2 [Disable debug modes in production environments](#62-disable-debug-modes-in-production-environments)

6.2.1 [Disable debug modes in production environments](#621-disable-debug-modes-in-production-environments)

6.3 [The origin header shall not be used for authentication of access control decisions](#63-the-origin-header-shall-not-be-used-for-authentication-of-access-control-decisions)

6.3.1 [The origin header shall not be used for authentication of access control decisions](#631-the-origin-header-shall-not-be-used-for-authentication-of-access-control-decisions)

6.4 [Protect Application from Subdomain Takeover](#64-protect-application-from-subdomain-takeover)

6.4.1 [The application shall not be susceptible to subdomain takeovers.](#641-the-application-shall-not-be-susceptible-to-subdomain-takeovers)

6.5 [Do not log credentials or payment details](#65-do-not-log-credentials-or-payment-details)

6.5.1 [The application shall not log credentials or payment details. Session tokens shall only be stored in logs in an irreversible, hashed form.](#651-the-application-shall-not-log-credentials-or-payment-details-session-tokens-shall-only-be-stored-in-logs-in-an-irreversible-hashed-form)

6.6 [Sensitive user data is either not stored in browser storage or is deleted when the user logs out](#66-sensitive-user-data-is-either-not-stored-in-browser-storage-or-is-deleted-when-the-user-logs-out)

6.6.1 [If data is stored in browser storage it shall not contain sensitive data.](#661-if-data-is-stored-in-browser-storage-it-shall-not-contain-sensitive-data)

6.7 [Securely store server-side secrets](#67-securely-store-server-side-secrets)

6.7.1 [The application shall securely store access tokens, API keys, and other server-side secrets.](#671-the-application-shall-securely-store-access-tokens-api-keys-and-other-server-side-secrets)


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


---
### 1.1.1 Authentication is resistant to brute force attacks
External Reference: ASVS Version 4.0.3 Requirement: 2.2.1


**Evidence**


*L1*
1. Provide a list of any external user authentication services.
2. If a proprietary user authentication service is used by the application, provide a written description of the password policy
3. If a proprietary user authentication service is used by the application, provide a written description of any anti-automation controls in place including rate limiting, CAPTCHAs, or soft account lockouts.
4. If a proprietary user authentication service is used by the application, provide screenshots of the anti-automation controls in action.


*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review list of external authentication services against ADA approved services.
2. Review provided evidence for adherence with the requirements

*L2*
1. Review list of external authentication services against ADA approved services.
2. For proprietary authentication services, perform the testing guidance provided by WSTG-ATHN-03 to validate anti-automation controls.


**Verification**


*L1 and L2*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, the application shall enforce at least one of the following controls:
   * 2.1. Rate limiting such that no more than 100 failed attempts on a single account per hour shall be allowed.
   * 2.2. CAPTCHA or other anti-automation controls on failed login attempts to limit the effectiveness of automated credential testing.
   * 2.3. Multi-factor authentication is enforced by default for all users.
   * 2.4. Minimum password length of 8 characters with the prohibition of weak or commonly breached passwords.


---
### 1.1.2 System generated initial passwords or activation codes shall be securely randomly generated and expire after a short period.
External Reference: ASVS Version 4.0.3 Requirement: 2.3.1


**Evidence**


*L1*
1. Provide a list of any external user authentication services.
2. If a proprietary user authentication service is used by the application, provide a written description of the initial password or activation code process. 
3. If a proprietary user authentication service is used by the application, provide screenshots of the initial password or activation code process in action.

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review list of external authentication services against ADA approved services.
2. Review provided evidence for adherence with the requirements.

*L2*
1. Review list of external authentication services against ADA approved services.
2. For proprietary authentication services, evaluate the application's initial password or activation code generation.


**Verification**


*L1*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, initial password or activation codes documentation shall include the following controls:
   * 2.1. The initial password or codes shall be at least 6 characters long.
   * 2.2. The initial password or codes shall contain letters and numbers.
   * 2.3. The initial password or codes shall expire after a short period of time. (24 hours is the recommended period. However, 48 hours is the maximum period allowed.)
   * 2.4. The initial password or codes shall not be permitted to become long term passwords.

*L2*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, initial password or activation codes shall be validated to include the following controls:
   * 2.1. The initial password or codes shall be at least 6 characters long.
   * 2.2. The initial password or codes shall contain letters and numbers.
   * 2.3. The initial password or codes shall expire after a short period of time.(24 hours is the recommended period. However, 48 hours is the maximum period allowed.)
   * 2.4. The initial password or codes shall not be permitted to become long term passwords.



---
### 1.1.3 Passwords shall be stored in a form that is resistant to offline attacks.
External Reference: ASVS Version 4.0.3 Requirement: 2.4.1


**Evidence**


*L1 and L2*
1. Provide a list of any external user authentication services.
2. If a proprietary user authentication service is used by the application, provide a written description of the password storage methods including any cryptographic protections such as salts or hashing.



**Test Procedure**


*L1 and L2*
1. Review list of external authentication services against ADA approved services.
2. Review provided evidence for adherence with the requirements.



**Verification**


*L1 and L2*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, cryptographic hashing methods shall follow industry best practices. The list of approved one-way key derivation functions is detailed in NIST 800-63 B section 5.1.1.2.



---
## 1.2 Disable any default accounts for public application access interfaces
### Description
Applications should not have any pre-configured or default user accounts that can be used to access its public-facing interfaces. This includes both user and administrative accounts that come with default credentials.
### Rationale
Default accounts can be easily discovered through publicly available documentation, online forums, or other sources, making them an attractive target for attackers. If an attacker is able to gain access to a default account, they may be able to escalate their privileges and move laterally within the application or underlying infrastructure.
### Audit


---
### 1.2.1 Default credentials shall not be present on publicly exposed interfaces.
External Reference: ASVS Version 4.0.3 Requirement: 2.5.4


**Evidence**


*L1*
1. If any default accounts are present on publicly exposed interfaces, a confirmation that default credentials are not used shall be provided.

*L2*
1. N/A (to be collected by labs)
   
**Test Procedure**


*L1*
1. Review provided evidence for adherence with the requirements.

*L2*
1. Perform the testing guidance provided by WSTG-ATHN-02 to validate default credentials are not present on publicly exposed interfaces.


**Verification**


*L1*
1. Default credentials shall not be present on publicly exposed interfaces.

*L2*
1. Test results from WSTG-ATHN-02 shall not detect the use of default credentials on publicly exposed interfaces.

---
## 1.3 Out of band verifiers shall be random and not reused
### Description
Any verification codes or tokens sent through out-of-band methods (such as SMS or email) should have sufficient entropy along with a suitable expiration duration. Once a verifier has been used or has expired, it should be invalidated and a new one should be generated for each subsequent verification attempt.
### Rationale
By ensuring that out of band verifiers are securely generated and managed, the risk of an adversary intercepting and using these verifiers is significantly reduced.
### Audit


---
### 1.3.1 Out of band verifier shall expire after 7 days.
External Reference: ASVS Version 4.0.3 Requirement: 2.7.2


**Evidence**


*L1 and L2*
1. Provide a list of any external user authentication services.
2. If a proprietary user authentication service is used by the application, provide a written description of the out of band verifier expiration process.



**Test Procedure**


*L1 and L2*
1. Review list of external authentication services against ADA approved services.
2. Review provided evidence for adherence with the requirements



**Verification**


*L2 and l2*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, the out-of-band verifier shall expire after 7 days.


---
### 1.3.2 Out of band verifier shall only be used once.
External Reference: ASVS Version 4.0.3 Requirement: 2.7.3


**Evidence**


*L1*
1. Provide a list of any external user authentication services.
2. If a proprietary user authentication service is used by the application, provide a written description of the out of band expiration process.

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review list of external authentication services against ADA approved services.
2. Review provided evidence for adherence with the requirements

*L2*
1. Review list of external authentication services against ADA approved services.
2. For proprietary authentication services, evaluate the application out of band verifier process.


**Verification**


*L1*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, out of band verifier shall only be used once.

*L2*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, evaluation shall verify that the application does not allow the out of band verifier to be used more than once.


---
### 1.3.3 Out of band verifier shall be securely random
External Reference: ASVS Version 4.0.3 Requirement: 2.7.6


**Evidence**


*L1*
1. Provide a list of any external user authentication services.
2. If a proprietary user authentication service is used by the application, provide a written description of the algorithm used to generate initial authentication codes.

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review list of external authentication services against ADA approved services.
2. Review provided evidence for adherence with the requirements.

*L2*
1. Review list of external authentication services against ADA approved services.
2. From the application, generate at least three initial authentication codes.


**Verification**


*L1*
1. An ADA-approved external user authentication service may be used.
2. Initial authentication code generation shall be securely random (generation of random numbers shall be in a way that is impossible for an attacker to predict or manipulate).

*L2*
1. An ADA-approved external user authentication service may be used.
2. Initial authentication code shall be observed to be random.


---
### 1.4.4 Out of band verifier shall be resistant to brute force attacks
External Reference: ASVS Version 4.0.3 Requirement: 2.7.6


**Evidence**


*L1*
1. Provide a list of any external user authentication services.
2. If a proprietary user authentication service is used by the application, provide a written description of the algorithm used to generate initial authentication codes and also of any rate-limiting applied during the application’s initial authentication code validation process.

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review list of external authentication services against ADA approved services.
2. Review provided evidence for adherence with the requirements.

*L2*
1. Review list of external authentication services against ADA approved services.
2. Validate application’s adherence with the requirements.


**Verification**


*L1*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, authentication codes shall contain at least 20 bits of entropy (typically a six digital random number is sufficient).
3. If a non-ADA approved service is used and the authentication secret has less than 64 bits of entropy, the application shall implement a rate-limiting mechanism.

*L2*
1. An ADA-approved external user authentication service may be used.
2. If a non-ADA approved service is used, evaluation shall verify authentication codes contain at least 20 bits of entropy (typically a six digital random number is sufficient).
3. If a non-ADA approved service is used and the authentication secret has less than 64 bits of entropy, evaluation shall verify the application implements a rate-limiting mechanism.


---
# 2 Session Management
## 2.1 URLs shall not expose sensitive information
### Description
Web applications must never expose sensitive data within URL parameters. Sensitive data should be transmitted securely, such as within HTTP headers or cookies with appropriate security flags.
### Rationale
Exposing sensitive data such as session tokens in URLs significantly increases the risk of data loss and session hijacking. Attackers can easily intercept this data through browser history, network sniffing, or by tricking users into visiting malicious links.  This vulnerability undermines data protection, the security of user sessions and makes the application susceptible to unauthorized access.
### Audit


---
### 2.1.1 The application shall not reveal passwords or session tokens in URL parameters. In cases where the application provides an API, the application shall prevent (or give developers an option to prevent) exposing sensitive information like API keys or session tokens within the URL query strings.
External Reference: ASVS Version 4.0.3 Requirement: 3.1.1


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.

*L2*
1. Perform exposed variable testing procedure defined in WSTG-SESS-04.


**Verification**


*L1*

1. Burp Suite scan shall not identify the following vulnerabilities:
   - 4195072 Password submitted using GET method
   - 4195328 Password returned in URL query string
   - 5244672 Session token in URL

2. Either sensitive information shall not be sent via the URL or an option shall exist to send sensitive data within the HTTP body or via Header values.

*L2*

1. Application requests shall not send passwords or session tokens as a URL parameter and the application API shall not require sensitive data to be sent via the URL.


---
## 2.2 Implement Session Invalidation on Logout, User Request, and Password Change
### Description
The application must invalidate session tokens upon logout, expiration, and shall provide the option (or acts by default) to terminate other active sessions after a successful password change (including reset).
### Rationale
These features protect against unauthorized access.  Logouts and expirations prevent lingering sessions, while password-change termination deters attackers who might know an old password.  Session visibility and control let users proactively manage their account, ensuring that only authorized devices are actively associated with their profile.
### Audit


---
### 2.2.1 Users shall have the ability to logout of the application. Logout or session expiration shall invalidate all stateful session tokens, including refresh tokens.
External Reference: ASVS Version 4.0.3 Requirement: 3.3.1


**Evidence**


*L1*

1. Provide code snippets that show how the logout and expiration functionality is implemented and that demonstrate user session tokens are invalidated when a user logs out or the session is expired.

or;

2. Provide documentation that describes how session tokens are handled on user logout and expiration.

*L2*

1. N/A (to be collected by labs)


**Test Procedure**


*L1*

1. Review evidence to validate logout and session expiration functions meet the specified requirements.

*L2* 

1. Perform session testing procedures defined in WSTG-SESS-06 and WSTG-SESS-07.


**Verification**


*L1*

1. Server-side session invalidation shall occur upon user logout and session expiration.

*L2*

1. Test shall confirm that the application performs server-side session invalidation on user logout and session expiration.


---
### 2.2.2 The application shall provide the option (or acts by default) to terminate all other active sessions, including stateful refresh tokens, after a successful password change (including change via password reset/recovery), and that this is effective across the application, federated login (if present), and any relying parties.
External Reference: ASVS Version 4.0.3 Requirement: 3.3.3


**Evidence**


*L1*
1. Provide code snippets that show how session invalidation is handled for a user after a successful password change.

or;

2. Provide documentation that describes how session invalidation is handled for a user after a successful password change.

*L2*
N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review evidence to validate session termination on password change meets the specified requirements.

*L2*
1. Perform session invalidation testing procedures defined in WSTG-SESS-07.


**Verification**


*L1*
1. User active sessions shall be terminated or an option is given to inactive active sessions on user password change.

*L2*
1. Test shall confirm that application performs server-side session invalidation of user active sessions or option shall be given to inactive active sessions on user password change.


---
### 2.2.3 Stateless authentication tokens must expire within 24 hours of being issued
External Reference: ASVS Version 4.0.3 Requirement: 3.3.4


**Evidence**


*L1*
1. Provide code snippets, screenshot, or documentation that shows the time period for which stateless tokens are valid (if utilized).

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review evidence to validate session expiration meets the specified requirements.

*L2* 
1. Obtain stateless authentication token from target application.


**Verification**


*L1*
1. Stateless authentication tokens shall have an expiration time within 24 hours of being issued.

*L2*
1. Stateless authentication tokens shall have an expiration time within 24 hours of being issued.


---
## 2.3 Implement and Secure Application Session Tokens
### Description
When using cookie-based session tokens, the application must enforce the 'Secure' attribute (ensuring transmission only over HTTPS) and the 'HttpOnly' attribute (preventing access by client-side JavaScript).  The application prioritizes session tokens over static API keys, except where legacy systems necessitate static secrets.
### Rationale
Secure' and 'HttpOnly' mitigate risks of token interception and Cross-Site Scripting (XSS) attacks, enhancing session security. Session tokens, being temporary and user-specific, offer better control and auditing compared to long-lived API secrets, making them the preferred approach for modern applications.
### Audit


---
### 2.3.1 Cookie-based session tokens shall have the 'Secure' attribute set.
External Reference: ASVS Version 4.0.3 Requirement: 3.4.1


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)



**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.

*L2*
1. Perform cookie attribute testing procedure defined in WSTG-SESS-02.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerability:
   - 5243392 TLS cookie without secure flag set

*L2*
1. Test shall confirm that application session cookies shall utilize the "Secure" attribute.


---
### 2.3.2 Cookie-based session tokens shall have the 'HttpOnly' attribute set.
External Reference: ASVS Version 4.0.3 Requirement: 3.4.2


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)



**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.

*L2*
1. Perform cookie attribute testing procedure defined in WSTG-SESS-02.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerability:
   - 500600 Cookie without HttpOnly flag set

*L2*
1. Test shall confirm that application session cookies utilize the "HttpOnly" attribute.


---
### 2.3.3 The application shall use session tokens rather than static API secrets and keys, except with legacy implementations.
External Reference: ASVS Version 4.0.3 Requirement: 3.5.2


**Evidence**


*L1*
1. Provide code snippets of session token creation; showing dynamically generated tokens

or;

2. Provide documentation that describes how session tokens are dynamically generated

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review evidence to validate session tokens meets the specified requirements

*L2* 
1. Perform session token testing procedures defined in WSTG-SESS-03


**Verification**


*L1*
1. Session tokens shall be dynamically generated after user authentication.

*L2*
1. Test shall confirm that application session tokens are dynamically generated and change after user authentication.


---
### 2.3.4 Stateless session tokens shall use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.
External Reference: ASVS Version 4.0.3 Requirement: 3.5.3


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)



**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.

*L2*
1. Perform testing procedures to validate stateless session tokens are securely generated and validated.  Where stateless tokens utilize JSON Web Tokens (JWT), perform testing procedures defined in WSTG-SESS-10.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 2099456 JWT signature not verified
   - 2099457 JWT none algorithm supported

*L2*
1. Test shall confirm that application stateless session token digital signatures are validated using server-side private key.


---
## 2.4 Protect Sensitive Account Modifications 
### Description
Applications must enforce a complete, valid login session or require re-authentication/secondary verification prior to any sensitive actions, such as sensitive data transactions or changes to account settings.
### Rationale
This requirement prevents unauthorized access to sensitive parts of an application.  Even if an attacker partially compromises a session, re-authentication or secondary checks create an extra barrier. It helps mitigate session hijacking attempts and safeguards user data, promoting overall account security.
### Audit


---
### 2.4.1 Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any sensitive transactions or account modifications.
External Reference: ASVS Version 4.0.3 Requirement: 3.7.1


**Evidence**


*L1*
1. Provide code snippets that shows either the user has a full login session or an account verification process is conducted before allowing user account modifications or sensitive data transaction

or;

2. Provide documentation that describes either the user has a full login session or an account verification process is conducted before allowing user account modifications or sensitive data transaction

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review evidence to validate user authentication meets the specified requirements

*L2* 
1. Perform state and authentication testing procedures defined in WSTG-SESS-01


**Verification**


*L1*
1. Either the user shall have a full login session or an account verification process shall be conducted before allowing user account modifications or transaction against sensitive data.

*L2*
1. Test shall confirm that a user is required to have a full login session or an account verification process is conducted before allowing user account modifications or transaction against sensitive data.


---
# 3 Access Control
## 3.1 Implement access control mechanisms to protect sensitive data and APIs
### Description
Applications shall enforce robust access controls at a trusted service layer, ensuring data integrity and applying the principle of least privilege. This includes protecting user/data attributes, limiting user manipulation, failing securely during exceptions, defending against Insecure Direct Object References (IDOR), and using strong anti-CSRF and multi-factor authentication (MFA) for administrative functions.
### Rationale
Resource-level permissions allow for precise control over individual objects or data, while URI-level controls offer broader protection of web resources. Combining URI and resource-level checks provides multiple layers of protection, enhancing security against unauthorized access.
### Audit


---
### 3.1.1 The application shall enforce least privilege access control rules on a trusted service layer.
External Reference: ASVS Version 4.0.3 Requirement: 4.1.1


**Evidence**


*L1*
1. Explain / Provide documentation how user authentication and authorization are implemented, what roles and permissions are defined, and how access control rules are enforced when users interact with the application.
2. Explain / Provide documentation that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization.
Note: A single written description shall be used for access control test cases 3.1.1 - 3.1.5.

*L2*
1. N/A (to be collected by labs)



**Test Procedure**


*L1*
1. Review provided evidence for adherence with the requirements

*L2*
1. Perform authorization bypass testing as defined in WSTG-ATHZ-02.


**Verification**


*L1*
1. Application shall enforce access control rules on a trusted service layer.

*L2*
1. Access control decisions shall be uniformly enforced on a trusted service layer.


---
### 3.1.2 All user and data attributes and policy information used by access controls shall not be able to be manipulated by end users unless specifically authorized.
External Reference: ASVS Version 4.0.3 Requirement: 4.1.2


**Evidence**


*L1*
1. Explain / Provide documentation how user authentication and authorization are implemented, what roles and permissions are defined, and how access control rules are enforced when users interact with the application.
2. Explain / Provide documentation that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization.
Note: A single written description shall be used for access control test cases 3.1.1 - 3.1.5.

*L2*
1. N/A (to be collected by labs)

**Test Procedure**


*L1*
1. Review provided evidence for adherence with the requirements.

*L2*
1. Perform authorization bypass testing as defined in WSTG-ATHZ-02.


**Verification**


*L1*
1. User and data attributes and policy information used by access controls shall not be manipulated by the end user.

*L2*
1. Test shall confirm that access controls are not be able to be manipulated by the end user unless specifically authorized.


---
### 3.1.3 Access controls shall fail securely including when an exception occurs.
External Reference: ASVS Version 4.0.3 Requirement: 4.1.5


**Evidence**


*L1*
1. Explain / Provide documentation how user authentication and authorization are implemented, what roles and permissions are defined, and how access control rules are enforced when users interact with the application.
2. Explain / Provide documentation that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization.
Note: A single written description shall be used for access control test cases 3.1.1 - 3.1.5.

*L2*
1. N/A (to be collected by labs)



**Test Procedure**


*L1*
1. Review provided evidence for adherence with the requirements.

*L2*
1. Perform testing for improper access control error handling as defined in WSTG-ERRH-01.


**Verification**


*L1*
1. Access controls shall fail securely.

*L2*
1. Test shall confirm that the application's access controls securely failed closed including when an exception occurs.


---
### 3.1.4 Sensitive resources shall be protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records.
External Reference: ASVS Version 4.0.3 Requirement: 4.2.1


**Evidence**


*L1*
1. Provide a list of APIs in which portions of the API/URL or parameters may be passed from the user into the application.
2. Provide a written description how the APIs are protected from Insecure Direct Object Reference attacks.

*L2*
1. Provide a list of APIs in which portions of the API/URL or parameters may be passed from the user into the application.


**Test Procedure**


*L1*
1. Review provided evidence for adherence with the requirements.

*L2*
1. Perform testing for Insecure Direction Object References as defined in WSTG-ATHZ-04.


**Verification**


*L1*
1. A process shall be in place to mitigate Insecure Direct Object Reference attacks.

*L2*
1. Any APIs that accept user facing parameters (or URIs) shall not exhibit signs of Insecure Direct Object References.


---
### 3.1.5 The application or framework shall enforce a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality.
External Reference: ASVS Version 4.0.3 Requirement: 4.2.2


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.

*L2*
1. Perform testing as defined in WSTG-SESS-05 (Testing for Cross Site Request Forgery).



**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 2098944 Cross-site request forgery

*L2*
1. Application or framework shall enforce effective controls to mitigate Cross Site Request Forgery (CSRF).


---
### 3.1.6 Directory browsing shall be disabled unless deliberately desired.
External Reference: ASVS Version 4.0.3 Requirement: 4.3.2


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1 and L2*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


**Verification**


*L1 and L2*
1. Burp Suite scan shall not identify the following vulnerability:
   - 6291712 Directory Listing


---
## 3.2 Implement secure OAuth integrations to protect user data and prevent unauthorized access
### Description
Applications which support OAuth integrations shall follow established security guidelines to safeguard user data and prevent unauthorized access.

### Rationale
OAuth is a widely adopted authorization framework that allows users to grant third-party applications limited access to their resources on another service without sharing their login credentials. However, if not implemented securely, OAuth can expose users to various attacks, including account compromises and information disclosure. By securely implementing OAuth integrations, the application minimizes these risks and provides users with a more secure experience.

### Audit


---
### 3.2.1 Application shall implement only secure and recommended OAuth 2.0 flows, such as the Authorization Code Flow or the Authorization Code Flow with PKCE, while avoiding the use of deprecated flows like the Implicit Flow or the Resource Owner Password Credentials Flow.
External Reference: ASVS Version 4.0.3 Requirement: 


**Evidence**


*L1*
1. If the application uses an OAuth 2.0 integration, provide a written description along with relevant evidence (screenshots, source code, or other documentation) detailing which OAuth 2.0 flow is used.  

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review evidence to verify which OAuth 2.0 flows are used by the application. 

*L2*
1. Perform the Testing for Deprecated Grant Types steps defined in WSTG-ATHZ-05 (Testing for OAuth Weaknesses).



**Verification**


*L1*
1. Documentation shall not indicate the use of a deprecated OAuth flow, including the Implicit Flow or the Resource Owner Password Credentials Flow. 

*L2*
1. Test shall confirm that the application is not using a deprecated OAuth flow, including the Implicit Flow or the Resource Owner Password Credentials Flow. 



---
### 3.2.2 Ensure that the application securely validates the redirect_uri and state parameters during the OAuth 2.0 authorization process to prevent open redirect and CSRF vulnerabilities.
External Reference: ASVS Version 4.0.3 Requirement: 


**Evidence**


*L1*
1. If the application uses an OAuth 2.0 integration, provide a written description along with relevant evidence (screenshots, source code, or other documentation) detailing how the application uses the state and redirect_uri parameters to prevent common OAuth vulnerabilities.

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review provided evidence to verify the application's usage of the redirect_uri and state parameters.

*L2*
1. Perform the Testing for OAuth Client Weaknesses steps defined in WSTG-ATHZ-05 (Testing for OAuth Weaknesses).



**Verification**


*L1*
1. Application shall securely utilize state and redirect_uri validation to prevent against open redirect and CSRF vulnerabilities. 

*L2*
1. Test shall confirm that the application is not vulnerable to open redirects or CSRF vulnerabilities in the OAuth authorization process.



---
## 3.3 Application exposed administrative interfaces shall use appropriate multi-factor authentication.
### Description
Multi-factor authentication shall be implemented for all application exposed administrative interfaces. These interfaces must be limited to application layer functionality and should not expose the underlying cloud infrastructure. This requirement applies to both custom admin interfaces and open source admin portals, such as the WordPress Admin dashboard.
### Rationale
Infrastructure administrative interfaces shall never be exposed through an internet facing interface. However, there are many cases where application layer administrative tasks may need to be exposed to the internet. It is critical that these interfaces be limited in functionality and always implement multi-factor authentication to prevent attackers from compromising administrative accounts.

### Audit


---
### 3.3.1 Application administrative interfaces shall use appropriate multi-factor authentication to prevent unauthorized use.
External Reference: ASVS Version 4.0.3 Requirement: 4.3.1


**Evidence**


*L1 and L2*
1. Provide evidence demonstrating that any application exposed administrative interfaces enforce multi-factor authentication for all accounts. 


**Test Procedure**


*L1 and L2*
1. Review provided evidence for adherence with the requirements.


**Verification**


*L1 and L2*
1. Multi-factor authentication shall be enforced for all administrative accounts.



---
# 4 Communications
## 4.1 Protect Sensitive Data Through Strong Cryptography 
### Description
Applications must enforce strong TLS configurations and cryptographic practices. This includes using up-to-date tools to enable only strong cipher suites (prioritizing the strongest), employing trusted TLS certificates, and ensuring secure failure modes in cryptographic modules to mitigate common cryptographic attacks.
### Rationale
Strong TLS and cipher suites ensure confidentiality and integrity of data in transit by protecting against eavesdropping and modification. Trusted TLS certificates verify authenticity and prevent adversary-in-the-middle attacks, while secure failure modes and robust cryptography deter advanced attacks exploiting weaknesses in cryptographic implementations.

### Audit


---
### 4.1.1 Application shall enforce the use of TLS for all connections and default to TLS 1.2+. In cases where support for legacy clients is necessary, TLS 1.0 and 1.1 may be supported if mitigations are implemented to minimize the risk of downgrade attacks and known TLS exploits. Regardless of the TLS version in use, the application shall default to secure cipher suites and reject those with known vulnerabilities.
External Reference: ASVS Version 4.0.3 Requirement: 9.1.2


**Evidence**


*L1*
1. Execute a Qualys SSL Labs scan for the application and provide a PDF export of the test results demonstrating that application meets the aforementioned TLS requirements. In most cases, this should result in a B or higher score.

*L2*
1. N/A (to be collected by lab)


**Test Procedure**


*L1*
1. Review PDF export from Qualys SSL Labs scan.

*L2* 
1. Perform the testing guidance defined in WSTG-CRYP-01 to inspect TLS configuration.


**Verification**


*L1*

1. Application shall meet the TLS configuration defined in NIST SP.800-52r2.

*L2*

1. Test shall confirm that the application meets the TLS configuration defined in NIST SP.800-52r2.




---
### 4.1.2 Connections to and from the server shall use trusted TLS certificates. Where internally generated or self-signed certificates are used, the server must be configured to only trust specific internal CAs and specific self-signed certificates. All others should be rejected.
External Reference: ASVS Version 4.0.3 Requirement: 9.2.1


**Evidence**


*L1*
1. Execute a Qualys SSL Labs scan for the application and provide a PDF export of the test results demonstrating that application meets the aforementioned TLS requirements. In most cases, this should result in a B or higher score.

*L2*
1. N/A (to be collected by lab)


**Test Procedure**


*L1*
1. Review PDF export from Qualys SSL Labs scan.

*L2* 
1. Perform the testing guidance provided in the Digital Certificates section of WSTG-CRYP-01.


**Verification**


*L1*

1. Application shall meet the TLS certification requirements defined in NIST SP.800-52r2.


*L2*

1. Test shall confirm that the application meets the TLS certificate requirements defined in NIST SP.800-52r2.


---
### 4.1.3 No instances of weak cryptography which meaningfully impact the confidentiality or integrity of sensitive data.
External Reference: ASVS Version 4.0.3 Requirement: 


**Evidence**


*L1 and L2*
1. Describe any situations in which your application uses the following cryptographic operations: 
   * Encryption or decryption
   * Hashing
   * MAC or HMAC

2. For each of these operations, briefly describe how your application performs the cryptographic operation including:
   * Chosen cryptographic algorithms
   * Key size and mechanism of generation
   * IV size and mechanism of generation (if applicable)
   * Key management (storage, rotation, and expiration)



**Test Procedure**


*L1*

1. Review evidence to validate cryptographic operations.


*L2*
1. Review evidence to validate cryptographic operations. Perform manual testing as appropriate using guidance defined in WSTG-CRYP-04 to validate cryptographic operations.


**Verification**


*L1*
1. Disallowed encryption schemes or domain parameters as defined in NIST.SP.800-131Ar2 shall not be present. 


*L2*
1. Disallowed encryption schemes or domain parameters as defined in NIST.SP.800-131Ar2 shall not be present. Cryptographic observations from manual validation will be made based on observed entropy.




---
### 4.1.4 All cryptographic modules shall fail securely, and errors are handled in a way that does not enable Padding Oracle attacks.
External Reference: ASVS Version 4.0.3 Requirement: 6.2.1


**Evidence**


*L1*
1. Describe how your application handles cryptographic failures for the previously identified crypto operations. Provide detailed evidence such as source code, screenshots, or other relevant sources that showcase how the application handles cryptographic failures.

*L2*
1. N/A (to be collected by lab)


**Test Procedure**


*L1*

1. Review the provided evidence to identify potential Padding Oracle scenarios as described in WSTG-CRYP-02.

*L2*
1. Perform the testing guidance provided by WSTG-CRYP-02 to identify potential Padding Oracles in the application. 


**Verification**


*L1*

1. Errors or other output resulting from cryptographic failures shall not disclose sensitive information about the operation’s state or reveal any details that could be exploited as a side channel. User-facing error messages shall be vague and consistent regardless of the failure type.

*L2*
1. Test shall confirm that errors or other output resulting from cryptographic failures do not disclose sensitive information about the operation's state or reveal any details that could be exploited as a side channel. User-facing error messages shall be vague and consistent regardless of the failure type.



---
# 5 Data Validation and Sanitization
## 5.1 Implement Validation & Input Sanitation
### Description
Web applications must implement robust input validation and output encoding to defend against a wide range of injection attacks. This includes protecting against HTTP Parameter Pollution, XSS (reflected, stored, and DOM-based), SQL injection, OS command injection, file inclusion vulnerabilities, template injection, SSRF, XPath/XML injection, and unsafe use of dynamic code execution features (like eval()).
### Rationale
Robust input validation and output encoding is essential for web applications to effectively defend against multiple injection attack types. Injection attacks pose a significant risk for web applications due to their simplicity and ease of automation, enabling potential attackers to readily target vulnerable sites. By implementing secure input validation, web applications can significantly reduce the risk of attackers exploiting injection vulnerabilities to gain unauthorized access, manipulate data, or compromise systems.
### Audit


---
### 5.1.1 Protect against HTTP parameter pollution.
External Reference: ASVS Version 4.0.3 Requirement: 5.1.1


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
1. Perform HTTP parameter pollution testing procedure defined in WSTG-INPV-04.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 5248000: Client-side HTTP parameter pollution (reflected)
   - 5248001: Client-side HTTP parameter pollution (stored)

*L2*
1. Test shall confirm that application is not vulnerable to HTTP parameter pollution as defined in WSTG-INPV-04.


---
### 5.1.2 URL redirects and forwards are limited to allowlisted URLs or a warning is displayed when redirecting to untrusted content.
External Reference: ASVS Version 4.0.3 Requirement: 5.1.5


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
1. Perform client-side URL redirect testing procedure defined in WSTG-CLNT-04.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 5243136: Open redirection (reflected)
   - 5243137: Open redirection (stored)
   - 5243152: Open redirection (DOM-based)
   - 5243153: Open redirection (reflected DOM-based)
   - 5243154: Open redirection (stored DOM-based)

*L2*
1. Test shall confirm that application restricts redirects to allowlisted URLs or displays a warning when redirecting to untrusted content.


---
### 5.1.3 Avoid the use of eval() or other dynamic code execution features. When there is no alternative, any user input is sanitized and sandboxed before being executed.
External Reference: ASVS Version 4.0.3 Requirement: 5.2.4


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
1. Perform code injection testing procedure defined in WSTG-INPV-11.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 1051904: Server-side JavaScript code injection
   - 1052160: Perl code injection
   - 1052416: Ruby code injection
   - 1052432: Python code injection
   - 1051648: PHP Code Injection
   - 1052672: Unidentified code injection
   - 1052448: Expression Language Injection

*L2*
1. Test shall confirm that application does not allow arbitrary code execution from user input. In scenarios where user-supplied code execution is expected, ensure all user input is sanitized and sandboxed prior to execution. 


---
### 5.1.4 Protect against template injection attacks by ensuring that any user input being included is sanitized or sandboxed.
External Reference: ASVS Version 4.0.3 Requirement: 5.2.5


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)




**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
1. Perform template injection testing procedure defined in WSTG-INPV-18.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 1052800: Server-side template injection

*L2*
1. Test shall confirm that application is not susceptible to template injection from untrusted input. 


---
### 5.1.5 Prevent Server-Side Request Forgery (SSRF)
External Reference: ASVS Version 4.0.3 Requirement: 5.2.6


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)




**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
1. Perform Server-Side Request Forgery (SSRF) testing procedure defined in WSTG-INPV-19.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 1051136: Out-of-band resource load (HTTP)
   - 3146240: External service interaction (DNS)
   - 3146256: External service interaction (HTTP)

*L2*
1. Test shall confirm that the application does not initiate arbitrary HTTP or DNS requests to either internal or external resources based on user-supplied input, unless it is a necessary part of the application functionality. In such cases, ensure application implements robust input validation and uses allowlists to restrict requests to trusted and necessary domains or IP addresses.


---
### 5.1.6 Sanitize, disable, or sandbox user supplied SVG files
External Reference: ASVS Version 4.0.3 Requirement: 5.2.7


**Evidence**


*L1*
1. Identify any situations in which your application accepts user file uploads and describe how the application sanitizes, disables, or sandboxes SVG files. Provide detailed evidence such as source code, screenshots, or other relevant sources. 


*L2*
1. N/A (to be collected by labs)




**Test Procedure**


*L1*
1. Review the provided evidence to validate SVG files are being handled securely.

*L2*
1. Perform malicious file upload testing procedure defined in WSTG-BUSL-09 focusing on Cross-Site Scripting (XSS) vulnerabilities resulting from SVG files containing inline scripts.


**Verification**


*L1*
1. Unrestricted upload or unsafe handling of SVG files shall not be present.


*L2*
1. Test shall confirm that the application does not allow malicious SVG file uploads containing inline scripts, resulting in Cross-Site Scripting (XSS) within the application.


---
### 5.1.7 Protect against XPath or XML injection attacks
External Reference: ASVS Version 4.0.3 Requirement: 5.3.10


**Evidence**


*L1 and L2*
N/A (to be collected by labs)




**Test Procedure**


*L1*
Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
Perform the XML injection testing procedure defined in WSTG-INPV-07 and the XPath testing procedure defined in WSTG-INPV-09.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 1050368: XML injection
   - 1050112: XPath injection
   - 1049600: XML external entity injection
   - 2098016 Client-side XPath injection (DOM-based)
   - 2098017 Client-side XPath injection (reflected DOM-based)
   - 2098018 Client-side XPath injection (stored DOM-based)



*L2*
1. Test shall confirm that the application safely parses XML input and is not susceptible to common XML parsing vulnerabilities including XML injection, XML external entities (XXE), or XPath injection. 


---
### 5.1.8 Context-aware output escaping or sanitization protects against reflected, stored, and DOM based XSS.
External Reference: ASVS Version 4.0.3 Requirement: 5.3.3


**Evidence**


*L1 and L2*
N/A (to be collected by labs)




**Test Procedure**


*L1*
Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
Perform the reflected Cross-Site Scripting (XSS) testing procedure defined in WSTG-INPV-01 and the stored Cross-Site Scripting (XSS) testing procedure defined in WSTG-INPV-02.


**Verification**


*L1*
1. Burp Suite scan shall not identify any of the following vulnerabilities:
   - 2097408: Cross-site scripting (stored)
   - 2097920: Cross-site scripting (reflected)
   - 2097936: Cross-site scripting (DOM-based)
   - 2097937: Cross-site scripting (reflected DOM-based)
   - 2097938: Cross-site scripting (stored DOM-based)

*L2*
1. Test shall confirm that application shall is not susceptible to stored, reflected, or DOM-based Cross-site Scripting (XSS) vulnerabilities.


---
### 5.1.9 Protect against database injection attacks
External Reference: ASVS Version 4.0.3 Requirement: 5.3.4


**Evidence**


*L1 and L2*
N/A (to be collected by labs)




**Test Procedure**


*L1*
Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
Perform the database injection testing procedure defined in WSTG-INPV-05.


**Verification**


*L1*
1. Burp Suite scan shall not identify any of the following vulnerabilities:
   - 1049088: SQL Injection
   - 1049104: SQL Injection (Second Order)


*L2*
1. Verification shall confirm that application is not vulnerable to SQL injection, including in-band, blind (inferential), and out-of-band attacks.


---
### 5.1.10 Protect against OS command injections
External Reference: ASVS Version 4.0.3 Requirement: 5.3.8


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)

**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
1. Perform the OS command injection testing procedure defined in WSTG-INPV-12.


**Verification**


*L1*
1. Burp Suite scan shall not identify any of the following vulnerabilities:
   - 1048832: OS Command Injection

*L2*
1. Verification shall confirm that testing evidence does not indicate the application is vulnerable to OS command injection vulnerabilities from parsing untrusted user input.


---
### 5.1.11 Protect against local file inclusion or remote file inclusion attacks
External Reference: ASVS Version 4.0.3 Requirement: 5.3.9


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.


*L2*
1. Perform the testing procedures defined in the Local File Inclusion (LFI) and Remote File Inclusion (RFI) subsections of WSTG-INPV-11. 


**Verification**


*L1*
1. Burp Suite scan shall not identify any of the following vulnerabilities:
   - 1049344: File path traversal
   - 1051392: File path manipulation


*L2*
1. Verification shall confirm that testing evidence does not indicate application is vulnerable to Local File Inclusion (LFI), Remote File Inclusion (RFI), or related directory traversal attacks. 


---
## 5.2 Securely Handle Untrusted Files 
### Description
Web applications must safely process and manage files that originate from untrusted or unknown sources. This includes restricting uploads to expected file types and preventing direct execution of uploaded content containing HTML, JavaScript, or dynamic server-side code.
### Rationale
Files from untrusted sources may contain malicious code which could allow compromise of the application. If these files are executed directly, they can compromise the security of the web application, leading to unauthorized access, data breaches, or other harmful actions.
### Audit


---
### 5.2.1 Protect against malicious file uploads by limiting uploads to expected file types and preventing direct execution of uploaded content.
External Reference: ASVS Version 4.0.3 Requirement: 12.2.1


**Evidence**


*L1*
1. Identify any situations in which the application accepts user file uploads. Describe how the application securely validates file type and prevents file execution. Provide detailed evidence such as source code, screenshots, or other relevant sources.


*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review the provided evidence to validate that application appropriately enforces file upload restrictions. 

*L2*
1. Perform the testing procedures defined in WSTG-BUSL-08 and WSTG-BUSL-09.



**Verification**


*L1*
1. Application shall enforce appropriate file type restrictions on file uploads.


*L2*
1. Testing shall confirm that the application restricts file uploads to expected file types and that application prevents direct execution of any uploaded content including HTML, JavaScript, and server-side code. In cases where the application intends for the user to upload executable file types, the application shall appropriately sanitize or sandbox executable files. 


---
# 6 Configuration
## 6.1 Keep all components up to date
### Description
Developers must verify that the libraries included in their application do not have any known exploitable vulnerabilities.
### Rationale
Attackers can perform automated scans to identify vulnerable applications based on published vulnerabilities. 
### Audit


---
### 6.1.1 The application only uses software components without known exploitable vulnerabilities.
External Reference: ASVS Version 4.0.3 Requirement: 


**Evidence**


*L1*
1. Provide output of a dependency scan of application and 3P libraries using OWASP dependency check or other ADA approved scanning tools.

*L2*
1. Developer to provide lab access to source code repository or application software manifest.


**Test Procedure**


*L1 *
1. Review provided evidence for adherence with the requirements.

*L2*
1. Perform dependency scan of source code repository or scan of developer provided manifest.


**Verification**


*L1*
1. The application shall not use any 3P libraries at a version vulnerable to a CVE with a severity >= CVSS 7.0. 

An application that uses a 3P library at a version vulnerable to a CVE with CVSS >= 7.0 can pass this test if the developer provides additional justification that: 
* The application does not invoke the vulnerable 3P library code, or 
* The 3P library has not yet made an update available. This is acceptable only if the 3P library has a regular patch process.

*L2*
1. Scan shall confirm that the application does not use any 3P libraries at a version vulnerable to a CVE with a severity >= CVSS 7.0. 

An application that uses a 3P library at a version vulnerable to a CVE with CVSS >= 7.0 can pass this test if the developer provides additional justification that: 
* The application does not invoke the vulnerable 3P library code or 
* The 3P library has not yet made an update available. This is acceptable only if the 3P library has a regular patch process.




---
## 6.2 Disable debug modes in production environments
### Description
Applications must strictly disable all debug modes before deployment into production environments.
### Rationale
Debug modes often expose sensitive information like stack traces, code internals, and environment variables. This information can aid attackers in understanding the application's structure and identifying vulnerabilities, significantly increasing the risk of targeted attacks and exploitation. Disabling debug modes removes this unnecessary risk in production.
### Audit


---
### 6.2.1 Disable debug modes in production environments
External Reference: ASVS Version 4.0.3 Requirement: 14.3.2


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.

*L2*
1. Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended security disclosures.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 1050624: ASP.NET debugging enabled

*L2*
1. Verification shall confirm that no debug modes are enabled in production environments.


---
## 6.3 The origin header shall not be used for authentication of access control decisions
### Description
The application must never rely solely on the Origin HTTP header for authentication or access control decisions.
### Rationale
The Origin header can be easily manipulated by attackers, making it an unreliable indicator of a request's true source. This could lead to unauthorized access if an application mistakenly trusts requests based on a forged  Origin header. Security mechanisms must use more robust and tamper-proof methods for authentication and authorization.
### Audit


---
### 6.3.1 The origin header shall not be used for authentication of access control decisions
External Reference: ASVS Version 4.0.3 Requirement: 14.5.2


**Evidence**


*L1 and L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Execute authenticated Burp Suite scan on the target application using the ADA scan configuration.

*L2*
1. Verify that the supplied Origin header is not used for authentication or access control decisions, as the Origin header can easily be changed by an attacker.


**Verification**


*L1*
1. Burp Suite scan shall not identify the following vulnerabilities:
   - 2098689: Cross-origin resource sharing: arbitrary origin trusted

*L2*
1. Verification shall confirm that origin header is not used for authentication of access control decisions.


---
## 6.4 Protect Application from Subdomain Takeover
### Description
The application must implement safeguards to prevent subdomain takeover vulnerabilities. This includes proactive identification and removal of dangling DNS records (e.g., CNAME records pointing to decommissioned services) and regular monitoring of third-party services integrated with the application's domains.
### Rationale
Dangling DNS records and vulnerable third-party services can allow attackers to take control of subdomains. This could enable them to host malicious content on the application's domain, harming reputation and potentially leading to phishing attacks or the compromise of user data.
### Audit


---
### 6.4.1 The application shall not be susceptible to subdomain takeovers.
External Reference: ASVS Version 4.0.3 Requirement: 10.3.3


**Evidence**


*L1*
1. Provide evidence of DNS configuration for the target domain and subdomains, confirming that either all subdomains are explicitly defined and point to IP addresses or other domains controlled by your organization; or where the record points to a third party owned domain, confirm that the subdomain record isn't configured to point to a non-existing or non-active resource/external service/endpoint.

*L2*
1. Provide evidence of DNS configuration for the target domain and subdomains, confirming that either all subdomains are explicitly defined and point to IP addresses or other domains controlled by your organization; or where the record points to a third party owned domain, confirm that the subdomain record isn't configured to point to a non-existing or non-active resource/external service/endpoint.
2. Provide screenshots of code, configurations, or other systems referenced in the written description.


**Test Procedure**


*L1*
1. Review provided evidence for adherence with the requirements.

*L2*
1. Verify application for adherence with the requirements as defined in WSTG-CONF-10.



**Verification**


*L1*
1. Appropriate controls to limit subdomain takeovers shall be implemented.

*L2*
1. Appropriate controls to limit subdomain takeovers shall be implemented.
2. Screenshots shall support the controls described in the written description.


---
## 6.5 Do not log credentials or payment details
### Description
Applications must never log sensitive user data, specifically credentials (e.g., passwords, API keys) and payment details (e.g., credit card numbers, CVVs).
### Rationale
Many data privacy regulations (PCI-DSS, GDPR, etc.) explicitly prohibit the storage of sensitive authentication and financial data, especially in plaintext. In addition, avoiding logging sensitive information minimizes the overall attack surface and demonstrates a commitment to responsible data handling.
### Audit


---
### 6.5.1 The application shall not log credentials or payment details. Session tokens shall only be stored in logs in an irreversible, hashed form.
External Reference: ASVS Version 4.0.3 Requirement: 7.1.1


**Evidence**


*L1*
1. Provide a written description highlighting the protections to prevent logging of credentials or payment details.
2. Provide a sample from a log captured during a login process.
3. Provide a sample from a log captured during a payment process. (If applicable)

*L2*
1. Provide access to logs captured during the testing of the application


**Test Procedure**


*L1*
1. Review provided evidence for adherence with the requirements

*L2*
1. Verify application for adherence with the requirements.


**Verification**


*L1*
1. Application shall not not log credentials or payment details.
2. Samples from log files shall not not contain credentials or payment details.

*L2*
1. Verification shall confirm that application does not log credentials or payment details.


---
## 6.6 Sensitive user data is either not stored in browser storage or is deleted when the user logs out
### Description
Web applications should never store sensitive user data (e.g., passwords, credit card numbers, session tokens) in browser storage mechanisms like local storage or session storage. However, if data is stored in browser storage it must be deleted when the user logs out.
### Rationale
Browser storage is inherently accessible to client-side JavaScript, making it vulnerable to attacks like Cross-Site Scripting (XSS). Storing sensitive data here exposes it to potential theft or misuse by an attacker if they manage to inject malicious code.
### Audit


---
### 6.6.1 If data is stored in browser storage it shall not contain sensitive data.
External Reference: ASVS Version 4.0.3 Requirement: 8.2.2


**Evidence**


*L1*
1. Provide a written description of what data (if any) is stored in browser storage.

*L2*
1. N/A (to be collected by labs)


**Test Procedure**


*L1*
1. Review provided evidence for adherence with the requirements

*L2*
1. Verify application for adherence with the requirements as defined in WSTG-CLNT-12.


**Verification**


*L1*
1. Application shall not store sensitive data in browser storage.
and;
2. Sensitive data stored in browser storage shall be deleted when the user logs out.

*L2*
1. Application does not store sensitive data in browser storage.
and;
2. Verification shall confirm that application deletes sensitive data stored in browser storage when the user logs out.


---
## 6.7 Securely store server-side secrets
### Description
Ensure server-side secrets are stored securely using an appropriate secrets management approach which provides encryption, access controls, and monitoring to prevent unauthorized access and maintain data confidentiality.
### Rationale
Secrets management helps protect API keys, access tokens, and other server-side secrets used by the application from being accessed or stolen by unauthorized parties.
### Audit


---
### 6.7.1 The application shall securely store access tokens, API keys, and other server-side secrets.
External Reference: ASVS Version 4.0.3 Requirement: 6.4.1


**Evidence**


*L1 and L2*
1. Provide a written description along with relevant evidence (source code, screenshots, architecture diagrams, etc.) describing your approach to secrets management for any access tokens, API keys, or other server-side secrets used by the application.


**Test Procedure**


*L1 and L2*
1. Review provided evidence for adherence with the requirements.


**Verification**


*L1 and L2*
1. An appropriate access control policy for server-side secrets shall be documented.
2. Secrets shall be stored using a cryptographically secure approach. 
3. Access to secrets shall be logged or monitored.


---
