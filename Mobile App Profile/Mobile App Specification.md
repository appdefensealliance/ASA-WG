
# App Defense Alliance Mobile Application Specification

Version 0.7 - June 14, 2024

## Revision History

| Version | Date | Description |
| --- | :--- | :--- |
| 0.5 | 5/10/24 | Initial draft based on Mobile App Tiger Team review of MASVS specification |
| 0.7 | 5/25/24 | Updates from Tiger Team review of 0.5 spec |

## Acknowledgements

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

### Application Security Assessment Working Group Leads
* Alex Duff (Meta) - ASA WG Chair
* Brooke Davis (Google) - ASA WG Vice Chair

### Mobile Profile Leads
* Brooke Davis (Google)
* Tim Bolton (Meta)

### Contributors
* Alex Duff (Meta)
* Ana Vargas
* Anna Bhirud (Google)
* Antonio Nappa (Zimperium)
* Anushree Shetty  (KPMG)
* Artem Chornyi
* Artur Gartvikh
* Asaf Peleg (Zimperium)
* Bhairavi Mehta (TAC Security)
* Brad Ree (Google)
* Brooke Davis (Google)
* Carlos Holguera
* Chris Cinnamo (Zimperium)
* Christian Schnell (Zimperium)
* Cody Martin (Leviathan Security)
* Corey Gagnon (Meta)
* Eugene Liderman (Google)
* Gianluca Braga (Zimperium)
* Joel Scambray (NCC Group)
* Jon Paterson (Zimperium)
* Jorge Damian
* Jorge Wallace Ruiz (Dekra)
* José María Santos López
* Juan Manuel Martinez Hernandez
* Julia McLaughlin (Google)
* Jullian Gerhart (NCC Group)
* Kelly Albrink (Bishop Fox)
* Mamachan Anish (KPMG)
* Mark Stribling (Leviathan Security)
* Mateo Morales Amador
* Michael Krueger
* Michael Whiteman (Meta)
* Nazariy Haliley (Bishop Fox)
* Nicole Weisenbach (NCC Group)
* Noelle Murata  (Leviathan Security)
* Olivier Tuchon
* Pamela Dingle  (Microsoft)
* Rubén Lirio (Dekra)
* Rupesh Nair (Net Sentries)
* Sebastian Porst
* Shad Malloy
* Soledad Antelada Toledano (Google)
* Syrone Hanks II
* Thomas Cannon (NCC Group)
* Tim Bolton (Meta)
* Viktor Sytnik (Leviathan Security)
* Yiannis Kozyrakis
* Zach Moreno (Bishop Fox)

## Introduction

In today’s digitally-driven world, mobile applications are the backbone of countless businesses and organizations. Unfortunately, they are also prime targets for cyberattacks that threaten data confidentiality, service availability, and overall business integrity. To mitigate risks and build a secure mobile environment, a robust mobile application security standard and certification program is essential.

### Our Approach: OWASP MASVS as the Foundation

This program leverages the internationally recognized OWASP Mobile Application Security Verification Standard (MASVS) as its core. The OWASP MASVS offers a comprehensive set of security assessment requirements and guidelines covering the entire mobile application development lifecycle. Building upon this base, the App Defense Alliance (ADA) focused on testable requirements with clear acceptance criteria. Further, the ADA approach emphasizes the use of automation where possible.

### Applicability

This document is intended for system and application administrators, security specialists, auditors, help desk, platform deployment, and/or DevOps personnel who plan to develop, deploy, assess, or secure mobile applications.

### References

1. [OWASP Mobile Application Security Verification Standard](https://github.com/OWASP/owasp-masvs/)

### Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License.](https://creativecommons.org/licenses/by-sa/4.0/)

### Assumptions

The following assumptions are intended to aid the Authorized Labs for baseline security testing.

#### Platform

The mobile application relies upon a trustworthy computing platform that runs a recent version of a mobile operating system (i.e. N-2) from the date of evaluation.   For the purposes of this document, N refers to a major operation system release.

#### Proper User

The user of the application software is not willfully negligent or hostile, and sets a device PIN/Passcode.

#### Sensitive or Confidential Data

Data that is of particular concern from a security perspective, including user data, user device data, company data, or other types of confidential information. Note that apps in certain verticals such as healthcare or finance may have to meet higher security, privacy, and regulatory requirements.

Throughout this documeent, the phrase "sensitive data" means non-public data such as user data, user device data, company data, or other types of confidential information and should not be confused with the meaning of Sensitive Data under regulations like GDPR or other regulatory regimes.

#### Tooling

The ADA approach emphasizes the use of automation where possible. We expect future tooling investment to assist with gathering of developer evidence for Level 1 assurance.

# Table of Contents

* [1 ANDROID](#1-android)
  * [1.1 Storage](#11-storage)
    * [1.1.1 The app securely stores sensitive data in external storage](#111-the-app-securely-stores-sensitive-data-in-external-storage)
    * [1.1.2 The app prevents leakage of sensitive data](#112-the-app-prevents-leakage-of-sensitive-data)
  * [1.2 Crypto](#12-crypto)
    * [1.2.1 The app employs current strong cryptography and uses it according to industry best practices](#121-the-app-employs-current-strong-cryptography-and-uses-it-according-to-industry-best-practices)
    * [1.2.2 The app performs key management according to industry best practices](#122-the-app-performs-key-management-according-to-industry-best-practices)
  * [1.3 Auth](#13-auth)
    * [1.3.1 The app uses secure authentication and authorization protocols and follows the relevant best practices](#131-the-app-uses-secure-authentication-and-authorization-protocols-and-follows-the-relevant-best-practices)
  * [1.4 Network](#14-network)
    * [1.4.1 The app secures all network traffic according to the current best practices](#141-the-app-secures-all-network-traffic-according-to-the-current-best-practices)
  * [1.5 Platform](#15-platform)
    * [1.5.1 The app uses IPC mechanisms securely](#151-the-app-uses-ipc-mechanisms-securely)
    * [1.5.2 The app uses WebViews securely](#152-the-app-uses-webviews-securely)
    * [1.5.3 The app uses the user interface securely](#153-the-app-uses-the-user-interface-securely)
  * [1.6 Code](#16-code)
    * [1.6.1 The app requires an up-to-date platform version](#161-the-app-requires-an-up-to-date-platform-version)
    * [1.6.2 The app only uses software components without known vulnerabilities](#162-the-app-only-uses-software-components-without-known-vulnerabilities)
    * [1.6.3 The app validates and sanitizes all untrusted inputs](#163-the-app-validates-and-sanitizes-all-untrusted-inputs)
  * [1.7 Resilience](#17-resilience)
    * [1.7.1 The app implements anti-tampering mechanisms](#171-the-app-implements-anti-tampering-mechanisms)
    * [1.7.2 The app implements anti-static analysis mechanisms](#172-the-app-implements-anti-static-analysis-mechanisms)
    * [1.7.3 The app implements anti-dynamic analysis mechanisms](#173-the-app-implements-anti-dynamic-analysis-mechanisms)
  * [1.8 Privacy](#18-privacy)
    * [1.8.1 The app minimizes access to sensitive data and resources](#181-the-app-minimizes-access-to-sensitive-data-and-resources)
    * [1.8.2 The app is transparent about data collection and usage](#182-the-app-is-transparent-about-data-collection-and-usage)
    * [1.8.3 The app offers user control over their data](#183-the-app-offers-user-control-over-their-data)
* [2 iOS](#2-ios)
  * [2.1 Storage](#21-storage)
    * [2.1.1 The app securely stores sensitive data in external storage](#211-the-app-securely-stores-sensitive-data-in-external-storage)
    * [2.1.2 The app prevents leakage of sensitive data](#212-the-app-prevents-leakage-of-sensitive-data)
  * [2.2 Crypto](#22-crypto)
    * [2.2.1 The app employs current strong cryptography and uses it according to industry best practices](#221-the-app-employs-current-strong-cryptography-and-uses-it-according-to-industry-best-practices)
    * [2.2.2 The app performs key management according to industry best practices](#222-the-app-performs-key-management-according-to-industry-best-practices)
  * [2.3 Auth](#23-auth)
    * [2.3.1 The app uses secure authentication and authorization protocols and follows the relevant best practices](#231-the-app-uses-secure-authentication-and-authorization-protocols-and-follows-the-relevant-best-practices)
  * [2.4 Network](#24-network)
    * [2.4.1 The app secures all network traffic according to the current best practices](#241-the-app-secures-all-network-traffic-according-to-the-current-best-practices)
  * [2.5 Platform](#25-platform)
    * [2.5.1 The app uses IPC mechanisms securely](#251-the-app-uses-ipc-mechanisms-securely)
    * [2.5.2 The app uses WebViews securely](#252-the-app-uses-webviews-securely)
    * [2.5.3 The app uses the user interface securely](#253-the-app-uses-the-user-interface-securely)
  * [2.6 Code](#26-code)
    * [2.6.1 The app requires an up-to-date platform version](#261-the-app-requires-an-up-to-date-platform-version)
    * [2.6.2 The app only uses software components without known vulnerabilities](#262-the-app-only-uses-software-components-without-known-vulnerabilities)
    * [2.6.3 The app validates and sanitizes all untrusted inputs](#263-the-app-validates-and-sanitizes-all-untrusted-inputs)
  * [2.7 Resilience](#27-resilience)
    * [2.7.1 The app implements anti-tampering mechanisms](#271-the-app-implements-anti-tampering-mechanisms)
    * [2.7.2 The app implements anti-static analysis mechanisms](#272-the-app-implements-anti-static-analysis-mechanisms)
    * [2.7.3 The app implements anti-dynamic analysis techniques](#273-the-app-implements-anti-dynamic-analysis-techniques)
  * [2.8 Privacy](#28-privacy)
    * [2.8.1 The app minimizes access to sensitive data and resources](#281-the-app-minimizes-access-to-sensitive-data-and-resources)
    * [2.8.2 The app is transparent about data collection and usage](#282-the-app-is-transparent-about-data-collection-and-usage)
    * [2.8.3 The app offers user control over their data](#283-the-app-offers-user-control-over-their-data)

# 1 ANDROID

## 1.1 [Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)

### 1.1.1 [The app securely stores sensitive data in external storage](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/)

#### Description

This control ensures that any sensitive data that is intentionally stored by the app is properly protected independently of the target location.

#### Rationale

Apps handle sensitive data coming from many sources such as the user, the backend, system services or other apps on the device and usually need to store it locally. The storage locations may be private to the app (e.g. its internal storage) or be public and therefore accessible by the user or other installed apps (e.g. public folders such as Downloads).

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.1.1.1 | The app shall securely store sensitive data in external storage |

### 1.1.2 [The app prevents leakage of sensitive data](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/)

#### Description

This control covers unintentional data leaks where the developer actually has a way to prevent it.

#### Rationale

There are cases when sensitive data is unintentionally stored or exposed to publicly accessible locations; typically as a side-effect of using certain APIs, system capabilities such as backups or logs.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.1.2.1 | The Keyboard Cache shall be disabled for sensitive data inputs |
| 1.1.2.2 | No sensitive data shall be stored in system logs |

## 1.2 [Crypto](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)

### 1.2.1 [The app employs current strong cryptography and uses it according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/)

#### Description

This control covers general cryptography best practices, which are typically defined in external standards.  For testing, the Crypto requirements only apply to sensitive data stored outside of the application sandbox.

#### Rationale

Cryptography plays an especially important role in securing the user's data - even more so in a mobile environment, where attackers having physical access to the user's device is a likely scenario.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.2.1.1 | No insecure random number generators shall be utilized for any security sensitive context |
| 1.2.1.2 | No insecure operations shall be used for symmetric cryptography |
| 1.2.1.3 | Strong cryptography shall be implemented according to industry best practices |

### 1.2.2 [The app performs key management according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/)

#### Description

This control covers the management of cryptographic keys throughout their lifecycle, including key generation, storage and protection. Crypto requirements only apply to sensitive data stored outside of the application sandbox.

#### Rationale

Even the strongest cryptography would be compromised by poor key management.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.2.2.1 | Cryptographic keys shall only be used for their defined purpose |
| 1.2.2.2 | Cryptographic key management shall be implemented properly |

## 1.3 [Auth](https://mas.owasp.org/MASVS/07-MASVS-AUTH/)

### 1.3.1 [The app uses secure authentication and authorization protocols and follows the relevant best practices](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/)

#### Description

Most apps connecting to a remote endpoint require user authentication and also enforce some kind of authorization. While the enforcement of these mechanisms must be on the remote endpoint, the apps also have to ensure that it follows all the relevant best practices to ensure a secure use of the involved protocols.

#### Rationale

Authentication and authorization provide an added layer of security and help prevent unauthorized access to sensitive user data.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.3.1.1 | If using OAuth 2.0 to authenticate, Proof Key for Code Exchange (PKCE) shall be implemented to protect the code grant |

## 1.4 [Network](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/)

### 1.4.1 [The app secures all network traffic according to the current best practices](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/)

#### Description

This control ensures that the app is in fact setting up secure connections in any situation. This is typically done by encrypting data and authenticating the remote endpoint, as TLS does. However, there are many ways for a developer to disable the platform secure defaults, or bypass them completely by using low-level APIs or third-party libraries.

#### Rationale

Ensuring data privacy and integrity of any data in transit is critical for any app that communicates over the network.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.4.1.1 | Network connections shall be encrypted |
| 1.4.1.2 | TLS configuration of network connections shall adhere to industry best practices |
| 1.4.1.3 | Endpoint identity shall be verified on network connections |

## 1.5 [Platform](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/)

### 1.5.1 [The app uses IPC mechanisms securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/)

#### Description

This control ensures that all interactions involving IPC mechanisms happen securely.

#### Rationale

Apps typically use platform provided IPC mechanisms to intentionally expose data or functionality. Both installed apps and the user are able to interact with the app in many different ways.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.5.1.1 | The app shall limit content provider exposure and harden queries against injection attacks |
| 1.5.1.2 | The app shall use verified links and sanitize all link input data |
| 1.5.1.3 | Any sensitive functionality exposed via IPC shall be intentional and at the minimum required level |
| 1.5.1.4 | All Pending Intents shall be immutable or otherwise justified for mutability |

### 1.5.2 [The app uses WebViews securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/)

#### Description

This control ensures that WebViews are configured securely to prevent sensitive data leakage as well as sensitive functionality exposure (e.g. via JavaScript bridges to native code).

#### Rationale

WebViews are typically used by apps that have a need for increased control over the UI. They can, however, also be exploited by attackers or other installed apps, potentially compromising the app's security.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.5.2.1 | WebViews shall securely execute JavaScript |
| 1.5.2.2 | WebView shall be configured to allow the minimum set of protocol handlers required while disabling potentially dangerous handlers |

### 1.5.3 [The app uses the user interface securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/)

#### Description

This control ensures that this data doesn't end up being unintentionally leaked due to platform mechanisms such as auto-generated screenshots or accidentally disclosed via e.g. shoulder surfing or sharing the device with another person.

#### Rationale

Sensitive data has to be displayed in the UI in many situations (e.g. passwords, credit card details, OTP codes in notifications) which can lead to unintentional leaks.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.5.3.1 | The app shall by default mask data in the User Interface when it is known to be sensitive |

## 1.6 [Code](https://mas.owasp.org/MASVS/10-MASVS-CODE/)

### 1.6.1 [The app requires an up-to-date platform version](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/)

#### Description

This control ensures that the app is running on an up-to-date platform version so that users have the latest security protections.

#### Rationale

Every release of the mobile OS includes security patches and new security features. By supporting older versions, apps stay vulnerable to well-known threats.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.6.1.1 | The app shall set the targetSdkVersion to an up-to-date platform version |

### 1.6.2 [The app only uses software components without known vulnerabilities](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/)

#### Description

To be truly secure, a full whitebox assessment should have been performed on all app components. However, as it usually happens with e.g. for third-party components this is not always feasible and not typically part of a penetration test. This control covers "low-hanging fruit" cases, such as those that can be detected just by scanning libraries for known vulnerabilities.

#### Rationale

The developer should protect users from known vulnerabilities.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.6.2.1 | The app only uses software components without known vulnerabilities |

### 1.6.3 [The app validates and sanitizes all untrusted inputs](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)

#### Description

Apps have many data entry points including the UI, IPC, the network, the file system, etc.  This control ensures that this data is treated as untrusted input and is properly verified and sanitized before it's used.

#### Rationale

This incoming data might have been inadvertently modified by untrusted actors and may lead to bypass of critical security checks as well as classical injection attacks such as SQL injection, XSS or insecure deserialization.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.6.3.1 | Compiler security features shall be enabled |
| 1.6.3.2 | The App shall Mitigate Against Injection Flaws in Content Providers |
| 1.6.3.3 | Arbitrary URL redirects shall not be included in the app's webviews |
| 1.6.3.4 | Any use of implicit intents shall be appropriate for the app's functionality and any return data shall be handled securely |

## 1.7 [Resilience](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)

### 1.7.1 [The app implements anti-tampering mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/)

#### Description

This control tries to ensure the integrity of the app's intended functionality by preventing modifications to the original code and resources.

#### Rationale

Apps run on a user-controlled device, and without proper protections it's relatively easy to run a modified version locally (e.g. to cheat in a game, or enable premium features without paying), or upload a backdoored version of it to third-party app stores.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.7.1.1 | The app shall be properly signed |

### 1.7.2 [The app implements anti-static analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/)

#### Description

This control tries to impede comprehension by making it as difficult as possible to figure out how an app works using static analysis.

#### Rationale

Understanding the internals of an app is typically the first step towards tampering with it.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.7.2.1 | The app shall disable all debugging symbols in the production version |

### [1.7.3 The app implements anti-dynamic analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/)

#### Description

Sometimes pure static analysis is very difficult and time consuming so it typically goes hand in hand with dynamic analysis.  This control aims to make it as difficult as possible to perform dynamic analysis, as well as prevent dynamic instrumentation which could allow an attacker to modify the code at runtime.

#### Rationale

Observing and manipulating an app during runtime makes it much easier to decipher its behavior.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.7.3.1 | The app shall not be debuggable if installed from outside of commercial app stores |

## 1.8 [Privacy](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/)

### 1.8.1 [The app minimizes access to sensitive data and resources](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/)

#### Description

Apps should only request access to the data they absolutely need for their functionality and always with informed consent from the user. This control ensures that apps practice data minimization and restricts access control.  Furthermore, apps should share data with third parties only when necessary, and this should include enforcing that third-party SDKs operate based on user consent, not by default or without it. Apps should prevent third-party SDKs from ignoring consent signals or from collecting data before consent is confirmed.  Additionally, apps should be aware of the 'supply chain' of SDKs they incorporate, ensuring that no data is unnecessarily passed down their chain of dependencies.

#### Rationale

Data minimization reduces the potential impact of data breaches or leaks.  This end-to-end responsibility for data aligns with recent SBOM regulatory requirements, making apps more accountable for their data practices.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.8.1.1 | The app shall minimize access to sensitive data and resources provided by the platform |

### 1.8.2 [The app is transparent about data collection and usage](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/)

#### Description

This control ensures that apps provide clear information about data collection, storage, and sharing practices, including any behavior a user wouldn't reasonably expect, such as background data collection. Apps should also adhere to platform guidelines on data declarations.

#### Rationale

Users have the right to know how their data is being used.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.8.2.1 | The app shall be transparent about data collection and usage |

### 1.8.3 [The app offers user control over their data](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/)

#### Description

This control ensures that apps provide mechanisms for users to manage, delete, and modify their data, and change privacy settings as needed (e.g. to revoke consent). Additionally, apps should re-prompt for consent and update their transparency disclosures when they require more data than initially specified.

#### Rationale

Users should have control over their data.

#### Audit

| Spec | Description |
| :--- | :--- |
| 1.8.3.1 | Users shall have the ability to request their data to be deleted via an in-app mechanism |

# 2 iOS

## 2.1 [Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)

### 2.1.1 [The app securely stores sensitive data in external storage](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.1.1.1 | The app shall securely store sensitive data in external storage |

### 2.1.2 [The app prevents leakage of sensitive data](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.1.2.1 | The Keyboard Cache shall be Disabled for sensitive data inputs |
| 2.1.2.2 | No sensitive data shall be stored in system logs |

## 2.2 [Crypto](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)

### 2.2.1 [The app employs current strong cryptography and uses it according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.2.1.1 | No insecure random number generators shall be utilized for any security sensitive context |
| 2.2.1.2 | Strong cryptography shall be implemented according to industry best practices |

### 2.2.2 [The app performs key management according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.2.2.1 | Cryptographic keys shall only be used for their defined purpose |
| 2.2.2.2 | Cryptographic key management shall be implemented properly |

## 2.3 [Auth](https://mas.owasp.org/MASVS/07-MASVS-AUTH/)

### 2.3.1 [The app uses secure authentication and authorization protocols and follows the relevant best practices](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.3.1.1 | If using OAuth 2.0 to authenticate, Proof Key for Code Exchange (PKCE) shall be implemented to protect the code grant |

## 2.4 [Network](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/)

### 2.4.1 [The app secures all network traffic according to the current best practices](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.4.1.1 | Network connections shall be encrypted |
| 2.4.1.2 | TLS configuration of network connections shall adhere to industry best practices |
| 2.4.1.3 | Endpoint identity shall be verified on network connections |

## 2.5 [Platform](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/)

### 2.5.1 [The app uses IPC mechanisms securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.5.1.1 | The app shall not expose sensitive data via IPC mechanisms |
| 2.5.1.2 | The app shall not expose sensitive data via App Extensions |
| 2.5.1.3 | The app shall not expose sensitive functionality via Custom URL Schemes |
| 2.5.1.4 | The app shall not expose sensitive data via UIActivity Sharing |
| 2.5.1.5 | The app shall not use the general pasteboard for sharing sensitive information |
| 2.5.1.6 | The app shall not expose sensitive functionality via Universal Links |

### 2.5.2 [The app uses WebViews securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.5.2.1 | WebViews shall securely execute JavaScript |
| 2.5.2.2 | WebView shall be configured securely |

### 2.5.3 [The app uses the user interface securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.5.3.1 | The app shall by default mask data in the User Interface when it is known to be sensitive |

## 2.6 [Code](https://mas.owasp.org/MASVS/10-MASVS-CODE/)

### 2.6.1 [The app requires an up-to-date platform version](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.6.1.1 | The app shall set the targetSdkVersion to an up-to-date platform version |

### 2.6.2 [The app only uses software components without known vulnerabilities](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.6.2.1 | The app only uses software components without known vulnerabilities |

### 2.6.3 [The app validates and sanitizes all untrusted inputs](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.6.3.1 | Compiler security features shall be enabled |

## 2.7 [Resilience](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)

### 2.7.1 [The app implements anti-tampering mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.7.1.1 | The app shall be properly signed |

### 2.7.2 [The app implements anti-static analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.7.2.1 | The app shall disable all debugging symbols in the production version |

### 2.7.3 [The app implements anti-dynamic analysis techniques](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.7.3.1 | The app shall not be debuggable if installed from outside of commercial app stores |

## 2.8 [Privacy](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/)

### 2.8.1 [The app minimizes access to sensitive data and resources](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.8.1.1 | The app shall minimize access to sensitive data and resources provided by the platform |

### 2.8.2 [The app is transparent about data collection and usage](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.8.2.1 | The app shall be transparent about data collection and usage |

### 2.8.3 [The app offers user control over their data](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/)

#### Audit

| Spec | Description |
| :--- | :--- |
| 2.8.3.1 | Users shall have the ability to request their data to be deleted via an in-app mechanism |
