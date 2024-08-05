# App Defense Alliance Mobile Application Specification

Version 0.7 - June 14, 2024

## Revision History

| Version | Date | Description |
| --- | :--- | :--- |
| 0.5 | 5/10/24 | Initial draft based on Mobile App Tiger Team review of MASVS specification |
| 0.7 | 5/25/24 | Updates from Tiger Team review of 0.5 spec |

## Contributors
The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification:

* Alex Duff (ASA WG Chair)
* Brooke Davis (ASA WG Vice Chair)
* Anna Bhirud
* Antonio Nappa
* Brad Ree
* Cody Martin
* Corey Gagnon
* Eugene Liderman
* Joel Scambray
* Jorge Damian
* José María Santos López
* Juan Manuel Martinez Hernandez
* Jullian Gerhart
* Olivier Tuchon
* Peter Mueller
* Riccardo Poffo
* Rupesh Nair
* Syrone Hanks II
* Thomas Cannon
* Tim Bolton
* Yiannis Kozyrakis

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

#### PLATFORM

The mobile application relies upon a trustworthy computing platform that runs a recent version of a mobile operating system (i.e. N-2) from the date of evaluation.   For the purposes of this document, N refers to a major operation system release.

#### PROPER_USER

The user of the application software is not willfully negligent or hostile, and sets a device PIN/Passcode.

#### SENSITIVE_DATA

Data that is of particular concern from a security perspective, including personal identifiable information, credentials, and keys. This is not taking into account regulatory requirements for privacy or compliance for various verticals such as healthcare or finance.

PII is any information that can be used to directly or indirectly identify a specific individual. This data, if mishandled, can lead to harm, discrimination, or privacy violations.

#### TOOLING

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

---

### 1.1.1 [The app securely stores sensitive data in external storage](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/)

#### Description

This control ensures that any sensitive data that is intentionally stored by the app is properly protected independently of the target location.

#### Rationale

Apps handle sensitive data coming from many sources such as the user, the backend, system services or other apps on the device and usually need to store it locally. The storage locations may be private to the app (e.g. its internal storage) or be public and therefore accessible by the user or other installed apps (e.g. public folders such as Downloads).

#### Audit

---

#### 1.1.1.1 The app shall securely store sensitive data in external storage

##### Evidence

L1: Attachment of the Android Manifest. If sensitive data is being written to external storage, provide the name and screenshot from a design document explaining how the data is encrypted.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0001](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-STORAGE/MASTG-TEST-0001.md).

##### Verification

_L1_

1. The Android Manifest does not declare the use of external storage.
2. Or, if sensitive data is being written to external storage, confirm the crypto implementation meets the [baseline crypto requirements](#22-crypto) by reviewing the relevant screenshot from the design document.

_L2_

1. Output of the analysis shows that the app does not write and store unencrypted and sensitive data in external storage.
2. Or, if sensitive data is being written to external storage, verify that the crypto implementation meets the [baseline crypto requirements](#22-crypto).

---

### 1.1.2 [The app prevents leakage of sensitive data](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/)

#### Description

This control covers unintentional data leaks where the developer actually has a way to prevent it.

#### Rationale

There are cases when sensitive data is unintentionally stored or exposed to publicly accessible locations; typically as a side-effect of using certain APIs, system capabilities such as backups or logs.

#### Audit

---

#### 1.1.2.1 The Keyboard Cache Is Disabled for sensitive data inputs

##### Evidence

L1: Provide an application resources file snippet showing that for every sensitive data field, the `android:inputType` property is set to one of the following values: `textNoSuggestions`, `textPassword`, `textVisiblePassword`, `numberPassword` or `textWebPassword`.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0006](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-STORAGE/MASTG-TEST-0006.md).

##### Verification

_L1_

1. Documentation does not suggest data on text inputs that process sensitive data.

_L2_

1. Output of the analysis shows that the app disables the keyboard cache for any sensitive data inputs.

---

#### 1.1.2.2 No sensitive data is stored in system logs

##### Evidence

L1: Provide a sample output of all the logs in your system logs that your app outputs though an average app session.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0003](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-STORAGE/MASTG-TEST-0003.md).

##### Verification

_L1_

1. Documentation review shows or states that no sensitive data is stored in plaintext in the system logs.

_L2_

1. Output of the analysis shows that no sensitive data is stored in plaintext.  The scope of this test is limited to logcat and storing any logs in public locations in external storage.

## 1.2 [Crypto](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)

---

### 1.2.1 [The app employs current strong cryptography and uses it according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/)

#### Description

This control covers general cryptography best practices, which are typically defined in external standards.  For testing, the Crypto requirements only apply to sensitive data stored outside of the application sandbox.

#### Rationale

Cryptography plays an especially important role in securing the user's data - even more so in a mobile environment, where attackers having physical access to the user's device is a likely scenario.

#### Audit

---

#### 1.2.1.1 No insecure random number generators shall be utilized for any security sensitive context

##### Evidence

L1: If your application leverages random number generators, provide an output demonstrating that it shall only use java.security.SecureRandom. If you are using java.util.Random or Math.random() it shall only be used for non-security purposes such as UI elements. For non-Java-based developer evidence demonstrates that for security-sensitive contexts, only kernel-based cryptographically-secure pseudorandom number generators are used.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0016](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CRYPTO/MASTG-TEST-0016.md).

##### Verification

_L1_

1. Developer evidence demonstrates that for security sensitive contexts only java.security.SecureRandom is used. For non-Java-based developer evidence demonstrates that for security-sensitive contexts, only kernel-based cryptographically-secure pseudorandom number generators are used.

_L2_

1. Output of the analysis shows that no insecure random number generators are utilized for any security sensitive context.

---

#### 1.2.1.2 No insecure operations shall be used for symmetric cryptography

##### Evidence

L1: If your application leverages symmetric cryptography, provide an output from static analysis demonstrating that your application is only using known good symmetric algorithms with a bit length of a minimum of 128 and that no hardcoded symmetric keys are used for security sensitive contexts.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0013](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CRYPTO/MASTG-TEST-0013.md).

##### Verification

_L1_

1. Developer evidence demonstrates that no insecure methods shall be used for symmetric cryptography as defined below.

_L2_

1. Output of the analysis shows that the app utilizes a minimum of AES-128 and that no insecure methods shall be used for symmetric cryptography as defined below unless specifically required for backwards compatibility with third party systems.

_Additional Context_

Industry best practices are commonly defined as:

* Verify that only cryptographic primitives approved by relevant industry or government standards are in use.
* Verify that contexts requiring confidentiality use an approved block cipher or stream cipher.
* Verify that contexts requiring integrity protection use an approved MAC or digital signature algorithm.
* Verify that contexts requiring both confidentiality and integrity protection use an approved AEAD cipher mode.

---

#### 1.2.1.3 Strong cryptography shall be implemented according to industry best practices

##### Evidence

L1: If your application implements cryptography, provide an output of all instances of cryptographic primitives in code either using a static analysis output, or source code snippets. If your application is relying on non-platform provided crypto you shall also provide evidence that the crypto has been independently reviewed for security.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0014](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CRYPTO/MASTG-TEST-0014.md). If the application is relying on non-platform provided crypto, the crypto shall be independently reviewed for security.

##### Verification

_L1_

1. Developer evidence demonstrates that strong cryptography shall be implemented according to industry best practices.

_L2_

1. Output of the analysis shows that strong cryptography shall be implemented according to industry best practices.

_Additional Context_

Industry best practices are commonly defined as:.

* Verify that only cryptographic primitives approved by relevant industry or government standards are in use.
* Verify that contexts requiring confidentiality use an approved block cipher or stream cipher.
* Verify that contexts requiring integrity protection use an approved MAC or digital signature algorithm.
* Verify that contexts requiring both confidentiality and integrity protection use an approved AEAD cipher mode.

---

### 1.2.2 [The app performs key management according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/)

#### Description

This control covers the management of cryptographic keys throughout their lifecycle, including key generation, storage and protection. Crypto requirements only apply to sensitive data stored outside of the application sandbox.

#### Rationale

Even the strongest cryptography would be compromised by poor key management.

#### Audit

---

#### 1.2.2.1 Cryptographic keys shall only be used for their defined purpose

##### Evidence

L1:  Provide design documentation for how crypto keys are used. For each identified instance the documentation should address the following:

* For encryption/decryption - to ensure data confidentiality
* For signing/verifying - to ensure integrity of data (as well as accountability in some cases)
* For maintenance - to protect keys during certain sensitive operations (such as being imported to the KeyStore)

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0015](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CRYPTO/MASTG-TEST-0015.md)

##### Verification

_L1_

1. Developer evidence demonstrates that cryptographic keys shall only be used for their defined purpose.

_L2_

1. Output of the analysis shows that cryptographic keys shall only be used for their defined purpose.

---

#### 1.2.2.2  Cryptographic key management shall be implemented properly

##### Evidence

L1: Provide design documentation that addresses the following criteria:

* keys are not synchronized over devices if it is used to protect high-risk data.
* keys are not stored without additional protection.
* keys are not hardcoded.
* keys are not derived from stable features of the device.
* keys are not hidden by use of lower level languages (e.g. C/C++).
* keys are not imported from unsafe locations.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0062](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-CRYPTO/MASTG-TEST-0062.md)

##### Verification

_L1_

1. Developer evidence demonstrates that cryptographic key management shall be implemented properly.

_L2_

1. Output of the analysis shows that cryptographic key management shall be implemented properly.

## 1.3 [Auth](https://mas.owasp.org/MASVS/07-MASVS-AUTH/)

---

### 1.3.1 [The app uses secure authentication and authorization protocols and follows the relevant best practices](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/)

#### Description

Most apps connecting to a remote endpoint require user authentication and also enforce some kind of authorization. While the enforcement of these mechanisms must be on the remote endpoint, the apps also have to ensure that it follows all the relevant best practices to ensure a secure use of the involved protocols.

#### Rationale

Authentication and authorization provide an added layer of security and help prevent unauthorized access to sensitive user data.

#### Audit

---

#### 1.3.1.1 If using OAuth 2.0 for authorization, or if using OpenID Connect for authentication, Proof Key for Code Exchange (PKCE) shall be implemented to protect the code grant

##### Evidence

L1: If your application utilizes OAuth 2.0, demonstrate the use of PKCE by either providing a network capture of the authorization flow where there is presence of code_challenge and code_verifier parameters. Alternatively you can present a design document that explicitly references PKCE being enabled and used.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Run static and dynamic analysis to ensure that PKCE is being utilized.

##### Verification

_L1_

1. Developer evidence demonstrates that if the developer is using OAuth 2.0, PKCE is implemented to protect the code grant.

_L2_

1. Output of the analysis shows that if the developer is using OAuth 2.0, PKCE is implemented to protect the code grant.

## 1.4 [Network](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/)

---

### 1.4.1 [The app secures all network traffic according to the current best practices](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/)

#### Description

This control ensures that the app is in fact setting up secure connections in any situation. This is typically done by encrypting data and authenticating the remote endpoint, as TLS does. However, there are many ways for a developer to disable the platform secure defaults, or bypass them completely by using low-level APIs or third-party libraries.

#### Rationale

Ensuring data privacy and integrity of any data in transit is critical for any app that communicates over the network.

#### Audit

---

#### 1.4.1.1 Network connections shall be encrypted

##### Evidence

L1: Attachment of the Android Manifest and the network-security-config XML files, along with justification if plaintext connections are allowed. If 3rd party networking libraries are used, provide design documentation describing their security configuration regarding plaintext connections.

##### Test Procedure

_L1_

1. Follow the testing procedures outlined in [MASTG-TEST-0019](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-NETWORK/MASTG-TEST-0019.md) that are applicable to Android manifest and network security config.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0019](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-NETWORK/MASTG-TEST-0019.md)

##### Verification

_L1_

1. The Android Manifest is not configured to allow plaintext connections. If it is, verify that valid justification has been provided.
2. Using developer design documentation, verify that plaintext connections are not used over the internet for security sensitive purposes.

_L2_

1. Verify that the application does not use plaintext network connections over the internet for security sensitive purposes.

_Additional Context_

The following are out of scope:

* Connections that are not used for security sensitive purposes (e.g. anonymized analytics)
* Connections initiated in WebViews to navigate to arbitrary user-selected URLs, for apps that have browser capabilities.
* Connections to on-device web-server within the application
* Connections to local network web server (e.g. IoT)
* Unencrypted connections that have a valid justification provided.

---

#### 1.4.1.2 TLS configuration of network connections shall adhere to industry best practices

##### Evidence

L1: If 3rd party networking libraries are used, provide design documentation describing their security configuration regarding supported ciphersuites, minimum and maximum TLS version.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0020](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-NETWORK/MASTG-TEST-0020.md) to intercept network traffic.

##### Verification

_L1_

1. Verify using design documentation that the app negotiates the best available ciphersuite that the backend offers
2. Verify using design documentation  that the app cannot negotiate to use known vulnerable ciphers
3. Verify using design documentation that the app uses industry best practices related to algorithms & ciphers

_L2_

1. Verify that the app negotiates the best available ciphersuite that the backend offers
2. Verify that the app cannot negotiate to use known vulnerable ciphers
3. Verify that the app uses industry best practices related to algorithms & ciphers

_Additional Context_

This test is limited in scope to the mobile app; not the backend.

For industry best practices, see section “Minimum Requirements for TLS Clients” in [SP.800-52r2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) and [BSI TR-02102-2](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile&v=6):

* Clients must support TLS1.2 or higher
* Clients must not support SSL2.0 or SSL3.0.
* Clients must not default to TLS1.0 or TLS1.1

---

#### 1.4.1.3 Endpoint identity shall be verified on network connections

##### Evidence

L1: Attachment of Android Manifest and Network Security Config. If 3rd party networking libraries are used, provide design documentation describing their security configuration regarding trusted CA certificates and hostname verification.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0021](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-NETWORK/MASTG-TEST-0021.md)

##### Verification

_L1_

1. Verify that the application targets SDK > 24 or higher and user certificates are not trusted for connections that can carry sensitive data.
2. If the system trusted CA store is not used, verify via design documentation that alternative mechanisms to validate trust such as certificate pinning are used.

_L2_

1. Verify that network connections carrying sensitive data are using trusted certificates and the connection is correctly validated as per  [MASTG-TEST-0021](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-NETWORK/MASTG-TEST-0021.md)
    * Verify that the app does not trust user installed certificates.
    * If the system trusted CA store is not used, alternative mechanisms to validate trust such as certificate pinning shall be used.

_Additional Context_

This test is limited in scope to connections that contain sensitive data.

## 1.5 [Platform](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/)

---

### 1.5.1 [The app uses IPC mechanisms securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/)

#### Description

This control ensures that all interactions involving IPC mechanisms happen securely.

#### Rationale

Apps typically use platform provided IPC mechanisms to intentionally expose data or functionality. Both installed apps and the user are able to interact with the app in many different ways.

#### Audit

---

#### 1.5.1.1 The app shall limit content provider exposure and harden queries against injection attacks

##### Evidence

L1: Attachment of the Android Manifest. If a content provider is exposed, a screenshot from a design document explaining how SQLi hardening measures are used shall be provided.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0007](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0007.md) and provide output

##### Verification

_L1_

1. Android Manifest shall demonstrate the limited necessary exposure of content providers.
2. Design document shall demonstrate hardening measures against queries.

_L2_

1. Testing output shall demonstrate limited content provider exposure, and hardening measures protecting against injection attacks.

---

#### 1.5.1.2 The app shall use verified links and sanitize all link input data

##### Evidence

L1: Attachment of the Android Manifest. If Android API 31 and below are used, a screenshot from a design doc demonstrates a validation and sanitization process for working with trusted inputs.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0028](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0028.md), with the understanding that sampling must be used given scope of test.
2. Run the Android "App Link Verification Tester" script.

##### Verification

_L1_

1. Android Manifest demonstrates that the app target API level is above API 31, otherwise the design documentation screenshot demonstrates a sanitizing process for working with trusted inputs.

_L2_

1. Output from Android "App Link Verification Tester" script shall verify that all links demonstrate input sanitization.

---

#### 1.5.1.3 Any sensitive functionality exposed via IPC shall be intentional and at the minimum required level

##### Evidence

L1: Attachment of the Android Manifest with justifications for exposure and permission levels.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0029](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0029.md)

##### Verification

_L1_

1. Enumerate IPC mechanisms via AndroidManifest.xml to evaluate the security policy of exposed surface area available to other apps.

_L2_

1. There shall be no leaked sensitive information from exposed sensitive functionality.
2. Sensitive functionality shall adhere to the principle of least privilege.

---

#### 1.5.1.4 All Pending Intents shall be immutable or otherwise justified for mutability

##### Evidence

L1: Attachment of the Android Manifest. If API level is below 31, screenshot from a design doc detailing secure usage of PendingIntents. For all mutable Intents, the developer shall provide a clear justification.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0030](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0030.md)

##### Verification

_L1_

1. Android Manifest shall use API level 31 or greater to ensure immutable by default PendingIntents being in place.
2. Or, verify the developer provided justification aligns with security tradeoffs required.

_L2_

1. Ensure that Pending Intents are immutable, and the app explicitly specifies the exact package, action, and component that receives the base intent.
2. [Reference DAC documentation: https://developer.android.com/privacy-and-security/risks/pending-intent](https://developer.android.com/privacy-and-security/risks/pending-intent)

---

### 1.5.2 [The app uses WebViews securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/)

#### Description

This control ensures that WebViews are configured securely to prevent sensitive data leakage as well as sensitive functionality exposure (e.g. via JavaScript bridges to native code).

#### Rationale

WebViews are typically used by apps that have a need for increased control over the UI. They can, however, also be exploited by attackers or other installed apps, potentially compromising the app's security.

#### Audit

---

#### 1.5.2.1 WebViews shall securely execute JavaScript

##### Evidence

L1

1. If JavaScript is enabled, provide a data flow diagram with trusted end-points, secure protocols, and trust boundaries demonstrating the app's control over resources being loaded.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0031](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0031.md)

##### Verification

_L1_

1. Output from semgrep rules shall demonstrate JavaScript is disabled.
2. If JavaScript is required the corresponding data flow diagram shall demonstrate developer controlled resource usage.

_L2_

1. Ensure that all endpoints use HTTPS (or other encrypted protocols) for connections.
2. Ensure that JS and HTML are loaded locally from within the app, or from trusted web servers only.
3. Ensure that users cannot define which data-sources to load based on user input.
4. [Refer to DAC guidance for scoping: https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading)

_Additional Context_

If the app has Javascript disabled, this shall pass automatically. This can be demonstrated by providing tooling output that JavaScript is disabled within WebView by running semgrep rules [MASTG-PLATFORM-5](https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/rules/platform/mstg-platform-5.yaml).

---

#### 1.5.2.2 WebView shall be configured to allow the minimum set of protocol handlers required while disabling potentially dangerous handlers

##### Evidence

_L1_

1. Provide Android Manifest for API level verification for hardening WebView defaults. If API level has a default permissive posture for file access, or file access controls have been changed to be more open, the developer must provide justification.
2. Run [MSTG-PLATFORM-6](https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/status.md) and provide output to verify WebView usage is adhering to [MASTG-TEST-0032](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0032.md) Static Analysis testing is configured accordingly.
3. For any deviations from [MASTG-TEST-0032](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0032.md) Static Analysis output, provide a justification.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0032](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0032.md)

##### Verification

_L1_

1. Android Manifest shall demonstrate API level 30 or above. If API level 29 or below is in use, `setAllowFileAccess` shall be set to `false`. If `setAllowFileAccess` is set to true, developer justification must demonstrate requirement for this configuration.
2. Output from [MSTG-PLATFORM-6](https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/status.md) shall demonstrate the usage of only necessary protocol handlers.
3. Output from [MSTG-PLATFORM-6](https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/status.md) shall demonstrate potentially dangerous handlers such as `file`, `tel`, and `app-id` are disabled. For any potentially dangerous handlers, the developer justification must demonstrate the need for implementation.

_L2_

1. Output from [MSTG-PLATFORM-6](https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/status.md) shall demonstrate the usage of only necessary protocol handlers.
2. Output from [MSTG-PLATFORM-6](https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/status.md) shall demonstrate that potentially dangerous handlers such as `file`, `tel`, and `app-id` are disabled. For any potentially dangerous handlers, the developer justification must demonstrate the need for implementation.
3. App shall not expose unnecessary, and unexpected, protocol handlers through dynamic analysis.

---

### 1.5.3 [The app uses the user interface securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/)

#### Description

This control ensures that this data doesn't end up being unintentionally leaked due to platform mechanisms such as auto-generated screenshots or accidentally disclosed via e.g. shoulder surfing or sharing the device with another person.

#### Rationale

Sensitive data has to be displayed in the UI in many situations (e.g. passwords, credit card details, OTP codes in notifications) which can lead to unintentional leaks.

#### Audit

---

#### 1.5.3.1 The app shall by default mask data in the User Interface when it is known to be sensitive

##### Evidence

_L1_

1. Provide screenshots of proper input typing demonstrating that android`:inputType="textPassword"` is in use for passwords, pins, credit card information, data commonly found on government IDs (such as social security, driver ID, passport ID) fields.
2. Show screenshots of any UI elements where passwords, pins, credit card information, data commonly found on government IDs (such as social security, driver ID, passport ID) are visible and demonstrate they are masked by default.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0008](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-PLATFORM/MASTG-TEST-0008.md)

##### Verification

_L1_

1. Provided documentation shall demonstrate appropriate input type implementation for the intended use of the input field.

_L2_

1. Passwords, pins, credit card information, data commonly found on government IDs (such as social security, driver ID, passport ID) must be properly masked for input fields and suppressed in notifications where the app knows the type of data it is displaying.
2. Passwords, pins, credit card information, data commonly found on government IDs (such as social security, driver ID, passport ID) shall only be displayed to the user in clear text through an explicit action, such as clicking a show password button.

## 1.6 [Code](https://mas.owasp.org/MASVS/10-MASVS-CODE/)

---

### 1.6.1 [The app requires an up-to-date platform version](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/)

#### Description

This control ensures that the app is running on an up-to-date platform version so that users have the latest security protections.

#### Rationale

Every release of the mobile OS includes security patches and new security features. By supporting older versions, apps stay vulnerable to well-known threats.

#### Audit

---

#### 1.6.1.1 The app shall set the targetSdkVersion to an up-to-date platform version

##### Evidence

L1: Attachment of the Android Manifest

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Obtain the Android Manifest and review for adherence with requirements

##### Verification

_L1_

1. Verify that targetSDKVersion is set to N-2 or above where N is the latest SDK at the time of test.

_L2_

1. Verify that the targetSdkVersion is set to N-2 or above where N is the latest SDK at the time of test.

---

### 1.6.2 [The app only uses software components without known vulnerabilities](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/)

#### Description

To be truly secure, a full whitebox assessment should have been performed on all app components. However, as it usually happens with e.g. for third-party components this is not always feasible and not typically part of a penetration test. This control covers "low-hanging fruit" cases, such as those that can be detected just by scanning libraries for known vulnerabilities.

#### Rationale

The developer should protect users from known vulnerabilities.

#### Audit

---

#### 1.6.2.1 The app only uses software components without known vulnerabilities

##### Evidence

L1: Follow the testing procedures outlined in [MASTG-TEST-0042](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CODE/MASTG-TEST-0042.md) and provide the generated report.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0042](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CODE/MASTG-TEST-0042.md)

##### Verification

_L1_

1. Verify that the app does not use any 3P libraries at a version vulnerable to a CVE with a severity >= CVSS 7.0.

_L2_

1. Verify that the app does not use any 3P libraries at a version vulnerable to a CVE with a severity >= CVSS 7.0.

_Additional Context_

An app that uses a 3P library at a version vulnerable to a CVE with CVSS >= 7.0 can pass this test if the developer provides additional justification that:

* The app does not invoke the vulnerable 3P library code or
* The 3P library has not yet made an update available. This is acceptable only if the 3P library has a regular patch process.

---

### 1.6.3 [The app validates and sanitizes all untrusted inputs](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)

#### Description

Apps have many data entry points including the UI, IPC, the network, the file system, etc.  This control ensures that this data is treated as untrusted input and is properly verified and sanitized before it's used.

#### Rationale

This incoming data might have been inadvertently modified by untrusted actors and may lead to bypass of critical security checks as well as classical injection attacks such as SQL injection, XSS or insecure deserialization.

#### Audit

---

#### 1.6.3.1 Compiler security features shall be enabled

##### Evidence

L1: Follow the instructions outlined in [MASTG-TEST-0044](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CODE/MASTG-TEST-0044.md) and export the output.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0044](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CODE/MASTG-TEST-0044.md)

##### Verification

_L1_

1. Developer evidence demonstrates that compiler security features (PIE/PIC and stack smashing protections) are enabled.

_L2_

1. Output of the analysis shows that demonstrates that compiler security features (PIE/PIC and stack smashing protections) are enabled

_Additional Context_

If a native 3P library that is packaged in the application does not have these enabled, this test can still pass if the developer provides justification that the 3P library does not build or work as expected if these are enabled.

---

#### 1.6.3.2 The App shall Mitigate Against Injection Flaws in Content Providers

##### Evidence

L1: Attachment of the Android Manifest. If a content provider is exposed, a screenshot from a design document explaining how injection hardening measures are used shall be provided.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0025](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CODE/MASTG-TEST-0025.md)

##### Verification

_L1_

1. Android Manifest shall demonstrate the limited necessary exposure of content providers.
2. Design document shall demonstrate hardening measures against queries.

_L2_

1. Testing output shall demonstrate limited content provider exposure, and hardening measures protecting against injection attacks.

---

#### 1.6.3.3 Arbitrary URL redirects shall not be included in the app's webviews

##### Evidence

_L1_

1. Grep output that WebView is never used as well as an attachment of the Android Manifest (or)
2. Documentation demonstrating that only trusted content can be loaded in the apps webview

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0027](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CODE/MASTG-TEST-0027.md)

##### Verification

_L1_

1. Verify SafeBrowsing is enabled

_L2_

1. Verify that only trusted content can be loaded in the app webview:
   * Verify that the app correctly validates the scheme and host parts of loaded URIs against an allowlist relevant to the app, as per [unsafe-uri-loading](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading).
   * Verify SafeBrowsing is enabled

_Additional Context_

If the app has no webviews, this test should pass automatically.

---

#### 1.6.3.4 Any use of implicit intents shall be appropriate for the app's functionality and any return data shall be handled securely

##### Evidence

L1: Attach the Android Manifest and an explanation of the rationale for every implicit intent.

##### Test Procedure

_L1_

1. Review all implicit intents and ensure rationale validates appropriateness for the apps functionality.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0026](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-CODE/MASTG-TEST-0026.md)

##### Verification

_L1_

1. Developer evidence demonstrates that the app either has no implicit intents or that the implicit intents are appropriate for the apps functionality.

_L2_

1. Verify that any use of implicit intents to send data to other apps is appropriate for the app’s functionality and does not leak sensitive data.
2. Verify that after calling startActivityForResult() any data returned by other apps is handled securely within onActivityResult()

## 1.7 [Resilience](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)

---

### 1.7.1 [The app implements anti-tampering mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/)

#### Description

This control tries to ensure the integrity of the app's intended functionality by preventing modifications to the original code and resources.

#### Rationale

Apps run on a user-controlled device, and without proper protections it's relatively easy to run a modified version locally (e.g. to cheat in a game, or enable premium features without paying), or upload a backdoored version of it to third-party app stores.

#### Audit

---

#### 1.7.1.1 The app shall be properly signed

##### Evidence

L1: Run the apksigner utility as documented in [MASTG-TEST-0038](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038.md) and provide the output.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0038](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-RESILIENCE/MASTG-TEST-0038.md).

##### Verification

_L1_

1. Developer evidence demonstrates that the app is signed using v2 or higher.

_L2_

1. Output of the analysis shows that the app is signed using v2 or higher.

---

### 1.7.2 [The app implements anti-static analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/)

#### Description

This control tries to impede comprehension by making it as difficult as possible to figure out how an app works using static analysis.

#### Rationale

Understanding the internals of an app is typically the first step towards tampering with it.

#### Audit

---

#### 1.7.2.1 The app shall disable all debugging symbols in the production version

##### Evidence

L1: Attach the results of semgrep rule [MSTG-CODE-3](https://github.com/mindedsecurity/semgrep-rules-android-security/blob/main/status.md). If you have a third-party library that this cannot be enabled for, please document this.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0040](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-RESILIENCE/MASTG-TEST-0040.md).

##### Verification

_L1_

1. Developer evidence demonstrates that debugging symbols are disabled in their production version.

_L2_

1. Output of the analysis shows that debugging symbols are disabled in their production version.

---

### 1.7.3 [The app implements anti-dynamic analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/)

#### Description

Sometimes pure static analysis is very difficult and time consuming so it typically goes hand in hand with dynamic analysis.  This control aims to make it as difficult as possible to perform dynamic analysis, as well as prevent dynamic instrumentation which could allow an attacker to modify the code at runtime.

#### Rationale

Observing and manipulating an app during runtime makes it much easier to decipher its behavior.

#### Audit

---

#### 1.7.3.1 The app shall not be debuggable if installed from outside of commercial app stores

##### Evidence

L1: Attach the application Android Manifest or a screenshot showing that “android:debuggable” is not set to “true”

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0039](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039.md).

##### Verification

_L1_

1. Developer evidence demonstrates that the application is not debuggable.

_L2_

1. Output of the analysis shows that the application is not debuggable.

## 1.8 [Privacy](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/)

---

### 1.8.1 [The app minimizes access to sensitive data and resources](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/)

#### Description

Apps should only request access to the data they absolutely need for their functionality and always with informed consent from the user. This control ensures that apps practice data minimization and restricts access control.  Furthermore, apps should share data with third parties only when necessary, and this should include enforcing that third-party SDKs operate based on user consent, not by default or without it. Apps should prevent third-party SDKs from ignoring consent signals or from collecting data before consent is confirmed.  Additionally, apps should be aware of the 'supply chain' of SDKs they incorporate, ensuring that no data is unnecessarily passed down their chain of dependencies.

#### Rationale

Data minimization reduces the potential impact of data breaches or leaks.  This end-to-end responsibility for data aligns with recent SBOM regulatory requirements, making apps more accountable for their data practices.

#### Audit

---

#### 1.8.1.1 The app shall minimize access to sensitive data and resources provided by the platform

##### Evidence

L1: Attachment of the Android manifest showing permission requests.  Provide justification for any runtime or signature permissions

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Using dynamic analysis, monitor runtime permission usage, data access patterns and third-party SDK behaviors.

##### Verification

_L1_

1. The Android Manifest adheres to least privilege principle by only requesting permissions that are needed for its functionality

_L2_

1. The app adheres to least privilege principle by only requesting permissions that are needed for its functionality.  Any flagged permissions requires the developer to provide justification for app functionality.

---

### 1.8.2 [The app is transparent about data collection and usage](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/)

#### Description

This control ensures that apps provide clear information about data collection, storage, and sharing practices, including any behavior a user wouldn't reasonably expect, such as background data collection. Apps should also adhere to platform guidelines on data declarations.

#### Rationale

Users have the right to know how their data is being used.

#### Audit

---

#### 1.8.2.1 The app shall be transparent about data collection and usage

##### Evidence

L1: Provide a URL to the app’s privacy policy.  Provide a screenshot of the App Store label with a mapping of declarations to the privacy policy.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Perform a match against data practices displayed in the Data Safety Section  against data practices explicitly listed in the privacy policy.  Check for data types being transmitted over the network that aren’t declared to users.

##### Verification

_L1_

1. Ensure the developer provides a valid privacy policy and the declarations match those in the App Store label

_L2_

1. All data collected should be included explicitly, either within the actual application or somewhere that can be accessed via the application.

---

### 1.8.3 [The app offers user control over their data](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/)

#### Description

This control ensures that apps provide mechanisms for users to manage, delete, and modify their data, and change privacy settings as needed (e.g. to revoke consent). Additionally, apps should re-prompt for consent and update their transparency disclosures when they require more data than initially specified.

#### Rationale

Users should have control over their data.

#### Audit

---

#### 1.8.3.1 Users shall have the ability to request their data to be deleted via an in-app mechanism

##### Evidence

L1: Provide a screenshot that shows an in-app URL which allows users to initiate app account deletion

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Review App Store label to verify existence of data deletion request mechanism.  Lab confirms availability of URL in app.

##### Verification

_L1 & L2_

1. The app provides an in-app mechanism which allows users to modify and delete their personal data.

# 2 iOS

## 2.1 [Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)

---

### 2.1.1 [The app securely stores sensitive data in external storage](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/)

#### Audit

---

#### 2.1.1.1 The app shall securely store sensitive data in external storage

##### Evidence

L1: Attach screenshots of all instances of files being saved outside of the app sandbox via `UIDocumentPickerViewController`. If sensitive data is being written to external storage, provide the name and screenshot from a design document explaining how the data is encrypted.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-00052](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-STORAGE/MASTG-TEST-0052.md).

##### Verification

_L1_

1. The app does not use `UIDocumentPickerViewController`.
2. If sensitive data is being written to external storage, confirm the crypto implementation meets the baseline [crypto requirements](#heading=h.qck736ryyi5) by reviewing the relevant screenshot from the design document.

_L2_

1. Output of the analysis shows that the app does not write and store unencrypted and sensitive data in external storage.
2. If sensitive data is being written to external storage, verify that the crypto implementation meets the [baseline crypto requirements](#heading=h.qck736ryyi5).

---

### 2.1.2 [The app prevents leakage of sensitive data](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/)

#### Audit

---

#### 2.1.2.1 The Keyboard Cache shall be disabled for sensitive data inputs

##### Evidence

L1: Provide a code snippet showing that sensitive input fields are marked as `secureTextEntry` or that autocorrect is manually disabled with `autocorrectionType = UITextAutocorrectionTypeNo`.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0055](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-STORAGE/MASTG-TEST-0055.md)

##### Verification

_L1_

1. Review the provided evidence to verify that sensitive fields will not cache keyboard input.

_L2_

1. Output of the analysis shows sensitive data is not present in the cache after typing into the respective text field.  Note: This only applies to input into text fields that are meant to be used for sensitive data.

---

#### 2.1.2.2 No sensitive data shall be stored in system logs

##### Evidence

L1: Provide a sample output of all the logs in your system logs that your app outputs though an average app session.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in[ MASTG-TEST-0053](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-STORAGE/MASTG-TEST-0053.md)

##### Verification

_L1_

1. Documentation review shows or states that no sensitive data is stored in plaintext in the system logs.

_L2_

1. Output of the analysis shows that no sensitive data is stored in plaintext in the application logs.

## 2.2 [Crypto](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)

---

### 2.2.1 [The app employs current strong cryptography and uses it according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/)

#### Audit

---

#### 2.2.1.1 No insecure random number generators shall be utilized for any security sensitive context

##### Evidence

L1: If your application leverages random number generators for security purposes, provide output demonstrating that it shall only use cryptographically-secure pseudorandom number generators. For swift and objective-c code, provide output from the semgrep rule [ios_insecure_random_no_generator](https://github.com/MobSF/mobsfscan/blob/main/mobsfscan/rules/patterns/ios/swift/swift_rules.yaml).

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0063](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-CRYPTO/MASTG-TEST-0063.md)

##### Verification

_L1_

1. Developer evidence demonstrates that insecure random number generators are not used in a security sensitive context.

_L2_

1. Output of the analysis shows that no insecure random number generators are utilized for any security sensitive context.

---

#### 2.2.1.2 Strong cryptography shall be implemented according to industry best practices

##### Evidence

L1:  If your application implements cryptography, provide an output of all instances of cryptographic primitives in code either using a static analysis output, or source code snippets. If your application is relying on non-platform provided crypto you shall also provide evidence that the crypto has been independently reviewed for security.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0061](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-CRYPTO/MASTG-TEST-0061.md). If the application is relying on non-platform provided crypto, the crypto shall be independently reviewed for security.

##### Verification

_L1_

1. Developer evidence demonstrates that strong cryptography shall be implemented according to industry best practices.

_L2_

1. Output of the analysis shows that strong cryptography shall be implemented according to industry best practices.

_Additional Context_

Refer to [SP.800-57p1r5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) and [SP.800-131Ar2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) with 112 bit of security as baseline:

* Hashing: SHA-224 or better
* Digital signatures & public key encryption: (Key length no less than 2048 bits for factoring or 224 for ECC)
* Custom implementations: If the provider has a custom implementation of a library (open-source library) test is in scope, home-grown implementation requires further developer assurance.

---

### 2.2.2 [The app performs key management according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/)

#### Audit

---

#### 2.2.2.1 Cryptographic keys shall only be used for their defined purpose

##### Evidence

L1: Provide design documentation for how crypto keys are used. For each identified instance the documentation should address the following:

* For encryption/decryption - to ensure data confidentiality
* For signing/verifying - to ensure integrity of data (as well as accountability in some cases)
* For maintenance - to protect keys during certain sensitive operations (such as being imported to the KeyStore)

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0062](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-CRYPTO/MASTG-TEST-0062.md). Use objection `ios monitor crypto `command to monitor crypto operations.

##### Verification

_L1_

1. Developer evidence demonstrates that cryptographic keys are used for their defined purpose.

_L2_

1. Dynamic analysis demonstrates that cryptographic keys are used for their defined purpose.

---

#### 2.2.2.2 Cryptographic key management shall be implemented properly

##### Evidence

L1: Provide design documentation that addresses the following criteria:

* keys are not synchronized over devices if it is used to protect high-risk data.
* keys are not stored without additional protection.
* keys are not hardcoded.
* keys are not derived from stable features of the device.
* keys are not hidden by use of lower level languages (e.g. C/C++).
* keys are not imported from unsafe locations.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0062](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-CRYPTO/MASTG-TEST-0062.md). Use objection `ios monitor crypto `command to monitor crypto operations.

##### Verification

_L1_

1. Developer evidence demonstrates that cryptographic key management shall be implemented properly.

_L2_

1. Output of the analysis shows that cryptographic key management shall be implemented properly.

## 2.3 [Auth](https://mas.owasp.org/MASVS/07-MASVS-AUTH/)

---

### 2.3.1 [The app uses secure authentication and authorization protocols and follows the relevant best practices](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/)

#### Audit

---

#### 2.3.1.1 If using OAuth 2.0 to authenticate, Proof Key for Code Exchange (PKCE) shall be implemented to protect the code grant

##### Evidence

L1: If your application utilizes OAuth 2.0, demonstrate the use of PKCE by either providing a network capture of the authorization flow where there is presence of code_challenge and code_verifier parameters. Alternatively you can present a design document that explicitly references PKCE being enabled and used.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Run static and dynamic analysis to ensure that PKCE is being utilized.

##### Verification

_L1_

1. Developer evidence demonstrates that if the developer is using OAuth 2.0, PKCE is implemented to protect the code grant.

_L2_

1. Output of the analysis shows that if the developer is using OAuth 2.0, PKCE is implemented to protect the code grant.

## 2.4 [Network](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/)

---

### 2.4.1 [The app secures all network traffic according to the current best practices](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/)

#### Audit

---

#### 2.4.1.1 Network connections shall be encrypted

##### Evidence

L1: Attach the Info.plist that shows the App Transport Security (ATS) policy, along with [justification](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) if plaintext connections are allowed. If 3rd party networking libraries are used, provide design documentation describing their security configuration regarding plaintext connections.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0065](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-NETWORK/MASTG-TEST-0065.md) to intercept traffic.

##### Verification

_L1_

1. ATS is not configured to allow plaintext connections. If it is, verify that valid justification has been provided.
2. Using developer design documentation, verify that plaintext connections are not used over the internet for security sensitive purposes.

_L2_

1. Verify that the application does not use plaintext network connections over the internet for security sensitive purposes.

_Additional Context_

The following are out of scope:

* Connections that are not used for security sensitive purposes (e.g. transferring sensitive data)
* Connections initiated in webviews to navigate to arbitrary user-selected URLs, for apps that have browser capabilities.
* Connections to on-device web-server within the application
* Connections to local network web server (e.g. IoT)
* Unencrypted connections that have a valid justification provided.

---

#### 2.4.1.2 TLS configuration of network connections shall adhere to industry best practices

##### Evidence

L1:Attach the Info.plist that shows the App Transport Security (ATS) policy, along with [justification](https://developer.apple.com/documentation/security/preventing_insecure_network_connections#3138036) if plaintext connections are allowed. If 3rd party networking libraries are used, provide design documentation describing their security configuration regarding supported ciphersuites, minimum and maximum TLS version.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0066](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-NETWORK/MASTG-TEST-0066.md) to intercept network traffic.

##### Verification

_L1_

1. Review the provided ATS policy to see if the app allows insecure connections.
2. Verify using design documentation that the app negotiates the best available ciphersuite that the backend offers
3. Verify using design documentation  that the app cannot negotiate to use known vulnerable ciphers
4. Verify using design documentation that the app uses industry best practices related to algorithms & ciphers

_L2_

1. Verify that the app negotiates the best available ciphersuite that the backend offers using the nscurl command:  `nscurl --ats-diagnostics --verbose`
2. Verify that the app cannot negotiate to use known vulnerable ciphers
3. Verify that the app uses industry best practices related to algorithms & ciphers

_Additional Context_

This test is limited in scope to the mobile app; not the backend.

For industry best practices, see section “Minimum Requirements for TLS Clients” in [SP.800-52r2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) and [BSI TR-02102-2](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile&v=6):

* Clients must support TLS1.2 or higher
* Clients must not support SSL2.0 or SSL3.0.
* Clients must not default to TLS1.0 or TLS1.1

---

#### 2.4.1.3 Endpoint identity shall be verified on network connections

##### Evidence

L1:Attachment of Info.plist file. If 3rd party networking libraries are used, provide design documentation describing their security configuration regarding trusted CA certificates and hostname verification.

##### Test Procedure

_L1_

1. Review the Info.plist file for the App Transport Security configuration for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0067](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-NETWORK/MASTG-TEST-0067.md)

##### Verification

_L1_

1. If the application targets iOS 9 or higher, verify that it does not trust user certificates for connections that can carry sensitive data.
2. If the system trusted CA store is not used, verify via design documentation that alternative mechanisms to validate trust such as certificate pinning are used.

_L2_

1. Verify that network connections carrying sensitive data are using trusted certificates and the connection is correctly validated as per  [MASTG-TEST-0067](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-NETWORK/MASTG-TEST-0067.md)
    1. Verify that the app does not trust user installed certificates.
    2. If the system trusted CA store is not used, alternative mechanisms to validate trust such as certificate pinning shall be used.

_Additional Context_

This test is limited in scope to connections that contain sensitive data.

## 2.5 [Platform](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/)

---

### 2.5.1 [The app uses IPC mechanisms securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/)

#### Audit

---

#### 2.5.1.1 The app shall not expose sensitive data via IPC mechanisms

##### Evidence

L1: Provide evidence of usage of IPC mechanisms listed in [MASTG-TEST-0056](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0056.md)

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0056](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0056.md)

##### Verification

_L1_

1. Review the provided documentation to validate that the application is not performing actions on behalf of the user without user interaction.

_L2_

1. Perform the dynamic analysis using Frida to understand functionality that is exposed via custom url schemes and verify that the application is not performing actions on behalf of the user without user interaction.

---

#### 2.5.1.2 The app shall not expose sensitive data via App Extensions

##### Evidence

L1:Attach the Info.plist file output from the following command along with an explanation of what the App Extension does.

```
grep -nr NSExtensionPointIdentifier <Payload>.app
```

##### Test Procedure

_L1_

2. Review provided evidence for adherence with requirements

_L2_

2. Follow the testing procedures outlined in [MASTG-TEST-0072](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0072.md) for identifying App Extensions.

##### Verification

_L1 & L2:_ Review the provided information to verify:

* Only data types required for App Extension functionality shall be supported.
* The application may restrict extensions (custom keyboards)

---

#### 2.5.1.3 The app shall not expose sensitive functionality via Custom URL Schemes

##### Evidence

L1: Attach the Info.plist containing any values for CFBundleURLSchemes along with design documentation describing functionality exposed via custom URL schemes.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0075](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075.md).

##### Verification

_L1_

1. Review the provided documentation to validate that the application is not performing actions on behalf of the user without user interaction.

_L2_

1. Perform the dynamic analysis using Frida to understand functionality that is exposed via custom url schemes and verify that the application is not performing actions on behalf of the user without user interaction.

---

#### 2.5.1.4 The app shall not expose sensitive data via UIActivity Sharing

##### Evidence

_L1 & L2:_ Provide documentation on UIActivity usage.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0071](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0071.md)

##### Verification

L1 & L2: Review the provided information to verify:

* The nature of the data being shared.
* The inclusion of custom activities.
* The exclusion of certain activity types.

---

#### 2.5.1.5 The app shall not use the general pasteboard for sharing sensitive information

##### Evidence

L1: Attach the Info.plist file and output from the semgrep rule [ios_general_paste](https://github.com/MobSF/mobsfscan/blob/main/mobsfscan/rules/patterns/ios/swift/swift_rules.yaml).

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0073](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0073.md) for dynamic analysis of pasteboard usage.

##### Verification

_L1_

1. Verify in the Info.plist that the application supports a minimum version of iOS 14.0 or newer.
2. Review the semgrep output to verify that the application is not using the general pasteboard to share sensitive information.

_L2_

1. Verify in the Info.plist that the application supports a minimum version of iOS 14.0 or newer.
2. Follow the steps in [MASTG-TEST-0073](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0073.md) to verify that the app is not automatically adding sensitive data to the general pasteboard.

---

#### 2.5.1.6 The app shall not expose sensitive functionality via Universal Links

##### Evidence

L1: Attach the values for the key `com.apple.developer.associated-domains` in the .entitlements file along with design documentation describing functionality exposed via universal links.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0070](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0070.md)

##### Verification

_L1_

1. Review the provided documentation to verify that the application is not performing actions on behalf of the user without user interaction.

_L2_

1. Perform the dynamic analysis using Frida to understand functionality that is exposed via universal links and verify that the application is not performing actions on behalf of the user without user interaction

---

### 2.5.2 [The app uses WebViews securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/)

#### Audit

---

#### 2.5.2.1 WebViews shall securely execute JavaScript

##### Evidence

L1:

1. Demonstrate that JavaScript is disabled within WebView.
2. If JavaScript is enabled, provide a data flow diagram with trusted end-points, secure protocols, and trust boundaries demonstrating the app's control over resources being loaded.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0076](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0076.md)

##### Verification

_L1_

1. If JavaScript is required the corresponding data flow diagram shall demonstrate developer controlled resource usage.

_L2_

1. Ensure that all endpoints use HTTPS (or other encrypted protocols) for connections.
2. Ensure that JS and HTML are loaded locally from within the app, or from trusted web servers only.
3. Ensure that users cannot define which data-sources to load based on user input.

_Additional Context_

If the app has Javascript disabled, this shall pass automatically.

---

#### 2.5.2.2 WebView shall be configured securely

##### Evidence

L1:

1. Provide output from [improper_wkwebview](https://github.com/akabe1/akabe1-semgrep-rules/blob/main/ios/swift/webview/improper_wkwebview.yaml) and [insecure_webview](https://github.com/akabe1/akabe1-semgrep-rules/blob/main/ios/swift/webview/insecure_webview.yaml) to demonstrate that WebView usage is adhering to [MASTG-TEST-0077](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0077.md)
2. Provide a justification for WebViews that load

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0077](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0077.md)

##### Verification

_L1_

1. Output from [improper_wkwebview](https://github.com/akabe1/akabe1-semgrep-rules/blob/main/ios/swift/webview/improper_wkwebview.yaml) to demonstrate the usage of WKWebView.
2. Output from [insecure_webview](https://github.com/akabe1/akabe1-semgrep-rules/blob/main/ios/swift/webview/insecure_webview.yaml) shall demonstrate potentially dangerous usage of deprecated UIWebView.
3. Review justification for WebViews do not unnecessarily access or allow access to local files and content providers and the app implement best practices for WebView settings

_L2_

1. Follow the testing procedures in [MASTG-TEST-0077](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0077.md) and review the Frida output.
2. Ensure that WebViews do not unnecessarily access or allow access to local files and content providers and the app implement best practices for loading WebView content and file access.

---

### 2.5.3 [The app uses the user interface securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/)

#### Audit

---

#### 2.5.3.1 The app shall by default mask data in the User Interface when it is known to be sensitive

##### Evidence

L1:

1. Provide screenshots of proper input typing demonstrating that `sensitiveTextField.isSecureTextEntry = true` is in use for passwords, pins, credit card information, data commonly found on government IDs (such as social security, driver ID, passport ID) fields where the app knows the type of data it is displaying..
2. Show screenshots of any UI elements where passwords, pins, credit card information, data commonly found on government IDs (such as social security, driver ID, passport ID) are visible and demonstrate they are masked by default.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0057](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-PLATFORM/MASTG-TEST-0057.md)

##### Verification

_L1_

1. Provided documentation shall demonstrate appropriate input type implementation for the intended use of the input field.

_L2_

1. Passwords, pins, credit card information, data commonly found on government IDs (such as social security, driver ID, passport ID) must be properly masked for input fields and suppressed in notifications.
2. Passwords, pins, credit card information, data commonly found on government IDs (such as social security, driver ID, passport ID) shall only be displayed to the user in clear text through an explicit action, such as clicking a show password button.

## 2.6 [Code](https://mas.owasp.org/MASVS/10-MASVS-CODE/)

---

### 2.6.1 [The app requires an up-to-date platform version](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/)

#### Audit

---

#### 2.6.1.1 The app shall target an up-to-date platform version

##### Evidence

L1: Attach the Info.plist containing the value for `DTPlatformVersion` and `DTXcodeBuild.`

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Unzip the IPA file and inspect the Info.plist to confirm the `DTPlatformVersion` and `DTXcodeBuild`  against https://xcodereleases.com/

##### Verification

_L1 & L2:_ Verify that the app was built with a version of Xcode (DTXcodeBuild) that is   N-2 or above where N is the latest version of Xcode at the time of test. The DTPlatformVersion should also be N-2 where N is the most recent version of iOS at the time of the test.

---

### 2.6.2 [The app only uses software components without known vulnerabilities](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/)

#### Audit

---

#### 2.6.2.1 The app shall only use software components without known vulnerabilities

##### Evidence

L1: Attach the HTML output from dependency check  `dependency-check --enableExperimental --scan &lt;source-path>`

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0085](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-CODE/MASTG-TEST-0085.md). Specifically the Dynamic Analysis section which uses objection to list the frameworks and bundles.

##### Verification

_L1_

1. Review the output from dependency-check to verify that the app does not use any 3P libraries that have a published vulnerability with a severity >= CVSS 7.0.

_L2_

1. Review the output from objection to verify that the app does not use any 3P libraries that have a published vulnerability with a severity >= CVSS 7.0.

_Additional Context_

An app that uses a vulnerable 3P library can still pass this test if the developer provides justification that the app doesn't invoke the vulnerable 3P library code or the 3P library hasn't yet made an update available. If the 3P library provider doesn't have a patch process this will result in a failure.

---

### 2.6.3 [The app validates and sanitizes all untrusted inputs](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)

#### Audit

---

#### 2.6.3.1 Compiler security features shall be enabled

##### Evidence

L1: Attach the pdf report generated by [mobsf](http://mobsf.live).

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0087](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-CODE/MASTG-TEST-0087.md). Specifically the Dynamic Analysis section which uses objection to list compiler flags.

##### Verification

_L1_

1. Verify the binary uses PIE ASLR, and stack canaries by observing the IPA BINARY ANALYSIS section of the mobsf report.

_L2_

1. Verify the binary uses PIE ASLR and stack canaries by observing the output from objection

## 2.7 [Resilience](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)

---

### 2.7.1 [The app implements anti-tampering mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/)

#### Audit

---

#### 2.7.1.1 The app shall be properly signed

##### Evidence

L1: This only applies to apps that will be distributed outside of the App Store. Attach the output from running the following command: `codesign -dvvv YOURAPP.app`

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0081](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0081.md).

##### Verification

_L1 & L2:_ Verify that the app is signed using the [latest code signature format](https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format).

---

### 2.7.2 [The app implements anti-static analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/)

#### Audit

---

#### 2.7.2.1 The app shall disable all debugging symbols in the production version

##### Evidence

L1: Attach a screenshot showing that `Strip Debug Symbols During Copy` is set to `YES` in your build settings. If you have a third-party library that this cannot be enabled for, please document this.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0083](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0083.md).

##### Verification

_L1_

1. Developer evidence demonstrates that debugging symbols are disabled in their production version.

_L2_

1. Output of the analysis shows that debugging symbols are disabled in their production version.

---

### 2.7.3 [The app implements anti-dynamic analysis techniques](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/)

#### Audit

---

#### 2.7.3.1 The app shall not be debuggable if installed from outside of commercial app stores

##### Evidence

L1: This only applies to apps that will be distributed outside of the App Store. Attach the output from running the following command: `codesign -d --entitlements - YOURAPP.app`

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements

_L2_

1. Follow the testing procedures outlined in [MASTG-TEST-0082](https://github.com/OWASP/owasp-mastg/blob/v1.7.0/tests/ios/MASVS-RESILIENCE/MASTG-TEST-0082.md) for using `codesign` to check if debugging is enabled.

##### Verification

_L1 & L2:_ Verify that the app does not allow debugging by ensuring the value for `get-task-allow` is `false`.

## 2.8 [Privacy](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/)

---

### 2.8.1 [The app minimizes access to sensitive data and resources](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/)

#### Audit

---

#### 2.8.1.1 The app shall minimize access to sensitive data and resources provided by the platform

##### Evidence

L1: Attachment of the Info.plist file showing permission requests along with descriptions.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Review Info.plist for adherence with requirement. Perform analysis to validate consent mechanisms upon data requests.

##### Verification

_L1_

1. The app adheres to least privilege principle by only requesting permissions that are needed for its functionality along with descriptive descriptions.

_L2_

1. The app adheres to least privilege principle by only requesting permissions that are needed for its functionality  with descriptive descriptions.

---

### 2.8.2 [The app is transparent about data collection and usage](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/)

#### Audit

---

#### 2.8.2.1 The app shall be transparent about data collection and usage

##### Evidence

L1: Provide a URL to the app’s privacy policy.  Provide a screenshot of the  Privacy Nutrition labels  with a mapping of declarations to the privacy policy.

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Perform a match against data practices displayed in the Privacy Nutrition labels   against data practices explicitly listed in the privacy policy.  Check for data types being transmitted over the network that aren’t declared to users.

##### Verification

_L1_

1. Ensure the developer provides a valid privacy policy and the declarations match those in the  Privacy Nutrition labels

_L2_

1. All data collected should be included explicitly, either within the actual application or somewhere that can be accessed via the application.

---

### 2.8.3 [The app offers user control over their data](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/)

#### Audit

---

#### 2.8.3.1 Users shall have the ability to request their data to be deleted via an in-app mechanism

##### Evidence

L1:  Provide a screenshot that shows an in-app URL which allows users to initiate app account deletion

##### Test Procedure

_L1_

1. Review provided evidence for adherence with requirements.

_L2_

1. Review App Store label to verify existence of data deletion request mechanism.  Lab confirms availability of URL in app.

##### Verification

_L1 & L2:_ The app provides an in-app mechanism which allows users to modify and delete their personal data.
