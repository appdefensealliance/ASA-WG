
# **App Defense Alliance Mobile Application Specification**

Version 0.7 - June 14, 2024


# **Revision History**


<table>
  <tr>
   <td><strong>Version</strong>
   </td>
   <td><strong>Date</strong>
   </td>
   <td><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>0.5
   </td>
   <td>5/10/24
   </td>
   <td>Initial draft based on Mobile App Tiger Team review of MASVS specification
   </td>
  </tr>
  <tr>
   <td style="background-color: #f3f3f3">0/7
   </td>
   <td style="background-color: #f3f3f3">5/25/24
   </td>
   <td style="background-color: #f3f3f3">Updates from TIger Team review of 0.5 spec
   </td>
  </tr>
</table>



# **Table of Contents**

**Android**

1.1 [Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)

1.1.1 [The app security stores sensitive data](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/)

1.1.2 [The app prevents leakage of sensitive data](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/)

1.2 [Crypto](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)

1.2.1 [The app employs strong cryptography and uses it according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/)

1.2.2 [The app performs key management according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/)

1.3 [Auth](https://mas.owasp.org/MASVS/07-MASVS-AUTH/)

1.3.1 [The app uses secure authentication and authorization protocols and follows the relevant best practices](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/)

1.4 [Network](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/)

1.4.1 [The app secures all network traffic according to the current best practices](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/)

1.5 [Platform](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/)

1.5.1 [The app uses IPC mechanisms securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/)

1.5.2 [The app uses WebViews securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/)

1.5.3 [The app uses the user interface securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/)

1.6 [Code](https://mas.owasp.org/MASVS/10-MASVS-CODE/)

1.6.1 [The app requires an up-to-date platform version](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/)

1.6.2 [The app only uses software components without known vulnerabilities](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/)

1.6.3 [The app validates and sanitizes all untrusted inputs](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)

1.7 [Resilience](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)

1.7.1 [The app implements anti-tampering mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/)

1.7.2 [The app implements anti-static analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/)

1.7.3 [The app implements anti-dynamic analysis techniques](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/)

1.8 [Privacy](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/)

1.8.1 [The app minimizes access to sensitive data and resources](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/)

1.8.2 [The app is transparent about data collection and usage](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/)

1.8.3 [The app offers user control over their data](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/)

**iOS**

2.1 [Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)

2.1.1 [The app security stores sensitive data](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/)

2.1.2 [The app prevents leakage of sensitive data](https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/)

2.2 [Crypto](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/)

2.2.1 [The app employs strong cryptography and uses it according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/)

2.2.2 [The app performs key management according to industry best practices](https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/)

2.3 [Auth](https://mas.owasp.org/MASVS/07-MASVS-AUTH/)

2.3.1 [The app uses secure authentication and authorization protocols and follows the relevant best practices](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/)

2.4 [Network](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/)

2.4.1 [The app secures all network traffic according to the current best practices](https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/)

2.5 [Platform](https://mas.owasp.org/MASVS/09-MASVS-PLATFORM/)

2.5.1 [The app uses IPC mechanisms securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/)

2.5.2 [The app uses WebViews securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/)

2.5.3 [The app uses the user interface securely](https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/)

2.6 [Code](https://mas.owasp.org/MASVS/10-MASVS-CODE/)

2.6.1 [The app requires an up-to-date platform version](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/)

2.6.2 [The app only uses software components without known vulnerabilities](https://mas.owasp.org/MASVS/controls/MASVS-CODE-3/)

2.6.3 [The app validates and sanitizes all untrusted inputs](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)

2.7 [Resilience](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)

2.7.1 [The app implements anti-tampering mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/)

2.7.2 [The app implements anti-static analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-3/)

2.7.3 [The app implements anti-dynamic analysis techniques](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/)

2.8 [Privacy](https://mas.owasp.org/MASVS/12-MASVS-PRIVACY/)

2.8.1 [The app minimizes access to sensitive data and resources](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-1/)

2.8.2 [The app is transparent about data collection and usage](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-3/)

2.8.3 [The app offers user control over their data](https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY-4/)

**Introduction**

In today’s digitally-driven world, mobile applications are the backbone of countless businesses and organizations. Unfortunately, they are also prime targets for cyberattacks that threaten data confidentiality, service availability, and overall business integrity. To mitigate risks and build a secure mobile environment, a robust mobile application security standard and certification program is essential.

**Our Approach: OWASP MASVS as the Foundation**

This program leverages the internationally recognized OWASP Mobile Application Security Verification Standard (MASVS) as its core. The OWASP MASVS offers a comprehensive set of security assessment requirements and guidelines covering the entire mobile application development lifecycle. Building upon this base, the App Defense Alliance (ADA) focused on testable requirements with clear acceptance criteria. Further, the ADA approach emphasizes the use of automation where possible.


# **Applicability**

This document is intended for system and application administrators, security specialists, auditors, help desk, platform deployment, and/or DevOps personnel who plan to develop, deploy, assess, or secure mobile applications.


# **References**



1. [OWASP Mobile Application Security Verification Standard](https://github.com/OWASP/owasp-masvs/)


# **Licensing**

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License.](https://creativecommons.org/licenses/by-sa/4.0/)


# **Assumptions**

The following assumptions are intended to aid the Authorized Labs for baseline security testing. 

**PLATFORM**

The mobile application relies upon a trustworthy computing platform that runs a recent version of a mobile operating system (i.e. N-2) from the date of evaluation.   For the purposes of this document, N refers to a major operation system release.

**PROPER_USER**

The user of the application software is not willfully negligent or hostile, and sets a device PIN/Passcode.

**SENSITIVE_DATA**

Data that is of particular concern from a security perspective, including personal identifiable information, credentials, and keys. This is not taking into account regulatory requirements for privacy or compliance for various verticals such as healthcare or finance.

PII is any information that can be used to directly or indirectly identify a specific individual. This data, if mishandled, can lead to harm, discrimination, or privacy violations.

**TOOLING**

The ADA approach emphasizes the use of automation where possible. We expect future tooling investment to assist with gathering of developer evidence for Level 1 assurance.


# 1 ANDROID

## 
    1.1 Storage


### **1.1.1 The app shall securely store sensitive data**

**Description**

This control ensures that any sensitive data that is intentionally stored by the app is properly protected independently of the target location.  

**Rationale**

Apps handle sensitive data coming from many sources such as the user, the backend, system services or other apps on the device and usually need to store it locally. The storage locations may be private to the app (e.g. its internal storage) or be public and therefore accessible by the user or other installed apps (e.g. public folders such as Downloads). 

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.1.1.1
   </td>
   <td>The app shall securely store sensitive data
   </td>
  </tr>
</table>





### **1.1.2 The app prevents leakage of sensitive data**

**Description**

This control covers unintentional data leaks where the developer actually has a way to prevent it.

**Rationale**

There are cases when sensitive data is unintentionally stored or exposed to publicly accessible locations; typically as a side-effect of using certain APIs, system capabilities such as backups or logs. 

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.1.2.1
   </td>
   <td>The Keyboard Cache shall be disabled for sensitive data inputs.
   </td>
  </tr>
  <tr>
   <td>1.1.2.2
   </td>
   <td>No sensitive data shall be stored in system logs
   </td>
  </tr>
</table>



## 
    1.2 Crypto


### **1.2.1 The app employs current strong cryptography and uses it according to industry best practices.**

**Description**

This control covers general cryptography best practices, which are typically defined in external standards.  For testing, the Crypto requirements only apply to sensitive data stored outside of the application sandbox.

**Rationale**

Cryptography plays an especially important role in securing the user's data - even more so in a mobile environment, where attackers having physical access to the user's device is a likely scenario.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.2.1.1
   </td>
   <td>No insecure random number generators shall be utilized for any security sensitive context.
   </td>
  </tr>
  <tr>
   <td>1.2.1.2
   </td>
   <td>No insecure operations shall be used for symmetric cryptography.
   </td>
  </tr>
  <tr>
   <td>1.2.1.3
   </td>
   <td>Strong cryptography shall be implemented according to industry best practices.
   </td>
  </tr>
</table>



### **1.2.2 The app performs key management according to industry best practices.**

**Description**

This control covers the management of cryptographic keys throughout their lifecycle, including key generation, storage and protection. Crypto requirements only apply to sensitive data stored outside of the application sandbox.

**Rationale**

Even the strongest cryptography would be compromised by poor key management.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.2.2.1
   </td>
   <td>Cryptographic keys shall only be used for their defined purpose.
   </td>
  </tr>
  <tr>
   <td>1.2.2.2
   </td>
   <td>Cryptographic key management shall be implemented properly.
   </td>
  </tr>
</table>



## 
    1.3 Auth


### **1.3.1 The app uses secure authentication and authorization protocols and follows the relevant best practices.**

**Description**

Most apps connecting to a remote endpoint require user authentication and also enforce some kind of authorization. While the enforcement of these mechanisms must be on the remote endpoint, the apps also have to ensure that it follows all the relevant best practices to ensure a secure use of the involved protocols.

**Rationale**

Authentication and authorization provide an added layer of security and help prevent unauthorized access to sensitive user data.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.3.1.1
   </td>
   <td>If using OAuth 2.0 to authenticate, Proof Key for Code Exchange (PKCE) shall be implemented to protect the code grant
   </td>
  </tr>
</table>



## 
    1.4 Network


### **1.4.1 The app secures all network traffic according to the current best practices.**

**Description**

This control ensures that the app is in fact setting up secure connections in any situation. This is typically done by encrypting data and authenticating the remote endpoint, as TLS does. However, there are many ways for a developer to disable the platform secure defaults, or bypass them completely by using low-level APIs or third-party libraries.

**Rationale**

Ensuring data privacy and integrity of any data in transit is critical for any app that communicates over the network. 

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.4.1.1
   </td>
   <td>Network connections shall be encrypted
   </td>
  </tr>
  <tr>
   <td>1.4.1.2
   </td>
   <td>TLS configuration of network connections shall adhere to industry best practices
   </td>
  </tr>
  <tr>
   <td>1.4.1.3
   </td>
   <td>Endpoint identity shall be verified on network connections
   </td>
  </tr>
</table>



## 
    1.5 Platform


### **1.5.1 The app uses IPC mechanisms securely.**

**Description**

This control ensures that all interactions involving IPC mechanisms happen securely.

**Rationale**

Apps typically use platform provided IPC mechanisms to intentionally expose data or functionality. Both installed apps and the user are able to interact with the app in many different ways.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.5.1.1
   </td>
   <td>The app shall limit content provider exposure and harden queries against injection attacks
   </td>
  </tr>
  <tr>
   <td>1.5.1.2
   </td>
   <td>The app shall use verified links and sanitize all link input data
   </td>
  </tr>
  <tr>
   <td>1.5.1.3
   </td>
   <td>Any sensitive functionality exposed via IPC shall be intentional and at the minimum required level.
   </td>
  </tr>
  <tr>
   <td>1.5.1.4
   </td>
   <td>All Pending Intents shall be immutable or otherwise justified for mutability
   </td>
  </tr>
</table>



### **1.5.2 The app uses WebViews securely.**

**Description**

This control ensures that WebViews are configured securely to prevent sensitive data leakage as well as sensitive functionality exposure (e.g. via JavaScript bridges to native code).

**Rationale**

WebViews are typically used by apps that have a need for increased control over the UI. They can, however, also be exploited by attackers or other installed apps, potentially compromising the app's security.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.5.2.1
   </td>
   <td>WebViews shall securely execute JavaScript
   </td>
  </tr>
  <tr>
   <td>1.5.2.2
   </td>
   <td>WebView shall be configured to allow the minimum set of protocol handlers required while disabling potentially dangerous handlers.
   </td>
  </tr>
</table>



### **1.5.3 The app uses the user interface securely.**

**Description**

This control ensures that this data doesn't end up being unintentionally leaked due to platform mechanisms such as auto-generated screenshots or accidentally disclosed via e.g. shoulder surfing or sharing the device with another person.

**Rationale**

Sensitive data has to be displayed in the UI in many situations (e.g. passwords, credit card details, OTP codes in notifications) which can lead to unintentional leaks.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.5.3.1
   </td>
   <td>The app shall by default mask data in the User Interface when it is known to be sensitive
   </td>
  </tr>
</table>



## 
    1.6 Code


### **[1.6.1 The app requires an up-to-date platform version.](https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/)**

**Description**

This control ensures that the app is running on an up-to-date platform version so that users have the latest security protections.

**Rationale**

Every release of the mobile OS includes security patches and new security features. By supporting older versions, apps stay vulnerable to well-known threats.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.6.1.1
   </td>
   <td>The app shall set the targetSdkVersion to an up-to-date platform version
   </td>
  </tr>
</table>



### **1.6.2 The app only uses software components without known vulnerabilities.**

**Description**

To be truly secure, a full whitebox assessment should have been performed on all app components. However, as it usually happens with e.g. for third-party components this is not always feasible and not typically part of a penetration test. This control covers "low-hanging fruit" cases, such as those that can be detected just by scanning libraries for known vulnerabilities.

**Rationale**

The developer should protect users from known vulnerabilities.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.6.2.1
   </td>
   <td>The app only uses software components without known vulnerabilities
   </td>
  </tr>
</table>



### **1.6.3 The app validates and sanitizes all untrusted inputs.**

**Description**

Apps have many data entry points including the UI, IPC, the network, the file system, etc.  This control ensures that this data is treated as untrusted input and is properly verified and sanitized before it's used.

**Rationale**

This incoming data might have been inadvertently modified by untrusted actors and may lead to bypass of critical security checks as well as classical injection attacks such as SQL injection, XSS or insecure deserialization.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.6.3.1
   </td>
   <td>Compiler security features shall be enabled
   </td>
  </tr>
  <tr>
   <td>1.6.3.2
   </td>
   <td>The App shall Mitigate Against Injection Flaws in Content Providers
   </td>
  </tr>
  <tr>
   <td>1.6.3.3
   </td>
   <td>Arbitrary URL redirects shall not be included in the app's webviews
   </td>
  </tr>
  <tr>
   <td>1.6.3.4
   </td>
   <td>Any use of implicit intents shall be appropriate for the app's functionality and any return data shall be handled securely
   </td>
  </tr>
</table>



## 
    1.7 Resilience


### **1.7.1 The app implements anti-tampering mechanisms.**

**Description**

This control tries to ensure the integrity of the app's intended functionality by preventing modifications to the original code and resources.

**Rationale**

Apps run on a user-controlled device, and without proper protections it's relatively easy to run a modified version locally (e.g. to cheat in a game, or enable premium features without paying), or upload a backdoored version of it to third-party app stores.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.7.1.1
   </td>
   <td>The app shall be properly signed.
   </td>
  </tr>
</table>



### **1.7.2 The app implements anti-static analysis mechanisms**

**Description**

This control tries to impede comprehension by making it as difficult as possible to figure out how an app works using static analysis.

**Rationale**

Understanding the internals of an app is typically the first step towards tampering with it.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.7.2.1
   </td>
   <td>The app shall disable all debugging symbols in the production version.
   </td>
  </tr>
</table>



### **[1.7.3 The app implements anti-dynamic analysis mechanisms](https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/)**

**Description**

Sometimes pure static analysis is very difficult and time consuming so it typically goes hand in hand with dynamic analysis.  This control aims to make it as difficult as possible to perform dynamic analysis, as well as prevent dynamic instrumentation which could allow an attacker to modify the code at runtime.

**Rationale**

Observing and manipulating an app during runtime makes it much easier to decipher its behavior. 

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.7.3.1
   </td>
   <td>The app shall not be debuggable if installed from outside of commercial app stores.
   </td>
  </tr>
</table>



## 
    1.8 Privacy


### **1.8.1 The app minimizes access to sensitive data and resources.**

**Description**

Apps should only request access to the data they absolutely need for their functionality and always with informed consent from the user. This control ensures that apps practice data minimization and restricts access control.  Furthermore, apps should share data with third parties only when necessary, and this should include enforcing that third-party SDKs operate based on user consent, not by default or without it. Apps should prevent third-party SDKs from ignoring consent signals or from collecting data before consent is confirmed.  Additionally, apps should be aware of the 'supply chain' of SDKs they incorporate, ensuring that no data is unnecessarily passed down their chain of dependencies. 

**Rationale**

Data minimization reduces the potential impact of data breaches or leaks.  This end-to-end responsibility for data aligns with recent SBOM regulatory requirements, making apps more accountable for their data practices.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.8.1.1
   </td>
   <td>The app shall minimize access to sensitive data and resources provided by the platform.
   </td>
  </tr>
</table>



### **1.8.2 The app is transparent about data collection and usage.**

**Description**

This control ensures that apps provide clear information about data collection, storage, and sharing practices, including any behavior a user wouldn't reasonably expect, such as background data collection. Apps should also adhere to platform guidelines on data declarations.

**Rationale**

Users have the right to know how their data is being used. 

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.8.2.1
   </td>
   <td>The app shall be transparent about data collection and usage.
   </td>
  </tr>
</table>



### **1.8.3 The app offers user control over their data.**

**Description**

This control ensures that apps provide mechanisms for users to manage, delete, and modify their data, and change privacy settings as needed (e.g. to revoke consent). Additionally, apps should re-prompt for consent and update their transparency disclosures when they require more data than initially specified.

**Rationale**

Users should have control over their data.

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>1.8.3.1
   </td>
   <td>Users shall have the ability to request their data to be deleted via an in-app mechanism.
   </td>
  </tr>
</table>



# 2 iOS


## 
    2.1 Storage


### **2.1.1 The app shall securely store sensitive data**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.1.1.1
   </td>
   <td>The app shall securely store sensitive data
   </td>
  </tr>
</table>





### **2.1.2 The app prevents leakage of sensitive data**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.1.2.1
   </td>
   <td>The Keyboard Cache shall be Disabled for sensitive data inputs.
   </td>
  </tr>
  <tr>
   <td>2.1.2.2
   </td>
   <td>No sensitive data shall be stored in system logs
   </td>
  </tr>
</table>



## 
    2.2 Crypto


### **2.2.1 The app employs current strong cryptography and uses it according to industry best practices.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.2.1.1
   </td>
   <td>No insecure random number generators shall be utilized for any security sensitive context.
   </td>
  </tr>
  <tr>
   <td>2.2.1.2
   </td>
   <td>Strong cryptography shall be implemented according to industry best practices.
   </td>
  </tr>
</table>



### **2.2.2 The app performs key management according to industry best practices.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.2.2.1
   </td>
   <td>Cryptographic keys shall only be used for their defined purpose.
   </td>
  </tr>
  <tr>
   <td>2.2.2.2
   </td>
   <td>Cryptographic key management shall be implemented properly.
   </td>
  </tr>
</table>



## 
    2.3 Auth


### **2.3.1 The app uses secure authentication and authorization protocols and follows the relevant best practices.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.3.1.1
   </td>
   <td>If using OAuth 2.0 to authenticate, Proof Key for Code Exchange (PKCE) shall be implemented to protect the code grant
   </td>
  </tr>
</table>



## 
    2.4 Network


### **2.4.1 The app secures all network traffic according to the current best practices.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.4.1.1
   </td>
   <td>Network connections shall be encrypted
   </td>
  </tr>
  <tr>
   <td>2.4.1.2
   </td>
   <td>TLS configuration of network connections shall adhere to industry best practices
   </td>
  </tr>
  <tr>
   <td>2.4.1.3
   </td>
   <td>Endpoint identity shall be verified on network connections
   </td>
  </tr>
</table>



## 
    2.5 Platform


### **2.5.1 The app uses IPC mechanisms securely.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.5.1.1
   </td>
   <td>The app shall not expose sensitive data via IPC mechanisms
   </td>
  </tr>
  <tr>
   <td>2.5.1.2
   </td>
   <td>The app shall not expose sensitive data via App Extensions
   </td>
  </tr>
  <tr>
   <td>2.5.1.3
   </td>
   <td>The app shall not expose sensitive functionality via Custom URL Schemes
   </td>
  </tr>
  <tr>
   <td>2.5.1.4
   </td>
   <td>The app shall not expose sensitive data via UIActivity Sharing
   </td>
  </tr>
  <tr>
   <td>2.5.1.5
   </td>
   <td>The app shall not use the general pasteboard for sharing sensitive information
   </td>
  </tr>
  <tr>
   <td>2.5.1.6
   </td>
   <td>The app shall not expose sensitive functionality via Universal Links
   </td>
  </tr>
</table>



### **2.5.2 The app uses WebViews securely.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.5.2.1
   </td>
   <td>WebViews shall securely execute JavaScript
   </td>
  </tr>
  <tr>
   <td>2.5.2.2
   </td>
   <td>WebView shall be configured securely
   </td>
  </tr>
</table>



### **2.5.3 The app uses the user interface securely.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.5.3.1
   </td>
   <td>The app shall by default mask data in the User Interface when it is known to be sensitive
   </td>
  </tr>
</table>



## 
    2.6 Code


### **2.6.1 The app requires an up-to-date platform version.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.6.1.1
   </td>
   <td>The app shall set the targetSdkVersion to an up-to-date platform version
   </td>
  </tr>
</table>



### **2.6.2 The app only uses software components without known vulnerabilities.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.6.2.1
   </td>
   <td>The app only uses software components without known vulnerabilities
   </td>
  </tr>
</table>



### **2.6.3 The app validates and sanitizes all untrusted inputs.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.6.3.1
   </td>
   <td>Compiler security features shall be enabled
   </td>
  </tr>
</table>



## 
    2.7 Resilience


### **2.7.1 The app implements anti-tampering mechanisms.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.7.1.1
   </td>
   <td>The app shall be properly signed.
   </td>
  </tr>
</table>



### **2.7.2 The app implements anti-static analysis mechanisms**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.7.2.1
   </td>
   <td>The app shall disable all debugging symbols in the production version.
   </td>
  </tr>
</table>



### **2.7.3 The app implements anti-dynamic analysis mechanisms**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.7.3.1
   </td>
   <td>The app shall not be debuggable if installed from outside of commercial app stores.
   </td>
  </tr>
</table>



## 
    2.8 Privacy


### **2.8.1 The app minimizes access to sensitive data and resources.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.8.1.1
   </td>
   <td>The app shall minimize access to sensitive data and resources provided by the platform.
   </td>
  </tr>
</table>



### **2.8.2 The app is transparent about data collection and usage.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.8.2.1
   </td>
   <td>The app shall be transparent about data collection and usage.
   </td>
  </tr>
</table>



### **2.8.3 The app offers user control over their data.**

**Audit**


<table>
  <tr>
   <td style="background-color: null"><strong>Spec</strong>
   </td>
   <td style="background-color: null"><strong>Description</strong>
   </td>
  </tr>
  <tr>
   <td>2.8.3.1
   </td>
   <td>Users shall have the ability to request their data to be deleted via an in-app mechanism.
   </td>
  </tr>
</table>
