# App Defense Alliance Desktop Application Specification

Version 0.1 - Draft

## Revision History

| Version | Date | Description |
| :---- | :---- | :---- |
| 0.1 | 25-MAR-26 | Initial draft proposal for ADA Desktop App Profile Tiger Team review |

## Acknowledgements

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the contributors who developed the open-source standards that form the foundation of this profile, specifically the creators of the AFINE Desktop Application Security Verification Standard (DASVS), the OWASP Desktop App Security Top 10, and the NIAP Protection Profile for Application Software (PP_APP).

### Desktop Profile Leads

* Tony Balkan (Microsoft)
* Alex Duff (Meta)

### Contributors

* Alex Duff (Meta)
* Tony Balkan (Microsoft)

## Introduction

Desktop applications remain a critical component of enterprise and consumer computing. They often process highly sensitive data, operate with significant system privileges, interact directly with the host operating system, and are prime targets for cyberattacks that threaten data confidentiality, service availability, and overall business integrity. Unlike web and mobile applications, desktop applications execute in an environment where the application binary itself is directly accessible to attackers, where shared libraries can be subverted, and where inter-process communication channels may be exploited. To mitigate these risks and build a secure computing environment, a robust desktop application security standard and certification program is essential.

### Our Approach: DASVS and NIAP PP_APP as the Foundation

This program leverages the AFINE Desktop Application Security Verification Standard (DASVS) and the NIAP Protection Profile for Application Software (PP_APP v2.0) as its primary foundations. The OWASP Desktop App Security Top 10 provides additional threat context. Building upon these sources, the App Defense Alliance (ADA) focused on testable requirements with clear acceptance criteria. The ADA approach emphasizes the use of automation where possible, specifically through automated binary analysis tools that can evaluate platform-specific security mitigations without requiring full source code access.

### Applicability

This document is intended for system and application administrators, security specialists, auditors, help desk, platform deployment, and/or DevOps personnel who plan to develop, deploy, assess, or secure desktop applications on Windows, macOS, or Linux operating systems.

### Scope

| In Scope | Out of Scope |
| :---- | :---- |
| Native desktop applications (e.g., C/C++, .NET, Swift, Rust, Go) | Web applications (covered by the ADA Web App Profile) |
| Electron/CEF-based desktop applications | Mobile applications (covered by the ADA Mobile App Profile) |
| Desktop applications that communicate with backend APIs | Backend server infrastructure (covered by the ADA Cloud Profile) |
| Application installers and updaters | Operating system security configuration |
| First-party libraries bundled with the application | Third-party OS-level drivers or kernel modules |

### References

1. [AFINE Desktop Application Security Verification Standard (DASVS)](https://github.com/afine-com/DASVS)  
2. [NIAP Protection Profile for Application Software v2.0](https://www.niap-ccevs.org/protectionprofiles/516)  
3. [OWASP Desktop App Security Top 10](https://owasp.org/www-project-desktop-app-security-top-10/)  
4. [OWASP Application Security Verification Standard (ASVS)](https://github.com/OWASP/ASVS)

### Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License.](https://creativecommons.org/licenses/by-sa/4.0/)

### Assumptions

The following assumptions are intended to aid the Authorized Labs for baseline security testing.

#### Platform

The desktop application relies upon a trustworthy computing platform that runs a supported version of a desktop operating system (i.e., N-2 major releases) from the date of evaluation. For the purposes of this document, N refers to the current major operating system release.

#### Proper User

The user of the application software is not willfully negligent or hostile, and utilizes standard OS-level authentication (e.g., password or biometrics) to access the desktop environment.

#### Sensitive or Confidential Data

Data that is of particular concern from a security perspective, including user data, user device data, company data, credentials, keys, or other types of confidential information. Throughout this document, the phrase "sensitive data" refers to these kinds of data and should not be confused with the meaning of *Sensitive Data* under regulations like GDPR or other regulatory regimes.

Note that apps in certain verticals such as healthcare or finance may have to meet higher security, privacy, and regulatory requirements.

#### Tooling

The ADA approach emphasizes the use of automation where possible. Authorized Labs shall utilize automated binary analysis tools (e.g., `checksec-anywhere`, `winchecksec`, OWASP `blint`) to verify platform-specific mitigations without requiring source code access. We expect future tooling investment to assist with gathering of developer evidence for Level 1 assurance.

### Definitions

| Term | Definition |
| :---- | :---- |
| (AL0) ADA Assurance Level 0 (Self Attestation) | The developer performs the application assessment using the same test cases as AL1 and generates the Developer Test Report and Compliance Report. The CB reviews the Compliance Report for completeness. No independent ASTL review is performed. |
| (AL1) ADA Assurance Level 1 (Verified Self Assessment) | The developer provides evidence and statements of compliance to each audit test case. The ADA approved lab reviews the evidence against the requirements. The ADA approved lab does not directly assess the application. |
| (AL2) ADA Assurance Level 2 (Lab Assessment) | The ADA approved lab evaluates each audit test case directly against the application. In some cases, the developer may need to provide limited information or code snippets. |
| ASTL | ADA Security Test Laboratory. An independent organization authorized by the ADA Certification Body to perform security evaluations. |
| Binary analysis | Examination of compiled application binaries to verify the presence of security mitigations without requiring source code. |
| CB | Certification Body. The ISO 17065 accredited organization that oversees ASTLs and issues ADA certificates. |
| Code signing | The process of digitally signing executables and libraries to confirm the software author and guarantee that the code has not been altered since it was signed. |
| DASVS | Desktop Application Security Verification Standard, developed by AFINE. |
| First-party binary | An executable or library that is compiled and distributed by the application developer, as opposed to OS-provided system libraries. |
| IPC | Inter-Process Communication. Mechanisms by which processes exchange data (e.g., named pipes, Unix domain sockets, D-Bus, COM). |
| Library hijacking | An attack where a malicious shared library is placed in a location where the application will load it instead of the legitimate library (e.g., DLL preloading, dylib hijacking). |
| NIAP PP_APP | Protection Profile for Application Software, published by the National Information Assurance Partnership. |
| SBOM | Software Bill of Materials. A formal, machine-readable inventory of software components and dependencies. |
| 3P library | Any library which was not developed by the developer. These libraries may be open source or commercial libraries or SDKs. |

---

# Table of Contents

* [1 Common Baseline Requirements](#1-common-baseline-requirements)  
  * [1.1 Communications Security](#11-communications-security)  
    * [1.1.1 The application shall enforce TLS for all network communications](#11-communications-security)  
    * [1.1.2 The application shall validate TLS certificates](#11-communications-security)  
    * [1.1.3 The application shall use strong cryptographic protocols and cipher suites](#11-communications-security)  
  * [1.2 Data Protection](#12-data-protection)  
    * [1.2.1 Sensitive data shall not be stored in plaintext in configuration files or logs](#12-data-protection)  
    * [1.2.2 Sensitive local data shall be encrypted using platform secure storage mechanisms](#12-data-protection)  
    * [1.2.3 The application shall securely handle data in memory](#12-data-protection)  
  * [1.3 Authentication and Privilege Management](#13-authentication-and-privilege-management)  
    * [1.3.1 The application shall not require administrative or root privileges for standard operation](#13-authentication-and-privilege-management)  
    * [1.3.2 The application shall securely store authentication tokens and credentials](#13-authentication-and-privilege-management)  
  * [1.4 Input Validation](#14-input-validation)  
    * [1.4.1 The application shall validate and sanitize all untrusted input](#14-input-validation)  
    * [1.4.2 The application shall protect against OS command injection](#14-input-validation)  
    * [1.4.3 The application shall protect against path traversal attacks](#14-input-validation)  
  * [1.5 Component and Dependency Management](#15-component-and-dependency-management)  
    * [1.5.1 The application shall only use software components without known exploitable vulnerabilities](#15-component-and-dependency-management)  
    * [1.5.2 The application shall employ safe library loading mechanisms to prevent hijacking](#15-component-and-dependency-management)  
  * [1.6 Secure Update Mechanism](#16-secure-update-mechanism)  
    * [1.6.1 Updates shall be delivered over encrypted channels](#16-secure-update-mechanism)  
    * [1.6.2 Update packages shall be cryptographically signed and verified prior to installation](#16-secure-update-mechanism)  
  * [1.7 Inter-Process Communication (IPC)](#17-inter-process-communication-ipc)  
    * [1.7.1 IPC endpoints shall validate the identity of connecting processes](#17-inter-process-communication-ipc)  
    * [1.7.2 Sensitive data transmitted via IPC shall be protected](#17-inter-process-communication-ipc)  
  * [1.8 Logging and Error Handling](#18-logging-and-error-handling)  
    * [1.8.1 The application shall not expose sensitive information in error messages](#18-logging-and-error-handling)  
    * [1.8.2 Debug modes shall be disabled in production builds](#18-logging-and-error-handling)  
* [2 Windows Annex](#2-windows-annex)  
  * [2.1 Binary Hardening (Windows)](#21-binary-hardening-windows)  
  * [2.2 Code Signing (Windows)](#22-code-signing-windows)  
  * [2.3 Platform Integration (Windows)](#23-platform-integration-windows)  
* [3 macOS Annex](#3-macos-annex)  
  * [3.1 Binary Hardening (macOS)](#31-binary-hardening-macos)  
  * [3.2 Code Signing and Notarization (macOS)](#32-code-signing-and-notarization-macos)  
  * [3.3 Platform Integration (macOS)](#33-platform-integration-macos)  
* [4 Linux Annex](#4-linux-annex)  
  * [4.1 Binary Hardening (Linux)](#41-binary-hardening-linux)  
  * [4.2 Distribution Integrity (Linux)](#42-distribution-integrity-linux)

---

# 1 Common Baseline Requirements

## 1.1 Communications Security

### Description

Desktop applications must protect data in transit when communicating with backend servers, APIs, or other network endpoints. This includes enforcing the use of modern TLS, validating server certificates, and using strong cipher suites.

### Rationale

Insecure communication allows network intermediaries to intercept, read, or modify sensitive data. Unlike web browsers, desktop applications may implement their own TLS stacks or override default certificate validation, creating opportunities for misconfiguration.

### Audit

| Spec | Description |
| :---- | :---- |
| [1.1.1](Desktop%20App%20Test%20Guide.md#111-the-application-shall-enforce-tls-for-all-network-communications) | The application shall enforce TLS for all network communications. |
| [1.1.2](Desktop%20App%20Test%20Guide.md#112-the-application-shall-validate-tls-certificates) | The application shall validate TLS certificates, checking validity, expiration, and trust chain. |
| [1.1.3](Desktop%20App%20Test%20Guide.md#113-the-application-shall-use-strong-cryptographic-protocols-and-cipher-suites) | The application shall use strong cryptographic protocols and cipher suites. |

---

## 1.2 Data Protection

### Description

Applications must protect sensitive data stored locally on the desktop file system and handle sensitive data securely in memory.

### Rationale

Desktop environments are often shared or susceptible to physical compromise. Sensitive data such as authentication tokens, PII, or encryption keys stored in plaintext can be easily extracted by other applications, malicious actors, or forensic analysis.

### Audit

| Spec | Description |
| :---- | :---- |
| [1.2.1](Desktop%20App%20Test%20Guide.md#121-sensitive-data-shall-not-be-stored-in-plaintext-in-configuration-files-or-logs) | Sensitive data shall not be stored in plaintext in configuration files or logs. |
| [1.2.2](Desktop%20App%20Test%20Guide.md#122-sensitive-local-data-shall-be-encrypted-using-platform-secure-storage-mechanisms) | Sensitive local data shall be encrypted using platform secure storage mechanisms. |
| [1.2.3](Desktop%20App%20Test%20Guide.md#123-the-application-shall-securely-handle-data-in-memory) | The application shall securely handle data in memory. |

---

## 1.3 Authentication and Privilege Management

### Description

Applications must implement secure authentication mechanisms and adhere to the principle of least privilege. Applications shall not request or require elevated system privileges beyond what is necessary for their core functionality.

### Rationale

Weak authentication allows unauthorized access, while excessive privileges (e.g., running unnecessarily as Administrator/root) increase the blast radius of any successful exploit. Desktop applications have direct access to OS privilege mechanisms, making this a critical control.

### Audit

| Spec | Description |
| :---- | :---- |
| [1.3.1](Desktop%20App%20Test%20Guide.md#131-the-application-shall-not-require-administrative-or-root-privileges-for-standard-operation) | The application shall not require administrative or root privileges for standard operation. |
| [1.3.2](Desktop%20App%20Test%20Guide.md#132-the-application-shall-securely-store-authentication-tokens-and-credentials) | The application shall securely store authentication tokens and credentials. |

---

## 1.4 Input Validation

### Description

Applications must validate and sanitize all input from untrusted sources, including user input, file input, network data, and IPC messages. This includes protection against OS command injection and path traversal attacks.

### Rationale

Desktop applications frequently interact with the underlying operating system shell, file system, and other local resources. Improper input validation can lead to command injection, path traversal, and other attacks that are particularly severe in a desktop context where the application may have broad file system access.

### Audit

| Spec | Description |
| :---- | :---- |
| [1.4.1](Desktop%20App%20Test%20Guide.md#141-the-application-shall-validate-and-sanitize-all-untrusted-input) | The application shall validate and sanitize all untrusted input. |
| [1.4.2](Desktop%20App%20Test%20Guide.md#142-the-application-shall-protect-against-os-command-injection) | The application shall protect against OS command injection. |
| [1.4.3](Desktop%20App%20Test%20Guide.md#143-the-application-shall-protect-against-path-traversal-attacks) | The application shall protect against path traversal attacks. |

---

## 1.5 Component and Dependency Management

### Description

Applications must manage third-party libraries and shared components securely, including maintaining an inventory of dependencies and preventing library hijacking attacks.

### Rationale

Desktop applications frequently rely on shared libraries (DLLs, dylibs, SOs). Insecure loading mechanisms can lead to library hijacking (e.g., DLL preloading attacks), and outdated components introduce known vulnerabilities that can be exploited without any user interaction.

### Audit

| Spec | Description |
| :---- | :---- |
| [1.5.1](Desktop%20App%20Test%20Guide.md#151-the-application-shall-only-use-software-components-without-known-exploitable-vulnerabilities) | The application shall only use software components without known exploitable vulnerabilities. |
| [1.5.2](Desktop%20App%20Test%20Guide.md#152-the-application-shall-employ-safe-library-loading-mechanisms-to-prevent-hijacking) | The application shall employ safe library loading mechanisms to prevent hijacking. |

---

## 1.6 Secure Update Mechanism

### Description

The application must possess a secure mechanism for delivering and installing updates, or must clearly document that it relies on an external update mechanism (e.g., OS package manager, enterprise deployment tool).

### Rationale

To respond to emerging threats, applications must be updatable. The update process itself must be secure to prevent attackers from delivering malicious payloads masquerading as legitimate updates. Compromised update mechanisms have been used in high-profile supply chain attacks.

### Audit

| Spec | Description |
| :---- | :---- |
| [1.6.1](Desktop%20App%20Test%20Guide.md#161-updates-shall-be-delivered-over-encrypted-channels) | Updates shall be delivered over encrypted channels. |
| [1.6.2](Desktop%20App%20Test%20Guide.md#162-update-packages-shall-be-cryptographically-signed-and-verified-prior-to-installation) | Update packages shall be cryptographically signed and verified prior to installation. |

---

## 1.7 Inter-Process Communication (IPC)

### Description

Applications that expose IPC endpoints (e.g., named pipes, Unix domain sockets, D-Bus interfaces, COM objects, XPC services) must secure those endpoints against unauthorized access and data interception.

### Rationale

Desktop applications often communicate with helper processes, services, or browser extensions via IPC. Unsecured IPC endpoints can be exploited by malicious local applications to escalate privileges, exfiltrate data, or inject commands.

### Audit

| Spec | Description |
| :---- | :---- |
| [1.7.1](Desktop%20App%20Test%20Guide.md#171-ipc-endpoints-shall-validate-the-identity-of-connecting-processes) | IPC endpoints shall validate the identity of connecting processes. |
| [1.7.2](Desktop%20App%20Test%20Guide.md#172-sensitive-data-transmitted-via-ipc-shall-be-protected) | Sensitive data transmitted via IPC shall be protected. |

---

## 1.8 Logging and Error Handling

### Description

Applications must handle errors securely and ensure that production builds do not expose sensitive information through verbose error messages or debug functionality.

### Rationale

Verbose error messages can reveal internal application state, file paths, stack traces, or database queries that assist attackers. Debug modes left enabled in production can bypass security controls or expose diagnostic interfaces.

### Audit

| Spec | Description |
| :---- | :---- |
| [1.8.1](Desktop%20App%20Test%20Guide.md#181-the-application-shall-not-expose-sensitive-information-in-error-messages) | The application shall not expose sensitive information in error messages. |
| [1.8.2](Desktop%20App%20Test%20Guide.md#182-debug-modes-shall-be-disabled-in-production-builds) | Debug modes shall be disabled in production builds. |

---

# 2 Windows Annex

## 2.1 Binary Hardening (Windows)

### Description

Windows executables (PE files) and dynamic-link libraries (DLLs) must utilize OS-level exploit mitigations provided by the compiler and linker.

### Rationale

Compiler-level mitigations such as ASLR, DEP, and Control Flow Guard significantly increase the difficulty of exploiting memory corruption vulnerabilities. These mitigations are well-established, incur minimal performance overhead, and are verifiable via automated binary analysis.

### Audit

| Spec | Description |
| :---- | :---- |
| [2.1.1](Desktop%20App%20Test%20Guide.md#211-windows-binaries-shall-enable-aslr-and-dep) | Windows binaries shall enable ASLR (Dynamic Base) and DEP (NX Compat). |
| [2.1.2](Desktop%20App%20Test%20Guide.md#212-windows-binaries-shall-enable-control-flow-guard-cfg) | Windows binaries shall enable Control Flow Guard (CFG). |
| [2.1.3](Desktop%20App%20Test%20Guide.md#213-windows-binaries-shall-enable-high-entropy-aslr) | Windows binaries shall enable High Entropy ASLR for 64-bit executables. |
| [2.1.4](Desktop%20App%20Test%20Guide.md#214-windows-binaries-shall-enable-safe-seh-or-be-compiled-for-64-bit) | Windows binaries shall enable SafeSEH (for 32-bit) or be compiled for 64-bit architecture. |

---

## 2.2 Code Signing (Windows)

### Description

Windows executables and libraries distributed by the developer must be signed with a valid code signing certificate.

### Rationale

Authenticode code signing provides integrity verification and publisher attribution. Unsigned binaries trigger security warnings from Windows SmartScreen and may be blocked by enterprise security policies.

### Audit

| Spec | Description |
| :---- | :---- |
| [2.2.1](Desktop%20App%20Test%20Guide.md#221-windows-executables-and-libraries-shall-be-signed-with-a-valid-authenticode-certificate) | Windows executables and libraries shall be signed with a valid Authenticode certificate. |

---

## 2.3 Platform Integration (Windows)

### Description

Windows applications must integrate securely with the Windows security ecosystem, including proper use of the Windows Firewall API and secure IPC mechanisms.

### Rationale

Proper integration with Windows security features ensures the application operates within the OS security model rather than circumventing it.

### Audit

| Spec | Description |
| :---- | :---- |
| [2.3.1](Desktop%20App%20Test%20Guide.md#231-the-application-shall-use-secure-windows-ipc-mechanisms-with-appropriate-access-controls) | The application shall use secure Windows IPC mechanisms with appropriate access controls. |

---

# 3 macOS Annex

## 3.1 Binary Hardening (macOS)

### Description

macOS executables (Mach-O files) must utilize OS-level exploit mitigations provided by the compiler.

### Rationale

Compiler-level mitigations significantly increase the difficulty of exploiting memory corruption vulnerabilities. Modern macOS toolchains enable most of these by default, but they must be verified.

### Audit

| Spec | Description |
| :---- | :---- |
| [3.1.1](Desktop%20App%20Test%20Guide.md#311-macos-binaries-shall-enable-pie-and-arc) | macOS binaries shall enable PIE (Position Independent Executable) and ARC (Automatic Reference Counting). |
| [3.1.2](Desktop%20App%20Test%20Guide.md#312-macos-binaries-shall-enable-stack-canaries) | macOS binaries shall enable stack canaries. |

---

## 3.2 Code Signing and Notarization (macOS)

### Description

macOS applications must be signed with a valid Developer ID and notarized by Apple.

### Rationale

Apple Gatekeeper blocks unsigned and unnotarized applications by default. Notarization involves an automated Apple security scan and provides a tamper-evident seal. Applications that bypass Gatekeeper require users to override security settings, which is not an acceptable baseline.

### Audit

| Spec | Description |
| :---- | :---- |
| [3.2.1](Desktop%20App%20Test%20Guide.md#321-macos-applications-shall-be-signed-with-a-valid-developer-id-and-notarized-by-apple) | macOS applications shall be signed with a valid Developer ID and notarized by Apple. |

---

## 3.3 Platform Integration (macOS)

### Description

macOS applications must enable the Hardened Runtime and minimize the use of dangerous entitlements.

### Rationale

The Hardened Runtime restricts the application from performing potentially dangerous operations such as loading unsigned code, disabling library validation, or accessing protected resources without entitlements. It is required for notarization and provides a strong security baseline.

### Audit

| Spec | Description |
| :---- | :---- |
| [3.3.1](Desktop%20App%20Test%20Guide.md#331-macos-applications-shall-enable-the-hardened-runtime) | macOS applications shall enable the Hardened Runtime. |
| [3.3.2](Desktop%20App%20Test%20Guide.md#332-macos-applications-shall-minimize-the-use-of-dangerous-entitlements) | macOS applications shall minimize the use of dangerous entitlements. |

---

# 4 Linux Annex

## 4.1 Binary Hardening (Linux)

### Description

Linux executables (ELF files) must utilize OS-level exploit mitigations provided by the compiler and linker.

### Rationale

Compiler-level mitigations significantly increase the difficulty of exploiting memory corruption vulnerabilities. These flags are widely supported by GCC and Clang and are verifiable via automated binary analysis.

### Audit

| Spec | Description |
| :---- | :---- |
| [4.1.1](Desktop%20App%20Test%20Guide.md#411-linux-binaries-shall-enable-pie-and-nx) | Linux binaries shall enable PIE (Position Independent Executable) and NX (No-Execute). |
| [4.1.2](Desktop%20App%20Test%20Guide.md#412-linux-binaries-shall-enable-full-relro-and-stack-canaries) | Linux binaries shall enable Full RELRO (Relocation Read-Only) and stack canaries. |
| [4.1.3](Desktop%20App%20Test%20Guide.md#413-linux-binaries-shall-enable-fortify-source) | Linux binaries shall enable FORTIFY_SOURCE. |

---

## 4.2 Distribution Integrity (Linux)

### Description

Linux applications must be distributed via mechanisms that provide cryptographic integrity verification.

### Rationale

Unlike Windows and macOS, Linux lacks a single unified code signing infrastructure. Applications must use secure distribution mechanisms to ensure that users can verify the authenticity and integrity of the software they install.

### Audit

| Spec | Description |
| :---- | :---- |
| [4.2.1](Desktop%20App%20Test%20Guide.md#421-linux-applications-shall-be-distributed-via-secure-integrity-verified-channels) | Linux applications shall be distributed via secure, integrity-verified channels (e.g., GPG-signed repositories, signed Flatpaks/Snaps/AppImages). |

