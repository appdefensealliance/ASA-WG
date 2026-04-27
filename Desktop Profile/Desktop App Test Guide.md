# App Defense Alliance Desktop Application Test Guide

Version 0.1 - Draft

## Revision History

| Version | Date | Description |
| :---- | :---- | :---- |
| 0.1 | 25-MAR-26 | Initial draft proposal for ADA Desktop App Test Guide Tiger Team review |

## Contributors

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification:

* Alex Duff (Meta)
* Tony Balkan (Microsoft)

## Introduction

Desktop applications remain a critical component of enterprise and consumer computing. They often process highly sensitive data, operate with significant system privileges, interact directly with the host operating system, and are prime targets for cyberattacks. This document serves as the testing methodology and evaluation guide for the App Defense Alliance (ADA) Desktop Application Profile.

### Our Approach: DASVS and NIAP PP_APP as the Foundation

This program leverages the AFINE Desktop Application Security Verification Standard (DASVS) and the NIAP Protection Profile for Application Software (PP_APP v2.0) as its primary foundations. Building upon these sources, the App Defense Alliance (ADA) focused on testable requirements with clear acceptance criteria. The ADA approach emphasizes the use of automation where possible, specifically through automated binary analysis tools.

### Applicability

This document is intended for system and application administrators, security specialists, auditors, help desk, platform deployment, and/or DevOps personnel who plan to develop, deploy, assess, or secure desktop applications.

### References

1. [AFINE Desktop Application Security Verification Standard (DASVS)](https://github.com/afine-com/DASVS)  
2. [NIAP Protection Profile for Application Software v2.0](https://www.niap-ccevs.org/protectionprofiles/516)  
3. [OWASP Desktop App Security Top 10](https://owasp.org/www-project-desktop-app-security-top-10/)

### Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License.](https://creativecommons.org/licenses/by-sa/4.0/)

### Assumptions

See the [ADA Desktop App Specification Assumptions section](Desktop%20App%20Specification.md#assumptions).

### Definitions

| Term | Definition |
| :---- | :---- |
| (AL0) ADA Assurance Level 0 (Self Attestation) | The developer performs the application assessment using the same test cases as AL1 and generates the Developer Test Report and Compliance Report. The CB reviews the Compliance Report for completeness. No independent ASTL review is performed. |
| (AL1) ADA Assurance Level 1 (Verified Self Assessment) | The developer provides evidence and statements of compliance to each audit test case. The ADA approved lab reviews the evidence against the requirements. The ADA approved lab does not directly assess the application. |
| (AL2) ADA Assurance Level 2 (Lab Assessment) | The ADA approved lab evaluates each audit test case directly against the application. In some cases, the developer may need to provide limited information or code snippets. |
| ASTL | ADA Security Test Laboratory. An independent organization authorized by the ADA Certification Body to perform security evaluations. |
| Binary analysis | Examination of compiled application binaries to verify the presence of security mitigations without requiring source code. |
| CB | Certification Body. The ISO 17065 accredited organization that oversees ASTLs and issues ADA certificates. |
| First-party binary | An executable or library that is compiled and distributed by the application developer, as opposed to OS-provided system libraries. |
| SBOM | Software Bill of Materials. A formal, machine-readable inventory of software components and dependencies. |
| 3P library | Any library which was not developed by the developer. These libraries may be open source or commercial libraries or SDKs. |

### Automated Binary Analysis Tooling Guidance

Various ADA Desktop Application Profile requirements are designed to be tested and validated utilizing automated binary analysis tools. The following tools are recommended for use by ASTLs:

| Tool | Platforms | Purpose |
| :---- | :---- | :---- |
| `checksec-anywhere` (Trail of Bits) | Windows, macOS, Linux | Cross-platform binary mitigation verification |
| `winchecksec` (Trail of Bits) | Windows | Windows PE binary mitigation verification |
| OWASP `blint` | Windows, macOS, Linux | Binary analysis, SBOM generation, capability detection |
| `checksec` (slimm609) | Linux | ELF binary mitigation verification |

ASTLs may use alternative tools provided they can demonstrate equivalent coverage of the automated test cases. Binary analysis shall be performed against all first-party executables and libraries in the application installation directory.

---

# Table of Contents

* [1 Common Baseline Requirements](#1-common-baseline-requirements)  
  * [1.1 Communications Security](#11-communications-security)  
  * [1.2 Data Protection](#12-data-protection)  
  * [1.3 Authentication and Privilege Management](#13-authentication-and-privilege-management)  
  * [1.4 Input Validation](#14-input-validation)  
  * [1.5 Component and Dependency Management](#15-component-and-dependency-management)  
  * [1.6 Secure Update Mechanism](#16-secure-update-mechanism)  
  * [1.7 Inter-Process Communication (IPC)](#17-inter-process-communication-ipc)  
  * [1.8 Logging and Error Handling](#18-logging-and-error-handling)  
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

---

#### 1.1.1 The application shall enforce TLS for all network communications

External Reference: DASVS 5.1, NIAP PP_APP FCS_TLSC_EXT

**Evidence**

*AL1*

1. Provide architectural documentation or code snippets demonstrating that all network communication endpoints utilize `https://` or secure protocols (e.g., `wss://`, `ftps://`).  
2. Provide a list of all external endpoints the application communicates with.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review provided documentation to ensure no `http://` or unencrypted protocols are used for external communication.  
2. Review the endpoint list for completeness.

*AL2*

1. Install the application and configure a network traffic interception proxy (e.g., Wireshark, tcpdump, or mitmproxy).  
2. Exercise all core application functionality including authentication, data synchronization, and update checks.  
3. Analyze captured traffic for any plaintext (unencrypted) network communications.

**Verification**

*AL1 and AL2*

1. All external network communications use TLS-encrypted protocols.  
2. No plaintext HTTP, FTP, Telnet, or other unencrypted protocols are used for transmitting application data.  
3. Exception: Plaintext communication to `localhost` or `127.0.0.1` for local IPC is acceptable if the IPC channel is otherwise secured (see Section 1.7).

---

#### 1.1.2 The application shall validate TLS certificates

External Reference: DASVS 5.2, NIAP PP_APP FCS_TLSC_EXT

**Evidence**

*AL1*

1. Provide documentation or code snippets showing how the application's network libraries handle TLS certificate validation (e.g., ensuring `verify_mode` is set to `CERT_REQUIRED` or equivalent).  
2. If the application uses a custom TLS implementation or overrides default validation, provide a description of the custom logic.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the provided evidence to confirm certificate validation is not disabled or bypassed.

*AL2*

1. Configure the test environment to route the application's traffic through a proxy presenting an invalid, self-signed, or expired TLS certificate.  
2. Attempt to trigger network communication from the application.  
3. Repeat with a certificate signed by an untrusted CA.

**Verification**

*AL1 and AL2*

1. The application rejects connections when presented with an invalid, self-signed, expired, or untrusted certificate.  
2. The application fails securely without transmitting sensitive data over the rejected connection.  
3. Certificate validation is not disabled via configuration files, environment variables, or command-line flags.

---

#### 1.1.3 The application shall use strong cryptographic protocols and cipher suites

External Reference: DASVS 5.3, NIAP PP_APP FCS_TLSC_EXT

**Evidence**

*AL1*

1. Provide documentation of the TLS library used and its configuration, including minimum TLS version and permitted cipher suites.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the provided TLS configuration for compliance with minimum requirements.

*AL2*

1. Intercept the application's TLS handshake using a network analysis tool (e.g., Wireshark).  
2. Inspect the `ClientHello` message for the TLS version and offered cipher suites.

**Verification**

*AL1 and AL2*

1. The application supports TLS 1.2 or higher. TLS 1.0 and 1.1 shall not be offered.  
2. The application does not offer cipher suites using NULL encryption, RC4, DES, 3DES, or export-grade cryptography.  
3. The application supports at least one cipher suite using AES-GCM or ChaCha20-Poly1305.

---

## 1.2 Data Protection

### Description

Applications must protect sensitive data stored locally on the desktop file system and handle sensitive data securely in memory.

### Rationale

Desktop environments are often shared or susceptible to physical compromise. Sensitive data such as authentication tokens, PII, or encryption keys stored in plaintext can be easily extracted by other applications, malicious actors, or forensic analysis.

### Audit

---

#### 1.2.1 Sensitive data shall not be stored in plaintext in configuration files or logs

External Reference: DASVS 2.1, OWASP Desktop Top 10 DA2

**Evidence**

*AL1*

1. Provide a sample of the application's configuration files generated during a typical installation.  
2. Provide a sample of application logs generated during a typical user session involving authentication and processing of sensitive data.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the provided configuration and log files for the presence of plaintext passwords, API keys, session tokens, or PII.

*AL2*

1. Install the application and perform a standard user session, including authentication and processing of sensitive data.  
2. Locate the application's configuration directories:  
   * Windows: `%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, registry keys  
   * macOS: `~/Library/Application Support`, `~/Library/Preferences`  
   * Linux: `~/.config`, `~/.local/share`, `/etc`  
3. Locate the application's log directories.  
4. Search all configuration and log files for plaintext sensitive data using `grep`, `findstr`, or equivalent tools.

**Verification**

*AL1 and AL2*

1. No plaintext passwords, API keys, session tokens, or PII are present in configuration files.  
2. No plaintext sensitive data is present in application log files.  
3. Session tokens shall only be stored in logs in an irreversible, hashed form (if logged at all).

---

#### 1.2.2 Sensitive local data shall be encrypted using platform secure storage mechanisms

External Reference: DASVS 2.2, NIAP PP_APP FDP_DAR_EXT

**Evidence**

*AL1*

1. Provide documentation or code snippets demonstrating the use of platform-native secure storage:  
   * Windows: DPAPI, Credential Locker, or Windows Credential Manager  
   * macOS: Keychain Services  
   * Linux: Secret Service API (libsecret), KWallet, or GNOME Keyring

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the provided evidence to confirm the use of platform-approved secure storage APIs for all sensitive data (credentials, tokens, encryption keys).

*AL2*

1. Identify where the application stores authentication tokens, credentials, or sensitive offline data by monitoring file system writes and API calls during authentication.  
2. Verify via dynamic analysis (e.g., API monitoring with Process Monitor on Windows, `dtrace`/`fs_usage` on macOS, or `strace` on Linux) that the application utilizes the native secure storage APIs.

**Verification**

*AL1 and AL2*

1. Authentication tokens, credentials, and encryption keys are stored using the platform-native secure storage mechanism.  
2. Sensitive data is not stored in custom flat files, SQLite databases, or other non-platform-protected locations without additional encryption.

---

#### 1.2.3 The application shall securely handle data in memory

External Reference: DASVS 2.3

**Evidence**

*AL1*

1. Provide documentation describing how the application handles sensitive data in memory, including whether sensitive buffers are zeroed after use.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the provided documentation for secure memory handling practices.

*AL2*

1. Authenticate to the application and perform operations involving sensitive data.  
2. Create a memory dump of the application process.  
3. Search the memory dump for plaintext credentials or sensitive data that should have been cleared.

**Verification**

*AL1 and AL2*

1. Sensitive data (e.g., user passwords) is not retained in process memory after it is no longer needed for the immediate operation.  
2. Note: This requirement applies to data the application directly handles (e.g., user-entered passwords). It does not apply to data managed by the OS or third-party frameworks outside the developer's control.

---

## 1.3 Authentication and Privilege Management

### Description

Applications must implement secure authentication mechanisms and adhere to the principle of least privilege.

### Rationale

Weak authentication allows unauthorized access, while excessive privileges increase the blast radius of any successful exploit.

### Audit

---

#### 1.3.1 The application shall not require administrative or root privileges for standard operation

External Reference: DASVS 3.1, NIAP PP_APP FPT_AEX_EXT

**Evidence**

*AL1*

1. Provide the application manifest or configuration demonstrating the requested execution level:  
   * Windows: `app.manifest` showing `<requestedExecutionLevel level="asInvoker" />`  
   * macOS: `Info.plist` (confirm no `SMJobBless` or `AuthorizationExecuteWithPrivileges` for core functionality)  
   * Linux: `.desktop` file or systemd unit file (confirm no `sudo` or `pkexec` requirement for core functionality)

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the manifest to ensure `requireAdministrator` (Windows) or equivalent flags are not set for the main application executable.

*AL2*

1. Install the application on a standard, non-administrative user account.  
2. Launch the application and perform all core workflows.  
3. Verify that the application functions correctly without prompting for UAC elevation (Windows), `sudo`/root passwords (Linux), or administrator authentication (macOS).

**Verification**

*AL1 and AL2*

1. The application operates successfully without administrative/root privileges for all core functionality.  
2. Installers and updaters may require elevation, but the primary application runtime shall not.  
3. If specific features require elevation (e.g., VPN configuration), the application shall use privilege separation to request elevation only for those specific operations.

---

#### 1.3.2 The application shall securely store authentication tokens and credentials

External Reference: DASVS 3.2, OWASP Desktop Top 10 DA1

**Evidence**

*AL1*

1. Provide a design document explaining the lifecycle of authentication tokens (e.g., OAuth refresh/access tokens) from issuance to storage and expiration.  
2. Describe the storage mechanism used (cross-reference with 1.2.2).

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the design document to ensure tokens are handled securely and not written to easily accessible disk locations.

*AL2*

1. Authenticate to the application.  
2. Search the application's disk footprint (configuration files, databases, temporary files) for the presence of long-lived credentials (e.g., user passwords stored in plaintext or reversible encryption).  
3. Verify that the application relies on temporary session tokens rather than persisting the user's raw password.

**Verification**

*AL1 and AL2*

1. The application does not store the user's raw password on disk.  
2. Authentication tokens are stored using the platform secure storage mechanism (verifying 1.2.2).  
3. Tokens have a defined expiration and are refreshed securely.

---

## 1.4 Input Validation

### Description

Applications must validate and sanitize all input from untrusted sources.

### Rationale

Desktop applications frequently interact with the underlying operating system shell, file system, and other local resources. Improper input validation can lead to command injection, path traversal, and other attacks.

### Audit

---

#### 1.4.1 The application shall validate and sanitize all untrusted input

External Reference: DASVS 4.1, OWASP Desktop Top 10 DA5

**Evidence**

*AL1*

1. Provide documentation describing the application's input validation strategy, including which input sources are considered untrusted (e.g., user input, file input, network data, IPC messages, clipboard data).  
2. Provide code snippets demonstrating input validation for representative input handlers.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the documentation and code snippets to confirm a consistent input validation strategy is applied.

*AL2*

1. Identify all input vectors (text fields, file open dialogs, drag-and-drop, command-line arguments, IPC messages, URL scheme handlers).  
2. Submit malformed, oversized, and boundary-condition inputs to each vector.  
3. Verify the application handles invalid input gracefully without crashing or exhibiting unexpected behavior.

**Verification**

*AL1 and AL2*

1. The application validates input from all untrusted sources before processing.  
2. The application does not crash, hang, or exhibit undefined behavior when processing malformed input.

---

#### 1.4.2 The application shall protect against OS command injection

External Reference: DASVS 4.2, OWASP Desktop Top 10 DA5

**Evidence**

*AL1*

1. Provide documentation or code snippets demonstrating how the application invokes OS commands (if at all).  
2. If the application invokes OS commands with user-controlled input, provide evidence of parameterization or sanitization.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the evidence to confirm that user input is not directly concatenated into OS command strings.

*AL2*

1. Identify all application features that invoke OS commands or shell processes.  
2. Attempt to inject OS commands through user-controllable input fields, file names, or other input vectors using standard injection payloads (e.g., `; whoami`, `| id`, `` `id` ``).

**Verification**

*AL1 and AL2*

1. The application does not pass unsanitized user input directly to OS command interpreters (e.g., `cmd.exe`, `/bin/sh`, `PowerShell`).  
2. Where OS commands must be invoked, the application uses parameterized APIs (e.g., `subprocess` with argument lists rather than shell=True in Python, `ProcessBuilder` in Java) or applies strict input sanitization.

---

#### 1.4.3 The application shall protect against path traversal attacks

External Reference: DASVS 4.3, OWASP Desktop Top 10 DA5

**Evidence**

*AL1*

1. Provide documentation or code snippets demonstrating how the application handles file paths provided by users or received from external sources.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the evidence to confirm that user-supplied file paths are validated and canonicalized before use.

*AL2*

1. Identify all application features that accept file paths as input (e.g., file open dialogs, import functions, command-line arguments).  
2. Attempt to access files outside the intended directory using path traversal sequences (e.g., `../../../etc/passwd`, `..\..\Windows\System32\config\SAM`).

**Verification**

*AL1 and AL2*

1. The application canonicalizes file paths and validates that the resolved path is within the expected directory.  
2. The application does not allow access to files outside the intended scope via path traversal.

---

## 1.5 Component and Dependency Management

### Description

Applications must manage third-party libraries and shared components securely.

### Rationale

Desktop applications frequently rely on shared libraries. Insecure loading mechanisms can lead to library hijacking, and outdated components introduce known vulnerabilities.

### Audit

---

#### 1.5.1 The application shall only use software components without known exploitable vulnerabilities

External Reference: DASVS 6.1, OWASP Desktop Top 10 DA6

**Evidence**

*AL1*

1. Provide a Software Bill of Materials (SBOM) in a standard format (e.g., CycloneDX, SPDX).  
2. Provide the output of a recent dependency scanning tool (e.g., OWASP Dependency-Check, Snyk, Trivy, or GitHub Dependabot) showing no known critical or high CVEs (CVSS >= 7.0) in third-party libraries.

*AL2*

1. Provide the application binaries or installer package.

**Test Procedure**

*AL1*

1. Review the SBOM and scan results to confirm no critical or high vulnerabilities (CVSS >= 7.0) exist in the application's dependencies.

*AL2*

1. Utilize a binary analysis tool (e.g., OWASP `blint`) against the application installation directory to generate an SBOM and check for known vulnerable components.  
2. Cross-reference identified components against the NVD or other CVE databases.

**Verification**

*AL1 and AL2*

1. No third-party components with known critical or high vulnerabilities (CVSS >= 7.0) are present.  
2. For components with medium vulnerabilities (CVSS 4.0-6.9), the developer has documented a risk assessment or remediation timeline.

---

#### 1.5.2 The application shall employ safe library loading mechanisms to prevent hijacking

External Reference: DASVS 6.2, OWASP Desktop Top 10 DA3

**Evidence**

*AL1*

1. Provide documentation or build configurations demonstrating how the application restricts library loading paths.  
2. For Windows: Confirm use of `SetDefaultDllDirectories`, absolute paths for `LoadLibrary`, or manifest-based side-by-side assemblies.  
3. For macOS/Linux: Provide `otool -l` or `readelf -d` output showing `RPATH`/`RUNPATH` configurations.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the provided evidence for safe library loading practices.

*AL2*

1. **Windows**: Place a dummy DLL with the same name as a required system DLL in the application directory and in the current working directory. Launch the application and verify the dummy DLL is not loaded (monitor with Process Monitor or similar).  
2. **macOS**: Inspect `RPATH` entries using `otool -l` and verify they do not include relative paths or world-writable directories. Test for dylib hijacking by placing a dummy dylib in candidate paths.  
3. **Linux**: Inspect `RPATH`/`RUNPATH` entries using `readelf -d` and verify they do not include relative paths, `$ORIGIN` pointing to world-writable directories, or empty entries.

**Verification**

*AL1 and AL2*

1. The application does not load libraries from insecure or attacker-controllable locations.  
2. **Windows**: The application uses `SetDefaultDllDirectories` or equivalent, or loads all non-system DLLs from absolute paths.  
3. **macOS/Linux**: `RPATH`/`RUNPATH` entries do not include world-writable or user-controllable directories.

---

## 1.6 Secure Update Mechanism

### Description

The application must possess a secure mechanism for delivering and installing updates, or must clearly document that it relies on an external update mechanism.

### Rationale

To respond to emerging threats, applications must be updatable. The update process itself must be secure to prevent supply chain attacks.

### Audit

---

#### 1.6.1 Updates shall be delivered over encrypted channels

External Reference: DASVS 7.1, NIAP PP_APP FCS_TLSC_EXT

**Evidence**

*AL1*

1. Provide documentation or code snippets of the update client demonstrating that the update server URL utilizes `https://`.  
2. If the application relies on an external update mechanism (e.g., OS package manager, enterprise deployment tool), document which mechanism is used.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the evidence to confirm the update mechanism relies on TLS.

*AL2*

1. Intercept the application's network traffic during an update check and download.  
2. Verify the update manifest and binary are fetched over HTTPS.

**Verification**

*AL1 and AL2*

1. Update metadata (manifest, version checks) and update payloads (binaries, patches) are delivered exclusively over TLS-encrypted channels.  
2. If the application relies on an external update mechanism, that mechanism must itself use encrypted channels.

---

#### 1.6.2 Update packages shall be cryptographically signed and verified prior to installation

External Reference: DASVS 7.2, NIAP PP_APP FPT_TUD_EXT

**Evidence**

*AL1*

1. Provide documentation detailing the cryptographic verification process performed by the updater before executing a downloaded payload.  
2. Describe the signing key management process (e.g., who holds the signing key, how it is protected).

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the documentation to confirm the updater verifies a digital signature before execution.

*AL2*

1. Intercept the update process and replace the legitimate update binary with an unsigned or improperly signed binary.  
2. Allow the updater to proceed and observe whether it accepts or rejects the modified binary.

**Verification**

*AL1 and AL2*

1. The updater verifies a cryptographic signature (e.g., Authenticode, Apple Developer ID, GPG, or a custom RSA/ECDSA signature) before installing the update.  
2. The updater rejects modified, unsigned, or improperly signed update packages.  
3. The signing key is not embedded in the application binary in a form that could be trivially extracted and reused.

---

## 1.7 Inter-Process Communication (IPC)

### Description

Applications that expose IPC endpoints must secure those endpoints against unauthorized access and data interception.

### Rationale

Desktop applications often communicate with helper processes, services, or browser extensions via IPC. Unsecured IPC endpoints can be exploited by malicious local applications to escalate privileges, exfiltrate data, or inject commands.

### Audit

---

#### 1.7.1 IPC endpoints shall validate the identity of connecting processes

External Reference: DASVS 8.1

**Evidence**

*AL1*

1. Provide documentation describing all IPC mechanisms used by the application (e.g., named pipes, Unix domain sockets, D-Bus, COM, XPC, shared memory).  
2. Describe the access control mechanisms applied to each IPC endpoint.  
3. If the application does not use IPC, provide a statement to that effect.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the documentation to confirm that IPC endpoints apply access controls.

*AL2*

1. Enumerate the application's IPC endpoints (e.g., using Process Monitor on Windows, `lsof` on macOS/Linux, or D-Bus introspection on Linux).  
2. Attempt to connect to each endpoint from an unauthorized process running under a different user context.

**Verification**

*AL1 and AL2*

1. IPC endpoints restrict access to authorized processes (e.g., via ACLs on named pipes, file permissions on Unix domain sockets, D-Bus policy configuration, or XPC connection validation).  
2. Unauthorized processes are denied access.  
3. If the application does not use IPC, this requirement is not applicable.

---

#### 1.7.2 Sensitive data transmitted via IPC shall be protected

External Reference: DASVS 8.2

**Evidence**

*AL1*

1. Provide documentation describing what data is transmitted via IPC and whether it includes sensitive information.  
2. If sensitive data is transmitted, describe the protection mechanism (e.g., encryption, OS-level access controls).

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the documentation to confirm sensitive IPC data is protected.

*AL2*

1. Monitor IPC traffic between the application and its helper processes using appropriate tools (e.g., named pipe monitoring, Unix socket interception).  
2. Inspect the captured data for plaintext sensitive information.

**Verification**

*AL1 and AL2*

1. Sensitive data transmitted via IPC is either encrypted or the IPC channel is protected by OS-level access controls that prevent unauthorized interception.  
2. If the application does not transmit sensitive data via IPC, this requirement is not applicable.

---

## 1.8 Logging and Error Handling

### Description

Applications must handle errors securely and ensure that production builds do not expose sensitive information.

### Rationale

Verbose error messages can reveal internal application state that assists attackers. Debug modes left enabled in production can bypass security controls.

### Audit

---

#### 1.8.1 The application shall not expose sensitive information in error messages

External Reference: DASVS 9.1, OWASP Desktop Top 10 DA8

**Evidence**

*AL1*

1. Provide screenshots or samples of error messages displayed to users during common error conditions (e.g., authentication failure, network timeout, file not found).

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the provided error messages for the presence of sensitive information.

*AL2*

1. Trigger common error conditions in the application (e.g., invalid credentials, network disconnection, corrupted input files).  
2. Inspect the error messages displayed to the user and written to log files.

**Verification**

*AL1 and AL2*

1. Error messages do not reveal internal file paths, stack traces, database queries, or other implementation details to the end user.  
2. Detailed error information may be written to log files (subject to 1.2.1) but shall not be displayed in the user interface.

---

#### 1.8.2 Debug modes shall be disabled in production builds

External Reference: DASVS 9.2, OWASP Desktop Top 10 DA9

**Evidence**

*AL1*

1. Provide build configuration files demonstrating that debug symbols are stripped and debug modes are disabled in the release build.  
2. For Electron/CEF applications: Confirm that DevTools are disabled in production.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the build configurations to confirm debug modes are disabled.

*AL2*

1. Launch the application and attempt to access debug functionality (e.g., developer consoles, debug menus, verbose logging flags).  
2. For Electron/CEF applications: Attempt to open DevTools via keyboard shortcuts (Ctrl+Shift+I / Cmd+Option+I) or command-line flags (`--remote-debugging-port`).  
3. Inspect the binary for the presence of unstripped debug symbols using platform-appropriate tools.

**Verification**

*AL1 and AL2*

1. Debug modes, developer consoles, and diagnostic interfaces are not accessible in the production build.  
2. For Electron/CEF applications: DevTools are disabled and remote debugging is not enabled.

---

# 2 Windows Annex

## 2.1 Binary Hardening (Windows)

### Description

Windows executables (PE files) and dynamic-link libraries (DLLs) must utilize OS-level exploit mitigations.

### Rationale

Compiler-level mitigations significantly increase the difficulty of exploiting memory corruption vulnerabilities. These mitigations are well-established, incur minimal performance overhead, and are verifiable via automated binary analysis.

### Audit

---

#### 2.1.1 Windows binaries shall enable ASLR and DEP

External Reference: DASVS 1.1 (Windows), NIAP PP_APP FPT_AEX_EXT

**Evidence**

*AL1*

1. Provide build configuration files (e.g., Visual Studio `.vcxproj`, CMake files, or linker flags) showing `/DYNAMICBASE` (ASLR) and `/NXCOMPAT` (DEP) are enabled.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the build configurations to confirm the flags are present.

*AL2*

1. Run `checksec-anywhere` or `winchecksec` against all `.exe` and `.dll` files in the application directory.  
   * Example: `winchecksec.exe <application.exe>`

**Verification**

*AL1 and AL2*

1. `Dynamic Base` (ASLR) is enabled on all first-party PE binaries.  
2. `NX` (DEP) is enabled on all first-party PE binaries.

---

#### 2.1.2 Windows binaries shall enable Control Flow Guard (CFG)

External Reference: DASVS 1.2 (Windows), Microsoft SDL

**Evidence**

*AL1*

1. Provide build configuration files showing `/guard:cf` is enabled.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the build configurations to confirm the CFG flag is present.

*AL2*

1. Run `checksec-anywhere` or `winchecksec` against the application binaries.

**Verification**

*AL1 and AL2*

1. `CFG` (Control Flow Guard) is enabled on all first-party PE binaries compiled with MSVC.  
2. For binaries compiled with other toolchains (e.g., MinGW, Rust, Go), CFG may not be applicable. The developer shall document the toolchain used and any equivalent control flow integrity mechanisms.

---

#### 2.1.3 Windows binaries shall enable High Entropy ASLR

External Reference: DASVS 1.3 (Windows), Microsoft SDL

**Evidence**

*AL1*

1. Provide build configuration files showing `/HIGHENTROPYVA` is enabled for 64-bit targets.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the build configurations to confirm the flag is present for 64-bit builds.

*AL2*

1. Run `checksec-anywhere` or `winchecksec` against the 64-bit application binaries.

**Verification**

*AL1 and AL2*

1. `High Entropy VA` is enabled on all 64-bit first-party PE binaries.  
2. This requirement is not applicable to 32-bit binaries.

---

#### 2.1.4 Windows binaries shall enable SafeSEH or be compiled for 64-bit

External Reference: DASVS 1.4 (Windows), Microsoft SDL

**Evidence**

*AL1*

1. Provide build configuration files showing `/SAFESEH` is enabled for 32-bit targets, or confirm the application is compiled exclusively for 64-bit.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the build configurations.

*AL2*

1. Run `checksec-anywhere` or `winchecksec` against the application binaries.

**Verification**

*AL1 and AL2*

1. For 32-bit PE binaries: `SafeSEH` is enabled.  
2. For 64-bit PE binaries: SafeSEH is not applicable (64-bit Windows uses table-based exception handling).  
3. Alternatively, the application is compiled exclusively for 64-bit, which inherently provides stronger exception handling security.

---

## 2.2 Code Signing (Windows)

### Description

Windows executables and libraries distributed by the developer must be signed with a valid code signing certificate.

### Rationale

Authenticode code signing provides integrity verification and publisher attribution. Unsigned binaries trigger security warnings from Windows SmartScreen.

### Audit

---

#### 2.2.1 Windows executables and libraries shall be signed with a valid Authenticode certificate

External Reference: DASVS 10.1 (Windows), NIAP PP_APP FPT_TUD_EXT

**Evidence**

*AL1*

1. Provide a screenshot or output of `signtool verify /v /pa <file>` or `Get-AuthenticodeSignature` for the main application executable and primary DLLs.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the evidence to confirm the presence of a valid digital signature.

*AL2*

1. Verify the digital signature of all first-party `.exe` and `.dll` files using:  
   * `signtool verify /v /pa <file>` or  
   * PowerShell: `Get-AuthenticodeSignature <file>`

**Verification**

*AL1 and AL2*

1. All first-party executables and DLLs possess a valid, non-expired Authenticode signature.  
2. The signature chain traces to a trusted root CA.  
3. The signature includes a trusted timestamp (countersignature) to remain valid after the signing certificate expires.

---

## 2.3 Platform Integration (Windows)

### Description

Windows applications must integrate securely with the Windows security ecosystem.

### Rationale

Proper integration with Windows security features ensures the application operates within the OS security model.

### Audit

---

#### 2.3.1 The application shall use secure Windows IPC mechanisms with appropriate access controls

External Reference: DASVS 8.1 (Windows)

**Evidence**

*AL1*

1. Provide documentation of all Windows IPC mechanisms used (e.g., named pipes, COM objects, Windows messages, shared memory, RPC).  
2. Provide the security descriptors (DACLs) applied to named pipes or other securable IPC objects.  
3. If the application does not use Windows IPC, provide a statement to that effect.

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the documentation and security descriptors for appropriate access restrictions.

*AL2*

1. Enumerate the application's named pipes, COM objects, and other IPC endpoints using Process Monitor or similar tools.  
2. Inspect the security descriptors on named pipes using `AccessChk` or equivalent.  
3. Attempt to connect to IPC endpoints from an unprivileged process.

**Verification**

*AL1 and AL2*

1. Named pipes and other securable IPC objects have explicit DACLs that restrict access to authorized users/processes.  
2. Named pipes do not use `NULL` DACLs (which grant access to all users).  
3. If the application does not use Windows IPC, this requirement is not applicable.

---

# 3 macOS Annex

## 3.1 Binary Hardening (macOS)

### Description

macOS executables (Mach-O files) must utilize OS-level exploit mitigations.

### Rationale

Compiler-level mitigations significantly increase the difficulty of exploiting memory corruption vulnerabilities. Modern macOS toolchains enable most of these by default, but they must be verified.

### Audit

---

#### 3.1.1 macOS binaries shall enable PIE and ARC

External Reference: DASVS 1.1 (macOS), NIAP PP_APP FPT_AEX_EXT

**Evidence**

*AL1*

1. Provide Xcode project settings or compiler flags showing PIE is enabled and ARC is enabled (`CLANG_ENABLE_OBJC_ARC = YES`).

*AL2*

1. Provide the application `.app` bundle.

**Test Procedure**

*AL1*

1. Review the Xcode settings to confirm PIE and ARC are enabled.

*AL2*

1. Run `checksec-anywhere` against the Mach-O binaries within the `.app` bundle.  
   * Example: `checksec-anywhere -f <Application.app/Contents/MacOS/executable>`  
2. Verify PIE using `otool`: `otool -hv <binary>` (look for `PIE` flag).

**Verification**

*AL1 and AL2*

1. `PIE` (Position Independent Executable) is enabled on all first-party Mach-O binaries.  
2. `ARC` (Automatic Reference Counting) is enabled for Objective-C/Swift code.  
3. For non-Objective-C/Swift binaries (e.g., C/C++, Rust), ARC is not applicable but PIE remains required.

---

#### 3.1.2 macOS binaries shall enable stack canaries

External Reference: DASVS 1.2 (macOS)

**Evidence**

*AL1*

1. Provide compiler flags showing `-fstack-protector-all` or `-fstack-protector-strong` is enabled.

*AL2*

1. Provide the application `.app` bundle.

**Test Procedure**

*AL1*

1. Review the compiler flags to confirm stack protectors are enabled.

*AL2*

1. Run `checksec-anywhere` against the Mach-O binaries.  
2. Alternatively, check for the presence of `___stack_chk_fail` and `___stack_chk_guard` symbols using `nm` or `otool`.

**Verification**

*AL1 and AL2*

1. Stack canaries are present on all first-party Mach-O binaries (indicated by the presence of stack check symbols).

---

## 3.2 Code Signing and Notarization (macOS)

### Description

macOS applications must be signed with a valid Developer ID and notarized by Apple.

### Rationale

Apple Gatekeeper blocks unsigned and unnotarized applications by default. Notarization involves an automated Apple security scan and provides a tamper-evident seal.

### Audit

---

#### 3.2.1 macOS applications shall be signed with a valid Developer ID and notarized by Apple

External Reference: DASVS 10.1 (macOS), NIAP PP_APP FPT_TUD_EXT

**Evidence**

*AL1*

1. Provide the output of the following commands:  
   * `spctl -a -t exec -vv <Application.app>`  
   * `stapler validate -v <Application.app>`

*AL2*

1. Provide the `.app` bundle or `.dmg`.

**Test Procedure**

*AL1*

1. Review the command output to confirm valid signature and notarization ticket.

*AL2*

1. Verify the signature and notarization status:  
   * `spctl -a -t exec -vv <Application.app>`  
   * `stapler validate -v <Application.app>`  
   * `codesign -dv --verbose=4 <Application.app>`

**Verification**

*AL1 and AL2*

1. `spctl` returns "accepted" with source "Notarized Developer ID".  
2. `stapler validate` confirms a valid notarization ticket is stapled to the application.  
3. The Developer ID certificate is valid and not expired or revoked.

---

## 3.3 Platform Integration (macOS)

### Description

macOS applications must enable the Hardened Runtime and minimize the use of dangerous entitlements.

### Rationale

The Hardened Runtime restricts the application from performing potentially dangerous operations. It is required for notarization and provides a strong security baseline.

### Audit

---

#### 3.3.1 macOS applications shall enable the Hardened Runtime

External Reference: DASVS 11.1 (macOS), Apple Developer Documentation

**Evidence**

*AL1*

1. Provide the output of `codesign -dv --entitlements :- <Application.app>` showing the Hardened Runtime flag.

*AL2*

1. Provide the `.app` bundle.

**Test Procedure**

*AL1*

1. Review the evidence to confirm the Hardened Runtime is enabled.

*AL2*

1. Verify the Hardened Runtime status:  
   * `codesign -dv --verbose=4 <Application.app>`  
2. Check for the `runtime` flag in the `CodeDirectory` flags output.

**Verification**

*AL1 and AL2*

1. The application is signed with the Hardened Runtime enabled (indicated by the `runtime` flag in `codesign` output).  
2. Note: Hardened Runtime is required for notarization (3.2.1), so passing 3.2.1 implicitly confirms this requirement.

---

#### 3.3.2 macOS applications shall minimize the use of dangerous entitlements

External Reference: DASVS 11.2 (macOS), Apple Developer Documentation

**Evidence**

*AL1*

1. Provide the full list of entitlements used by the application (output of `codesign -dv --entitlements :- <Application.app>`).  
2. For each entitlement that weakens the Hardened Runtime (e.g., `com.apple.security.cs.disable-library-validation`, `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.security.cs.allow-dyld-environment-variables`), provide a justification for its use.

*AL2*

1. Provide the `.app` bundle.

**Test Procedure**

*AL1*

1. Review the entitlements list and justifications for dangerous entitlements.

*AL2*

1. Extract the application's entitlements:  
   * `codesign -dv --entitlements :- <Application.app>`  
2. Identify any entitlements that weaken the Hardened Runtime protections.

**Verification**

*AL1 and AL2*

1. The application does not use the following entitlements without documented justification:  
   * `com.apple.security.cs.disable-library-validation`  
   * `com.apple.security.cs.allow-unsigned-executable-memory`  
   * `com.apple.security.cs.allow-dyld-environment-variables`  
   * `com.apple.security.cs.disable-executable-page-protection`  
2. If any of these entitlements are used, the justification is reviewed and deemed reasonable by the ASTL.

---

# 4 Linux Annex

## 4.1 Binary Hardening (Linux)

### Description

Linux executables (ELF files) must utilize OS-level exploit mitigations.

### Rationale

Compiler-level mitigations significantly increase the difficulty of exploiting memory corruption vulnerabilities. These flags are widely supported by GCC and Clang.

### Audit

---

#### 4.1.1 Linux binaries shall enable PIE and NX

External Reference: DASVS 1.1 (Linux), NIAP PP_APP FPT_AEX_EXT

**Evidence**

*AL1*

1. Provide Makefile or build configurations showing `-fPIE -pie` and `-z noexecstack` are utilized.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the build configurations to confirm the PIE and NX flags are present.

*AL2*

1. Run `checksec-anywhere` or `checksec` against all ELF binaries in the application directory.  
   * Example: `checksec --file=<executable>`

**Verification**

*AL1 and AL2*

1. `PIE` (Position Independent Executable) is enabled on all first-party ELF binaries (type `DYN` in ELF header).  
2. `NX` (No-Execute / non-executable stack) is enabled on all first-party ELF binaries.

---

#### 4.1.2 Linux binaries shall enable Full RELRO and stack canaries

External Reference: DASVS 1.2 (Linux)

**Evidence**

*AL1*

1. Provide Makefile or build configurations showing `-Wl,-z,relro,-z,now` (Full RELRO) and `-fstack-protector-strong` are utilized.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the build configurations to confirm RELRO and stack canary flags are present.

*AL2*

1. Run `checksec-anywhere` or `checksec` against the ELF binaries.

**Verification**

*AL1 and AL2*

1. `Full RELRO` is enabled on all first-party ELF binaries (both `RELRO` and `BIND_NOW` flags present).  
2. `Stack Canary` is enabled on all first-party ELF binaries.

---

#### 4.1.3 Linux binaries shall enable FORTIFY_SOURCE

External Reference: DASVS 1.3 (Linux)

**Evidence**

*AL1*

1. Provide Makefile or build configurations showing `-D_FORTIFY_SOURCE=2` (or higher) is utilized.

*AL2*

1. Provide the application binaries.

**Test Procedure**

*AL1*

1. Review the build configurations to confirm FORTIFY_SOURCE is enabled.

*AL2*

1. Run `checksec-anywhere` or `checksec` against the ELF binaries.  
2. Alternatively, check for the presence of `__*_chk` symbols (e.g., `__printf_chk`, `__memcpy_chk`) using `nm` or `readelf`.

**Verification**

*AL1 and AL2*

1. `FORTIFY_SOURCE` is enabled on all first-party ELF binaries (indicated by the presence of fortified function variants in the symbol table).

---

## 4.2 Distribution Integrity (Linux)

### Description

Linux applications must be distributed via mechanisms that provide cryptographic integrity verification.

### Rationale

Unlike Windows and macOS, Linux lacks a single unified code signing infrastructure. Applications must use secure distribution mechanisms to ensure authenticity and integrity.

### Audit

---

#### 4.2.1 Linux applications shall be distributed via secure, integrity-verified channels

External Reference: DASVS 10.1 (Linux), NIAP PP_APP FPT_TUD_EXT

**Evidence**

*AL1*

1. Provide documentation detailing the distribution method, including one of the following:  
   * Link to a Flatpak/Snap store listing  
   * Documentation on importing the developer's GPG key for APT/YUM/DNF repositories  
   * GPG-signed checksums published alongside the download  
   * AppImage with embedded signature

*AL2*

1. N/A (to be collected by labs).

**Test Procedure**

*AL1*

1. Review the documentation to confirm the distribution channel relies on cryptographic integrity verification.

*AL2*

1. Download the application using the documented distribution method.  
2. Verify that the package manager or distribution system automatically verifies a cryptographic signature before allowing installation.  
3. For direct downloads: Verify that GPG-signed checksums are available and match the downloaded binary.

**Verification**

*AL1 and AL2*

1. The application is distributed via at least one of the following integrity-verified mechanisms:  
   * Signed package in a GPG-signed APT/YUM/DNF repository  
   * Flatpak from a verified publisher on Flathub or equivalent  
   * Snap from the Snap Store  
   * AppImage with embedded GPG signature  
   * Direct download with GPG-signed SHA-256 checksums published on the developer's website over HTTPS  
2. The cryptographic signature or checksum is verifiable by the end user or package manager.

