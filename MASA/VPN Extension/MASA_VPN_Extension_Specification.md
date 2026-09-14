# App Defense Alliance MASA Specification

Version 0.0.1 - 2026-09-14

> **Version history** is maintained via [GitHub Releases](https://github.com/appdefensealliance/ASA-WG/releases) and [`CHANGELOG.md`](../CHANGELOG.md).

## Acknowledgements

The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

### Application Security Assessment Working Group Leads
* 
* 

### MASA Profile Leads
* 
* 

### Contributors
* 
* 

## About This Specification

The **MASA VPN Security Extension** defines a specialized Mobile Application Security Assessment (MASA) Level 2 (AL2) evaluation framework for high-privilege mobile virtual private network (VPN) applications on Android and iOS platforms. 

Because VPN applications instantiate virtual network adapters and possess absolute visibility and control over outbound user-plane network traffic, they represent a unique trust boundary on mobile devices. Standard bytecode-level self-assessments (AL1) are insufficient to evaluate their true security posture. This specification establishes a rigorous, binary-level, independent laboratory auditing regime to verify complete traffic encapsulation, DNS leak prevention, cryptographic integrity, and least-privilege compliance.


## Introduction

Additionally, this specialized extension serves as a catalyst to modernize baseline MASA controls globally, ensuring that general mobile security verification remains resilient against native-level compiled binary bypasses.

### Our Approach: OWASP MASVS as the Foundation

This VPN Extension builds upon the baseline ADA MASA Specification and the leverages the the internationally recognized OWASP Mobile Application Security Verification Standard (MASVS) as its core. The OWASP MASVS offers a comprehensive set of security assessment requirements and guidelines covering the entire mobile application development lifecycle. Building upon this base, the App Defense Alliance (ADA) focused on testable requirements with clear acceptance criteria. Further, the ADA approach emphasizes the use of automation where possible.

### Applicability

This document is intended for system and application administrators, security specialists, auditors, help desk, platform deployment, and/or DevOps personnel who plan to develop, deploy, assess, or secure mobile VPN applications.

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

Data that is of particular concern from a security perspective, including user data, user device data, company data, credentials, keys, or other types of confidential information. Throughout this document, the phrase "sensitive data" refers to these kinds of data and should not be confused with the meaning of *Sensitive Data* under regulations like GDPR or other regulatory regimes.

#### Tooling

The ADA approach emphasizes the use of automation where possible. We expect future tooling investment to assist with gathering of developer evidence for Level 1 assurance.

### Definitions
| Term | Definition |
| --- | ----- |
| (AL1) ADA Assurance Level 1 (Verified Self Assessment) | The developer provides evidence and statements of compliance to each audit test case. The ADA approved lab reviews the evidence against the requirements. The ADA approved lab does not directly assess the application. |
| (AL2) ADA Assurance Level 2 (Lab Assessment) |  The ADA approved lab evaluates each audit test case directly against the application. In some cases, the developer may need to provide limited information or code snippets. |

## Scope & Architectural Models

### Supported Architectural Models
Mobile VPN applications implement routing through distinct OS platform frameworks. This specification explicitly covers and mandates laboratory auditing for both architectural models:

*   **Model A (Custom Packet Tunnel Provider):** Applications utilizing custom, client-side packet-processing engines (e.g., `VpnService` with custom C/C++ tunneling libraries like WireGuard or OpenVPN on Android; `NETunnelProviderManager` within the NetworkExtension framework on iOS).
*   **Model B (System-Managed / Platform Framework):** Applications utilizing platform-native VPN configurations (e.g., `VpnManager` provisioning native platform IPsec profiles on Android; `NEVPNManager` with `NEVPNProtocolIKEv2` on iOS).

### Core Functional Pillars
The specification evaluates client applications across three generalized, outcome-driven pillars:
1.  **On-Device App Hardening:** Verifying client-side compiled binaries are structurally secure against exploitation, free of hardcoded secrets, and strictly bound by least-privilege permission scopes.
2.  **Tunnel Integrity & Leak Prevention:** Actively verifying that the virtual adapter acts as an impenetrable cryptographic barrier, securely encapsulating 100% of user traffic and local DNS requests in default mode, and strictly enforcing boundary isolation when split tunneling is active.
3.  **Version Consistency & Application Creep Prevention:** Governing post-audit code changes through objective, hash-bound delta compliance (governed under ADA-026 policy) to prevent post-audit feature drift.

### Explicit Out-of-Scope Boundaries
To preserve deterministic laboratory execution and prevent unconstrained cost inflation, the following domain areas are strictly **OUT OF SCOPE** for client binary certification:
*   **Active Censorship Evasion & DPI Bypass Efficacy:** Real-world firewall evasion and Deep Packet Inspection (DPI) bypass capabilities are highly volatile, geographically non-deterministic, and represent a cat-and-mouse transport metric rather than a client binary security flaw.
*   **Corporate Ownership & Administrative Entity Vetting:** Investigating offshore shell companies, tax filings, or beneficial ownership is an administrative policy function handled downstream via storefront Developer Organization Verification (Gate A), not client binary testing.
*   **Remote Server Infrastructure Hardening:** MASA is strictly a client-side binary evaluation. Remote VPN gateway server hardening, data center physical security, and cloud backend infrastructure scans are explicitly excluded.

---
# Table of Contents
To Be Updated

## 1. Mandatory VPN Extension Requirements (Specialized Controls)

### 1.1 Verified Only Acceptable Protocols Are Used
* **Requirement Identifier:** `PC104-VPN` *(Integration: MASA 1.6.3.1 & 1.7.2.1)*
* **Summary:** To eliminate insecure, outdated, or unencrypted proxy protocols that expose user traffic to interception or unauthenticated tunneling.
* **Proposed Control:** The application must exclusively employ modern, secure, and authenticated VPN protocols (such as WireGuard, OpenVPN, or IKEv2/IPsec). The application must not contain compiled code paths, linked native libraries, or configuration declarations for legacy or insecure protocols—including SOCKS, Shadowsocks, PPTP, or L2TP—even if those features are disabled within the user interface.

---

### 1.2 Complete Traffic Encapsulation & Leak Prevention
* **Requirement Identifier:** `SI114-VPN` *(Integration: MASA 1.4.1.1)*
* **Summary:** To ensure that all outbound user data and system DNS queries are safely encapsulated within the encrypted tunnel, preventing physical adapter leaks across IPv4 and IPv6 dual-stack networks.
* **Proposed Control:** The application must, by default (**Non-Bypassable / Full Tunnel Mode**), securely route 100% of outbound IPv4 and IPv6 traffic, as well as 100% of local DNS queries (Port 53/853), inside the encrypted virtual network tunnel without exception. If the application provides user-configurable **Bypassable Mode (Split Tunneling / App Bypass)**, the client must strictly restrict unencapsulated physical adapter routing exclusively to explicitly designated applications, subnets, or domains, ensuring that all non-bypassed traffic and default system DNS queries remain 100% encapsulated within the secure tunnel.

---

### 1.3 Connection Resiliency and Fail-Secure Controls
* **Requirement Identifier:** `SI115-VPN` *(Integration: MASA 1.4.1.x)*
* **Summary:** To maintain a tight cryptographic boundary during unexpected server-side outages or sudden network drops.
* **Proposed Control:** In the event of an unexpected VPN tunnel disruption or server-side disconnection, the application must immediately execute a fail-secure block (kill-switch) on the virtual interface, halting all outbound device communications until the secure tunnel is re-established.
* **Exclusions & Clarifications:** OS-level Always-On settings and UI Heads-Up Notifications are user-controlled UX options and are strictly excluded from security failure criteria. Sub-second network handover blips during active interface transitions are classified as network robustness metrics, not security failures.

---

### 1.4 OpenVPN Profile Hardening & Control Channel Integrity
* **Requirement Identifier:** `SI116-VPN` *(Integration: MASA 1.4.1.x)*
* **Summary:** To prevent tunnel hijacking, cipher degradation, or control channel injection in OpenVPN-based implementations.
* **Proposed Control:** Bundled OpenVPN configuration profiles (`.ovpn`) or dynamic connection templates must not specify deprecated or vulnerable ciphers (such as Blowfish/`BF-CBC`, 3DES, or RC4) and must explicitly enforce control-channel message authentication via active `tls-auth` or `tls-crypt` HMAC signatures.
---

### 1.5 Telemetry and AdID Segregation
* **Requirement Identifier:** `SI114-VPN-EXT` *(Integration: MASA 1.8.1.x)*
* **Summary:** To prevent mobile VPN applications from serving as predatory tracking vectors by exfiltrating persistent device identifiers.
* **Proposed Control:** The application must not exfiltrate persistent, non-revocable hardware identifiers (such as `Build.SERIAL`, `MAC` address, or `IMEI`) or formatted advertising identifiers (Google Advertising ID / AdID or iOS IDFA) over unencrypted physical channels or inside the tunnel for user tracking, profiling, or third-party marketing exfiltration.
---
