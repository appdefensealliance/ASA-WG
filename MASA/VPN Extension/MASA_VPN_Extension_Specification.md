# MASA VPN Extension Specification

**Document Version:** 1.0  
**Status:** Working Group Review Draft  
**Target Authority:** App Defense Alliance (ADA) Technical Working Group  

---

## 1. Introduction and Architectural Intent

The **MASA VPN Security Extension** defines a specialized Mobile Application Security Assessment (MASA) Level 2 (AL2) evaluation framework for high-privilege mobile virtual private network (VPN) applications on Android and iOS platforms. 

Because VPN applications instantiate virtual network adapters and possess absolute visibility and control over outbound user-plane network traffic, they represent a unique trust boundary on mobile devices. Standard bytecode-level self-assessments (AL1) are insufficient to evaluate their true security posture. This specification establishes a rigorous, binary-level, independent laboratory auditing regime to verify complete traffic encapsulation, DNS leak prevention, cryptographic integrity, and least-privilege compliance.

Additionally, this specialized extension serves as a catalyst to modernize baseline MASA controls globally, ensuring that general mobile security verification remains resilient against native-level compiled binary bypasses.

---

## 2. Scope & Architectural Models

### 2.1 Supported Architectural Models
Mobile VPN applications implement routing through distinct OS platform frameworks. This specification explicitly covers and mandates laboratory auditing for both architectural models:

*   **Model A (Custom Packet Tunnel Provider):** Applications utilizing custom, client-side packet-processing engines (e.g., `VpnService` with custom C/C++ tunneling libraries like WireGuard or OpenVPN on Android; `NETunnelProviderManager` within the NetworkExtension framework on iOS).
*   **Model B (System-Managed / Platform Framework):** Applications utilizing platform-native VPN configurations (e.g., `VpnManager` provisioning native platform IPsec profiles on Android; `NEVPNManager` with `NEVPNProtocolIKEv2` on iOS).

### 2.2 Core Functional Pillars
The specification evaluates client applications across three generalized, outcome-driven pillars:
1.  **On-Device App Hardening:** Verifying client-side compiled binaries are structurally secure against exploitation, free of hardcoded secrets, and strictly bound by least-privilege permission scopes.
2.  **Tunnel Integrity & Leak Prevention:** Actively verifying that the virtual adapter acts as an impenetrable cryptographic barrier, securely encapsulating 100% of user traffic and local DNS requests in default mode, and strictly enforcing boundary isolation when split tunneling is active.
3.  **Version Consistency & Application Creep Prevention:** Governing post-audit code changes through objective, hash-bound delta compliance (governed under ADA-026 policy) to prevent post-audit feature drift.

### 2.3 Explicit Out-of-Scope Boundaries
To preserve deterministic laboratory execution and prevent unconstrained cost inflation, the following domain areas are strictly **OUT OF SCOPE** for client binary certification:
*   **Active Censorship Evasion & DPI Bypass Efficacy:** Real-world firewall evasion and Deep Packet Inspection (DPI) bypass capabilities are highly volatile, geographically non-deterministic, and represent a cat-and-mouse transport metric rather than a client binary security flaw.
*   **Corporate Ownership & Administrative Entity Vetting:** Investigating offshore shell companies, tax filings, or beneficial ownership is an administrative policy function handled downstream via storefront Developer Organization Verification (Gate A), not client binary testing.
*   **Remote Server Infrastructure Hardening:** MASA is strictly a client-side binary evaluation. Remote VPN gateway server hardening, data center physical security, and cloud backend infrastructure scans are explicitly excluded.

---

## 3. Section 3: Mandatory VPN Extension Requirements (Specialized Controls)

### 3.1 Verified Only Acceptable Protocols Are Used
* **Requirement Identifier:** `PC104-VPN` *(Integration: MASA 1.6.3.1 & 1.7.2.1)*
* **Summary:** To eliminate insecure, outdated, or unencrypted proxy protocols that expose user traffic to interception or unauthenticated tunneling.
* **Proposed Control:** The application must exclusively employ modern, secure, and authenticated VPN protocols (such as WireGuard, OpenVPN, or IKEv2/IPsec). The application must not contain compiled code paths, linked native libraries, or configuration declarations for legacy or insecure protocols—including SOCKS, Shadowsocks, PPTP, or L2TP—even if those features are disabled within the user interface.
* **Acceptance Criteria:**
  * **PASS (Model A - Custom Packet Engines):** Decompiled native binaries (`.so` / `.dylib`) are verified to be completely free of symbols, classes, or linked frameworks associated with legacy proxy protocols (SOCKS, Shadowsocks, PPTP, L2TP).
  * **PASS (Model B - Platform VPNs):** Platform configuration profiles explicitly enforce modern authenticated protocols (`NEVPNProtocolIKEv2` or `VpnManager` IPsec) with zero legacy declarations.
  * **FAIL:** Compiled native binaries contain active or dead code paths associated with unapproved proxy protocols, OR the platform configuration permits legacy/insecure protocols (L2TP/PPTP).

---

### 3.2 Complete Traffic Encapsulation & Leak Prevention
* **Requirement Identifier:** `SI114-VPN` *(Integration: MASA 1.4.1.1)*
* **Summary:** To ensure that all outbound user data and system DNS queries are safely encapsulated within the encrypted tunnel, preventing physical adapter leaks across IPv4 and IPv6 dual-stack networks.
* **Proposed Control:** The application must, by default (**Non-Bypassable / Full Tunnel Mode**), securely route 100% of outbound IPv4 and IPv6 traffic, as well as 100% of local DNS queries (Port 53/853), inside the encrypted virtual network tunnel without exception. If the application provides user-configurable **Bypassable Mode (Split Tunneling / App Bypass)**, the client must strictly restrict unencapsulated physical adapter routing exclusively to explicitly designated applications, subnets, or domains, ensuring that all non-bypassed traffic and default system DNS queries remain 100% encapsulated within the secure tunnel.
* **Acceptance Criteria:**
  * **PASS (Full Tunnel Mode):** Default configuration results in 100% traffic encapsulation with **zero plaintext user payloads, TLS SNI handshakes, or unencrypted DNS requests** exiting the physical interface (`wlan0` / `en0`).
  * **PASS (Split Tunnel Mode):** When split tunneling is active, unencapsulated traffic escaping onto `wlan0` / `en0` is strictly restricted to designated bypass rules, with zero accidental leaks from non-bypassed apps or system services.
  * **FAIL:** Plaintext user data, SNI handshakes, or raw DNS queries leak onto physical interfaces (`wlan0` / `en0`) in default mode, OR non-designated applications leak outside the tunnel when split tunneling is active.

---

### 3.3 Connection Resiliency and Fail-Secure Controls
* **Requirement Identifier:** `SI115-VPN` *(Integration: MASA 1.4.1.x)*
* **Summary:** To maintain a tight cryptographic boundary during unexpected server-side outages or sudden network drops.
* **Proposed Control:** In the event of an unexpected VPN tunnel disruption or server-side disconnection, the application must immediately execute a fail-secure block (kill-switch) on the virtual interface, halting all outbound device communications until the secure tunnel is re-established.
* **Exclusions & Clarifications:** OS-level Always-On settings and UI Heads-Up Notifications are user-controlled UX options and are strictly excluded from security failure criteria. Sub-second network handover blips during active interface transitions are classified as network robustness metrics, not security failures.
* **Acceptance Criteria:**
  * **PASS:** Outbound device communication is instantly halted upon unexpected tunnel drop, guaranteeing zero cleartext payload escapes onto physical adapters (`wlan0` / `en0`).
  * **FAIL:** Upon tunnel failure, the client fails to block outbound sockets, allowing the device to transparently resume unencrypted raw internet access over the physical adapter.

---

### 3.4 OpenVPN Profile Hardening & Control Channel Integrity
* **Requirement Identifier:** `SI116-VPN` *(Integration: MASA 1.4.1.x)*
* **Summary:** To prevent tunnel hijacking, cipher degradation, or control channel injection in OpenVPN-based implementations.
* **Proposed Control:** Bundled OpenVPN configuration profiles (`.ovpn`) or dynamic connection templates must not specify deprecated or vulnerable ciphers (such as Blowfish/`BF-CBC`, 3DES, or RC4) and must explicitly enforce control-channel message authentication via active `tls-auth` or `tls-crypt` HMAC signatures.
* **Acceptance Criteria:**
  * **PASS:** Profiles mandate modern AEAD ciphers (AES-256-GCM, AES-128-GCM, or ChaCha20-Poly1305) and include active control-channel HMAC signatures (`tls-auth` or `tls-crypt`).
  * **FAIL:** Bundled profiles specify deprecated ciphers (`BF-CBC`, 3DES), allow cleartext fallback, or lack control-channel HMAC authentication signatures.

---

### 3.5 Telemetry and AdID Segregation
* **Requirement Identifier:** `SI114-VPN-EXT` *(Integration: MASA 1.8.1.x)*
* **Summary:** To prevent mobile VPN applications from serving as predatory tracking vectors by exfiltrating persistent device identifiers.
* **Proposed Control:** The application must not exfiltrate persistent, non-revocable hardware identifiers (such as `Build.SERIAL`, `MAC` address, or `IMEI`) or formatted advertising identifiers (Google Advertising ID / AdID or iOS IDFA) over unencrypted physical channels or inside the tunnel for user tracking, profiling, or third-party marketing exfiltration.
* **Acceptance Criteria:**
  * **PASS:** Captured traffic logs on physical (`wlan0` / `en0`) and virtual (`tunX` / `ipsecX` / `utunX`) adapters show zero exfiltration of persistent hardware IDs or unencrypted AdID/IDFA tracking payloads.
  * **FAIL:** The client exfiltrates persistent hardware serials or unencrypted user tracking identifiers to external collection endpoints.

---

### 3.6 Strong Client Authentication
* **Requirement Identifier:** `PC105-VPN` *(Integration: MASA 1.2.2.x)*
* **Summary:** To prevent global credential compromise arising from hardcoded shared client secrets.
* **Proposed Control:** Client authentication handshakes must utilize dynamic, session-bound credentials (such as OAuth 2.0 with PKCE, ephemeral X.509 client certificates, or short-lived token exchanges). The application must not rely on static, globally shared pre-shared keys (PSKs) embedded within the application binary.
* **Acceptance Criteria:**
  * **PASS:** Authentication mechanisms generate dynamic, unique per-session credentials.
  * **FAIL:** The application relies on a static, globally shared pre-shared key or hardcoded master password compiled into the release APK/IPA.

---

### 3.7 Version Consistency & Application Creep Mitigation
* **Requirement Identifier:** `ADA-026-GOV` *(Integration: Certification Scheme Overview)*
* **Summary:** To bind certification strictly to verified binary states, preventing post-audit security regressions.
* **Proposed Control:** Certification is bound strictly to the evaluated application's SHA-256 binary hash. Modifying native C/C++ compiled libraries (`.so` / `.dylib`), adding sensitive permission scopes (`READ_LOGS`, `LOCATION_ALWAYS`), or altering network security configurations invalidates current compliance, requiring an automated Delta Audit under ADA-026 governance.

---
