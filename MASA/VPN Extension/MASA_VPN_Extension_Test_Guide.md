# MASA VPN Extension Test Guide

**Document Version:** 1.0  
**Status:** Working Group Review Draft  
**Target Authority:** App Defense Alliance (ADA) Technical Working Group  

---

## 1. Laboratory Environment & Prerequisites Setup

### 1.1 Physical Dual-Stack Test Bed
Testing laboratories must provision a physical, isolated network environment featuring:
*   Native, routable public **IPv4** network access.
*   Native, routable public **IPv6** network access.
*   Physical wireless access points (`wlan0` for Android / `en0` for iOS) connected to an intercepting network tap or mirror port for unencapsulated packet capture.

### 1.2 Hard Testing Dependency
*   The VPN tunnel under test must be actively connected, authenticated, and passing user traffic during all dynamic dynamic capture routines.

### 1.3 Virtual Adapter Interface Discovery Prerequisite
Because Android and iOS instantiate different virtual interface naming conventions depending on the underlying framework, testing laboratories must dynamically enumerate active device interfaces prior to running dynamic packet captures (`adb shell ip addr` on Android / `ifconfig` on iOS):

*   **Custom Packet Engines (Model A - `VpnService` / `NETunnelProviderManager`):** Enumerate and capture on **`tunX`** (e.g., `tun0`, `tun1` on Android) or **`utunX`** (e.g., `utun0`, `utun1` on iOS).
*   **Platform VPN Profiles (Model B - `VpnManager` / `NEVPNManager`):** Android kernel XFRM IPsec tunnels instantiate **`ipsecX`** (e.g., `ipsec0`, `ipsec1`). iOS native IKEv2 tunnels instantiate **`utunX`**. Laboratories must bind captures directly to `ipsecX` or `utunX` rather than assuming `tun0`.

---

## 2. Statement of Evidence Requirements

Prior to testing, developers must submit an evidence package based on their application architecture:

### 2.1 Model A (Custom Packet Engines)
*   **Android:**
    *   **AL1:** Source code / build configuration files (`build.gradle.kts`) showing custom tunnel integration (`VpnService.Builder` assigning wildcard catch-all routes `0.0.0.0/0` and `::/0`), dependency declarations, and native C/C++ source code/libraries.
    *   **AL2:** Release production APK, test credentials, and active server endpoints.
*   **iOS:**
    *   **AL1:** Source code / dependency logs (`Podfile.lock`, `Package.resolved`), Network Extension target configuration (`NEPacketTunnelNetworkSettings`), `NEIPv4Settings`, `NEIPv6Settings` wildcard routes, and custom C/C++ framework wrappers.
    *   **AL2:** Release production IPA, test credentials, and active server endpoints.

### 2.2 Model B (Platform VPN Profiles)
*   **Android:**
    *   **AL1:** Source code showing `PlatformVpnProfile` / `VpnManager` initialization, inclusive routing definitions, and explicit protocol configuration.
    *   **AL2:** Release production APK and active test server credentials.
*   **iOS:**
    *   **AL1:** Source code showing `NEVPNManager` instantiation, `NEVPNProtocolIKEv2` configuration, setting `isDisconnectOnSleep = false`, and inclusive routing definitions.
    *   **AL2:** Release production IPA and active test server credentials.

---

## 3. Step-by-Step Testing Procedures: Specialized VPN Controls

### 3.1 Protocol Restriction Audit (PC104-VPN)

#### AL1 (Build & Source Audit)
1.  **Android:** Audit `build.gradle.kts` and dependency resolution logs to verify that only approved tunnel wrappers (e.g., `wireguard-android`, official OpenVPN 3 libraries) or platform `VpnManager` profiles are imported.
2.  **iOS:** Audit project dependency manifests (`Podfile.lock`, `Package.resolved`) to confirm no unapproved proxy frameworks (Shadowsocks, unencrypted SOCKS, legacy PPTP) are linked.

#### AL2 (Native Symbol & Config Audit)
1.  **Model A (Custom Engines):**
    *   Decompress the release APK/IPA.
    *   Extract all compiled native shared libraries from the `/lib/` directory (Android `.so` files) or `Frameworks/` directory (iOS `.dylib` files).
    *   Execute a static native-symbol pass (using `nm -gU`, `strings`, Ghidra, or `objdump`). Search symbol tables, compiled strings, and exported function calls for unapproved proxy frameworks (SOCKS, Shadowsocks, PPTP, L2TP).
2.  **Model B (Platform VPN Profiles):**
    *   Decompile the application configuration.
    *   Audit `NEVPNManager` (iOS) or `VpnManager` (Android) protocol objects to verify that modern authenticated protocols (`NEVPNProtocolIKEv2`) are explicitly set, and legacy configurations (`NEVPNProtocolL2TP` or PPTP) are strictly absent.

---

### 3.2 Traffic Encapsulation & Leak Prevention (SI114-VPN)

#### AL1 (Routing Configuration Audit)
*   **Android:** Inspect `VpnService.Builder` to confirm catch-all wildcard routes (`addRoute("0.0.0.0", 0)` and `addRoute("::", 0)`) and DNS capture declarations, OR inspect `PlatformVpnProfile` inclusive routing rules.
*   **iOS:** Inspect `NEPacketTunnelNetworkSettings` to confirm `NEIPv4Settings` and `NEIPv6Settings` instantiate catch-all wildcard routes (`0.0.0.0/0` and `::/0`), OR inspect `NEVPNProtocolIKEv2` catch-all declarations.

#### AL2 (Dynamic Dual-Stack Packet Capture)
1.  **Setup:** Connect the test device to the dual-stack lab Wi-Fi network (`wlan0` / `en0`). Authenticate and establish an active VPN tunnel.
2.  **Interface Binding:** Discover active adapters (`adb shell ip addr` or `ifconfig`). Bind simultaneous `tcpdump` captures to physical interface (`wlan0` / `en0`) and virtual interface (`tunX` / `ipsecX` / `utunX`).
3.  **DNS Exception Rule:** Routing DNS queries to a public resolver (e.g., Google `8.8.8.8` or Cloudflare `1.1.1.1`) **inside the encrypted virtual adapter** is fully acceptable and is **NOT** a leak.
4.  **Test Case A: Non-Bypassable Mode (Default Full-Tunnel Verification)**
    *   *Procedure:* Ensure split-tunneling / app bypass is disabled (default state). Initiate diverse dual-stack traffic (HTTP/HTTPS, IPv4/IPv6 web destinations, background app traffic, system DNS queries).
    *   *Verification:* Parse physical capture (`wlan0` / `en0`). Confirm **100% of traffic traverses virtual interface** (`tunX` / `ipsecX` / `utunX`). Verify **zero plaintext user payloads, TLS SNI handshakes, or raw DNS requests** escape onto the physical adapter.
5.  **Test Case B: Bypassable Mode (Split-Tunneling Boundary Verification)**
    *   *Procedure:* If split-tunneling is supported, enable the feature and add App A to the bypass list. Initiate simultaneous traffic from App A (bypassed) and App B (non-bypassed).
    *   *Verification:* Parse physical capture (`wlan0` / `en0`). Confirm that traffic exiting the physical adapter is **strictly confined to App A**. All traffic from App B, background system traffic, and default system DNS queries must remain 100% encapsulated inside the virtual adapter.

---

### 3.3 Connection Resiliency and Fail-Secure Controls (SI115-VPN)

#### AL1 (Source Callback Review)
*   **Android:** Verify registration of `ConnectivityManager.NetworkCallback` or `onLost()` overrides (custom `VpnService`) or profile exception handlers (platform `VpnManager`) to catch interface drops and trigger immediate socket blocking.
*   **iOS:** Verify `NWPathMonitor` status tracking (`.unsatisfied` / disconnected states) or `NEVPNManager` status callbacks to trigger socket teardown on drop.

#### AL2 (Lab-Induced Tunnel Drop Test)
1.  Establish an active VPN tunnel during an active high-volume data stream.
2.  Simulate a sudden server-side drop by blocking the VPN gateway IP address at the physical lab router.
3.  Execute simultaneous `tcpdump` capture on physical interface (`wlan0` / `en0`).
4.  **Verification:** Confirm that 100% of outbound device traffic is instantly halted (fails secure) with zero cleartext payload data leaking onto `wlan0` / `en0`.
5.  **Exclusions:** Do NOT fail applications for lacking Always-On enforcement (user-owned OS setting), lacking Heads-Up notifications (UX preference), or sub-second handover blips (network robustness metric).

---

### 3.4 OpenVPN Profile Hardening & Control Channel Audit (SI116-VPN)

#### AL1 & AL2 Static Profile Analysis
1.  Extract all bundled `.ovpn` configuration profiles, assets, and dynamic config templates from the APK/IPA package.
2.  Parse configuration directives:
    *   Search for deprecated ciphers: `cipher BF-CBC`, `cipher DES`, `cipher RC4`, or `ncp-disable`.
    *   Verify control-channel HMAC signatures: Confirm explicit presence of active `tls-auth <key_file>` or `tls-crypt <key_file>` directives.
3.  **Verification:** Flag any profile specifying deprecated ciphers or omitting control-channel HMAC signatures.

---

### 3.5 Telemetry and AdID Isolation Audit (SI114-VPN-EXT)

#### AL1 & AL2 Dynamic Exfiltration Pass
1.  Execute dynamic traffic capture across physical (`wlan0` / `en0`) and virtual (`tunX` / `ipsecX` / `utunX`) interfaces during app startup, connection establishment, and active routing.
2.  Run regex search scripts against captured packet payloads searching for:
    *   Formatted Google Advertising ID (AdID) UUID strings (`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).
    *   iOS Identifier for Advertisers (IDFA) UUID strings.
    *   Persistent hardware serials (`Build.SERIAL`, `MAC`, `IMEI`).
3.  **Verification:** Confirm zero persistent hardware serials or unencrypted AdID/IDFA tracking payloads are exfiltrated to tracking or marketing collection endpoints.

---

### 3.6 Strong Client Authentication Audit (PC105-VPN)

#### AL1 & AL2 Handshake Analysis
1.  Audit authentication exchange in source code and dynamic capture logs.
2.  Verify authentication relies on dynamic OAuth 2.0 / PKCE tokens, dynamic X.509 client certificate generation, or short-lived token exchanges.
3.  Verify that no static master pre-shared key (PSK) or global client password is hardcoded within compiled binary strings.
