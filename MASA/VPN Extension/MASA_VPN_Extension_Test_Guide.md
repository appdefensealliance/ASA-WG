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
    _AL1_ Source code / build configuration files (`build.gradle.kts`) showing custom tunnel integration (`VpnService.Builder` assigning wildcard catch-all routes `0.0.0.0/0` and `::/0`), dependency declarations, and native C/C++ source code/libraries.
    *   **AL2:** Release production APK, test credentials, and active server endpoints.
*   **iOS:**
    _AL1_ Source code / dependency logs (`Podfile.lock`, `Package.resolved`), Network Extension target configuration (`NEPacketTunnelNetworkSettings`), `NEIPv4Settings`, `NEIPv6Settings` wildcard routes, and custom C/C++ framework wrappers.
    *   **AL2:** Release production IPA, test credentials, and active server endpoints.

### 2.2 Model B (Platform VPN Profiles)
*   **Android:**
    _AL1_ Source code showing `PlatformVpnProfile` / `VpnManager` initialization, inclusive routing definitions, and explicit protocol configuration.
    *   **AL2:** Release production APK and active test server credentials.
*   **iOS:**
    _AL1_ Source code showing `NEVPNManager` instantiation, `NEVPNProtocolIKEv2` configuration, setting `isDisconnectOnSleep = false`, and inclusive routing definitions.
    *   **AL2:** Release production IPA and active test server credentials.

---

## 3. Step-by-Step Testing Procedures: Specialized VPN Controls

### 3.1 Verified Only Acceptable Protocols Are Used (PC104-VPN)

_AL1_ (Build & Source Audit)
1.  **Android:** Audit `build.gradle.kts` and dependency resolution logs to verify that only approved tunnel wrappers (e.g., `wireguard-android`, official OpenVPN 3 libraries) or platform `VpnManager` profiles are imported.
2.  **iOS:** Audit project dependency manifests (`Podfile.lock`, `Package.resolved`) to confirm no unapproved proxy frameworks (Shadowsocks, unencrypted SOCKS, legacy PPTP) are linked.

_AL1_ (Native Symbol & Config Audit)
1.  **Model A (Custom Engines):**
    *   Decompress the release APK/IPA.
    *   Extract all compiled native shared libraries from the `/lib/` directory (Android `.so` files) or `Frameworks/` directory (iOS `.dylib` files).
    *   Execute a static native-symbol pass (using `nm -gU`, `strings`, Ghidra, or `objdump`). Search symbol tables, compiled strings, and exported function calls for unapproved proxy frameworks (SOCKS, Shadowsocks, PPTP, L2TP).
2.  **Model B (Platform VPN Profiles):**
    *   Decompile the application configuration.
    *   Audit `NEVPNManager` (iOS) or `VpnManager` (Android) protocol objects to verify that modern authenticated protocols (`NEVPNProtocolIKEv2`) are explicitly set, and legacy configurations (`NEVPNProtocolL2TP` or PPTP) are strictly absent.
  
#### Testing Guidance
_AL1_
* Android: Audit the application's build files (build.gradle.kts) and dependency resolution logs. Verify that either approved custom tunnel wrappers (e.g., wireguard-android, official OpenVPN 3 libraries) OR platform-level VpnManager profile declarations are declared and imported.
* iOS: Statically review dependency management logs (Podfile.lock, Cartfile.resolved, Package.resolved) to verify that no unapproved proxy frameworks (Shadowsocks, unencrypted SOCKS, legacy PPTP) are linked.
#### AL2
* Android: Decompress the APK. Perform a static native-symbol pass (aligning with MASA 1.6.3.1 / 1.7.2.1). Run command-line utilities (such as nm -gU or strings) against all native compiled shared libraries inside the /lib/ directory (e.g., libopvpnutil.so or libcore.so). Search for protocol allow/deny list symbols, function names, or legacy proxy libraries.
* iOS: 
For Custom Packet Tunnel Extensions (NETunnelProviderManager): Decompress the IPA and extract the Mach-O binary and embedded frameworks in the Frameworks/ folder. Run symbol mapping tools (objdump / Hopper) to search for compiled references to prohibited proxy functions or legacy protocols.
For System-Managed Models (NEVPNManager): Audit the NEVPNManager protocol configuration in source code/Info.plist to verify that modern, authenticated protocols (NEVPNProtocolIKEv2) are configured, and that legacy or insecure configurations (NEVPNProtocolL2TP or deprecated PPTP identifiers) are strictly prohibited.


#### Acceptance Criteria:
**PASS:** Custom Packet Engines (NETunnelProviderManager / VpnService): The compiled native binaries (.so or .dylib files) are strictly free of legacy proxy symbols, classes, or library linkages for SOCKS, Shadowsocks, or legacy PPTP/L2TP.
System-Managed Platform VPNs (NEVPNManager / VpnManager): The platform protocol configuration explicitly enforces modern, authenticated protocols (such as NEVPNProtocolIKEv2) with zero legacy protocol declarations (e.g., NEVPNProtocolL2TP or PPTP).

**FAIL:** The compiled native libraries (such as .so or .dylib files) contain active symbols, classes, or code paths associated with unapproved protocols, even if those options are disabled in the UI, or the platform VPN configuration specifies or permits legacy/insecure platform protocols (such as L2TP or PPTP).


---

### 3.2 Complete Traffic Encapsulation & Leak Prevention (SI114-VPN)

_AL1_ (Routing Configuration Audit)
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

#### Testing Guidance
_AL1_
Android: Inspect the initialization methods. For custom VpnService implementations, confirm catch-all wildcard routes for IPv4/IPv6 and explicit DNS capturing. For platform VpnManager implementations, verify the PlatformVpnProfile specifies default catch-all routes.
iOS: Audit the network configuration block. For custom NETunnelProviderManager targets, verify NEIPv4Settings and NEIPv6Settings use wildcard catch-all scopes. For system-managed NEVPNManager setups, confirm NEVPNProtocolIKEv2 applies inclusive routing across all traffic types.
#### AL2

#### Android & iOS:
Hard Testing Dependency: The VPN tunnel must be actively connected during traffic capture.
Dual-Stack Packet Capture: Establish a physical lab network provisioning native public IPv4 and IPv6 addresses.
Connect the mobile test device, establish an active tunnel, and execute a dynamic packet capture (via tcpdump or Wireshark) on both the physical network interface (wlan0 / en0) and the virtual private adapter (tun0 / utun0).
Generate active traffic by visiting a variety of dual-stack destinations.
Verify: Confirm that zero plaintext payload traffic or unencrypted DNS requests exit the physical adapter (wlan0 / en0).
DNS Resolve Exception: Using a public, secure DNS resolver (such as Google 8.8.8.8 or Cloudflare 1.1.1.1) reached securely through the virtual private tunnel is fully acceptable and is NOT a leak.

#### Test Case Execution:
**Test Case A:** Non-Bypassable Mode (Default Full-Tunnel Verification)
Procedure: With split-tunneling / app bypass disabled, generate active dual-stack traffic by accessing diverse IPv4/IPv6 web destinations and initiating system DNS queries.
**Verification:** Confirm that zero plaintext payload data, TLS SNI handshakes, or raw unencrypted DNS queries exit the physical network interface (wlan0 / en0). 100% of user-plane traffic must traverse tun0 / utun0.
**Test Case B:** Bypassable Mode (Split-Tunneling Boundary Verification)
**Procedure:** If the application provides user-configurable split tunneling, enable the feature and configure a test rule explicitly designating a specific test app (e.g., App A) to bypass the virtual tunnel. Initiate network traffic simultaneously from App A (designated bypass) and App B (non-bypassed).
**Verification:** Confirm that traffic exiting the physical adapter (wlan0 / en0) is strictly confined to App A. All traffic from non-bypassed applications (App B), background system services, and default system DNS queries must remain 100% encapsulated inside the virtual private adapter (tun0 / utun0).

#### Acceptance Criteria:
* **PASS (Full Tunnel):** Default configuration results in zero plaintext payload or unencrypted DNS leaks on wlan0 / en0.
* **PASS (Split Tunnel):** When enabled, traffic escaping onto wlan0 / en0 is strictly confined to user-designated bypass rules, with zero accidental leaks from non-bypassed apps or system services.
* **FAIL:** Plaintext traffic or DNS queries leak onto wlan0 / en0 when the app is in default (non-bypassable) mode, OR undesignated apps/system services leak outside the tunnel when split-tunneling is active.

---

### 3.3 Connection Resiliency and Fail-Secure Controls (SI115-VPN)

_AL1_ (Source Callback Review)
*   **Android:** Verify registration of `ConnectivityManager.NetworkCallback` or `onLost()` overrides (custom `VpnService`) or profile exception handlers (platform `VpnManager`) to catch interface drops and trigger immediate socket blocking.
*   **iOS:** Verify `NWPathMonitor` status tracking (`.unsatisfied` / disconnected states) or `NEVPNManager` status callbacks to trigger socket teardown on drop.

_AL2_ (Lab-Induced Tunnel Drop Test)
1.  Establish an active VPN tunnel during an active high-volume data stream.
2.  Simulate a sudden server-side drop by blocking the VPN gateway IP address at the physical lab router.
3.  Execute simultaneous `tcpdump` capture on physical interface (`wlan0` / `en0`).
4.  **Verification:** Confirm that 100% of outbound device traffic is instantly halted (fails secure) with zero cleartext payload data leaking onto `wlan0` / `en0`.
5.  **Exclusions:** Do NOT fail applications for lacking Always-On enforcement (user-owned OS setting), lacking Heads-Up notifications (UX preference), or sub-second handover blips (network robustness metric).

#### Testing Guidance
_AL1_
* Android: Review the network exception-handling routines. Confirm that the application registers callbacks to capture interface drops and execute immediate traffic-blocking rules.
* iOS: Verify that the application actively listens to path changes and executes an automated socket-blocking or teardown routine when the active path drops.
_AL2_
#### Android & iOS:
* **Fail-Secure (Kill-Switch) Verification:** Connect the test device to the lab Wi-Fi network and establish an active tunnel.
* Initiate a high-volume network transfer, then simulate a sudden server-side drop by blocking the VPN gateway's IP at the physical lab router.
* Run a physical interface packet capture (tcpdump on wlan0 / en0).
* **Verify:** Confirm that 100% of outbound device traffic is instantly halted (fails secure).
* **UX Exclusions:** To prevent test-suite inflation and respect platform-level ownership, the application must NOT fail for lacking Always-On enforcement (as this is an OS/user-owned setting that cannot be programmatically forced) or for lacking a mandatory Heads-Up notification (which is a UX preference, not a security boundary). Additionally, sub-second interface handover leaks are classified as robustness metrics rather than security FAIL criteria.

#### Acceptance Criteria:
**PASS:** The application successfully stops all outbound network communication immediately upon unexpected tunnel disconnection, ensuring zero cleartext data escapes onto the physical network interface.

**FAIL:** When the secure tunnel drops, the client fails to block traffic, allowing the mobile device to transparently resume unencrypted, raw internet access over the physical adapter.

---

### 3.4 OpenVPN Profile Hardening & Control Channel Audit (SI116-VPN)

_AL1_ & _AL2_ Static Profile Analysis
1.  Extract all bundled `.ovpn` configuration profiles, assets, and dynamic config templates from the APK/IPA package.
2.  Parse configuration directives:
    *   Search for deprecated ciphers: `cipher BF-CBC`, `cipher DES`, `cipher RC4`, or `ncp-disable`.
    *   Verify control-channel HMAC signatures: Confirm explicit presence of active `tls-auth <key_file>` or `tls-crypt <key_file>` directives.
3.  **Verification:** Flag any profile specifying deprecated ciphers or omitting control-channel HMAC signatures.

#### Testing Guidance
_AL1_
**Android:** Inspect the platform configuration file to confirm that user-installed credentials are not trusted for connections carrying sensitive data.
**iOS:** Verify using the Info.plist that the NSAppTransportSecurity dictionary does not configure insecure exceptions (like NSExceptionAllowsInsecureHTTPLoads) for primary API hostnames.
_AL2_
**Android & iOS:**
* **Trust-Store Interception Test:** Install an untrusted custom root CA certificate into the test device's user store.
Configure the device to route traffic through an intercepting proxy (such as Burp Suite) and trigger a configuration or server-list sync.
* **Verify:** The application must detect the untrusted certificate, reject the connection, and abort the TLS handshake immediately.
* **Server-Side Exclusions:** To maintain a client-side binary focus, testing laboratories must NOT perform server-side TLS configuration scans (such as running sslyze against the remote API servers) or exit-node ad/script injection checks, as backend infrastructure is out of scope.

#### Acceptance Criteria
**PASS:** The application successfully blocks TLS interception by enforcing strict certificate validation, aborting connections when encountering untrusted or spoofed certificates.

**FAIL:** The application completes connections and accepts invalid, self-signed, or user-installed certificates during core API transactions, enabling silent on-path decryption.

---

### 3.5 Telemetry and AdID Isolation Audit (SI114-VPN-EXT)

_AL1_ & _AL2_ Dynamic Exfiltration Pass
1.  Execute dynamic traffic capture across physical (`wlan0` / `en0`) and virtual (`tunX` / `ipsecX` / `utunX`) interfaces during app startup, connection establishment, and active routing.
2.  Run regex search scripts against captured packet payloads searching for:
    *   Formatted Google Advertising ID (AdID) UUID strings (`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).
    *   iOS Identifier for Advertisers (IDFA) UUID strings.
    *   Persistent hardware serials (`Build.SERIAL`, `MAC`, `IMEI`).
3.  **Verification:** Confirm zero persistent hardware serials or unencrypted AdID/IDFA tracking payloads are exfiltrated to tracking or marketing collection endpoints.

#### Testing Guidance
_AL1_
**Android & iOS:** Statically analyze the integrated third-party libraries and SDK manifests. Verify that any diagnostics or telemetry modules are isolated from standard user-plane routing APIs.
_AL2_
**Android & iOS:**
* Establish an active VPN tunnel on the test device.
* Initiate an active packet capture (PCAP) on the virtual interface (tun0 / utun0) to isolate all outbound packet streams.
* Generate diagnostic traffic and stimulate standard client behaviors.
**Verify:** Programmatically analyze the captured payload logs using regex-matching and string-search tools.
* The app fails if it transmits formatted 36-character AdID/IDFA UUIDs, persistent MAC addresses, serial numbers, or contacts known tracking/marketing endpoints over the tunnel interface.

#### Acceptance Criteria
**PASS:** The application successfully isolates persistent advertising, hardware, and user identifiers, transmitting zero tracking packets over the virtual network adapter.

**FAIL:** The client exfiltrates persistent hardware IDs, advertising IDs, or user PII over the active virtual adapter (tun0 / utun0), enabling cross-correlation and user profiling.

