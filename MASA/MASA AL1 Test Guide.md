# App Defense Alliance MASA Testing Guide — Assurance Level 1
Version 3.0 - 2026-10-13

> **Version history** is maintained via GitHub Releases and `CHANGELOG.md`.

# How to Use This Guide

This guide defines the evidence, test procedure and verification criteria for the **9 requirements of the MASA AL1 Specification v3.0**. The lab runs every test against the release artifact the developer submits for each declared `Mobile` surface; nothing the developer writes about the application is evidence. Evidence formats, reference-tooling substitution, verdict rules and compensating-control rules are those of the CASA AL1 Testing Guide v3.0 and apply unchanged.

| **Evidence** | **Format** | **Standard** |
| --- | --- | --- |
| Mobile binary analysis | SARIF 2.1.0 + manifest / `Info.plist` extract | OWASP MASTG |
| Bundled SDK inventory and vulnerabilities | CycloneDX 1.5+ or SPDX 2.3+; findings in SARIF 2.1.0 | NTIA minimum elements |

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

# Test Cases

**Lab execution.** Static analysis of the submitted `.aab`, `.apk` or `.ipa` — manifest and `Info.plist` parsing, bytecode and binary scanning, embedded-SDK inventory. Output as SARIF 2.1.0. For a declared `Mobile` surface the binary is the application itself: if the developer withholds it, every requirement is `FAIL`, not `Not_Covered`.

### MOB-01 Release artifact is properly signed (Android APK Signature Scheme v2+; iOS valid distribution provisioning profile)

External Reference: MASA 1.7.1.1 / 2.7.1.1; MASVS-RESILIENCE-2 · Applicable profile: `Mobile`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Verify the signature of the release artifact and print its signing certificates; on iOS, verify the code signature and extract the provisioning profile.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): apksigner, codesign.

**Verification**

* **PASS** — Android reports `Verified using v2 scheme: true` or v3/v4, with v1-only false; iOS carries a valid distribution profile with `get-task-allow` absent.
* **FAIL** — v1-only signing, verification failure, or a development provisioning profile.

---

### MOB-02 Release build is not debuggable and debug symbols are stripped (`android:debuggable=false`; no `get-task-allow`)

External Reference: MASA 1.7.2.1, 1.7.3.1 / 2.7.2.1; MASVS-RESILIENCE-3/4 · Applicable profile: `Mobile`, `Native`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Read the debuggable flag from the manifest, dump the entitlements, and inspect the symbol table of the shipped binary.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): aapt2, MobSF, codesign.

**Verification**

* **PASS** — `android:debuggable` absent or false; no `get-task-allow` entitlement; no debug symbol table or `dSYM` in the shipped artifact.
* **FAIL** — `android:debuggable=true`, `get-task-allow=true`, or unstripped debug symbols.

---

### MOB-03 Cleartext traffic disabled — `usesCleartextTraffic=false` with a restrictive Network Security Config; iOS ATS without `NSAllowsArbitraryLoads`

External Reference: MASA 1.4.1.1 / 2.4.1.1; MASVS-NETWORK-1 · Applicable profile: `Mobile`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Parse the manifest and Network Security Configuration, and the App Transport Security dictionary in the property list.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): MobSF, apktool.

**Verification**

* **PASS** — `usesCleartextTraffic=false` (or absent with `targetSdkVersion` ≥ 28) and no NSC domain with `cleartextTrafficPermitted="true"`; iOS has neither `NSAllowsArbitraryLoads` nor a per-domain `NSExceptionAllowsInsecureHTTPLoads`.
* **FAIL** — Any cleartext permission at application or domain level.

---

### MOB-04 TLS validation is not weakened — no trust-all `TrustManager`, no permissive `HostnameVerifier`, no blanket ATS exception

External Reference: MASA 1.4.1.3 / 2.4.1.3; CWE-295 · Applicable profile: `Mobile`, `Native`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Scan the bytecode for custom trust managers, hostname-verifier overrides and socket-factory customisation, and parse the App Transport Security exceptions.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): MobSF, semgrep.

**Verification**

* **PASS** — No `checkServerTrusted` with an empty body, no `HostnameVerifier` returning constant true, no `NSExceptionMinimumTLSVersion` below `TLSv1.2` and no `NSExceptionRequiresForwardSecrecy=false`.
* **FAIL** — ≥ 1 trust-all or permissive validation construct.

---

### MOB-05 `targetSdkVersion` / iOS deployment target is current (within one major platform release)

External Reference: MASA 1.6.1.1 / 2.6.1.1; MASVS-CODE-1 · Applicable profile: `Mobile`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Read the target SDK version from the manifest and the minimum OS version from the property list.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): aapt2, MobSF.

**Verification**

* **PASS** — `targetSdkVersion` meets the current platform store requirement and is within one major release of the latest published API level; iOS deployment target within one major release.
* **FAIL** — Below either threshold.

---

### MOB-06 Exported components are minimised and permission-protected; `PendingIntent`s are immutable; content providers are not world-accessible; and every http/https intent filter is verified (`android:autoVerify="true"` with a resolvable Digital Asset Links file; iOS `applinks:` entitlement with a served `apple-app-site-association`)

External Reference: MASA 1.5.1.1, 1.5.1.2, 1.5.1.3, 1.5.1.4 / 2.5.1.6; CWE-926, CWE-939 · Applicable profile: `Mobile`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Parse every component and intent filter in the manifest, scan the bytecode for PendingIntent flags, and fetch the digital asset links and Apple app-site-association files for every declared link host.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): MobSF, apktool.

**Verification**

* **PASS** — Every exported component is either required for launch or protected by a `signature`-or-stronger permission; every `PendingIntent` carries `FLAG_IMMUTABLE`; no provider is exported without a permission; every http/https intent filter declares `autoVerify="true"` and its asset-links file returns 200 listing the package and signing-certificate digest; every iOS `applinks:` host serves a valid AASA.
* **FAIL** — Any unprotected exported component, any mutable `PendingIntent`, any world-accessible provider, or any link filter without `autoVerify` or with an unresolvable asset-links or AASA file.

---

### MOB-07 WebViews are hardened — JavaScript enabled only for compile-time-constant allowlisted origins, no `addJavascriptInterface` reachable by untrusted content, file access disabled, mixed content blocked, no arbitrary URL loading

External Reference: MASA 1.5.2.1, 1.5.2.2, 1.6.3.3 / 2.5.2.1, 2.5.2.2; MASVS-PLATFORM-2 · Applicable profile: `Mobile`, `Native`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Scan the bytecode for every WebView construction site and the configuration calls applied to it.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): MobSF, semgrep.

**Verification**

* **PASS** — For every web view: `setJavaScriptEnabled(true)` occurs only where every URL loaded into that view is a compile-time constant on an allowlisted origin; no `addJavascriptInterface` on a view reachable by non-allowlisted content; `setAllowFileAccess`, `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs` all false; `setMixedContentMode(MIXED_CONTENT_NEVER_ALLOW)`; no `loadUrl`/`load` with an externally-derived URL; iOS equivalents hold.
* **FAIL** — Any web view failing any clause of the pass signal.

---

### MOB-08 No sensitive data in external storage, system logs, or device backups (`allowBackup=false` or explicit exclusion)

External Reference: MASA 1.1.1.1, 1.1.2.2 / 2.1.2.2; CWE-532 · Applicable profile: `Mobile`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Parse the backup settings in the manifest, and run data-flow tracking from sensitive sources to external storage, media store, system log and unprotected container paths.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): MobSF, semgrep.
3. Lab adjudication of tool output: budget 6 minutes per application.

**Verification**

* **PASS** — `allowBackup=false`, or backup rules exclude every credential and token path; and no taint path the assessor confirms to carry sensitive data reaches external storage, a log sink, or an unprotected container path.
* **FAIL** — ≥ 1 confirmed sensitive write to external storage, a log sink, or a backup-included path.

---

### MOB-09 Bundled third-party SDKs and native libraries contain no known Critical/High vulnerabilities

External Reference: MASA 1.6.2.1 / 2.6.2.1; MASVS-CODE-3 · Applicable profile: `Mobile`, `Native`

**Evidence**

1. SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Inventory the embedded SDKs and native libraries in the unpacked bundle and match them against the vulnerability databases using the Specification's Critical/High, reachability and KEV thresholds.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): syft, osv-scanner.

**Verification**

* **PASS** — No bundled SDK or native library carries an advisory at CVSS ≥ 7.0 or a CISA KEV entry.
* **FAIL** — ≥ 1 bundled component at CVSS ≥ 7.0 or on CISA KEV.

---
