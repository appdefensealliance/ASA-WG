# App Defense Alliance MASA Specification — Assurance Level 1
Version 3.0 - 2026-10-13

> **Version history** is maintained via GitHub Releases and `CHANGELOG.md`.

# Introduction

The Mobile Application Security Assessment (MASA) Assurance Level 1 specification defines the **9 requirements** that an Android or iOS client must meet as part of a CASA AL1 certification. Every requirement is derived from the OWASP Mobile Application Security Verification Standard (MASVS) and is verifiable **statically from the submitted release binary**: a defined pass signal, a defined fail signal and an open evidence format, so that any ADA-approved lab produces the same verdict on the same artifact.

# Applicability

This document applies to every `Mobile` surface declared for a CASA AL1 or AL2 assessment, and — for the requirements marked `Native` — to declared `Native` surfaces. It is incorporated by reference as Domain 8 of the CASA AL1 Specification v3.0; the CASA AL1 assurance-level definitions, scoping guidance, verdicts and certification rules apply unchanged and are not repeated here.

# References

1. OWASP Mobile Application Security Verification Standard (MASVS) 2.x and Mobile Application Security Testing Guide (MASTG)
2. App Defense Alliance MASA requirements (cited per requirement)
3. MITRE CWE
4. OASIS SARIF 2.1.0

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

# Scope and Evidence

**Declared surface.** The developer declares each mobile package (Android application ID, iOS bundle identifier) and submits the release artifact (`.aab`, `.apk` or `.ipa`) that is, or will be, distributed. The lab assesses exactly the submitted artifact. For a declared `Mobile` surface the binary is the application itself: if the developer withholds it, every requirement below is `FAIL`, not `Not_Covered`.

**Evidence.** SARIF 2.1.0 plus the manifest / `Info.plist` extract from the submitted release binary. Developer-supplied scan output and attestations are not accepted.

**Backend.** The HTTP APIs that serve the mobile client are assessed under the `Web_Application` profile of the CASA AL1 Specification, not here.

# Requirements (9)

**Objective:** proportionate coverage of Android and iOS clients at **zero additional developer friction**. Every control is derivable from the submitted release binary by static analysis alone — **no device farm, no instrumented runtime, no separate engagement**.

| **ID** | **Requirement** | **Reference** | **Profile** |
| --- | --- | --- | --- |
| **MOB-01** | Release artifact is properly signed (Android APK Signature Scheme v2+; iOS valid distribution provisioning profile) | MASA 1.7.1.1 / 2.7.1.1; MASVS-RESILIENCE-2 | `Mobile` |
| **MOB-02** | Release build is not debuggable and debug symbols are stripped (`android:debuggable=false`; no `get-task-allow`) | MASA 1.7.2.1, 1.7.3.1 / 2.7.2.1; MASVS-RESILIENCE-3/4 | `Mobile`, `Native` |
| **MOB-03** | Cleartext traffic disabled — `usesCleartextTraffic=false` with a restrictive Network Security Config; iOS ATS without `NSAllowsArbitraryLoads` | MASA 1.4.1.1 / 2.4.1.1; MASVS-NETWORK-1 | `Mobile` |
| **MOB-04** | TLS validation is not weakened — no trust-all `TrustManager`, no permissive `HostnameVerifier`, no blanket ATS exception | MASA 1.4.1.3 / 2.4.1.3; CWE-295 | `Mobile`, `Native` |
| **MOB-05** | `targetSdkVersion` / iOS deployment target is current (within one major platform release) | MASA 1.6.1.1 / 2.6.1.1; MASVS-CODE-1 | `Mobile` |
| **MOB-06** | Exported components are minimised and permission-protected; `PendingIntent`s are immutable; content providers are not world-accessible; and every http/https intent filter is verified (`android:autoVerify="true"` with a resolvable Digital Asset Links file; iOS `applinks:` entitlement with a served `apple-app-site-association`) | MASA 1.5.1.1, 1.5.1.2, 1.5.1.3, 1.5.1.4 / 2.5.1.6; CWE-926, CWE-939 | `Mobile` |
| **MOB-07** | WebViews are hardened — JavaScript enabled only for compile-time-constant allowlisted origins, no `addJavascriptInterface` reachable by untrusted content, file access disabled, mixed content blocked, no arbitrary URL loading | MASA 1.5.2.1, 1.5.2.2, 1.6.3.3 / 2.5.2.1, 2.5.2.2; MASVS-PLATFORM-2 | `Mobile`, `Native` |
| **MOB-08** | No sensitive data in external storage, system logs, or device backups (`allowBackup=false` or explicit exclusion) | MASA 1.1.1.1, 1.1.2.2 / 2.1.2.2; CWE-532 | `Mobile` |
| **MOB-09** | Bundled third-party SDKs and native libraries contain no known Critical/High vulnerabilities | MASA 1.6.2.1 / 2.6.2.1; MASVS-CODE-3 | `Mobile`, `Native` |

# Verdicts

Verdicts (`PASS`, `FAIL`, `PASS_WITH_COMPENSATING_CONTROL`, `NOT_APPLICABLE`, `Not_Covered`), severity scoring and certification preconditions are those of the CASA AL1 Specification v3.0. `NOT_APPLICABLE` applies only where a requirement's precondition is absent in the artifact (for example, no WebView). A Critical or High finding (MOB-09 bundled SDK vulnerabilities) blocks certification of the `Mobile` surface until fixed and re-verified by the lab.
