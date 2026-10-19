# App Defense Alliance CASA 3.0 (AL1) Test Guide
Version 3.0 - 2026-10-16

> **Version history** is maintained via GitHub Releases and `CHANGELOG.md`.

# How to Use This Guide

**Execution.** The lab runs every test. The developer provides: the deployed application (staging or production), authenticated accounts as described in the Specification's scoping guidance, release binaries for declared mobile and native surfaces, and — where a test requires it — source code or a build artifact. Nothing the developer writes about the application is evidence.

**Evidence formats.** All evidence is retained in an evidence bundle in open interchange formats so that results from different tools are comparable and machine-checkable:

| **Evidence** | **Format** | **Standard** |
| --- | --- | --- |
| SAST / DAST / harness findings | SARIF 2.1.0 | OASIS SARIF |
| Dependency inventory | CycloneDX 1.5+ or SPDX 2.3+ | NTIA minimum elements |
| TLS assessment | Machine-readable (JSON) TLS scanner output | — |
| OAuth / HTTP flow capture | Redacted HAR 1.2 | W3C HAR |

**Reference tooling.** Tools named in a test procedure are reference implementations. A lab may substitute any tool whose output is expressible in the required format and that exercises the same pass and fail signals. A satisfied fail signal from a scripted harness is recorded as a SARIF `error` finding.

**Verdicts.** Each test case states its `PASS` and `FAIL` criteria. `NOT_APPLICABLE` applies only where the control's precondition is absent on the declared surfaces; `Not_Covered` where a required source or build artifact was not provided or the control depends on an undeclared surface. Withheld access to a declared surface — including the release binary of a declared `Mobile` surface — is always `FAIL`. Critical and High findings (CVSS v3.1 ≥ 7.0; any CISA KEV entry) block certification until fixed and re-verified by the lab; no remediation deadline is set.

**Compensating controls.** Accepted only where the lab independently verifies the mitigation by active test and records its own evidence; never for a Critical or High finding. Developer-asserted mitigations are not accepted.

# Licensing

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

# Test Cases

## 1. Software Composition & Supply Chain

**Lab execution.** SCA engine plus container scanner run against the SBOM source material, lockfiles and image digests the assessor records for the engagement, with call-graph reachability analysis enabled.

### SCA-01 No dependency contains a reachable Critical/High vulnerability, or any CISA KEV entry

External Reference: ASVS 4.0.3 V14.2.1 (L1); CWE-1395 · Applicable profile: `All`

**Evidence**

1. Assessor-generated SBOM (CycloneDX 1.5+ or SPDX 2.3+) and vulnerability findings in SARIF 2.1.0.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Generate a dependency inventory (SBOM) from the application's lockfiles and container image digests. Match every component against the vulnerability databases (NVD, OSV.dev). For each Critical or High finding, run call-graph reachability analysis to determine whether the vulnerable symbol is reachable from an application entry point. Check every component against the CISA Known Exploited Vulnerabilities catalogue.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): syft, osv-scanner, NVD / OSV.dev / CISA KEV feeds.

**Verification**

* **PASS** — Zero findings whose CVSS v3.1 base ≥ 7.0 **and** whose vulnerable symbol is call-graph reachable, **and** zero components matching a CISA KEV identifier.
* **FAIL** — ≥ 1 reachable finding at CVSS ≥ 7.0, or ≥ 1 KEV-listed component whether reachable or not.

---

### SCA-02 No component is end-of-life, unmaintained, or sourced from an untrusted repository

External Reference: ASVS V14.2.4 (L2); OpenSSF Scorecard `Maintained` · Applicable profile: `All`

**Evidence**

1. Assessor-generated SBOM (CycloneDX 1.5+ or SPDX 2.3+) and vulnerability findings in SARIF 2.1.0.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. For every direct dependency, resolve its source registry from the lockfile, check its maintainer-activity signal, and check the component version against its published end-of-life date.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): OpenSSF Scorecard, endoflife.date.

**Verification**

* **PASS** — Every direct dependency has Scorecard `Maintained` of 5 or more, is not past its published EOL date, and resolves to the canonical public registry or a developer-controlled mirror pinned by digest.
* **FAIL** — Any direct dependency with `Maintained` below 5, past EOL, or resolved from an unpinned third-party registry.

---

### SCA-03 Container base images and OS packages contain no unmitigated Critical/High CVEs

External Reference: CIS Docker Benchmark §4; *ADA-defined* · Applicable profile: `Web_Application`

**Evidence**

1. Assessor-generated SBOM (CycloneDX 1.5+ or SPDX 2.3+) and vulnerability findings in SARIF 2.1.0.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Scan every container image digest declared for the engagement for base-image and operating-system package vulnerabilities, including vulnerabilities for which no fix is yet published.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): trivy, grype.

**Verification**

* **PASS** — Zero OS-package or base-layer findings at HIGH or CRITICAL that the distribution has not marked `will_not_fix` with a documented mitigation.
* **FAIL** — ≥ 1 unmitigated HIGH or CRITICAL finding in the base image or OS package set.

---

### SCA-04 A complete, machine-readable SBOM is published for the assessed build, and it matches an SBOM the assessor generates independently

External Reference: ASVS V14.2.5 (L2); NTIA Minimum Elements; CycloneDX 1.5 · Applicable profile: `All`

**Evidence**

1. Assessor-generated SBOM (CycloneDX 1.5+ or SPDX 2.3+) and vulnerability findings in SARIF 2.1.0.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Generate an SBOM independently from the application's lockfiles and image digests, obtain the SBOM the developer publishes for the same build, and compare the two component lists.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): syft, cyclonedx-cli.

**Verification**

* **PASS** — Published SBOM parses as CycloneDX 1.5+ or SPDX 2.3+, every component carries all NTIA minimum elements, and the set difference (assessor SBOM − published SBOM) is empty.
* **FAIL** — SBOM absent or unparseable, any component missing an NTIA minimum element, or ≥ 1 component present in the assessor-generated SBOM and absent from the published one.

---

### SCA-05 No dependency matches a known-malicious package advisory (typosquat, protestware, compromised maintainer)

External Reference: OpenSSF Malicious Packages; CWE-1357 · Applicable profile: `All`

**Evidence**

1. Assessor-generated SBOM (CycloneDX 1.5+ or SPDX 2.3+) and vulnerability findings in SARIF 2.1.0.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Match every dependency against the OpenSSF malicious-package advisories, and check every package name for close-distance similarity to the most popular package names in its registry.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): osv-scanner, OpenSSF malicious-packages feed.

**Verification**

* **PASS** — Zero components match a `MAL-` advisory, and zero components are within Levenshtein distance 1 of a top-10k package name under a different maintainer.
* **FAIL** — ≥ 1 component matches a `MAL-` advisory or the typosquat predicate.

---

## 2. Static Code Analysis & Secrets

**Lab execution.** Secret detectors (`gitleaks`, `trufflehog`) over the repository, its history and every shipped artifact; `semgrep` and CodeQL rules, many taint-configured from request sources to dangerous sinks, over the source code or over the application code extracted from the container image or server bundle; configuration, IaC and image-layer inspection for secrets held outside a managed store; and, for log hygiene, a scripted replay of the authentication, token-refresh and payment flows with canary values, followed by a scan of the application's log sink, to which the developer provides read access.

### SAST-01 No hardcoded passwords, API keys, tokens or credentials in source, resources or build config

External Reference: CWE-798; ASVS V2.10.4 (L2) · Applicable profile: `All`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run secret detection over the source repository, its build configuration and every shipped artifact, using both pattern-based and entropy-based detectors. Triage each hit as a live credential or a false positive.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): gitleaks, trufflehog.

**Verification**

* **PASS** — Zero findings at SARIF `error` level from either detector across source, resources, build config and shipped artifacts.
* **FAIL** — ≥ 1 `error`-level secret finding, or ≥ 1 `trufflehog` finding with `verified: true`.

---

### SAST-02 No private keys, certificates or trust material committed to the repository or shipped in artifacts

External Reference: CWE-321, CWE-798; *ADA-defined* (ASVS 4.0.3 has no requirement on committed trust material) · Applicable profile: `All`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run private-key detection over the full repository history, and walk every shipped artifact for key-store and certificate files and for PEM private-key blocks.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): gitleaks.

**Verification**

* **PASS** — Zero private-key or keystore files and zero PEM `PRIVATE KEY` blocks in repository history or in any shipped artifact.
* **FAIL** — ≥ 1 such file or block.

---

### SAST-03 No deprecated or broken cipher algorithms (DES, 3DES, RC4, Blowfish, ECB mode)

External Reference: CWE-327; NIST SP 800-131A Rev.2; ASVS V6.2.5 (L2) · Applicable profile: `All`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static cryptography rules over the source code (or the decompiled artifact) to find uses of deprecated or broken cipher algorithms and ECB mode.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep, CodeQL.

**Verification**

* **PASS** — Zero uses of DES, 3DES, RC4 or Blowfish, and zero cipher instantiations with `ECB` mode.
* **FAIL** — ≥ 1 `error`-level finding from the banned-algorithm rule set.

---

### SAST-04 No weak hash functions (MD5, SHA-1) used in any security-relevant context

External Reference: CWE-328; NIST SP 800-131A Rev.2 · Applicable profile: `All`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static weak-hash rules with data-flow (taint) tracking from MD5 and SHA-1 constructors to signature, token, password, integrity-check and key-derivation sinks.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep, CodeQL.

**Verification**

* **PASS** — Zero MD5 or SHA-1 calls reaching a security-relevant sink; non-security uses (cache key, ETag) are reported informational.
* **FAIL** — ≥ 1 `error`-level taint path from a weak hash to a security-relevant sink.

---

### SAST-05 Passwords stored using an approved memory-hard KDF with per-user salt

External Reference: ASVS V2.4.1 (L2); NIST SP 800-63B §5.1.1.2 (Argon2id, scrypt, bcrypt, PBKDF2) · Applicable profile: `Web_Application`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Locate every place where a password is persisted and extract the key-derivation function and its parameters from the surrounding code.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep.

**Verification**

* **PASS** — Every password-persistence sink uses Argon2id, scrypt, bcrypt or PBKDF2-HMAC-SHA256 **and** meets the NIST SP 800-63B floor — Argon2id `m` ≥ 19456 KiB with `t` ≥ 2, scrypt `N` ≥ 32768, bcrypt cost ≥ 10, PBKDF2 ≥ 600000 iterations — **and** passes a per-record CSPRNG salt argument.
* **FAIL** — Any sink using an algorithm outside that set, any cost parameter below the floor, or a salt argument that is a literal constant, empty, or shared across records.

---

### SAST-06 All security-relevant randomness uses a CSPRNG

External Reference: CWE-338; ASVS V6.3.1, V6.3.2 (L2) · Applicable profile: `All`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static rules that find non-cryptographic random sources and time-based seeds, with data-flow tracking to token, key, nonce, salt, IV and password-reset sinks.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep.

**Verification**

* **PASS** — Zero non-CSPRNG sources reach a security-relevant sink; every such sink is fed by `SecureRandom`, `crypto.randomBytes`, `os.urandom` or an equivalent.
* **FAIL** — ≥ 1 `error`-level taint path from a non-CSPRNG source to a security-relevant sink.

---

### SAST-07 Frameworks protect against mass assignment / unsafe auto-binding

External Reference: ASVS V5.1.2 (L1); CWE-915; OWASP API6:2023 · Applicable profile: `Web_Application`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static mass-assignment rules over the model-binding layer. Then, from an authenticated session, inject privileged fields (role, administrator flag, owner identifier, object identifier) into every JSON and form body and re-read the object to see whether the value was bound.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep, ZAP, Burp Suite.

**Verification**

* **PASS** — No binder accepts fields outside an explicit allowlist, **and** no probe-injected privileged field is reflected as changed on re-read.
* **FAIL** — ≥ 1 unrestricted binder at `error` level, or ≥ 1 probe request that mutates a privileged field.

---

### SAST-08 Database access exclusively uses parameterized queries, ORMs or escaped input

External Reference: ASVS V5.3.4 (L1); CWE-89 · Applicable profile: `Web_Application`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static SQL-injection rules across every database access path in the source code or, where only a build artifact is available, over the application code extracted from it.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): CodeQL, semgrep.

**Verification**

* **PASS** — Zero `error`-level findings of query construction by concatenation or interpolation on a tainted value; every query path resolves to a parameterized API or an ORM binding.
* **FAIL** — ≥ 1 `error`-level SQL/NoSQL construction finding on tainted input.

---

### SAST-09 Deserialization of untrusted data is avoided or integrity-protected

External Reference: ASVS V5.5.3 (L1); CWE-502 · Applicable profile: `All`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static deserialization rules over every deserialization call site for native object streams, pickle, YAML, PHP unserialize, .NET formatters and equivalents.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep, CodeQL.

**Verification**

* **PASS** — Zero untrusted-input deserialization sinks without a type allowlist, `ObjectInputFilter`, or a verified integrity check on the serialized blob.
* **FAIL** — ≥ 1 `error`-level untrusted deserialization sink.

---

### SAST-10 No dynamic code execution on untrusted input (`eval`, `Function`, `exec`, reflection)

External Reference: ASVS V5.2.4 (L1); CWE-95 · Applicable profile: `All`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static rules for dynamic code execution, command execution and reflective class loading, with data-flow tracking from request sources.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep.

**Verification**

* **PASS** — Zero dynamic-execution sinks reachable from an untrusted source.
* **FAIL** — ≥ 1 `error`-level taint path into a dynamic-execution sink.

---

### SAST-11 File paths are not constructed from unvalidated user-supplied metadata

External Reference: ASVS V12.3.1 (L1); CWE-22 · Applicable profile: `Web_Application`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static path-traversal rules with data-flow tracking from request parameters, uploaded filenames and archive entries to file-system APIs, over the source code or the application code extracted from the build artifact.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep, CodeQL.

**Verification**

* **PASS** — Every file-system path built from user-supplied metadata is canonicalised and checked against a base-directory allowlist before use.
* **FAIL** — ≥ 1 `error`-level path constructed from unvalidated user-supplied metadata.

---

### SAST-12 Server-side secrets are held in a managed secrets store, not in config files or environment baked into images

External Reference: ASVS V6.4.1 (L2); CWE-522 · Applicable profile: `Web_Application`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run configuration and infrastructure-as-code rules over the repository, dump the environment layers of every container image, and inventory the secrets-manager SDK call sites, to establish where each server-side secret is held.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep, trivy, docker.
3. Lab adjudication of tool output: budget 8 minutes per application.

**Verification**

* **PASS** — Every secret-shaped literal the assessor confirms to be a live secret resolves through a secrets-manager SDK call or an injected runtime mount; none is present in config files, IaC, or image environment layers.
* **FAIL** — ≥ 1 literal the assessor confirms to be a live secret held outside the managed store.

---

### SAST-13 Credentials, payment details and tokens are never written to logs; session tokens appear only in irreversible hashed form

External Reference: ASVS V7.1.1 (L1); CWE-532 · Applicable profile: `Web_Application`

**Evidence**

1. Static-analysis and secret-scan findings in SARIF 2.1.0, with rule identifiers and file locations.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run static log-sink rules with data-flow tracking from credential, token and card-number sources. Then replay the authentication, token-refresh and payment flows with unique canary values and search the application's log sink, to which the developer provides read access, for those values.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): semgrep, scripted replay harness.

**Verification**

* **PASS** — No canary value appears literally in any log record, **and** no taint path from a credential, token or payment source reaches a logging sink without an intervening masking or hashing function.
* **FAIL** — ≥ 1 canary value present literally in the log sink, or ≥ 1 `error`-level unmasked taint path to a logging sink.

---

## 3. Transport Security

**Lab execution.** `testssl.sh` or the Qualys SSL Labs CLI against every host of the declared surfaces, JSON output retained in the evidence bundle.

### TLS-01 TLS enforced on all endpoints; no cleartext fallback; HTTP redirects to HTTPS

External Reference: ASVS V9.1.1 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Machine-readable (JSON) TLS scanner output, for every declared host.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run a TLS assessment against every declared host and probe port 80 to observe whether cleartext is served or redirected.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): testssl.sh, Qualys SSL Labs.

**Verification**

* **PASS** — Every host completes a TLS handshake on 443, and every port-80 request returns 301 or 308 to the same host over `https`.
* **FAIL** — Any endpoint serves application content over cleartext, or any port-80 request returns 200.

---

### TLS-02 Only TLS 1.2 and TLS 1.3 enabled; SSLv3, TLS 1.0 and TLS 1.1 rejected

External Reference: ASVS V9.1.3 (L1); NIST SP 800-52 Rev.2 · Applicable profile: `Web_Application`

**Evidence**

1. Machine-readable (JSON) TLS scanner output, for every declared host.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. From the TLS assessment, read the protocol versions each declared host offers.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): testssl.sh, Qualys SSL Labs.

**Verification**

* **PASS** — `.protocols` reports TLS 1.2 or TLS 1.3 `offered`, and SSLv2, SSLv3, TLS 1.0 and TLS 1.1 all `not offered`.
* **FAIL** — Any of SSLv2, SSLv3, TLS 1.0 or TLS 1.1 reported `offered`.

---

### TLS-03 Only strong cipher suites; NULL, EXPORT, anonymous, RC4 and legacy CBC suites rejected; forward secrecy preferred

External Reference: ASVS V9.1.2 (L1); NIST SP 800-52 Rev.2 · Applicable profile: `Web_Application`

**Evidence**

1. Machine-readable (JSON) TLS scanner output, for every declared host.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. From the TLS assessment, read the cipher suites each declared host offers and whether forward-secrecy suites are preferred.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): testssl.sh, Qualys SSL Labs.

**Verification**

* **PASS** — No NULL, EXPORT, anonymous, RC4, 3DES or CBC-SHA1 suite is offered, and forward secrecy is offered on every TLS 1.2 suite negotiated.
* **FAIL** — ≥ 1 suite from the banned list is offered.

---

### TLS-04 Certificate chain is valid, trusted, unexpired and matches the hostname

External Reference: ASVS V9.2.1 (L2); CA/Browser Forum Baseline Requirements · Applicable profile: `Web_Application`

**Evidence**

1. Machine-readable (JSON) TLS scanner output, for every declared host.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. From the TLS assessment, validate the certificate chain of each declared host against a public root store and check hostname match and expiry.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): testssl.sh, Qualys SSL Labs.

**Verification**

* **PASS** — Chain validates to a public root, `cert_expiration` remaining `> 0` days, and CN/SAN matches every host tested; remaining lifetime under 30 days is reported informational.
* **FAIL** — Any chain validation error, expired certificate, or hostname mismatch.

---

### TLS-05 `Strict-Transport-Security` present with `max-age` ≥ 31536000

External Reference: ASVS V14.4.5 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Machine-readable (JSON) TLS scanner output, for every declared host.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. From the TLS assessment, read the Strict-Transport-Security header and its max-age on each declared host.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): testssl.sh.

**Verification**

* **PASS** — `HSTS_time` ≥ 31536000 on every host.
* **FAIL** — Header absent on any host, or `max-age` below 31536000.

---

### TLS-06 No known TLS implementation vulnerabilities (Heartbleed, ROBOT, insecure renegotiation, CRIME)

External Reference: *ADA-defined*; OWASP WSTG-CRYP-01 · Applicable profile: `Web_Application`

**Evidence**

1. Machine-readable (JSON) TLS scanner output, for every declared host.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run the known-vulnerability checks of the TLS assessment against every declared host.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): testssl.sh.

**Verification**

* **PASS** — Every entry in the vulnerability section reports `OK`, including `heartbleed`, `ROBOT`, `secure_renego`, `secure_client_renego`, `CRIME_TLS` and `ticketbleed`.
* **FAIL** — ≥ 1 vulnerability entry at severity HIGH or CRITICAL.

---

## 4. Server Configuration & Response Headers

**Lab execution.** DAST crawl (e.g. ZAP), unauthenticated and authenticated, with header and body inspection on every response; targeted `curl` probes for debug endpoints, CORS origin reflection and forced error responses; `csp-evaluator` over the policy of every HTML response; a differential crawl that replays authenticated routes without credentials, plus admin-panel wordlists; and `dnsx` and `nuclei` takeover checks over every declared host and its CNAME chain.

### CFG-01 Directory browsing disabled; file and directory enumeration not possible

External Reference: ASVS V4.3.2 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Spider every declared web origin, then request every directory prefix discovered in the crawl and observe whether a listing is returned.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — No response body contains a directory-index signature (`Index of /`, autoindex markup, S3 `ListBucketResult`) and no path returns an enumerable listing.
* **FAIL** — ≥ 1 path returns a directory listing.

---

### CFG-02 Framework and server debug modes disabled in production

External Reference: ASVS V14.3.2 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Request the known debug and diagnostic endpoints of common frameworks on every declared host.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, nuclei.

**Verification**

* **PASS** — No debug console, profiler or actuator endpoint returns 2xx unauthenticated, and no response carries a framework debug marker.
* **FAIL** — ≥ 1 debug endpoint returns 2xx, or ≥ 1 response carries a debug marker.

---

### CFG-03 No detailed version or stack disclosure in headers or response bodies

External Reference: ASVS V14.3.3 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Inspect the response headers and bodies across the crawl for server, framework and version identifiers.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — No header or body discloses a product version token matching `[A-Za-z-]+/[0-9]+\.[0-9]+`.
* **FAIL** — ≥ 1 version token disclosed.

---

### CFG-04 Content-Security-Policy enforced; `script-src` excludes `unsafe-inline` and `unsafe-eval`

External Reference: ASVS V14.4.3 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Fetch the response headers of every HTML route and evaluate the Content-Security-Policy with a policy evaluator.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): csp-evaluator.

**Verification**

* **PASS** — Every HTML response carries a `Content-Security-Policy`, and the effective `script-src` (or `default-src` fallback) contains none of `unsafe-inline`, `unsafe-eval`, `*`, `data:`.
* **FAIL** — CSP absent on any HTML response, or any of those tokens present in the effective `script-src`.

---

### CFG-05 Clickjacking prevented via `frame-ancestors` or `X-Frame-Options`

External Reference: ASVS V14.4.7 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Inspect the response headers across the crawl for frame-ancestors and X-Frame-Options.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — Every HTML response carries `frame-ancestors` restricted to an explicit origin list, or `X-Frame-Options: DENY` or `SAMEORIGIN`.
* **FAIL** — Neither directive present on any HTML response, or `frame-ancestors *`.

---

### CFG-06 `X-Content-Type-Options: nosniff` on all responses

External Reference: ASVS V14.4.4 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Inspect the response headers across the crawl for X-Content-Type-Options.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — `X-Content-Type-Options: nosniff` present on 100% of responses.
* **FAIL** — Present on fewer than 100% of responses.

---

### CFG-07 Anti-caching headers on all authenticated and sensitive responses

External Reference: ASVS V8.2.1 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Inspect the response headers of every authenticated and sensitive response in the crawl for cache-control directives.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — Every authenticated response carries `Cache-Control` including `no-store`.
* **FAIL** — ≥ 1 authenticated response without `no-store`.

---

### CFG-08 CORS uses a strict allow list; no wildcard with credentials; no unvalidated origin reflection

External Reference: ASVS V14.5.3 (L1); CWE-942 · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Send requests to every endpoint with a foreign origin, a null origin and an origin that only shares a suffix with the application's domain, and inspect the CORS response headers.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — No probe origin is reflected in `Access-Control-Allow-Origin`; no response combines `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`; `null` origin is not accepted.
* **FAIL** — Any probe origin reflected, `null` accepted, or wildcard combined with credentials.

---

### CFG-09 4xx/5xx responses return generic messages; no stack traces, internal paths or routing detail

External Reference: ASVS V7.4.1 (L1); CWE-209 · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Send malformed types, oversize bodies and inputs that force server errors across the crawl, and inspect the error responses returned.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — Every 4xx and 5xx body matches the generic error template and contains no stack frame, file-system path, SQL fragment, or internal route name.
* **FAIL** — ≥ 1 error response containing any of those elements.

---

### CFG-10 No administrative interface reachable without authentication

External Reference: CWE-306; *ADA-defined* · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Replay the authenticated route set with credentials removed, and request common administrative paths unauthenticated, on every declared host.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite, SecLists.

**Verification**

* **PASS** — Every route in the authenticated set returns 401, 403 or a redirect to authentication when requested without credentials, **and** no wordlist path returns 2xx whose body similarity to its authenticated response is ≥ 0.90.
* **FAIL** — ≥ 1 route or wordlist path returns 2xx unauthenticated with body similarity ≥ 0.90 to the authenticated response.

---

### CFG-11 No dangling DNS record on any declared host or its CNAME chain permits subdomain takeover

External Reference: ASVS V10.3.3 (L1); CWE-350 · Applicable profile: `Web_Application`

**Evidence**

1. DAST findings in SARIF 2.1.0 and a HAR 1.2 capture of the probed requests and responses.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Resolve every declared host, follow each CNAME chain to its terminal target, and check every host and chain target against known takeover fingerprints.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): dnsx, nuclei.

**Verification**

* **PASS** — Zero CNAME, ALIAS or NS records on a declared host or in its CNAME chain resolve to an unclaimed provider fingerprint.
* **FAIL** — ≥ 1 record on a declared host or in its CNAME chain matches a takeover fingerprint.

---

## 5. Authentication & Session Management

**Lab execution.** A scripted, authenticated test harness: default-credential replay; entropy estimation over 200 sampled session tokens; session-fixation and post-logout replay of session cookies and refresh tokens; proxy-log scans for tokens in URLs and `Referer` headers; `Set-Cookie` inspection across the authenticated crawl; `jwt_tool` and a crafted-token harness for stateless tokens; and a headless-browser dump of client-side storage before and after logout, matched against canary values seeded on the assessor's identity-provider test account.

### AUT-01 No default, shared or vendor-supplied credentials accepted

External Reference: ASVS V2.5.4 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Replay a corpus of default credentials, plus the vendor defaults for every product identified in the version-disclosure check, against every authentication endpoint.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): SecLists, scripted replay harness.

**Verification**

* **PASS** — Zero credential pairs from the corpus authenticate on any login surface.
* **FAIL** — ≥ 1 pair authenticates.

---

### AUT-02 Session tokens possess ≥ 64 bits of entropy

External Reference: ASVS V3.2.2 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Collect 200 session tokens from fresh authentications and compute a min-entropy estimate over them.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Burp Sequencer, SP 800-90B entropy estimator.

**Verification**

* **PASS** — All 200 tokens distinct **and** min-entropy estimate ≥ 64 bits.
* **FAIL** — Any repeated token, or a min-entropy estimate below 64 bits.

---

### AUT-03 A new session token is issued upon authentication (session fixation prevented)

External Reference: ASVS V3.2.1 (L1); CWE-384 · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Capture the session identifier before authentication, authenticate, capture it again, and replay the pre-authentication identifier against an authenticated route.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness.

**Verification**

* **PASS** — Post-authentication session identifier differs from the pre-authentication identifier, **and** the pre-authentication identifier is rejected afterwards.
* **FAIL** — Identifier unchanged across authentication, or the pre-authentication identifier remains valid.

---

### AUT-04 Session tokens and credentials never appear in URLs, query strings or `Referer`

External Reference: ASVS V3.1.1 (L1); CWE-598 · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Scan the proxy log of the authenticated crawl, including outbound Referer headers, for session tokens and credentials.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — No session, access or refresh token value appears in any request URL, query string, fragment or outbound `Referer`.
* **FAIL** — ≥ 1 token value present in any of those locations.

---

### AUT-05 Logout invalidates the session server-side, including refresh tokens

External Reference: ASVS V3.3.1 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Log out, then replay the session cookie and the refresh token against protected routes.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness.

**Verification**

* **PASS** — Both the replayed session cookie and the replayed refresh token return 401 or 403 after logout.
* **FAIL** — Either is accepted after logout.

---

### AUT-06 Session cookies set `Secure`, `HttpOnly` and `SameSite` (`Lax` or `Strict`)

External Reference: ASVS V3.4.1, V3.4.2, V3.4.3 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Inspect every Set-Cookie header observed in the authenticated crawl for the Secure, HttpOnly and SameSite attributes.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — Every session cookie carries `Secure`, `HttpOnly`, and `SameSite=Lax` or `SameSite=Strict`.
* **FAIL** — ≥ 1 session cookie missing any of the three attributes.

---

### AUT-07 Stateless tokens are signed with a strong algorithm; `alg:none`, algorithm confusion and key substitution rejected; non-revocable tokens expire ≤ 24 hours

External Reference: ASVS V3.5.3 (L2); RFC 8725 (JWT BCP); CWE-347 · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Submit crafted tokens to protected routes: unsigned, algorithm-confused, foreign key identifier, injected key URL, and modified payload with the original signature. Read the signing algorithm and lifetime from a genuine token.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): jwt_tool.

**Verification**

* **PASS** — Every crafted token is rejected with 401 or 403, the signing algorithm is in {RS256, RS384, RS512, ES256, ES384, PS256, EdDSA, HS256 with a ≥ 256-bit key}, and for tokens with no server-side revocation check `exp − iat ≤ 86400`.
* **FAIL** — Any crafted token accepted, an algorithm outside the allowlist, or `exp − iat > 86400` on a token that survives the AUT-05 logout replay.

---

### AUT-08 Client-side storage holds no sensitive data or authentication material, and is cleared on logout

External Reference: ASVS V8.2.3 (L1) · Applicable profile: `Web_Application`

**Evidence**

1. Harness and DAST findings in SARIF 2.1.0 and a redacted HAR 1.2 capture of the replayed requests.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. With a headless browser, dump browser storage (localStorage, sessionStorage, IndexedDB and non-HttpOnly cookies) before and after logout, and match the contents against the canary values seeded on the lab's test account and every field value returned by the identity provider during the authorization flow.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Playwright.

**Verification**

* **PASS** — No stored value equals an observed session, access or refresh token, matches a JWT or Luhn-valid PAN pattern, equals a seeded canary value, or equals any identity-provider profile field value observed in the authorization-flow capture; and no authentication-material entry survives logout.
* **FAIL** — ≥ 1 stored value matches any of those, or ≥ 1 authentication-material entry persists after logout.

---

## 6. Authorization & Injection

**Lab execution.** Authenticated DAST — a ZAP or Burp active scan plus a DOM XSS scanner, with an out-of-band script-execution callback; `sqlmap` and a NoSQL operator-injection payload set; a command-injection payload set with out-of-band DNS and HTTP callbacks; traversal and inclusion payload sets; open-redirect payloads and duplicated-parameter probes; and scripted replay of every state-changing request with its anti-CSRF token removed, replaced or taken from another session. The assessor reproduces any cross-site scripting candidate the scanner cannot confirm.

### AZI-01 Strong anti-CSRF mechanism on all state-changing authenticated functionality

External Reference: ASVS V4.2.2 (L1); CWE-352 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Replay every state-changing authenticated request with the anti-CSRF token removed, with it replaced, and with a token taken from a second session.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness, Burp Suite.

**Verification**

* **PASS** — Every such request is rejected with 4xx and no state change is observable on re-read; the session cookie is not `SameSite=None`.
* **FAIL** — ≥ 1 state-changing request succeeds without a valid, session-bound anti-CSRF token.

---

### AZI-02 No Cross-Site Scripting — reflected, stored or DOM-based

External Reference: ASVS V5.3.3 (L1); CWE-79 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run an authenticated active cross-site-scripting scan and a DOM-based scan across the crawl, with an out-of-band callback that confirms script execution.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite, DOM Invader.
3. Lab adjudication of tool output: budget 10 minutes per application.

**Verification**

* **PASS** — Zero findings confirmed by execution callback, **and** every unconfirmed candidate is reproduced by the assessor and recorded as non-exploitable.
* **FAIL** — ≥ 1 callback-confirmed execution, or ≥ 1 unconfirmed candidate the assessor reproduces as exploitable.

---

### AZI-03 No SQL or NoSQL injection

External Reference: ASVS V5.3.4 (L1); CWE-89, CWE-943 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Run an authenticated SQL-injection scan over the crawl, and a NoSQL operator-injection payload set over every parameter.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): sqlmap, ZAP, Burp Suite.

**Verification**

* **PASS** — `sqlmap` reports no injectable parameter and no NoSQL payload alters the result set of a query.
* **FAIL** — ≥ 1 parameter reported injectable, or ≥ 1 NoSQL payload alters results.

---

### AZI-04 No OS command injection

External Reference: ASVS V5.3.8 (L1); CWE-78 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Send a command-injection payload set with out-of-band DNS and HTTP callbacks to every parameter.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite, interactsh.

**Verification**

* **PASS** — No out-of-band callback is received and no response contains command output markers.
* **FAIL** — ≥ 1 callback or command-output marker.

---

### AZI-05 No Local/Remote File Inclusion or path traversal

External Reference: ASVS V5.3.9, V12.3.2, V12.3.3 (L1); CWE-22, CWE-98 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Send a traversal and file-inclusion payload set (encoded, double-encoded, null-byte, absolute and UNC forms) to every parameter that influences a path.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — No response returns content from outside the document root and no remote inclusion marker appears.
* **FAIL** — ≥ 1 response containing out-of-root file content or an inclusion marker.

---

### AZI-06 No open redirect or unvalidated forward; HTTP parameter pollution handled safely

External Reference: ASVS V5.1.5, V5.1.1 (L1); CWE-601 · Applicable profile: `Web_Application`

**Evidence**

1. Authenticated DAST and harness findings in SARIF 2.1.0 and a redacted HAR 1.2 capture.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Send an open-redirect payload set to every parameter that influences a redirect, and duplicated-parameter requests to authorization-relevant endpoints.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): ZAP, Burp Suite.

**Verification**

* **PASS** — No 3xx `Location`, meta-refresh or JavaScript redirect resolves to a host outside the scope-record allowlist, and duplicate parameters do not change an authorization decision.
* **FAIL** — ≥ 1 off-allowlist redirect, or a duplicated parameter changes an authorization outcome.

---

## 7. Application Use of OAuth 2.0 / OpenID Connect

**Lab execution.** OAuth flow capture — the assessor completes the application's identity-provider sign-in through an intercepting proxy — against the staging authorization endpoint; static analysis of client binaries for OAU-02, OAU-05 and OAU-06; API probing for OAU-08 and OAU-09.

### OAU-01 Only the Authorization Code flow is used — Implicit and Resource Owner Password Credentials grants are prohibited

External Reference: RFC 9700 §2.1.2, §2.4 (OAuth 2.0 Security BCP); RFC 6749 · Applicable profile: `All`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Complete the application's identity-provider sign-in through an intercepting proxy and read the grant type from the captured authorization and token requests. Where source code or a build artifact is available, scan it for password-grant token requests.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): mitmproxy, Burp Suite, semgrep.

**Verification**

* **PASS** — Captured authorization request carries `response_type=code`; no token request uses `grant_type=password`.
* **FAIL** — Any other `response_type`, or any ROPC token request.

---

### OAU-02 PKCE with `S256` is enforced on **all** authorization code flows, public and confidential

External Reference: RFC 7636; RFC 9700 §2.1.1; MASA 1.3.1.1 / 2.3.1.1 · Applicable profile: `All`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. From the captured authorization flow, read the PKCE parameters on the authorization and token requests. Where client code is available, scan it for the PKCE parameters.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): mitmproxy, Burp Suite, semgrep.

**Verification**

* **PASS** — Every captured authorization request carries `code_challenge_method=S256` and a `code_challenge` of ≥ 43 characters, and the token exchange carries a matching `code_verifier`.
* **FAIL** — `code_challenge` absent, `code_challenge_method=plain`, or a token exchange without `code_verifier`.

---

### OAU-03 The application registers only exact, non-wildcard redirect URIs, and its own callback endpoint contains no open redirect or forwarding chain. *(Exact-match enforcement is performed by the identity provider; what is assessed here is what the application registers and what its callback does)*

External Reference: RFC 9700 §2.1; CWE-601 · Applicable profile: `All`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. From the captured authorization flow, read the registered redirect URIs. Fuzz the redirect, next, continue, return_to and RelayState parameters of the application's callback endpoint.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): mitmproxy, Burp Suite.

**Verification**

* **PASS** — No observed redirect URI contains a wildcard or uses `http:` other than `http://127.0.0.1` loopback for a native client, and no callback fuzz produces a 3xx `Location`, meta-refresh or script redirect to a host outside the registered set.
* **FAIL** — ≥ 1 wildcard or non-loopback cleartext redirect URI, or ≥ 1 callback redirect to an off-set host.

---

### OAU-04 `state` and OIDC `nonce` are CSPRNG-generated, bound to the user agent session, and validated on return

External Reference: RFC 9700 §4.7; OIDC Core §3.1.2.1; CWE-352 · Applicable profile: `All`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Capture 200 scripted authorization requests, compute a min-entropy estimate over the state values, and replay a callback with a state that belongs to a different session.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): mitmproxy, Burp Suite, SP 800-90B entropy estimator.

**Verification**

* **PASS** — All 200 `state` values distinct with min-entropy ≥ 128 bits; the callback issues no session when `state` is omitted, replayed, modified, or presented from a different user-agent session; where an ID token is requested, `nonce` is echoed and validated.
* **FAIL** — Entropy below 128 bits, any repeat, or any of the four callback manipulations yields an authenticated session.

---

### OAU-05 Native, mobile and desktop clients perform authorization in the **system browser** (Custom Tabs / `ASWebAuthenticationSession`) — never an embedded WebView

External Reference: RFC 8252 §8.12 · Applicable profile: `Mobile`, `Native`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Observe which surface presents the authorization page during the captured flow. Scan the client binary for embedded web views that load the identity provider's authorization endpoint.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): mitmproxy, MobSF, semgrep.

**Verification**

* **PASS** — The authorization URL is presented by Custom Tabs, `ASWebAuthenticationSession` or the system browser, and no embedded web view class loads the authorization endpoint.
* **FAIL** — The authorization endpoint is loaded in an embedded web view.

---

### OAU-06 No client secret is embedded in a public client binary, bundle or extension package

External Reference: RFC 8252 §8.5; CWE-798 · Applicable profile: `Mobile`, `Native`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Extract strings, resources and constant pools from the shipped binary, bundle or extension package and match them against the OAuth client-secret format and client-secret assignments.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): MobSF, apktool, strings.

**Verification**

* **PASS** — No value matching `GOCSPX-[A-Za-z0-9_-]{28,}` and no `client_secret` assignment with a literal value is present in any public-client artifact.
* **FAIL** — ≥ 1 client secret recovered from a public-client artifact.

---

### OAU-07 Access and refresh tokens are held in platform secure storage — Keystore, Keychain, or `HttpOnly Secure` cookie. Never `localStorage`, `SharedPreferences` plaintext, or disk cache

External Reference: MASA 1.1.1.1 / 2.1.1.1; CWE-922; ASVS V6.4.1 (L2) *(server-side token storage only)* · Applicable profile: `All`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Enumerate browser storage on web surfaces and, from the mobile binary, the preference stores, property lists, keychain calls and caches; match the contents exactly against the token values observed in the captured flow.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): Playwright, MobSF.

**Verification**

* **PASS** — No observed access or refresh token value appears in `localStorage`, `sessionStorage`, IndexedDB, `SharedPreferences`, `NSUserDefaults`, a plist or an on-disk cache; web tokens are carried in `HttpOnly; Secure` cookies or held only in memory; mobile token writes resolve to Keystore or Keychain APIs.
* **FAIL** — ≥ 1 token value recovered from an insecure store, or a token-bearing cookie lacking `HttpOnly` or `Secure`.

---

### OAU-08 Access tokens are transmitted only in the `Authorization` header; never in query strings or URL fragments

External Reference: RFC 6750 §2.3; ASVS V3.1.1 (L1) · Applicable profile: `All`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Scan the proxy log of the captured and crawled traffic for every request bearing an identity-provider-issued token and record where in the request the token appears.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): mitmproxy, Burp Suite.

**Verification**

* **PASS** — Every token-bearing request carries the token in an `Authorization: Bearer` header; no token value appears in a URL path, query string, fragment or form body.
* **FAIL** — ≥ 1 token value outside the `Authorization` header.

---

### OAU-09 Where the application's own backend accepts identity-provider ID tokens or access tokens as proof of identity, it validates signature, `iss`, `aud`, `exp` and `scope` against the identity provider's published keys; `alg:none` and algorithm confusion are rejected

External Reference: RFC 9700 §4.9; RFC 8725; CWE-347 · Applicable profile: `Web_Application`

**Evidence**

1. Redacted HAR 1.2 capture of the authorization flow; SARIF 2.1.0 where a client artifact is analysed statically.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Replay crafted tokens against every endpoint observed to accept an identity-provider token: unsigned, foreign signing key, expired, wrong audience, wrong issuer and insufficient scope. Confirm each rejection is a validation failure.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): jwt_tool, scripted harness.
3. Lab adjudication of tool output: budget 6 minutes per application.

**Verification**

* **PASS** — Every endpoint that accepts an identity-provider token rejects all six crafted tokens with 401 or 403 while accepting a valid one, and the assessor confirms each rejection is a validation failure rather than an unrelated error.
* **FAIL** — ≥ 1 crafted token accepted at any endpoint.

---

## 8. Webhook Security

**Lab execution.** Delivery attempts to each declared receiver over cleartext HTTP and legacy TLS, plus `testssl.sh` against the receiver host; a signed-payload harness sending absent, truncated, modified and foreign-key signatures, with a `semgrep` check of the comparison API and MAC algorithm where source code or a build artifact is available; callback-URL registration probes against private, loopback, link-local and cloud-metadata addresses, including redirect chains and DNS rebinding; and the SAST-01 secret detectors over signing-secret material.

### WHK-01 Webhook traffic is delivered exclusively over HTTPS with TLS 1.2+; cleartext endpoints are refused

External Reference: CASA v2.1.1 §7.1.1; Standard Webhooks · Applicable profile: `Web_Application`

**Evidence**

1. Redacted HAR 1.2 capture of delivery attempts, `testssl.sh` JSON for the receiver host, and SARIF 2.1.0 for static checks.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Attempt delivery to each declared receiver over cleartext HTTP and over TLS 1.0 and 1.1, and run a TLS assessment against the receiver host.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): testssl.sh, scripted delivery harness.

**Verification**

* **PASS** — The receiver returns no 2xx for any cleartext delivery and negotiates only TLS 1.2 or 1.3.
* **FAIL** — ≥ 1 cleartext delivery accepted, or a legacy TLS version negotiated.

---

### WHK-02 Payloads are authenticated with HMAC-SHA256 or stronger, verified using a timing-safe comparison

External Reference: CASA v2.1.1 §7.2.1, §7.2.2; CWE-208 · Applicable profile: `Web_Application`

**Evidence**

1. Redacted HAR 1.2 capture of delivery attempts, `testssl.sh` JSON for the receiver host, and SARIF 2.1.0 for static checks.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Deliver payloads with an absent, truncated, modified and foreign-key signature to each receiver. Where source code or a build artifact is available, inspect the signature-verification call site for the comparison function and MAC algorithm.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted delivery harness, semgrep.

**Verification**

* **PASS** — Every payload with an absent, truncated, modified or foreign-key signature is rejected with 4xx and produces no side effect; the MAC is HMAC-SHA256 or stronger; and the comparison uses a constant-time API (`hmac.compare_digest`, `MessageDigest.isEqual`, `crypto.timingSafeEqual`). Without source code or a build artifact the constant-time clause is recorded `Not_Covered`.
* **FAIL** — Any invalid-signature payload accepted, a MAC weaker than HMAC-SHA256, or a MAC compared with `==`, `equals` or `strcmp`.

---

### WHK-03 User-supplied callback URLs are SSRF-protected; signing secrets are not hardcoded or committed to version control

External Reference: CASA v2.1.1 §7.3.1, §7.3.2; CWE-918 · Applicable profile: `Web_Application`

**Evidence**

1. Redacted HAR 1.2 capture of delivery attempts, `testssl.sh` JSON for the receiver host, and SARIF 2.1.0 for static checks.
2. Produced by the ADA-approved lab. Developer-supplied scan output or attestations are not accepted.

**Test Procedure**

1. Through each declared callback-registration facility, attempt to register callback URLs pointing at private, loopback, link-local and cloud-metadata addresses, including via redirect chains and DNS rebinding. Run secret detection over the signing-secret material.
2. Reference tooling (for reference only; any tool producing the evidence format above may be used): scripted harness, interactsh, gitleaks.

**Verification**

* **PASS** — Every callback URL resolving to `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` or `::1` is rejected at registration and after redirect re-resolution; no signing secret appears in source or artifacts.
* **FAIL** — ≥ 1 private or metadata address accepted, or ≥ 1 signing secret found in source or artifacts.

---
