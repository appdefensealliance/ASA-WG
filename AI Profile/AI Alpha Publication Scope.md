# AI Alpha Publication Scope

<!-- ai-profile-version: AI-profiles-0.1.0-alpha.1 -->
Version 0.1.0-alpha.1 — 2026-11-03

This alpha defines AI security requirements and assessment procedures within the [AI-only publication scope](AI%20Alpha%20Publication%20Scope.md). A document version alone does not grant assessor authorization or authority to issue ADA certificates.

## AI-only package

The AI profiles version **0.1.0-alpha.1** comprise the AI Agent and AI Tool specifications, Test Guides, interface Contract, optional Wire Format, retained Android annex, assessment protocol, applicability/plan records and examples. They do not release a new CASA, MASA or DASA version. A full-repository merge scenario is an integration test, not the publication manifest.

Unreleased CASA 2.x/MASA changes and CASA 3.0 AL1/AL2 documents are outside this AI package. Their presence in an integration tree does not make them an underlying released baseline.

## Exact underlying references

- Mobile Agents: released MASA **2.1.1**.
- Web Agents: released CASA **2.1.1**.
- Desktop Agents: released DASA **2.2.0**.
- These underlying Specification/Guide snapshots are referenced at released-main commit `63be51be0977512225c0bedf69c5dd69b98eab90`.
- The Tool register's independent published CASA floor is **2.1.1 / 48 audit IDs**, pinned at `7ad3cce0cbb8d6ece5a096afe4a669c1604af583`. Its criteria, alternatives and exceptions are not replaced by unreleased 55-ID or CASA 3.0 text.

Every assessment record binds the exact AI/procedure/corpus and underlying releases, product/model versions and security configuration. A moving branch name is insufficient.

## Supported boundaries and limits

The standalone Tool scope is remote HTTP plus local Android under the retained source requirements. Other standalone desktop/iOS/local Tool routes are outside this alpha's scope. That does not waive the desktop/mobile Agent's DASA/MASA and AI runtime/integration duties. Remote HTTP/MCP transport alone does not make commissioned or first-party Tool execution independent.

The requirements and assessment procedures are operative within this alpha's stated scope. A document version, structural validation or lab worksheet alone does not grant assessor authorization or authority to issue ADA certificates. Certification use additionally requires the applicable authorized scheme, qualified assessor, actual admissible evidence and scheme release controls. The worksheets do not independently grant a new lab authorization.

The revocation source in merged #528 uses “short validity TTL” without a numeric ceiling. No arbitrary duration is declared acceptable by this alpha: known revoked/disabled authority stops the next dispatch even inside cached TTL, and a required admission state that cannot be established fails closed. Any certificate claim must establish the applicable scheme's cache-freshness policy; this alpha does not invent one.

## Publication and assessment artifacts

The repository lifecycle in [CONTRIBUTING](../CONTRIBUTING.md) governs WG consensus, release-branch/version/changelog preparation, SC review and publication. The PR process records agreement; these versioned files do not assert that an approval, merge, tag or certificate was already performed. The AI-only publication manifest must preserve the excluded underlying-profile paths.

Use the [assessment worksheet](AI%20Alpha%20Pilot%20Worksheet.md), [assessment plan](AI%20Agent%20Assessment%20Plans.md), [Protocol](AI%20Agent%20Assessment%20Protocol.md) and [machine-readable scope](AI%20Alpha%20Publication%20Scope.json). Synthetic examples are not approved fixtures, product-security results or actual assessor-hours.
