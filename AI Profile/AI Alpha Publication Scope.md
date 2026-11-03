# AI Alpha Publication Scope

<!-- ai-alpha-preview: AI-profiles-0.1.0-alpha.1 -->
**AI profiles 0.1.0-alpha.1 — proposed WG alpha for pilot assessment; not a basis for ADA certificates.**

This candidate's prospective requirements do not authorize certificate issuance. [AI-only publication scope and exact released baseline references](AI%20Alpha%20Publication%20Scope.md) govern the pilot; WG/SC adoption and release preparation remain outstanding.

**AI profiles 0.1.0-alpha.1 — proposed WG alpha for pilot assessment; not a basis for ADA certificates.**

## What the alpha would publish

This proposal packages the **AI Agent and AI Tool** documents, their Contract/optional Wire Format, retained Android annex, assessment protocol, applicability and plan records, and validation examples. It does not publish a new CASA, MASA or DASA release. The full-repository hypothetical merge is an integration/review scenario, not the publication manifest.

In particular, pending CASA 2.x/MASA changes and draft CASA 3.0 AL1/AL2 documents remain outside this AI alpha publication. Their presence in a local merged tree does not make them a released underlying baseline.

## Exact baseline references for the pilot

- Mobile: released **MASA 2.1.1**.
- Web: released **CASA 2.1.1**.
- Desktop: released **DASA 2.2.0**.
- Released-main snapshot: `63be51be0977512225c0bedf69c5dd69b98eab90`; record the corresponding immutable files/version references in the assessment plan.
- The Tool register's independent published CASA floor remains **v2.1.1 / 48 audit IDs**, at document pin `7ad3cce0cbb8d6ece5a096afe4a669c1604af583`. Its acceptance criteria, alternatives and exceptions are not replaced by develop's 55-ID draft or CASA 3.0.

A later production scheme release must approve and record its exact baseline versions. It cannot silently mix a newly released CASA with the old Tool floor or select a less demanding profile. Branch `main` is a source location, not a substitute for an immutable version/reference.

## Tool versus Agent boundaries

The standalone Tool alpha covers **remote HTTP** and **local Android under the retained requirements**. A desktop or iOS standalone local-Tool certification route is deferred, rather than established by a historical commit reference. This does not remove desktop/mobile **Agent** runtime obligations: DASA/MASA and the applicable AI Agent managed-execution, authority, isolation, consent and safe-outcome controls still apply. Remote dependencies remain untrusted and do not require a Tool certificate before the Agent is assessed.

## Authority and release preparation

The requirements describe the proposed future assessment bar; their MUSTs do not authorize issuing ADA certificates against this alpha. Pilot results identify the exact build/configuration/source and remain scoped observations. The plan schema and worked records are provisional lab/developer worksheets, not certificate templates or proof of assessor qualification.

Publication/adoption requires the WG and SC process in [CONTRIBUTING](../CONTRIBUTING.md): review and recorded consensus, with a formal vote where required by that process; a release branch, changelog/version stamps and approved release artifacts. No actual PR merge, tag, alpha publication or certificate issuance is performed by this proposal.

The [pilot lab/developer worksheet](AI%20Alpha%20Pilot%20Worksheet.md) records proposed assessor readiness, actual evidence, optional benchmarks and maintenance/change responsibilities. It is not a certificate template or a new lab-authorization grant.

The [machine-readable publication scope](AI%20Alpha%20Publication%20Scope.json) is checked with the candidate. A complete pilot bundle must pin every relevant document, procedure/corpus revision, model/configuration and original evidence; an old feature-branch provenance record is not a claim that the whole future release was approved.
