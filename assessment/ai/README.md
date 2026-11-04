# AI assessment assets

Machine-readable companions to the [Agent Test Guide and assessment methodology](../../AI%20Profile/AI%20Agent%20Test%20Guide.md) and [Tool Testing Guide](../../AI%20Profile/AI%20Tool%20Testing%20Guide.md). The Specifications and Test Guides govern requirements, applicability and evidence. These assets encode those duties for validation; they are not additional normative document sets or product-security results.

- [Agent applicability and verification matrix](AI%20Agent%20Assessment%20Applicability.json): 37 audit IDs and their per-assertion conditions, cases, populations and permitted evidence routes.
- [Agent assessment plan/record schema](AI%20Agent%20Assessment%20Plan.schema.json): configuration, fixtures, independent executions, evidence, effort and retained findings.
- [Tool assessment case ledger](AI%20Tool%20Assessment%20Cases.json): source-retained 40 test contexts/210 cases, with distinct mandatory and advisory assertions.
- [Tool minimum security register](AI%20Tool%20Minimum%20Security%20Register.json): the independent published CASA 48-ID floor, supplemental mappings and source traceability.

[Illustrative examples](../../scripts/tests/fixtures/ai/README.md) and [maintainer regression/provenance records](../../scripts/data/ai/README.md) live separately. No declaration, file checksum or successful structural validation establishes actual evidence, lab authorization, WG/SC approval or certificate authority.

From the repository root:

```sh
python3 scripts/agent_assessment_policy_validate.py
python3 scripts/tool_case_render.py
python3 scripts/agent_policy_alignment.py
python3 scripts/ai_document_set.py
python3 scripts/spec_guide_lint.py --strict
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```
