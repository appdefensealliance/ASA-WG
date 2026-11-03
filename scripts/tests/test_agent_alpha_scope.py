"""AI-only alpha authority/baseline and optional benchmark regressions.

These check candidate documents, not actual Agent security or certificate scope.
"""
import copy
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
AI = ROOT / "AI Profile"
sys.path.insert(0, str(ROOT / "scripts"))
from ai_alpha_scope import BANNER, FILES, MARKER, errors


class AgentAlphaScopeTests(unittest.TestCase):
    def test_uniform_alpha_is_pilot_only_with_exact_baselines(self):
        self.assertEqual([], errors(AI))
        scope = json.loads((AI / "AI Alpha Publication Scope.json").read_text())
        self.assertFalse(scope["certification_authority"])
        self.assertTrue(scope["underlying_profiles_are_references_not_released_by_this_alpha"])
        self.assertEqual(48, scope["tool_CASA_floor"]["audit_ids"])
        self.assertEqual("2.1.1", scope["underlying_versions"]["web_CASA"])
        self.assertIn("CASA 3.0 AL1/AL2 documents", scope["not_in_alpha_publication"])
        for name in FILES:
            if name.endswith(".md"):
                text = (AI / name).read_text()
                self.assertEqual(1, text.count(MARKER))
                self.assertIn(BANNER, text)
            else:
                publication = json.loads((AI / name).read_text())["x_profile_release"]
                self.assertEqual("alpha", publication["document_state"])
                self.assertFalse(publication["certification_authority"])

    def test_versioned_publication_fields_are_canonical_without_authority_escalation(self):
        for name in FILES:
            if not name.endswith('.json'):
                continue
            data = json.loads((AI / name).read_text())
            self.assertNotIn('x_alpha_preview', data)
            self.assertEqual('alpha', data['x_profile_release']['document_state'])
            self.assertFalse(data['x_profile_release']['certification_authority'])
        ledger = json.loads((AI / 'AI Tool Assessment Cases.json').read_text())
        for test in ledger['tests']:
            self.assertIn('gate_class', test)
            self.assertIn('mandatory_outcome', test)
            self.assertIn('advisory_outcome', test)
            self.assertFalse(any(k.startswith('proposed_') for k in test))
            for case in test['cases']:
                self.assertIn('disposition', case)
                self.assertIn('requirement_text', case)
                self.assertFalse(any(k.startswith('proposed_') for k in case))
        self.assertEqual(210, sum(len(t['cases']) for t in ledger['tests']))
        self.assertEqual('0.1.0-alpha.1', json.loads((AI / 'AI Alpha Publication Scope.json').read_text())['version'])

    def test_mlc_benchmarks_remain_strictly_optional(self):
        spec = (AI / "AI Agent Specification.md").read_text()
        guide = (AI / "AI Agent Test Guide.md").read_text()
        for text in (spec, guide):
            self.assertIn("SHOULD and strictly optional", text)
            self.assertIn("no mandatory failure, evidence prerequisite or compulsory", text)
        for cid, benchmark in [("1.1.2", "Jailbreak"), ("1.1.3", "safety")]:
            block = re.search(r"<!-- ada:test Agent:" + re.escape(cid) + r" covers=Agent:" + re.escape(cid) + r" -->(.*?)(?=\n#{1,3} |\Z)", guide, re.S)[1]
            self.assertIn("SHOULD perform [AILuminate " + benchmark, block)
            self.assertIn("optional and thus does not have any mandatory verification conditions", block)
            self.assertNotIn("SHALL perform [AILuminate", block)
            self.assertNotIn("MUST perform [AILuminate", block)
            self.assertNotIn("**Model:** Repeat test", block)
            self.assertIn("Nonperformance requires no benchmark evidence", block)

    def test_special_modes_and_declared_bounds_cannot_be_scope_bypasses(self):
        for name in ("AI Agent Specification.md", "AI Agent Test Guide.md"):
            text = (AI / name).read_text()
            self.assertIn("production-equivalence approval rules", text)
            self.assertIn("does not bypass or alter admission, authorization, consent", text)
            self.assertIn("missing required declared/enforced ceiling is a missing protection", text)
            self.assertNotIn("[PROPOSED DEFAULT — WG to confirm]", text)
        guide = (AI / "AI Agent Test Guide.md").read_text()
        self.assertIn("not demand unavailable provider-internal deletion records", guide)
        self.assertIn("Document Review (conditional provider dependency)", guide)
    def test_known_revocation_within_ttl_cannot_drop_out_of_plan(self):
        import agent_assessment_policy_validate as policy
        matrix = json.loads((AI / "AI Agent Assessment Applicability.json").read_text())
        record = policy.inventory(matrix)["Agent:2.4.2:admission_integrity"][1]
        self.assertIn("within that TTL", record["case"])
        self.assertIn("Known revoked or disabled admission MUST block the next dispatch even within", record["assertion"])
        self.assertIn("Required security audit/consent records", policy.inventory(matrix)["Agent:1.2.1:store_masking"][1]["assertion"])
        for field in ("case", "assertion"):
            broken = copy.deepcopy(matrix)
            policy.inventory(broken)["Agent:2.4.2:admission_integrity"][1][field] = "Deadline-only case, missing known-status check"
            self.assertTrue(any("inside-cached-TTL" in e for e in policy.matrix_errors(broken)))
        for name in ("AI Agent Specification.md", "AI Agent Test Guide.md"):
            text = (AI / name).read_text()
            self.assertIn("Separately declared and authorized security audit/consent records", text)
            self.assertIn("relabeling unrestricted diagnostic records 'audit' creates no exception", text)

    def test_matrix_mirrors_reviewed_store_provider_and_bounds_rules(self):
        matrix = json.loads((AI / "AI Agent Assessment Applicability.json").read_text())
        records = {a["id"] + ":" + v["key"]: v for a in matrix["audits"] for v in a["verifications"]}
        masking = records["Agent:1.2.1:store_masking"]["assertion"]
        self.assertIn("protected user-scoped stores", masking)
        self.assertIn("relabeling a diagnostic/shared store is no exception", masking)
        self.assertIn("Dedicated credential-store protections remain", masking)
        retention = records["Agent:5.1.2:retention_scope"]
        self.assertIn("D-provider", retention["evidence"])
        self.assertIn("not hidden provider deletion logs", retention["assertion"])
        self.assertEqual("Document Review", matrix["evidence_routes"]["D-provider"]["type"])
        self.assertIn("missing protection, not N/A", records["Agent:2.1.3:automatic_bounds"]["assertion"])
        self.assertIn("commissioned/delegated runtime execution", matrix["conditions"]["managed"]["basis"])
        guide = (AI / "AI Agent Test Guide.md").read_text()
        self.assertIn("Known revocation inside a cached-status TTL", guide)
        self.assertIn("recording the timestamp of this second invocation attempt", guide)
        coverage = json.loads((AI / "AI Agent Migration Coverage.json").read_text())
        self.assertEqual("a153c9090c83cde6c556e6f9b1e3fdb081637cf6", coverage["upstream_revocation_followup"]["head"])
        self.assertIn("not a grace period for admission already known to be revoked", guide)


if __name__ == "__main__":
    unittest.main()
