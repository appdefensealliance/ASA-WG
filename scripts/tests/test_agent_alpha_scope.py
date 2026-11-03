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
        self.assertIn("draft CASA 3.0 AL1/AL2 documents", scope["not_in_alpha_publication"])
        for name in FILES:
            if name.endswith(".md"):
                text = (AI / name).read_text()
                self.assertEqual(1, text.count(MARKER))
                self.assertIn(BANNER, text)
            else:
                preview = json.loads((AI / name).read_text())["x_alpha_preview"]
                self.assertFalse(preview["certification_authority"])

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


if __name__ == "__main__":
    unittest.main()
