"""Regression checks for the AI Agent's combined platform-profile prerequisite.

These check the proposed documents and migration record, not product conformance.
Run: python3 -m unittest discover -s scripts/tests -p test_agent_platform_extension.py
"""

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
AI = ROOT / "AI Profile"
START = "## Integration with Conventional Security\n"
END = "## Conformance with the Agent–Tool Interface Contract\n"
REQUIRED_CLAUSES = (
    "It is not a standalone product-certification profile",
    "together at Assurance Level 2 (AL2 Lab Assessment)",
    "single combined product certification",
    "released underlying Specification and Test Guide from `main`",
    "not draft underlying-profile requirements from `develop`",
    "every applicable mandatory requirement of both the underlying profile and this AI Agent profile at AL2",
    "A prior underlying-profile certificate, an AL0/AL1 assessment, or an AI-only assessment MUST NOT substitute",
    "No separately issued underlying-profile certificate is required",
    "AI-specific SHOULD provisions, optional features, or scope exclusions MUST NOT relax",
    "original applicability, alternatives, and exceptions",
    "remote inference alone MUST NOT require a separate CASA evaluation or certificate for the LLM provider's backend",
    "not the Agent product's own in-scope components",
    "Underlying-profile selection follows the Agent product's deployment architecture, not the model's hosting location",
)


def integration_block(text):
    return text.split(START, 1)[1].split(END, 1)[0]


def missing_clauses(block):
    return [clause for clause in REQUIRED_CLAUSES if clause not in block]


class AgentPlatformExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = (AI / "AI Agent Specification.md").read_text()
        cls.guide = (AI / "AI Agent Test Guide.md").read_text()
        cls.coverage = json.loads((AI / "AI Agent Migration Coverage.json").read_text())
        cls.block = integration_block(cls.spec)

    def test_shared_certification_requirements_match(self):
        self.assertEqual(self.block, integration_block(self.guide))
        self.assertEqual([], missing_clauses(self.block))

    def test_architecture_mapping_and_multi_component_scope(self):
        for clause in (
            "**Mobile Agents:** MASA + AI Agent profile.",
            "**Desktop Agents, including PC and Mac applications:** DASA + AI Agent profile.",
            "**Web Agents:** CASA + AI Agent profile.",
            "each underlying profile MUST be applied to its corresponding components",
            "MUST NOT select a less demanding profile",
        ):
            self.assertIn(clause, self.block)

    def test_underlying_evidence_methods_are_not_overridden(self):
        clause = (
            "The AI extension's functional-testing default and evidence taxonomy MUST NOT "
            "override the AL2 test procedures or evidence requirements of the released underlying profile."
        )
        self.assertIn(clause, self.spec)
        self.assertIn(clause, self.guide)

    def test_guide_assesses_the_prerequisite_not_an_extra_model_audit(self):
        assessment = self.guide.split("### Combined Certification Prerequisite Assessment\n", 1)[1]
        assessment = assessment.split("Due to the non-deterministic nature", 1)[0]
        for clause in (
            "not an additional numbered AI model/behaviour audit",
            "**Evidence — Document Review:**",
            "same assessed product and configuration",
            "an AL0/AL1 underlying assessment",
            "a prior underlying certificate alone",
            "unresolved mandatory underlying failures",
            "MUST NOT be scored as an optional AI enhancement",
            "does not certify the external model-provider backend",
        ):
            self.assertIn(clause, assessment)

    def test_migration_record_matches_joint_al2_policy(self):
        policy = self.coverage["certification_prerequisite"]
        self.assertEqual("AL2", policy["assurance_level_for_both"])
        self.assertEqual("single combined product certification", policy["certificate"])
        self.assertEqual(
            {"mobile": "MASA", "desktop_PC_or_Mac": "DASA", "web": "CASA"},
            policy["underlying_profiles_by_architecture"],
        )
        self.assertFalse(policy["prior_certificate_alone_sufficient"])
        self.assertFalse(policy["separate_underlying_certificate_required"])
        self.assertFalse(policy["AI_SHOULD_may_waive_underlying_MUST"])
        self.assertTrue(policy["underlying_AL2_evidence_preserved"])
        self.assertEqual(0, policy["numbered_AI_audits_added"])
        self.assertIn("WG consensus pending", policy["status"])

    def test_existing_37_agent_ids_are_preserved(self):
        spec_ids = re.findall(r"<!-- ada:requirement Agent:(\d+\.\d+\.\d+) -->", self.spec)
        guide_ids = re.findall(r"<!-- ada:test Agent:(\d+\.\d+\.\d+) covers=Agent:\1 -->", self.guide)
        coverage_ids = [control["id"] for control in self.coverage["controls"]]
        self.assertEqual(37, len(spec_ids))
        self.assertEqual(37, len(set(spec_ids)))
        self.assertEqual(spec_ids, guide_ids)
        self.assertEqual(spec_ids, coverage_ids)
        self.assertEqual(37, self.coverage["audit_count"])
        self.assertTrue(self.coverage["stable_ID_relaxations_included"])
        self.assertEqual("MUST", self.coverage["owner_decision_amendment"]["required_interface_and_correct_ID_use_strength"])

    def test_remote_model_does_not_waive_model_behaviour(self):
        self.assertIn(
            "The Agent's model-behaviour, supported-model/version evidence, data handling, "
            "authorization, and communication-security requirements remain applicable.",
            self.block,
        )
        for text in (self.spec, self.guide):
            self.assertIn("Agent Developer must re-run the model-level tests", text)

    def test_missing_or_weakened_prerequisite_is_detected(self):
        for clause in REQUIRED_CLAUSES:
            with self.subTest(clause=clause):
                weakened = self.block.replace(clause, "REMOVED_PREREQUISITE", 1)
                self.assertIn(clause, missing_clauses(weakened))


if __name__ == "__main__":
    unittest.main()
