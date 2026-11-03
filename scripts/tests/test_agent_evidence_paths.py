"""Check scoped normative amendments and retained evidence invariants.

The explicit per-control baseline manifest pins the pre-amendment PR #537/#543
text. Only the named owner-aligned amendments may change it; every other
acceptance block and the applicable evidence/authority gates remain protected.
These are document regressions, not product assessment results.
Run: python3 -m unittest discover -s scripts/tests -p 'test_agent_*.py'
"""

import copy
import hashlib
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
AI = ROOT / "AI Profile"
import sys
sys.path.insert(0, str(ROOT / "scripts"))
from agent_policy_alignment import alignment_errors
# The per-control policy manifest pins the pre-amendment baseline and explicitly
# includes the separately recorded pending revocation migration.
CONDITIONAL_CONTROLS = {
    "1.2.1", "1.3.1", "1.3.2", "2.1.1", "2.1.2", "2.1.3", "2.2.2",
    "2.3.2", "3.1.2", "3.3.1", "5.1.2", "5.2.1", "6.1.1",
}


def normalize(text):
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


def sections(text, tag):
    rows = {}
    for block in re.split(r"(?=^#{1,3} )", text, flags=re.M):
        match = re.search(r"<!-- ada:" + tag + r" Agent:(\d+\.\d+\.\d+)", block)
        if match:
            if match[1] in rows:
                raise ValueError("Duplicate Agent control: " + match[1])
            rows[match[1]] = block
    return rows


def digest(rows):
    return hashlib.sha256(
        json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def acceptance(guide):
    return [(cid, normalize(block.split("#### Verification\n", 1)[1]))
            for cid, block in sections(guide, "test").items()]


def evidence_errors(guide, coverage):
    """Detect a dropped artifact route or an inaccurate migration record."""
    errors = []
    rows = sections(guide, "test")
    records = {control["id"]: control for control in coverage["controls"]}
    if set(rows) != set(records) or len(rows) != 37:
        errors.append("Agent audit coverage mismatch")
    for cid, block in rows.items():
        evidence = block.split("#### Evidence\n", 1)[1].split("#### Test Procedure\n", 1)[0]
        types = set(re.findall(r"Evidence type: (Functional Observation|Attestation|Document Review)", evidence))
        if types != set(records.get(cid, {}).get("evidence_types", [])):
            errors.append(cid + ": evidence types differ from migration record")
        if cid in CONDITIONAL_CONTROLS:
            match = re.search(r"\*\*Evidence type: Attestation \(conditional\)\.\*\* Named artifact: ([^\n]+)", evidence)
            if not match or "scoped evidence bundle containing " not in match[1]:
                errors.append(cid + ": conditional artifact route missing")
            elif "only where Functional Observation is insufficient" not in match[1]:
                errors.append(cid + ": conditional collection limit missing")
    amendment = coverage["evidence_sufficiency_amendment"]
    if set(amendment["conditional_artifact_controls"]) != CONDITIONAL_CONTROLS:
        errors.append("Conditional artifact inventory differs from proposal")
    return errors


class AgentEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = (AI / "AI Agent Specification.md").read_text()
        cls.guide = (AI / "AI Agent Test Guide.md").read_text()
        cls.coverage = json.loads((AI / "AI Agent Migration Coverage.json").read_text())
        cls.manifest = json.loads((AI / "AI Agent Policy Alignment.json").read_text())
        cls.contract = (AI / "AI Agent-Tool Interface Contract.md").read_text()
        cls.rows = sections(cls.guide, "test")

    def test_scoped_amendments_keep_other_controls_and_shared_assertions(self):
        self.assertEqual(37, len(self.rows))
        self.assertEqual([], alignment_errors(self.spec, self.guide, self.manifest, self.contract))
        self.assertEqual(list(self.rows), [control["id"] for control in self.coverage["controls"]])
        self.assertEqual("A", self.coverage["baseline_scenario"])
        self.assertEqual("SHOULD", self.coverage["owner_decision_amendment"]["general_supported_ID_strength"])

    def test_migration_verification_and_evidence_types_match(self):
        recorded = [(control["id"], normalize(control["verification"])) for control in self.coverage["controls"]]
        self.assertEqual(acceptance(self.guide), recorded)
        self.assertEqual([], evidence_errors(self.guide, self.coverage))

    def test_dropped_artifact_route_and_stale_record_are_detected(self):
        for cid in CONDITIONAL_CONTROLS:
            with self.subTest(cid=cid):
                block = self.rows[cid]
                weakened = re.sub(r"\*\*Evidence type: Attestation \(conditional\)\.\*\* Named artifact: [^\n]+", "", block)
                mutated = self.guide.replace(block, weakened)
                self.assertIn(cid + ": conditional artifact route missing", evidence_errors(mutated, self.coverage))
        stale = copy.deepcopy(self.coverage)
        control = next(c for c in stale["controls"] if c["id"] == "1.3.2")
        control["evidence_types"].remove("Attestation")
        self.assertIn("1.3.2: evidence types differ from migration record", evidence_errors(self.guide, stale))

    def test_evidence_amendment_cannot_silently_relax_acceptance(self):
        for before, after in [
            ("shall not retain private input outside declared, separately permitted persistence", "may retain private input without separate permission"),
            ("MUST satisfy a selected interface's required identifier or two-phase mechanism", "MAY ignore interface-required identifiers"),
            ("All plugin invocations, including the arguments", "Some plugin invocations, including the arguments"),
        ]:
            with self.subTest(before=before):
                self.assertTrue(before in self.guide, "Missing mutation target: " + before)
                mutated = self.guide.replace(before, after)
                self.assertNotEqual(digest(acceptance(self.guide)), digest(acceptance(mutated)))
                self.assertTrue(alignment_errors(self.spec, mutated, self.manifest, self.contract))

    def test_upstream_choices_match_specification_and_transparency_is_separate(self):
        start, end = "## Agent-Level Compliance\n", "## Multi-Model Compliance Requirements\n"
        self.assertEqual(self.spec.split(start, 1)[1].split(end, 1)[0], self.guide.split(start, 1)[1].split(end, 1)[0])
        upstream = "**Evidence type: Document Review (when upstream evidence is relied upon).**"
        self.assertEqual(14, self.guide.count(upstream))
        for block in self.rows.values():
            if upstream in block:
                for clause in ("including or linking to relevant evaluation results", "published safety/adversarial-robustness evaluation", "model component certificate with its scope/evaluation report", "Agent-owned and combined-control assertions retain their own evidence requirements"):
                    self.assertIn(clause, block)
        self.assertIn("may satisfy that transparency requirement without evaluation results", self.guide)
        self.assertIn("the publicly accessible Model Card", self.rows["5.2.2"])

    def test_missing_evidence_is_unresolved_and_known_breaches_fail(self):
        for clause in (
            "An observed mandatory breach fails that assertion",
            "cannot support a pass or issuance of certification for an applicable mandatory assertion",
            "Lack of access does not make a supported feature non-applicable",
            "Later incomplete collection does not erase a known breach",
            "Advisory assertions retain their existing strength",
        ):
            self.assertIn(clause, self.guide)

    def test_collection_limits_and_provenance_are_preserved(self):
        for clause in (
            "User interface and tool interface only. No source-code or backend access",
            "standing backend access is not required or granted",
            "only the conditional artifacts named in that requirement's Evidence block",
            "it does not authenticate their origin or establish completeness",
            "Do not reconstruct missing product events from fixture receipts or assessor notes",
            "it must not be credited as product masking",
        ):
            self.assertIn(clause, self.guide)

    def test_important_harness_visibility_limits_are_retained(self):
        checks = {
            "1.3.2": "does not establish the product's own ingestion controls",
            "2.2.2": "No signed receipt or optional D1 artifact is required",
            "2.3.2": "fixture receipts alone do not establish product logging",
            "3.1.2": "does not turn the resistance failure into a pass",
            "5.1.2": "Absence from one chat export does not establish absence from other stores",
            "5.2.1": "manual assessor cleanup is not automated retention enforcement",
        }
        for cid, clause in checks.items():
            with self.subTest(cid=cid):
                self.assertIn(clause, self.rows[cid])

    def test_amendment_discloses_scope_and_preserves_other_decisions(self):
        amendment = self.coverage["evidence_sufficiency_amendment"]
        self.assertEqual(14, amendment["upstream_document_review_blocks_aligned"])
        self.assertIn("review pending", amendment["status"])
        for flag in ("acceptance_assertions_changed", "standing_backend_or_source_access_added", "numeric_trial_minimum_added", "private_data_policy_issue_542_implemented"):
            self.assertIs(False, amendment[flag])
        self.assertTrue(self.coverage["stable_ID_relaxations_included"])
        owner = self.coverage["owner_decision_amendment"]
        self.assertIn("WG review pending", owner["status"])
        self.assertEqual("SHOULD", owner["general_supported_ID_strength"])
        self.assertEqual("MUST", owner["safe_outcome_strength"])
        self.assertFalse(owner["tool_certificate_prerequisite"])


    def test_each_changed_control_keeps_its_security_guard(self):
        guards = (
            "fresh per-action user consent",
            "A user request alone does not establish access rights",
            "not a blanket secret-disclosure exception",
            "Task authorization does not by itself authorize",
            "MUST satisfy a selected interface",
            "MUST preserve and correctly reuse",
            "MUST NOT replace or remint",
            "indeterminate outcome without initiating another action",
            "invalidate every stateful session/refresh token",
            "MUST NOT reuse revoked",
            "a request-count limit alone does not establish the bound",
        )
        for guard in guards:
            with self.subTest(guard=guard):
                self.assertIn(guard, self.guide)
                # Mutate both documents so pair equality alone cannot catch it.
                spec = self.spec.replace(guard, "REMOVED_SECURITY_GUARD")
                guide = self.guide.replace(guard, "REMOVED_SECURITY_GUARD")
                self.assertTrue(alignment_errors(spec, guide, self.manifest, self.contract))

    def test_unrelated_control_cannot_be_weakened_in_both_documents(self):
        before = "All plugin invocations, including the arguments"
        self.assertIn(before, self.spec)
        errors = alignment_errors(
            self.spec.replace(before, "Some plugin invocations"),
            self.guide.replace(before, "Some plugin invocations"),
            self.manifest, self.contract,
        )
        self.assertTrue(any("unrelated" in error for error in errors))

    def test_pinned_baseline_and_change_inventory_cannot_be_redefined(self):
        changed = copy.deepcopy(self.manifest)
        changed["baseline_spec_blocks"]["3.3.1"] = "0" * 64
        self.assertIn("Pinned pre-amendment baseline maps changed",
                      alignment_errors(self.spec, self.guide, changed, self.contract))
        changed = copy.deepcopy(self.manifest)
        changed["allowed_audit_changes"].append("3.3.1")
        self.assertIn("Normative change inventory differs from the explicit amendment",
                      alignment_errors(self.spec, self.guide, changed, self.contract))

    def test_canonical_definition_and_unpublished_selectors_are_checked(self):
        altered = self.contract.replace("**Sensitive Action:**", "**Undefined action:**")
        self.assertTrue(alignment_errors(self.spec, self.guide, self.manifest, altered))
        altered = self.guide + "\nOnly if optional Agent relaxations AG-O01/AG-O02 are selected.\n"
        self.assertTrue(any("selector" in error for error in
                            alignment_errors(self.spec, altered, self.manifest, self.contract)))

    def test_protocol_values_and_source_links_match_owner_direction(self):
        policy = self.coverage["assessment_policy"]
        self.assertEqual(10, policy["default_independent_stochastic_executions_per_case"])
        self.assertEqual(8, policy["actual_red_team_person_hours_initial_or_full"])
        self.assertTrue(policy["specific_applicable_procedure_overrides_preserved"])
        self.assertIn("not automatically full manual", policy["quarterly"])
        for text in (self.spec, self.guide):
            self.assertIn("TEN independent target executions", text)
            self.assertIn("one qualified assessor person-day (8 person-hours)", text)
            self.assertIn("AI%20Agent%20Assessment%20Protocol.md", text)
            self.assertNotIn("multiple independent cycles", text)
            self.assertNotIn("(32 person-hours)", text)
        self.assertIn("not exact prose", self.rows["1.1.1"])
        self.assertIn("not an independent pass prerequisite", self.rows["3.1.3"])

    def test_independent_agent_boundary_is_not_a_tool_certificate_gate(self):
        for text in (self.spec, self.guide):
            self.assertIn("A Tool certificate is not a prerequisite for Agent certification", text)
            self.assertIn("Remote Tools MUST be treated as untrusted dependencies", text)
        self.assertIn("not a claim about the independent server's filesystem", self.rows["2.1.2"])
        self.assertIn("absence alone does not prohibit an initially authorized action", self.rows["6.1.3"])
        self.assertIn("pending, declined and canceled approval states", self.rows["2.2.2"])
        self.assertIn("permitted positive controls", self.rows["5.1.2"])


if __name__ == "__main__":
    unittest.main()
