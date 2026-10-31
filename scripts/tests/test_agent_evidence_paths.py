"""Check evidence amendments without changing the existing Agent acceptance bar.

These document regressions do not assess a product. Acceptance snapshots are
from PR #537 at 409b8cb0d39566de8a3e0ef66ade6ea75374e358; changing them requires
an explicit normative amendment, rather than an evidence-only update.
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
GUIDE_ACCEPTANCE_SHA256 = "c2f71772d36c4da97729349b74b721ed00767b12e8de3a420358a3eaeeb6856a"
SPEC_CONTROLS_SHA256 = "223d5f6e25caed89b86c66e3f464748d73388a789c68698d216a563f1a4f0dd7"
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
        cls.rows = sections(cls.guide, "test")

    def test_all_acceptance_assertions_and_specification_controls_preserved(self):
        self.assertEqual(37, len(self.rows))
        self.assertEqual(GUIDE_ACCEPTANCE_SHA256, digest(acceptance(self.guide)))
        spec_rows = [(cid, normalize(block)) for cid, block in sections(self.spec, "requirement").items()]
        self.assertEqual(SPEC_CONTROLS_SHA256, digest(spec_rows))
        self.assertEqual(list(self.rows), [control["id"] for control in self.coverage["controls"]])

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
            ("shall not retain sensitive information provided as input", "may retain sensitive information provided as input"),
            ("shall provide a stable intent or idempotency identifier", "may provide a stable intent or idempotency identifier"),
            ("All plugin invocations, including the arguments", "Some plugin invocations, including the arguments"),
        ]:
            with self.subTest(before=before):
                self.assertTrue(before in self.guide, "Missing mutation target: " + before)
                self.assertNotEqual(GUIDE_ACCEPTANCE_SHA256, digest(acceptance(self.guide.replace(before, after))))

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
        self.assertFalse(self.coverage["stable_ID_relaxations_included"])


if __name__ == "__main__":
    unittest.main()
