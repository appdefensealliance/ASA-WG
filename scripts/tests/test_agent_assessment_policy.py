"""Synthetic structural regressions for #410/#541; no Agents/humans tested.

The fake observations below exercise record invariants, not the truth of any
security claim, production equivalence, calibration or actual assessor effort.
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts" / "agent_assessment_policy_validate.py"
spec = importlib.util.spec_from_file_location("agent_assessment_policy_validate", MODULE)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
AI = ROOT / "AI Profile"


class AssessmentPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = policy.read_json(AI / "AI Agent Assessment Applicability.json")
        cls.schema = policy.read_json(AI / "AI Agent Assessment Plan.schema.json")
        cls.examples = policy.read_json(AI / "AI Agent Assessment Examples.json")
        cls.plans = {e["id"]: policy.expand_example(cls.matrix, cls.examples, e) for e in cls.examples["examples"]}

    def errors(self, plan):
        return policy.plan_errors(plan, self.matrix, self.schema)

    def record(self, plan, vid, context=None):
        return next(r for r in plan["records"] if r["verification_id"] == vid and (context is None or r["context_id"] == context))

    def observed(self, vid="Agent:3.1.2:untrusted_consequence", route="F"):
        """Build a declared synthetic ten-execution pass to mutate, not evidence."""
        plan = copy.deepcopy(self.plans["mcp-http"])
        plan["status"] = "assessment_record"
        for context in plan["contexts"]:
            context["configuration_status"] = "verified"  # synthetic declaration for structural tests only
        plan["fixtures"][0]["approval"]["status"] = "approved"
        plan["fixtures"][0]["approval"]["assessor"] = "synthetic-regression-assessor"
        r = self.record(plan, vid)
        r["result"] = "satisfied"
        r["evidence_routes"] = [route]
        context = next(c for c in plan["contexts"] if c["id"] == r["context_id"])
        original = {"reference": "synthetic-test://original-product-observation", "route": route,
                    "producer": "synthetic product observation/export", "export_time": "2026-11-03T20:00:00Z",
                    "covered_interval": "synthetic ten execution interval", "configuration": context["security_configuration"],
                    "filtering_redaction": "none; synthetic markers only", "visibility_limits": "only specified synthetic assertion",
                    "correlation": ["synthetic-case-markers"], "controls": ["synthetic-benign-exposure-control"], "supports_assertion": True}
        r["original_artifacts"] = [original]
        r["executions"] = [{"id": "target-" + str(i), "reset_context": "independent-reset-" + str(i), "independent": True,
                            "model_version": context["model_version"], "security_configuration": context["security_configuration"],
                            "exposed": True, "outcome": "satisfied", "original_references": [original["reference"]]} for i in range(10)]
        return plan, r

    def assertError(self, errors, fragment):
        self.assertTrue(any(fragment in error for error in errors), (fragment, errors))

    def test_all_37_audits_match_source_stable_tags(self):
        self.assertEqual(37, len(self.matrix["audits"]))
        self.assertEqual([], policy.matrix_errors(self.matrix, (AI / "AI Agent Test Guide.md").read_text(), (AI / "AI Agent Specification.md").read_text()))

    def test_every_worked_plan_expands_complete_per_context_inventory(self):
        self.assertEqual({"mcp-http", "mcp-stdio", "appfunctions", "desktop-local", "fixed-rest", "multimodal", "hybrid"}, set(self.plans))
        for name, plan in self.plans.items():
            with self.subTest(name=name):
                self.assertEqual([], self.errors(plan))
                self.assertEqual(len(policy.EXPECTED_VERIFICATIONS) * len(plan["contexts"]), len(plan["records"]))
                for context in plan["contexts"]:
                    self.assertEqual(policy.EXPECTED_VERIFICATIONS, {r["verification_id"] for r in plan["records"] if r["context_id"] == context["id"]})

    def test_duplicate_missing_and_wrong_actor_inventory_rejected(self):
        for mutation in ("duplicate", "missing", "actor", "verification"):
            m = copy.deepcopy(self.matrix)
            if mutation == "duplicate": m["audits"].append(m["audits"][0])
            if mutation == "missing": m["audits"].pop()
            if mutation == "actor": m["audits"][0]["id"] = "Tool:1.1.1"
            if mutation == "verification": m["audits"][0]["verifications"].pop()
            self.assertTrue(policy.matrix_errors(m), mutation)

    def test_optional_benchmarks_and_mixed_strength_not_promoted(self):
        p = self.plans["mcp-http"]
        for vid in ("Agent:1.1.2:jailbreak_benchmark", "Agent:1.1.3:safety_benchmark"):
            r = self.record(p, vid)
            self.assertEqual("OPTIONAL", r["strength"])
            self.assertEqual("advisory_not_performed", r["result"])
        self.assertEqual("SHOULD", self.record(p, "Agent:5.2.1:minimization")["strength"])
        self.assertEqual("SHOULD", self.record(p, "Agent:6.1.3:supported_id_use")["strength"])
        self.assertEqual("MUST", self.record(p, "Agent:6.1.3:required_id_preservation")["strength"])

    def test_unsupported_elicitation_still_exercised_when_feature_absent(self):
        p = self.plans["mcp-http"]
        self.assertEqual("applicable", self.record(p, "Agent:2.2.3:unsupported_request")["applicability"])
        self.assertEqual("justified_non_applicability", self.record(p, "Agent:2.2.3:presentation_actions")["applicability"])
        p = self.plans["appfunctions"]
        self.assertEqual("justified_non_applicability", self.record(p, "Agent:2.2.3:unsupported_request")["applicability"])
        self.assertEqual("applicable", self.record(p, "Agent:2.2.2:independent_gate")["applicability"])

    def test_local_excludes_remote_example_not_independent_controls(self):
        for name in ("mcp-stdio", "appfunctions", "desktop-local"):
            p = self.plans[name]
            self.assertEqual("justified_non_applicability", self.record(p, "Agent:6.1.1:transport_auth")["applicability"])
            self.assertEqual("justified_non_applicability", self.record(p, "Agent:6.1.5:s256_exchange")["applicability"])
            for vid in ("Agent:6.1.3:lifecycle", "Agent:6.1.3:unknown_outcome", "Agent:2.3.2:complete_audit"):
                self.assertEqual("applicable", self.record(p, vid)["applicability"])

    def test_missing_required_protection_or_evidence_cannot_be_na(self):
        p = copy.deepcopy(self.plans["mcp-http"])
        r = self.record(p, "Agent:2.3.2:complete_audit")
        r["applicability"] = r["result"] = "justified_non_applicability"
        r["basis"] = "Developer says no logging exists"
        self.assertError(self.errors(p), "applicability contradicts")
        p = copy.deepcopy(self.plans["mcp-http"])
        p["contexts"][0]["features"]["logging_protection"] = False
        self.assertError(self.errors(p), "protection flags prohibited")

    def test_ten_independent_target_executions_not_ten_judges(self):
        p, r = self.observed()
        self.assertEqual([], self.errors(p))
        r["executions"][1]["reset_context"] = r["executions"][0]["reset_context"]
        self.assertError(self.errors(p), "not independent executions")
        r["executions"][1]["id"] = r["executions"][0]["id"]
        self.assertError(self.errors(p), "rejudging is not repetition")

    def test_missing_repetition_and_deterministic_judge_cannot_pass(self):
        p, r = self.observed()
        r["executions"].pop()
        self.assertError(self.errors(p), "insufficient independent target population")
        r["population"]["target_kind"] = "deterministic"
        self.assertError(self.errors(p), "deterministic judge does not change stochastic target")

    def test_explicit_approved_population_exception_and_no_automatic_escalation(self):
        p, r = self.observed()
        r["population"]["count"] = 3
        r["executions"] = r["executions"][:3]
        self.assertError(self.errors(p), "default TEN")
        r["population"]["exception"] = {"explicit_population": 3, "source_revision": "synthetic-approved-procedure-v1-explicit-three", "approval": "synthetic-lab-approval", "rationale": "Specific applicable approved population, not high-impact escalation"}
        self.assertEqual([], self.errors(p))
        r["population"]["exception"]["explicit_population"] = 5
        self.assertError(self.errors(p), "explicit approved population differs")

    def test_one_mandatory_breach_cannot_be_averaged_or_hidden(self):
        p, r = self.observed()
        r["executions"][0]["outcome"] = "observed_breach"
        self.assertError(self.errors(p), "known mandatory breach")
        r["result"] = "insufficient_evidence"
        self.assertError(self.errors(p), "known mandatory breach")
        r["result"] = "observed_breach"
        self.assertEqual([], self.errors(p))

    def test_prior_pilot_breach_retained_until_new_configuration(self):
        p, r = self.observed()
        c = p["contexts"][0]
        p["prior_findings"] = [{"verification_id":r["verification_id"], "configuration":c["security_configuration"], "result":"observed_breach", "original_reference":"synthetic-test://retained-adverse-pilot-original"}]
        self.assertError(self.errors(p), "known mandatory breach")
        p["prior_findings"][0]["configuration"] = "retained-old-remediated-configuration"
        self.assertEqual([], self.errors(p))

    def test_unexposed_and_ambiguous_are_not_passes(self):
        p, r = self.observed()
        r["executions"][2]["exposed"] = False
        self.assertError(self.errors(p), "unexposed/ambiguous")
        r["executions"][2]["exposed"] = True
        r["executions"][2]["outcome"] = "insufficient_evidence"
        self.assertError(self.errors(p), "unexposed/ambiguous")
        r["result"] = "insufficient_evidence"
        self.assertEqual([], self.errors(p))

    def test_original_audit_cannot_be_replaced_by_fixture_receipt(self):
        p, r = self.observed("Agent:2.3.2:complete_audit", "A-capability")
        self.assertEqual([], self.errors(p))
        r["original_artifacts"][0]["producer"] = "test fixture receipt"
        self.assertError(self.errors(p), "fixture receipt is not original product")
        r["original_artifacts"] = []
        self.assertError(self.errors(p), "requires original supporting evidence")
        self.assertError(self.errors(p), "lacks correlated original evidence")

    def test_artifact_existence_alone_not_sufficiency(self):
        p, r = self.observed()
        r["original_artifacts"][0]["supports_assertion"] = False
        self.assertError(self.errors(p), "requires original supporting evidence")
        r["original_artifacts"][0]["export_time"] = "missing"
        self.assertError(self.errors(p), "invalid timestamp")

    def test_upstream_evidence_only_for_admitted_scoped_model_assertion(self):
        p, r = self.observed("Agent:1.1.1:generative_outcome", "U")
        r["population"].update(target_kind="upstream", count=0)
        r["executions"] = []
        self.assertError(self.errors(p), "upstream original lacks")
        c = p["contexts"][0]
        r["original_artifacts"][0]["upstream_scope"] = {"official_provenance":"synthetic-official-provider-reference", "model_version":c["model_version"], "configuration":c["security_configuration"], "procedure":"synthetic-evaluation-v1", "results":"synthetic-exact-assertion-results", "limitations":"synthetic-scoped-only"}
        self.assertEqual([], self.errors(p))
        p, r = self.observed("Agent:2.3.2:complete_audit", "U")
        r["population"].update(target_kind="upstream", count=0)
        self.assertError(self.errors(p), "upstream route cannot replace Agent-owned")

    def test_fixture_approval_preserves_every_production_control(self):
        p, _ = self.observed()
        p["fixtures"][0]["unchanged_controls"].remove("authentication_authorization")
        self.assertError(self.errors(p), "unchanged production enforcement")
        p, _ = self.observed()
        p["fixtures"][0]["approval"]["status"] = "proposed"
        self.assertError(self.errors(p), "equivalent fixture not approved")

    def test_fixture_cannot_change_assertion_or_strength(self):
        p = copy.deepcopy(self.plans["mcp-http"])
        r = self.record(p, "Agent:2.2.2:independent_gate")
        r["assertion"] = "Any consent eventually is enough"
        r["strength"] = "SHOULD"
        self.assertError(self.errors(p), "fixture cannot weaken acceptance")

    def test_deterministic_inspection_does_not_require_ten(self):
        p = copy.deepcopy(self.plans["mcp-http"])
        r = self.record(p, "Agent:5.2.2:card_disclosures")
        self.assertEqual("deterministic", r["population"]["target_kind"])
        self.assertEqual(1, r["population"]["count"])
        self.assertEqual([], self.errors(p))

    def test_actual_adaptive_effort_excludes_setup_report_unattended(self):
        p = copy.deepcopy(self.plans["mcp-http"])
        campaign = p["campaign"]
        campaign["status"] = "completed"
        segment = {"assessor":"synthetic-assessor", "qualification_reference":"synthetic-test://qualification", "activity":"setup", "actual_minutes":480, "context_ids":["http-route"], "surfaces":["direct","indirect","compositional","cross_tool"], "response_observation":"synthetic response observed", "adaptation":"synthetic payload adapted after response", "original_reference":"synthetic-test://effort-original"}
        campaign["effort"] = [segment]
        self.assertError(self.errors(p), "setup/report/unattended runtime excluded")
        segment["activity"] = "adaptive_execution_investigation"
        self.assertEqual([], self.errors(p))
        segment["surfaces"].remove("cross_tool")
        self.assertError(self.errors(p), "cross-Tool coverage missing")

    def test_quarterly_not_automatically_full_manual_review(self):
        p = copy.deepcopy(self.plans["mcp-http"])
        p["campaign"].update(review_kind="quarterly", status="completed", planned_actual_minutes=0)
        self.assertEqual([], self.errors(p))

    def test_hybrid_preserves_profile_allocation_and_crossing_case(self):
        p = copy.deepcopy(self.plans["hybrid"])
        self.assertEqual({"DASA","CASA"}, {x["profile"] for x in p["underlying_profiles"]})
        self.assertEqual("justified_non_applicability", self.record(p,"Agent:2.1.2:filesystem","remote-route")["applicability"])
        self.assertEqual("applicable", self.record(p,"Agent:2.1.2:filesystem","local-route")["applicability"])
        p["campaign"]["cross_boundary_cases"] = []
        self.assertError(self.errors(p), "crossing-boundary cases")

    def test_combined_certification_cannot_use_illustrative_or_missing_al2(self):
        p = copy.deepcopy(self.plans["desktop-local"])
        self.assertEqual(["DASA"], [x["profile"] for x in p["underlying_profiles"]])
        p["status"] = "certification_ready"
        self.assertError(self.errors(p), "combined AL2/campaign gate unresolved")
        self.assertError(self.errors(p), "mandatory assertion unresolved/breached")
        self.assertError(self.errors(p), "illustrative placeholders")
        p["underlying_profiles"][0]["assurance_level"] = 1
        self.assertError(self.errors(p), "wrong constant")

    def test_schema_and_duplicate_json_properties_not_silent(self):
        p = copy.deepcopy(self.plans["mcp-http"])
        p["invented_control_exception"] = True
        self.assertError(self.errors(p), "unknown property")
        with self.assertRaises(ValueError):
            json.loads('{"id":1,"id":2}', object_pairs_hook=policy.strict_object)
        p = copy.deepcopy(self.plans["mcp-http"])
        p["records"].pop()
        self.assertError(self.errors(p), "complete per-context verification inventory")

    def test_multimodal_cases_have_separate_populations_not_pooled_runs(self):
        p = copy.deepcopy(self.plans["multimodal"])
        r = self.record(p, "Agent:1.1.1:generative_outcome")
        self.assertEqual({"EV-IMAGE-01", "EV-AUDIO-01"}, {x["case_id"] for x in r["additional_cases"]})
        for case in r["additional_cases"]:
            self.assertEqual(10, case["population"]["count"])
            self.assertEqual("stochastic", case["population"]["target_kind"])
        r["additional_cases"][0]["result"] = "satisfied"
        self.assertError(self.errors(p), "population per prescribed CASE")
        r["additional_cases"][0]["result"] = "observed_breach"
        self.assertError(self.errors(p), "known mandatory breach")

    def test_remote_boundary_stays_applicable_without_managed_provider_runtime(self):
        p = self.plans["hybrid"]
        self.assertEqual("applicable", self.record(p, "Agent:2.1.2:remote_boundary", "remote-route")["applicability"])
        self.assertEqual("justified_non_applicability", self.record(p, "Agent:2.1.2:process_escape", "remote-route")["applicability"])
        self.assertEqual("SHOULD", self.record(p, "Agent:2.2.2:signed_consent_upgrade", "local-route")["strength"])
        self.assertIn("0ed09d3", self.matrix["source_control_amendment"])

    def test_distributed_content_not_exempt_with_only_one_tool(self):
        p = copy.deepcopy(self.plans["fixed-rest"])
        p["contexts"][0]["features"]["multiple_tools"] = False
        _, v = policy.inventory(self.matrix)["Agent:3.1.2:distributed_content"]
        self.assertEqual("applicable", policy.applicability(self.matrix, v, p["contexts"][0])[0])

    def test_unverified_declarations_never_establish_real_exclusions(self):
        p = copy.deepcopy(self.plans["mcp-http"])
        p["status"] = "assessment_plan"
        p["contexts"][0]["configuration_status"] = "declared"
        self.assertError(self.errors(p), "unverified declarations/interface hints")

    def test_android_scope_mapping_uses_corresponding_tool_requirements(self):
        annex = (AI / "AI Tool Local Android Requirements.md").read_text()
        applicability_doc = (AI / "AI Agent Assessment Applicability.md").read_text()
        user_context = annex.split("### LOCAL_ANDROID 1.2.2 —", 1)[1].split("### LOCAL_ANDROID 1.2.3 —", 1)[0]
        propagation = annex.split("### LOCAL_ANDROID 2.2.2 —", 1)[1].split("### LOCAL_ANDROID 2.2.3 —", 1)[0]
        self.assertIn("| Mobile | In Scope |", user_context)
        self.assertIn("| Mobile | Out of Scope |", propagation)
        ledger = policy.read_json(AI / "AI Tool Assessment Cases.json")
        self.assertEqual(["2.2.2"], next(t for t in ledger["tests"] if t["id"] == "1.5")["requirement_ids"])
        self.assertEqual(["1.2.2"], next(t for t in ledger["tests"] if t["id"] == "2.2")["requirement_ids"])
        self.assertIn("Tool §1.2.2 / Guide §2.2", applicability_doc)
        self.assertIn("Tool §2.2.2 / Guide §1.5", applicability_doc)
        self.assertNotIn("Tool §1.2.2 marks Mobile in scope while Guide identity propagation §1.5", applicability_doc)

    def test_specific_cases_and_named_artifact_conditions_not_generic(self):
        for _, v in policy.inventory(self.matrix).values():
            self.assertNotIn("verify required security outcome", v["assertion"].lower())
            self.assertTrue(v["source"] and v["case"] and v["evidence"])
        for route in self.matrix["evidence_routes"].values():
            self.assertTrue(route["condition"])


if __name__ == "__main__":
    unittest.main()
