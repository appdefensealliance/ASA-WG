"""Synthetic structural regressions for #410/#541; no Agents/humans tested.

The fake observations below exercise record invariants, not the truth of any
security claim, production equivalence, calibration or actual assessor effort.
"""
import copy
import importlib.util
import json
import re
from pathlib import Path
import unittest
import subprocess
import types
import sys

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts" / "agent_assessment_policy_validate.py"
spec = importlib.util.spec_from_file_location("agent_assessment_policy_validate", MODULE)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
AI = ROOT / "AI Profile"


class AssessmentPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = policy.read_json(policy.ASSESSMENT / "AI Agent Assessment Applicability.json")
        cls.schema = policy.read_json(policy.ASSESSMENT / "AI Agent Assessment Plan.schema.json")
        cls.examples = policy.read_json(policy.FIXTURES / "AI Agent Assessment Examples.json")
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
        r["population"]["classification_evidence"] = [original["reference"]]
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
        r["population"]["exception"] = {"explicit_population": 3, "procedure_id": r["verification_id"], "case_id": r["case_id"], "source_revision": policy.SOURCE_PIN, "approval": "synthetic-lab-approval", "rationale": "Lab budget plan, not source guidance"}
        self.assertError(self.errors(p), "specifically applicable known source/case guidance")
        # A positive fixture simulates reviewed, pinned, case-specific guidance;
        # it is not an added production policy/catalog population.
        from unittest.mock import patch
        g = {"procedure_id": r["verification_id"], "case_id": r["case_id"],
             "source_revision": policy.SOURCE_PIN, "explicit_population": 3}
        m = copy.deepcopy(self.matrix)
        m["procedure_catalog"]["specific_source_populations"] = [g]
        with patch.object(policy, "SPECIFIC_SOURCE_GUIDANCE", [g]):
            self.assertEqual([], policy.plan_errors(p, m, self.schema))
        r["population"]["exception"]["case_id"] = "unrelated-case"
        self.assertError(self.errors(p), "specifically applicable known source/case guidance")

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
        p["prior_findings"] = [{"id":"pilot-1", "verification_id":r["verification_id"], "context_id":c["id"], "model_version":c["model_version"], "case_id":r["case_id"], "origin":"pilot", "configuration":c["security_configuration"], "result":"observed_breach", "original_reference":"synthetic-test://retained-adverse-pilot-original"}]
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
        p["fixtures"][0]["approval"]["status"] = "pending"
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
        segment = {"assessor":"synthetic-assessor", "qualification_reference":"synthetic-test://qualification", "activity":"setup", "actual_minutes":480, "context_ids":["http-route"], "surfaces":["direct","indirect","compositional","cross_tool"], "response_observation":"synthetic response observed", "adaptation":"synthetic payload adapted after response", "original_reference":"synthetic-test://effort-original", "finding_ids":[]}
        campaign["effort"] = [segment]
        self.assertError(self.errors(p), "setup/report/unattended runtime excluded")
        segment["activity"] = "adaptive_execution_investigation"
        c = p["contexts"][0]
        p["findings"] = [{"id":"adaptive-1", "verification_id":"Agent:3.1.2:untrusted_consequence", "context_id":c["id"], "configuration":c["security_configuration"], "model_version":c["model_version"], "case_id":"adaptive-probe-1", "origin":"adaptive", "result":"satisfied", "original_reference":"synthetic-test://observed-adaptive-outcome"}]
        segment["finding_ids"] = ["adaptive-1"]
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
        self.assertIn("AI Agent Policy Alignment.json", self.matrix["source_control_amendment"])

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
        agent_doc = policy.GUIDE.read_text().split("# Assessment Methodology\n",1)[1]
        self.assertIn("AI%20Tool%20Local%20Android%20Requirements.md#local-android-applicability", agent_doc)
        user_context = annex.split("### LOCAL_ANDROID 1.2.2 —", 1)[1].split("### LOCAL_ANDROID 1.2.3 —", 1)[0]
        propagation = annex.split("### LOCAL_ANDROID 2.2.2 —", 1)[1].split("### LOCAL_ANDROID 2.2.3 —", 1)[0]
        self.assertIn("| Mobile | In Scope |", user_context)
        self.assertIn("| Mobile | Out of Scope |", propagation)
        ledger_path=policy.ASSESSMENT / "AI Tool Assessment Cases.json"
        if not ledger_path.exists():
            # Read-only compatibility with the uncombined parent move; not a product/evidence fallback.
            ledger_path=AI / "AI Tool Assessment Cases.json"
        ledger = policy.read_json(ledger_path)
        self.assertEqual(["2.2.2"], next(t for t in ledger["tests"] if t["id"] == "1.5")["requirement_ids"])
        self.assertEqual(["1.2.2"], next(t for t in ledger["tests"] if t["id"] == "2.2")["requirement_ids"])

    def baseline_observed(self, vid="Agent:3.1.2:untrusted_consequence", example="mcp-http"):
        """Read the exact pushed base in memory; no extra files or checkout writes."""
        def at_base(path):
            try:
                # Keep exploit reproduction pinned to the unremediated pushed base,
                # independently of the current governing assessment source pin.
                return subprocess.check_output(["git","show","2b04647d0ee312f361e3b9fb6a390ffe6599a4d7"+":"+path], cwd=ROOT, text=True, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                self.skipTest("pushed review-base commit unavailable in this checkout")
        base = types.ModuleType("review_base_policy")
        base.__file__ = str(MODULE)
        exec(compile(at_base("scripts/agent_assessment_policy_validate.py"),str(MODULE),"exec"),base.__dict__)
        m = json.loads(at_base("AI Profile/AI Agent Assessment Applicability.json"))
        s = json.loads(at_base("AI Profile/AI Agent Assessment Plan.schema.json"))
        e = json.loads(at_base("AI Profile/AI Agent Assessment Examples.json"))
        p = base.expand_example(m,e,next(x for x in e["examples"] if x["id"]==example))
        r = self.record(p,vid)
        c = next(x for x in p["contexts"] if x["id"]==r["context_id"])
        r["result"] = "satisfied"
        p["fixtures"][0]["approval"]["status"] = "approved"
        a = {"reference":"synthetic-test://base-original","route":"F","producer":"synthetic product observation","export_time":"2026-11-03T21:00:00Z","covered_interval":"synthetic trials","configuration":c["security_configuration"],"filtering_redaction":"none","visibility_limits":"synthetic case only","correlation":["test"],"controls":["benign exposed control"],"supports_assertion":True}
        r["original_artifacts"]=[a]
        r["executions"]=[{"id":str(i),"reset_context":"reset-"+str(i),"independent":True,"model_version":c["model_version"],"security_configuration":c["security_configuration"],"exposed":True,"outcome":"satisfied","original_references":[a["reference"]]} for i in range(10)]
        return base,m,s,p,r

    def finding(self, p, vid, result="observed_breach", origin="adaptive", case_id="adaptive-case-1", context=None):
        r = self.record(p,vid,context)
        c = next(c for c in p["contexts"] if c["id"]==r["context_id"])
        return {"id":"finding-"+c["id"],"verification_id":vid,"context_id":c["id"],"configuration":c["security_configuration"],"model_version":c["model_version"],"case_id":case_id,"origin":origin,"result":result,"original_reference":"synthetic-test://typed-observed-outcome"}

    def test_base_global_false_flag_loophole_is_closed(self):
        base,m,s,p,r = self.baseline_observed()
        p["contexts"][0]["stochastic_target"] = False
        for row in p["records"]:
            if base.inventory(m)[row["verification_id"]][1]["target"]=="behavior":
                row["population"].update(target_kind="deterministic",count=1)
        r["executions"] = r["executions"][:1]
        self.assertEqual([],base.plan_errors(p,m,s),"confirmed baseline accepted one-run generative case")
        fixed,r = self.observed()
        fixed["contexts"][0]["stochastic_target"] = False
        r["population"].update(target_kind="deterministic",count=1)
        r["executions"] = r["executions"][:1]
        self.assertError(self.errors(fixed),"target classification drift")
        for example in self.examples["examples"]:
            changed = copy.deepcopy(example)
            for c in changed["contexts"]: c["stochastic_target"] = False
            expanded = policy.expand_example(self.matrix,self.examples,changed)
            for row in expanded["records"]:
                if policy.inventory(self.matrix)[row["verification_id"]][1]["target"]=="llm_mediated":
                    self.assertEqual(("stochastic",10),(row["population"]["target_kind"],row["population"]["count"]))

    def test_base_arbitrary_budget_exception_is_closed(self):
        base,m,s,p,r = self.baseline_observed()
        r["population"].update(count=1,exception={"explicit_population":1,"source_revision":"lab plan","approval":"lab lead","rationale":"budget"})
        r["executions"] = r["executions"][:1]
        self.assertEqual([],base.plan_errors(p,m,s),"confirmed baseline accepted budget as source guidance")
        fixed,r = self.observed()
        r["population"].update(count=1,exception={"explicit_population":1,"procedure_id":r["verification_id"],"case_id":r["case_id"],"source_revision":policy.SOURCE_PIN,"approval":"lab lead","rationale":"budget"})
        r["executions"] = r["executions"][:1]
        self.assertError(self.errors(fixed),"specifically applicable known source/case guidance")
        r["population"]["source_revision"]="lab plan"
        self.assertError(self.errors(fixed),"governing known procedure/case")

    def test_base_dynamic_feature_na_flags_are_closed(self):
        base,m,s,p,r = self.baseline_observed("Agent:3.2.3:grounded_references")
        for feature in policy.FEATURE_PROBES: p["contexts"][0]["features"][feature]=False
        for row in p["records"]:
            _,v = base.inventory(m)[row["verification_id"]]
            disposition,basis = base.applicability(m,v,p["contexts"][0])
            row["applicability"],row["basis"] = disposition,basis
            if disposition=="justified_non_applicability": row["result"]=disposition
        self.assertEqual([],base.plan_errors(p,m,s),"confirmed baseline accepted unprobed generative output exclusions")
        fixed = copy.deepcopy(self.plans["mcp-http"])
        for feature,vid in policy.FEATURE_PROBES.items():
            fixed["contexts"][0]["features"][feature]=False
            row=self.record(fixed,vid)
            row["applicability"]=row["result"]="justified_non_applicability"
        self.assertError(self.errors(fixed),"applicability contradicts")

    def test_source_bound_protocol_checks_not_forced_to_ten(self):
        p,r = self.observed("Agent:6.1.5:s256_exchange")
        self.assertEqual("deterministic",r["population"]["target_kind"])
        self.assertEqual(1,r["population"]["count"])
        r["executions"] = r["executions"][:1]
        self.assertEqual([],self.errors(p))
        r["population"]["classification_evidence"]= ["synthetic-test://missing-path-proof"]
        self.assertError(self.errors(p),"original evidence for its prescribed target-path classification")

    def test_actual_feature_probe_not_empty_record_justifies_absence(self):
        p = copy.deepcopy(self.plans["mcp-http"])
        c=p["contexts"][0]
        c["features"]["actionable_references"]=False
        vid=policy.FEATURE_PROBES["actionable_references"]
        probe={"feature":"actionable_references","status":"verified_absent","procedure_id":vid,"case_id":"REFERENCE-01","source_revision":policy.SOURCE_PIN,"boundary_reference":"synthetic-test://actual-production-reference-output-boundary","observations":[],"original_artifacts":[]}
        c["feature_exclusions"].append(probe)
        self.assertError(self.errors(p),"absence lacks exposed")
        good,r=self.observed()
        a=copy.deepcopy(r["original_artifacts"][0])
        probe["original_artifacts"]=[a]
        probe["observations"]=[{"id":k,"kind":k,"exposed":True,"result":"safe_refusal","model_version":c["model_version"],"configuration":c["security_configuration"],"original_reference":a["reference"]} for k in ["direct_request","supported_boundary_refusal"]]
        for row in p["records"]:
            _,v=policy.inventory(self.matrix)[row["verification_id"]]
            row["applicability"],row["basis"]=policy.applicability(self.matrix,v,c)
            if row["applicability"]=="justified_non_applicability": row["result"]=row["applicability"]
        self.assertEqual([],self.errors(p),"synthetic evidence links only, not authentication or universal absence proof")
        probe["observations"][0]["result"]="feature_present"
        self.assertError(self.errors(p),"missing protection is not absence")

    def adaptive_effort(self, p, context_id, finding_id, minutes=480):
        return {"assessor":"synthetic-assessor","qualification_reference":"synthetic-test://qualification","activity":"adaptive_execution_investigation","actual_minutes":minutes,"context_ids":[context_id],"surfaces":["direct","indirect","compositional","cross_tool"],"response_observation":"synthetic observed downstream outcome","adaptation":"response-informed synthetic revision","original_reference":"synthetic-test://effort-original","finding_ids":[finding_id]}

    def test_base_adaptive_breach_cannot_vanish_in_clean_regression(self):
        vid="Agent:2.2.2:independent_gate"
        base,m,s,p,r=self.baseline_observed(vid)
        e=self.adaptive_effort(p,r["context_id"],"unused")
        e.pop("finding_ids")
        e["response_observation"]="Confirmed fresh-consent bypass in adaptive attack, then regression 0/10"
        p["campaign"].update(status="completed",effort=[e])
        self.assertEqual([],base.plan_errors(p,m,s),"confirmed baseline lost a narrative adaptive breach")
        fixed,r=self.observed(vid)
        f=self.finding(fixed,vid)
        fixed["findings"]=[f]
        fixed["campaign"].update(status="completed",effort=[self.adaptive_effort(fixed,r["context_id"],f["id"])])
        self.assertError(self.errors(fixed),"known mandatory breach")
        r["result"]="insufficient_evidence"
        self.assertError(self.errors(fixed),"known mandatory breach")
        r["result"]="observed_breach"
        self.assertEqual([],self.errors(fixed))
        fixed["campaign"]["effort"][0]["finding_ids"]=[]
        self.assertError(self.errors(fixed),"typed finding links")

    def test_base_cross_boundary_breach_has_sticky_owning_verification(self):
        vid="Agent:2.2.2:binding_fidelity"
        base,m,s,p,r=self.baseline_observed(vid,"hybrid")
        p["campaign"]["cross_boundary_cases"][0]["observations"].append("Confirmed recipient substitution during chain; later regression clean")
        self.assertEqual([],base.plan_errors(p,m,s),"confirmed baseline did not link observed crossing failure")
        fixed=copy.deepcopy(self.plans["hybrid"])
        f=self.finding(fixed,vid,origin="cross_boundary",case_id="HYBRID-CHAIN-01",context="local-route")
        fixed["findings"]=[f]
        chain=fixed["campaign"]["cross_boundary_cases"][0]
        chain.update(result="observed_breach",finding_ids=[f["id"]])
        self.assertError(self.errors(fixed),"known mandatory breach")
        self.record(fixed,vid,"local-route")["result"]="observed_breach"
        self.assertEqual([],self.errors(fixed))
        chain["result"]="satisfied"
        self.assertError(self.errors(fixed),"cross-boundary breach is sticky")
        chain["result"]="observed_breach"
        fixed["findings"]=[]
        self.assertError(self.errors(fixed),"finding/context link")

    def test_fresh_configuration_retains_old_finding_without_laundering_current(self):
        p,r=self.observed()
        old=self.finding(p,r["verification_id"])
        p["prior_findings"]=[old]
        self.assertError(self.errors(p),"known mandatory breach")
        c=p["contexts"][0]
        c["security_configuration"]="separately-assessed-remediated-v2"
        for row in p["records"]:
            for a in row["original_artifacts"]: a["configuration"]=c["security_configuration"]
            for run in row["executions"]: run["security_configuration"]=c["security_configuration"]
        self.assertEqual([],self.errors(p),"old adverse configuration is retained, not erased")
        p["campaign"]["effort"]=[self.adaptive_effort(p,c["id"],old["id"])]
        self.assertError(self.errors(p),"different/remediated configuration")

    def test_eight_total_hours_allocated_across_models_not_per_model(self):
        p=copy.deepcopy(self.plans["hybrid"])
        p["campaign"].update(status="completed",planned_actual_minutes=480)
        p["findings"]=[]
        p["campaign"]["effort"]=[]
        for c in p["contexts"]:
            f=self.finding(p,"Agent:3.1.2:untrusted_consequence",result="satisfied",context=c["id"])
            p["findings"].append(f)
            p["campaign"]["effort"].append(self.adaptive_effort(p,c["id"],f["id"],240))
        self.assertEqual([],self.errors(p),"240+240=480 actual minutes, not 480 per context")
        p["campaign"]["effort"][0]["context_ids"].append("remote-route")
        self.assertError(self.errors(p),"finding links for every claimed model/config context")

    def test_matrix_restores_exact_source_duties_and_keeps_528_case(self):
        base,m,s,p,r=self.baseline_observed()
        current=policy.inventory(self.matrix)
        previous=base.inventory(m)
        v=current["Agent:2.4.1:user_audience"][1]
        self.assertIn("MUST NOT forward a token received from the Agent's own client for another audience",v["assertion"])
        self.assertIn("reuse MUST cease",v["assertion"])
        self.assertIn("revocation",v["case"])
        self.assertNotIn("MUST NOT forward",previous["Agent:2.4.1:user_audience"][1]["assertion"])
        v=current["Agent:3.2.3:grounded_references"][1]
        self.assertIn("MUST NOT recommend or emit a nonexistent package",v["assertion"])
        self.assertIn("even when flagged unverified",v["assertion"])
        self.assertNotIn("even when flagged unverified",previous["Agent:3.2.3:grounded_references"][1]["assertion"])
        self.assertIn("instantly",current["Agent:2.1.1:termination"][1]["assertion"])
        revocation = current["Agent:2.4.2:admission_integrity"][1]
        self.assertEqual(previous["Agent:2.4.2:admission_integrity"][1]["source"], revocation["source"])
        for clause in ("verify establishment and admission before dispatch", "reject post-pin tampering", "documented deadline", "admission/revocation status cannot be established", "A denial after execution fails", "universal online revocation endpoint"):
            self.assertIn(clause, revocation["assertion"], "preserve original invocation-time/TTL/status #528 duty")
        self.assertIn("TOOL-PIN-01:", revocation["case"])
        self.assertIn("within an unexpired cached-status TTL", revocation["assertion"])
        self.assertIn("known-revocation delivery times", revocation["assertion"])

    def test_cli_default_examples_roundtrip_and_rejections(self):
        def cli(*args, stdin=None):
            return subprocess.run([sys.executable,str(MODULE),*args],cwd=ROOT,text=True,input=stdin,capture_output=True,timeout=30)
        self.assertEqual(0,cli().returncode)
        for name in self.plans:
            result=cli("--example",name,"--expand")
            self.assertEqual(0,result.returncode,result.stderr)
            expanded=json.loads(result.stdout)
            self.assertEqual("0.2",expanded["schema_version"])
            self.assertEqual(0,cli("--plan","-",stdin=result.stdout).returncode)
        for args in [("--example","missing"),("--expand",),("--plan","-","--example","hybrid")]:
            self.assertNotEqual(0,cli(*args).returncode)
        self.assertNotEqual(0,cli("--plan","-",stdin='{"bad":').returncode)
        p,r=self.observed()
        p["contexts"][0]["stochastic_target"]=False
        r["population"].update(target_kind="deterministic",count=1)
        r["executions"]=r["executions"][:1]
        rejected=cli("--plan","-",stdin=json.dumps(p))
        self.assertEqual(1,rejected.returncode)
        self.assertIn("target classification drift",rejected.stderr)

    def test_consolidated_methodology_structure_and_live_records(self):
        guide=policy.GUIDE.read_text()
        self.assertEqual([],policy.methodology_errors(guide))
        method=guide.split("# Assessment Methodology\n",1)[1]
        for heading in ("Assessment Protocol","Assessment Applicability","Assessment Plans and Records"):
            self.assertEqual(1,method.count("## "+heading+"\n"))
        for case in ("EV-TEXT-01","EV-IMAGE-01","EV-AUTH-01","HYBRID-CHAIN-01"):
            self.assertIn(case,method)
        self.assertIn('id="5-111-task-appropriate-outcomes"',method)
        for name in ("AI Agent Assessment Protocol.md","AI Agent Assessment Applicability.md","AI Agent Assessment Plans.md"):
            self.assertFalse((AI/name).exists(),"retired standalone methodology")
        self.assertTrue((policy.ASSESSMENT/"AI Agent Assessment Applicability.json").is_file())
        self.assertTrue((policy.ASSESSMENT/"AI Agent Assessment Plan.schema.json").is_file())
        self.assertTrue((policy.FIXTURES/"AI Agent Assessment Examples.json").is_file())
        self.assertTrue(policy.methodology_errors(guide.replace("## Assessment Applicability\n","## Missing\n")))
        self.assertTrue(policy.methodology_errors(guide+"\n# Assessment Methodology\n"))

    def test_neutral_revision_and_schema_are_not_publication_authority(self):
        self.assertEqual("unassigned",self.matrix["target_release"])
        self.assertEqual("https://json-schema.org/draft/2020-12/schema",self.schema["$schema"])
        for data in (self.matrix,self.schema,self.examples):
            self.assertNotIn("x_profile_release",data)
        self.assertFalse(hasattr(policy,"publication_state_errors"))
        self.assertFalse(hasattr(policy,"PROFILE_VERSION"))
        method=policy.GUIDE.read_text().split("# Assessment Methodology\n",1)[1]
        self.assertNotIn("0.1.0-alpha",method)
        self.assertNotIn("AI-only publication scope",method)
        self.assertIn("proposed parameters/consent",method)
        self.assertIn("**Pilot:**",method,"pilot testing stage remains methodology")
        self.assertIn("**Full campaign:**",method)
        self.assertIn("**Remediation:**",method)
        p=copy.deepcopy(self.plans["desktop-local"])
        p["status"]="certification_ready"
        self.assertError(self.errors(p),"illustrative placeholders/unassigned release")
        self.assertError(self.errors(p),"mandatory assertion unresolved/breached")
        p["target_release"]="invented-release"
        self.assertError(self.errors(p),"governing profile revision")

    def test_pending_fixture_is_never_an_approved_or_passing_fixture(self):
        for p in self.plans.values():
            self.assertTrue(all(f["approval"]["status"]=="pending" for f in p["fixtures"]))
        p,r=self.observed()
        p["fixtures"][0]["approval"]["status"]="pending"
        self.assertError(self.errors(p),"equivalent fixture not approved")
        p["fixtures"][0]["approval"]["status"]="proposed"
        self.assertError(self.errors(p),"invalid enum value")
        p["fixtures"][0]["approval"]["status"]="approved"
        self.assertEqual([],self.errors(p),"synthetic structural case only; no real approval/security claim")

    def test_consolidation_preserves_security_controls_and_data(self):
        base="94f0ac2067d005fad9c4644fd98f8dc9b731900f"
        def at_base(name):
            try:
                return subprocess.check_output(["git","show",base+":"+name],cwd=ROOT,text=True,stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                self.skipTest("consolidation base unavailable in this checkout")
        old=json.loads(at_base("AI Profile/AI Agent Assessment Applicability.json"))
        old.pop("x_profile_release",None)
        old["status"]=self.matrix["status"]
        old["target_release"]=self.matrix["target_release"]
        for a in old["audits"]:
            for v in a["verifications"]:
                v["assertion"]=v["assertion"].replace("No 25-step fallback is adopted by this alpha","No 25-step fallback is provided here")
        old["source_control_amendment"] = self.matrix["source_control_amendment"]
        old["source_baseline"] = self.matrix["source_baseline"]
        old["procedure_catalog"]["source_revision"] = self.matrix["procedure_catalog"]["source_revision"]
        old["procedure_catalog"]["reference"] = self.matrix["procedure_catalog"]["reference"]
        # #456 intentionally extends only §§2.2.3/6.2.2; its dedicated tests
        # preserve their old safeguards and exercise new supported-mode cases.
        comparable = copy.deepcopy(self.matrix)
        for m in (old, comparable):
            m['audits'] = [a for a in m['audits'] if a['id'] not in {'Agent:2.2.3', 'Agent:6.2.2'}]
        for key in ('elicitation_form', 'elicitation_url'):
            comparable['conditions'].pop(key)
        comparable['conditions']['elicitation'] = old['conditions']['elicitation']
        self.assertEqual(old,comparable,"unrelated inventories/cases/strength/evidence unchanged; source pin and path identify the reorganized snapshot")
        old_schema=json.loads(at_base("AI Profile/AI Agent Assessment Plan.schema.json"))
        old_schema.pop("x_profile_release",None)
        old_schema["title"]=self.schema["title"]
        self.assertEqual(old_schema,self.schema,"schema0.2 and pending fixtures unchanged")
        old_examples=json.loads(at_base("AI Profile/AI Agent Assessment Examples.json"))
        old_examples.pop("x_profile_release",None)
        old_examples['common_features'].update(elicitation_form=False, elicitation_url=False)
        for example in old_examples['examples']:
            for context in example['contexts']:
                if example['id'] == 'mcp-stdio':
                    context['feature_overrides']['elicitation_form'] = True
                if example['id'] == 'hybrid' and context['id'] == 'remote-route':
                    context['feature_overrides'].update(elicitation=True, elicitation_url=True)
                    context['role'] += '; URL-only MCP elicitation client'
                    context['configuration_evidence'].append('example://hybrid/verified-url-only-elicitation-and-isolated-browser-boundary')
        self.assertEqual(old_examples,self.examples,"synthetic scenarios/evidence unchanged apart from explicit #456 supported-mode plan variations")
        before=at_base("AI Profile/AI Agent Test Guide.md").split("# 1. Model & Data Integrity\n",1)[1]
        after=policy.GUIDE.read_text().split("# 1. Model & Data Integrity\n",1)[1].split("\n# Assessment Methodology\n",1)[0]
        before=before.replace("(AI%20Agent%20Assessment%20Protocol.md#5-111-task-appropriate-outcomes)","(#5-task-appropriate-evasion-resistance-111)")
        before=before.replace("No generic 25-step fallback applies to this alpha.","No generic 25-step fallback applies.")
        before=before.replace("not a new TTL chosen by this alpha", "not a numeric TTL selected by these requirements")
        def without_456_blocks(text):
            return ''.join(b for b in re.split(r'(?=^#{1,3} )', text, flags=re.M)
                           if not any('<!-- ada:test Agent:' + cid + ' ' in b for cid in ('2.2.3', '6.2.2')))
        self.assertEqual(without_456_blocks(before).rstrip(), without_456_blocks(after).rstrip(),
                         "unrelated audit/security clauses unchanged apart from named publication wording")

    def test_substantive_methodology_paragraphs_preserved(self):
        import re
        base="94f0ac2067d005fad9c4644fd98f8dc9b731900f"
        def normalize(text):
            text=re.sub(r"\[([^\]]+)\]\([^)]+\)",r"\1",text)
            text=re.sub(r"(?m)^#{1,4} ","",text)
            return " ".join(text.split())
        method=normalize(policy.GUIDE.read_text().split("# Assessment Methodology\n",1)[1])
        for name in ("AI Agent Assessment Protocol.md","AI Agent Assessment Applicability.md","AI Agent Assessment Plans.md"):
            try:
                old=subprocess.check_output(["git","show",base+":AI Profile/"+name],cwd=ROOT,text=True,stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                self.skipTest("consolidation base unavailable")
            for paragraph in old.split("\n\n"):
                # File identity, navigation and publication wrappers are not controls.
                if not paragraph.strip() or paragraph.startswith(("# AI Agent Assessment","<!-- ai-profile-version:","This alpha defines","**AI Agent assessment","This companion governs","Companions:","Files:","These records are paired")):
                    continue
                if paragraph.startswith("The corresponding retained **Tool**"):
                    continue  # Parent relocated this live source into the annex.
                paragraph=paragraph.replace("Eight actual qualified red-team hours and the ten-execution default are the alpha assessment requirements","Eight actual qualified red-team hours and the ten-execution default are the assessment requirements")
                paragraph=paragraph.replace(" These operative rules make no assertion about a WG/SC vote or certificate-issuance authority.","")
                paragraph=paragraph.replace("Passing structural validation is not product security evidence, a governance decision or authority to issue an ADA certificate.","Passing structural validation is not product security evidence.")
                paragraph=paragraph.replace("; alpha assessment conformance does not authorize ADA certificate issuance.",".")
                paragraph=paragraph.replace("[Plans and worked examples](AI%20Agent%20Assessment%20Plans.md)","[Assessment Plans and Records](#assessment-plans-and-records)")
                if paragraph.startswith("The matrix's #539"):
                    paragraph=paragraph.replace("AI Agent Policy Alignment.json.","[AI Agent Policy Alignment.json](../scripts/data/ai/AI%20Agent%20Policy%20Alignment.json).")
                paragraph=paragraph.replace('An implemented interface with unsupported optional elicitation retains the safe-unsupported-request case.', 'An implemented MCP interface retains the safe-unsupported-request case. Record form and URL elicitation support separately; form-only products do not take URL-mode gates, URL-only products do not take form-schema gates, and a missing supported-mode protection is not an absent feature.')
                self.assertIn(normalize(paragraph),method,(name,paragraph[:160]))

    def test_specific_cases_and_named_artifact_conditions_not_generic(self):
        for _, v in policy.inventory(self.matrix).values():
            self.assertNotIn("verify required security outcome", v["assertion"].lower())
            self.assertTrue(v["source"] and v["case"] and v["evidence"])
        for route in self.matrix["evidence_routes"].values():
            self.assertTrue(route["condition"])


if __name__ == "__main__":
    unittest.main()
