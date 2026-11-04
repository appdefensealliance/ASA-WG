"""Document layout and retained assessment/security regressions.

The repository checks do not certify products or establish governance approval.
"""
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
AI = ROOT / 'AI Profile'
ASSET = ROOT / 'assessment/ai'
DATA = ROOT / 'scripts/data/ai'
sys.path.insert(0, str(ROOT / 'scripts'))
from ai_document_set import DOCUMENTS, ASSETS, INDEXES, errors


class AgentDocumentSetTests(unittest.TestCase):
    def test_primary_documents_and_supporting_assets_are_separate(self):
        self.assertEqual([], errors(ROOT))
        for name in DOCUMENTS:
            text = (AI/name).read_text()
            self.assertNotIn('Certification is not presently available', text)
            self.assertNotIn('These documents are being finalized for WG consensus', text)
        for name in ('AI Agent Specification.md', 'AI Agent Test Guide.md'):
            text = (AI/name).read_text()
            self.assertIn('single combined product certification', text)
            self.assertIn('every applicable mandatory requirement', text)
        self.assertEqual(48, len(json.loads((ASSET/'AI Tool Minimum Security Register.json').read_text())['CASA_floor']))
        self.assertIn('Local Android applicability', (AI/'AI Tool Local Android Requirements.md').read_text())
        self.assertIn('# Assessment Methodology', (AI/'AI Agent Test Guide.md').read_text())

    def test_session_publication_framing_cannot_be_reintroduced(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            for rel in ['AI Profile/'+n for n in DOCUMENTS] + list(ASSETS) + list(INDEXES) + ['CONTRIBUTING.md']:
                dest=root/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,dest)
            p=root/'AI Profile/AI Agent Specification.md'
            original=p.read_text()
            for phrase, error in (
                ('This is an alpha pilot.', 'publication/pilot framing'),
                ('Certification is not presently available against these documents.', 'certification-readiness commentary'),
                ('Certification is not possible.', 'certification-readiness commentary'),
            ):
                with self.subTest(phrase=phrase):
                    p.write_text(original+'\n'+phrase+'\n')
                    self.assertTrue(any(error in e for e in errors(root)))

    def test_tool_assessment_fields_remain_canonical(self):
        ledger=json.loads((ASSET/'AI Tool Assessment Cases.json').read_text())
        for test in ledger['tests']:
            for key in ('gate_class','mandatory_outcome','advisory_outcome'):
                self.assertIn(key,test)
            self.assertFalse(any(k.startswith('proposed_') for k in test))
            for case in test['cases']:
                self.assertIn('disposition',case)
                self.assertIn('requirement_text',case)
                self.assertFalse(any(k.startswith('proposed_') for k in case))
        self.assertEqual(210,sum(len(t['cases']) for t in ledger['tests']))

    def test_standalone_scope_is_consistent_and_exclusions_do_not_waive_agent_duties(self):
        names = ('AI Tool Specification.md', 'AI Tool Testing Guide.md',
                 'AI Agent-Tool Interface Contract.md', 'AI Agent-Tool Identity and Consent Wire Format.md',
                 'AI Tool Minimum Security Register.md')
        for name in names:
            text = (AI/name).read_text()
            self.assertIn('standalone Tool profile covers remote HTTP and local Android Tools', text)
            self.assertIn("Other standalone local/desktop/iOS Tool variants are outside this revision's scope", text)
            self.assertIn('do not waive desktop/mobile Agent runtime or integration obligations', text)
        guide = (AI/'AI Tool Testing Guide.md').read_text()
        self.assertNotIn('Other local/mobile variants continue to use the pinned source', guide)
        self.assertNotIn('other local/mobile variants retain their current source disposition pending', guide)
        ledger = json.loads((ASSET/'AI Tool Assessment Cases.json').read_text())
        self.assertIn("outside this revision's scope", ledger['assessment_rules']['retained_variants'])
        for test in ledger['tests']:
            for case in test['cases']:
                self.assertEqual('OUTSIDE_STANDALONE_TOOL_SCOPE', case['gate_by_variant']['other_local_mobile'])
                self.assertEqual('RETAIN_CURRENT_TEST_GATE_IF_ORIGINALLY_APPLICABLE', case['gate_by_variant']['local_android_tool'])
        scope = json.loads((ASSET/'AI Tool Minimum Security Register.json').read_text())['standalone_tool_scope']
        self.assertFalse(scope['agent_protections_waived_by_tool_scope_exclusion'])
        self.assertFalse(scope['historical_source_is_excluded_variant_assessment_route'])

    def test_optional_wire_has_no_unfinished_local_conformance_claim(self):
        wire = (AI/'AI Agent-Tool Identity and Consent Wire Format.md').read_text()
        self.assertIn('D1 remains optional', wire)
        self.assertIn('does not define a D1 conformance route for local stdio or Android AppFunctions', wire)
        self.assertIn('Any credential or proof used to establish protected authority MUST satisfy its applicable validation requirements', wire)
        self.assertIn('A key authorized only for C3 MUST NOT authorize C1', wire)
        self.assertIn('Its own consent/workload key cannot authenticate an arbitrary user', wire)
        for stale in ('## Open WG decisions', '## Pre-normative verification tasks', '_meta` carrier (stdio)'):
            self.assertNotIn(stale, wire)
        annex = (AI/'AI Tool Local Android Requirements.md').read_text()
        self.assertIn('Only the unfinished optional-wire conformance material is excluded', annex)
        self.assertIn('mandatory local Android Specification, Testing Guide and Contract obligations above retain their original strength', annex)
        self.assertIn('No local D1 conformance claim is required', annex)
        self.assertNotIn('pending Open Decision 4', annex)
        self.assertNotIn('original unresolved local-transport scope', annex)

    def test_native_android_and_case_security_obligations_are_preserved(self):
        base = '6ec5b54e62888771220a008151a9b074e87988ac'
        def original(rel):
            try:
                return subprocess.check_output(['git','show',base+':'+rel], cwd=ROOT, text=True, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                self.skipTest('scope-clarification base unavailable')
        begin = '## AI Tool Specification.md — retained source'
        old = original('AI Profile/AI Tool Local Android Requirements.md')
        old_native = old.split(begin,1)[1].split('## AI Agent-Tool Identity and Consent Wire Format.md — retained source',1)[0]
        new = (AI/'AI Tool Local Android Requirements.md').read_text()
        new_native = new.split(begin,1)[1].split('## Optional local-wire conformance boundary',1)[0]
        self.assertEqual(old_native, new_native, 'Native Android Spec/Guide/Contract bodies must not be demoted')
        old_cases = json.loads(original('assessment/ai/AI Tool Assessment Cases.json'))
        new_cases = json.loads((ASSET/'AI Tool Assessment Cases.json').read_text())
        for old_test, new_test in zip(old_cases['tests'],new_cases['tests']):
            self.assertEqual(old_test['id'],new_test['id'])
            def spacing(text):
                for old, new in (('CASAadmin', 'CASA admin'), ('defaultTLS', 'default TLS'), ('secureIPC', 'secure IPC')):
                    text = text.replace(old, new)
                return text
            self.assertEqual(spacing(old_test['mandatory_outcome']),new_test['mandatory_outcome'])
            self.assertEqual(spacing(old_test['advisory_outcome']),new_test['advisory_outcome'])
            for before, after in zip(old_test['cases'],new_test['cases']):
                for field in ('case_id','current_text','original_assurance_tier','disposition'):
                    self.assertEqual(before[field],after[field])
                for field in ('mandatory_assertions','advisory_assertions'):
                    self.assertEqual(before['assessment'][field],after['assessment'][field])
                self.assertEqual(before['gate_by_variant']['local_android_tool'],after['gate_by_variant']['local_android_tool'])
                self.assertEqual(before['gate_by_variant']['remote_http_tool'],after['gate_by_variant']['remote_http_tool'])
        old_floor = json.loads(original('assessment/ai/AI Tool Minimum Security Register.json'))['CASA_floor']
        self.assertEqual(old_floor,json.loads((ASSET/'AI Tool Minimum Security Register.json').read_text())['CASA_floor'])

    def test_mlc_benchmarks_remain_strictly_optional(self):
        for name in ('AI Agent Specification.md','AI Agent Test Guide.md'):
            text=(AI/name).read_text()
            self.assertIn('SHOULD and strictly optional',text)
            self.assertIn('no mandatory failure, evidence prerequisite or compulsory',text)
        guide=(AI/'AI Agent Test Guide.md').read_text()
        for cid,benchmark in [('1.1.2','Jailbreak'),('1.1.3','safety')]:
            block=re.search(r'<!-- ada:test Agent:'+re.escape(cid)+r' covers=Agent:'+re.escape(cid)+r' -->(.*?)(?=\n#{1,3} |\Z)',guide,re.S)[1]
            self.assertIn('SHOULD perform [AILuminate '+benchmark,block)
            self.assertIn('optional and thus does not have any mandatory verification conditions',block)
            self.assertNotIn('SHALL perform [AILuminate',block)
            self.assertNotIn('MUST perform [AILuminate',block)
            self.assertNotIn('**Model:** Repeat test',block)
            self.assertIn('Nonperformance requires no benchmark evidence',block)

    def test_special_modes_and_declared_bounds_cannot_be_scope_bypasses(self):
        for name in ('AI Agent Specification.md','AI Agent Test Guide.md'):
            text=(AI/name).read_text()
            self.assertIn('production-equivalence approval rules',text)
            self.assertIn('does not bypass or alter admission, authorization, consent',text)
            self.assertIn('missing required declared/enforced ceiling is a missing protection',text)
            self.assertNotIn('[PROPOSED DEFAULT — WG to confirm]',text)
        guide=(AI/'AI Agent Test Guide.md').read_text()
        self.assertIn('not demand unavailable provider-internal deletion records',guide)
        self.assertIn('Document Review (conditional provider dependency)',guide)

    def test_known_revocation_within_ttl_cannot_drop_out_of_plan(self):
        import agent_assessment_policy_validate as policy
        matrix=json.loads((ASSET/'AI Agent Assessment Applicability.json').read_text())
        record=policy.inventory(matrix)['Agent:2.4.2:admission_integrity'][1]
        self.assertIn('within that TTL',record['case'])
        self.assertIn('Known revoked or disabled admission MUST block the next dispatch even within',record['assertion'])
        self.assertIn('Required security audit/consent records',policy.inventory(matrix)['Agent:1.2.1:store_masking'][1]['assertion'])
        for field in ('case','assertion'):
            broken=copy.deepcopy(matrix)
            policy.inventory(broken)['Agent:2.4.2:admission_integrity'][1][field]='Deadline-only case, missing known-status check'
            self.assertTrue(any('inside-cached-TTL' in e for e in policy.matrix_errors(broken)))
        for name in ('AI Agent Specification.md','AI Agent Test Guide.md'):
            text=(AI/name).read_text()
            self.assertIn('Separately declared and authorized security audit/consent records',text)
            self.assertIn("relabeling unrestricted diagnostic records 'audit' creates no exception",text)

    def test_matrix_mirrors_reviewed_store_provider_and_bounds_rules(self):
        matrix=json.loads((ASSET/'AI Agent Assessment Applicability.json').read_text())
        records={a['id']+':'+v['key']:v for a in matrix['audits'] for v in a['verifications']}
        masking=records['Agent:1.2.1:store_masking']['assertion']
        self.assertIn('protected user-scoped stores',masking)
        self.assertIn('relabeling a diagnostic/shared store is no exception',masking)
        self.assertIn('Dedicated credential-store protections remain',masking)
        retention=records['Agent:5.1.2:retention_scope']
        self.assertIn('D-provider',retention['evidence'])
        self.assertIn('not hidden provider deletion logs',retention['assertion'])
        self.assertEqual('Document Review',matrix['evidence_routes']['D-provider']['type'])
        self.assertIn('missing protection, not N/A',records['Agent:2.1.3:automatic_bounds']['assertion'])
        self.assertIn('commissioned/delegated runtime execution',matrix['conditions']['managed']['basis'])
        guide=(AI/'AI Agent Test Guide.md').read_text()
        self.assertIn('Known revocation inside a cached-status TTL',guide)
        self.assertIn('recording the timestamp of this second invocation attempt',guide)
        coverage=json.loads((DATA/'AI Agent Migration Coverage.json').read_text())
        self.assertEqual('a153c9090c83cde6c556e6f9b1e3fdb081637cf6',coverage['upstream_revocation_followup']['head'])
        self.assertIn('not a grace period for admission already known to be revoked',guide)


if __name__=='__main__':
    unittest.main()
