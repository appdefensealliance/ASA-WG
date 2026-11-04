"""#456 document and synthetic assessment-record regressions.

No real Agent, browser, server or user is tested. These guard the source duties
and their record applicability/population/retained-finding rules.
"""
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
AI=ROOT/'AI Profile'
ASSET=ROOT/'assessment/ai'
sys.path.insert(0,str(ROOT/'scripts'))
import agent_assessment_policy_validate as policy
import agent_policy_alignment as alignment

URL_KEYS=('url_navigation','url_no_prefetch','url_isolation')


class ToolImpersonationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix=policy.read_json(ASSET/'AI Agent Assessment Applicability.json')
        cls.schema=policy.read_json(ASSET/'AI Agent Assessment Plan.schema.json')
        cls.examples=policy.read_json(ROOT/'scripts/tests/fixtures/ai/AI Agent Assessment Examples.json')
        cls.plans={e['id']:policy.expand_example(cls.matrix,cls.examples,e) for e in cls.examples['examples']}
        cls.spec=(AI/'AI Agent Specification.md').read_text()
        cls.guide=(AI/'AI Agent Test Guide.md').read_text()
        cls.manifest=policy.read_json(ROOT/'scripts/data/ai/AI Agent Policy Alignment.json')

    def record(self,p,key,context=None):
        return next(r for r in p['records'] if r['verification_id']==key and (context is None or r['context_id']==context))

    def test_mcp_required_duties_and_advisory_hardening_are_paired(self):
        for text in (self.spec,self.guide):
            for clause in ('Requester Attribution','trusted admission/protocol context',
                           'full target URL','explicit user consent before opening that exact URL',
                           'MUST NOT automatically prefetch','does not enable the client or LLM to inspect',
                           'SHOULD highlight the domain','not required to add an unsupported mode'):
                self.assertIn(clause,text)
        self.assertEqual([],alignment.alignment_errors(self.spec,self.guide,self.manifest))
        index=policy.inventory(self.matrix)
        for key in URL_KEYS:
            self.assertEqual('MUST',index['Agent:2.2.3:'+key][1]['strength'])
            self.assertEqual(['elicitation_url'],index['Agent:2.2.3:'+key][1]['when'])
        self.assertEqual('SHOULD',index['Agent:2.2.3:url_hardening'][1]['strength'])
        self.assertEqual('inspection',index['Agent:2.2.3:url_hardening'][1]['target'])
        self.assertIn('not established as Agent-owned',self.guide)

    def test_all_mode_combinations_without_making_optional_url_mandatory(self):
        for form,url in ((False,False),(True,False),(False,True),(True,True)):
            example=copy.deepcopy(next(x for x in self.examples['examples'] if x['id']=='mcp-http'))
            example['contexts'][0]['feature_overrides'].update(elicitation=form or url,elicitation_form=form,elicitation_url=url)
            p=policy.expand_example(self.matrix,self.examples,example)
            with self.subTest(form=form,url=url):
                self.assertEqual([],policy.plan_errors(p,self.matrix,self.schema))
                schema=self.record(p,'Agent:2.2.3:schema')
                self.assertEqual('applicable' if form else 'justified_non_applicability',schema['applicability'])
                for key in URL_KEYS:
                    r=self.record(p,'Agent:2.2.3:'+key)
                    self.assertEqual('applicable' if url else 'justified_non_applicability',r['applicability'])
                self.assertEqual('applicable',self.record(p,'Agent:2.2.3:unsupported_request')['applicability'])
                self.assertEqual('applicable' if form or url else 'justified_non_applicability',self.record(p,'Agent:2.2.3:requester_attribution')['applicability'])

    def test_form_only_and_url_only_worked_plans_exercise_different_scopes(self):
        form=self.plans['mcp-stdio']
        url=self.plans['hybrid']
        self.assertEqual('applicable',self.record(form,'Agent:2.2.3:schema')['applicability'])
        self.assertEqual('justified_non_applicability',self.record(form,'Agent:2.2.3:url_isolation')['applicability'])
        self.assertEqual('justified_non_applicability',self.record(url,'Agent:2.2.3:schema','remote-route')['applicability'])
        for key in URL_KEYS:
            r=self.record(url,'Agent:2.2.3:'+key,'remote-route')
            self.assertEqual('applicable',r['applicability'])
            self.assertEqual(10,r['population']['count'])
            self.assertEqual('pending',r['result'])
        self.assertNotEqual(self.record(url,'Agent:2.2.3:url_navigation','remote-route')['case_id'],
                            self.record(url,'Agent:2.2.3:url_isolation','remote-route')['case_id'])

    def test_non_mcp_does_not_waive_tool_presentation_protection(self):
        for name in ('appfunctions','desktop-local','fixed-rest'):
            p=self.plans[name]
            self.assertEqual('justified_non_applicability',self.record(p,'Agent:2.2.3:unsupported_request')['applicability'])
            self.assertEqual('applicable',self.record(p,'Agent:6.2.2:trusted_presentation')['applicability'])
        for clause in ('Tool-supplied text or active content MUST NOT impersonate',
                       'trusted integration/admission context', 'public-only Tools excluded from standalone Tool certification'):
            self.assertIn(clause,self.spec)
            self.assertIn(clause,self.guide)

    def test_false_mode_inventory_and_gate_demotions_are_rejected(self):
        p=copy.deepcopy(self.plans['hybrid'])
        c=next(c for c in p['contexts'] if c['id']=='remote-route')
        c['features']['elicitation']=False
        self.assertTrue(any('elicitation mode inventory contradicts' in e for e in policy.plan_errors(p,self.matrix,self.schema)))
        p=copy.deepcopy(self.plans['appfunctions'])
        p['contexts'][0]['features'].update(elicitation=True,elicitation_url=True)
        self.assertTrue(any('requires an implemented MCP interface' in e for e in policy.plan_errors(p,self.matrix,self.schema)))
        for key in URL_KEYS:
            m=copy.deepcopy(self.matrix)
            policy.inventory(m)['Agent:2.2.3:'+key][1]['strength']='SHOULD'
            self.assertTrue(any('strength drift' in e for e in policy.matrix_errors(m)))
            m=copy.deepcopy(self.matrix)
            policy.inventory(m)['Agent:2.2.3:'+key][1]['when']=['elicitation_form']
            self.assertTrue(any('supported-mode protection or optionality changed' in e for e in policy.matrix_errors(m)))
        m=copy.deepcopy(self.matrix)
        policy.inventory(m)['Agent:6.2.2:trusted_presentation'][1]['when']=['mcp']
        self.assertTrue(any('independent of optional MCP elicitation' in e for e in policy.matrix_errors(m)))

    def test_supported_mode_failure_cannot_be_na_or_hidden_by_clean_runs(self):
        p=copy.deepcopy(self.plans['hybrid'])
        r=self.record(p,'Agent:2.2.3:url_isolation','remote-route')
        r['result']=r['applicability']='justified_non_applicability'
        errors=policy.plan_errors(p,self.matrix,self.schema)
        self.assertTrue(any('applicability contradicts' in e or 'required protection/evidence cannot become N/A' in e for e in errors))
        p=copy.deepcopy(self.plans['hybrid'])
        r=self.record(p,'Agent:2.2.3:url_no_prefetch','remote-route')
        c=next(c for c in p['contexts'] if c['id']=='remote-route')
        p['findings'].append({'id':'synthetic-prefetch-breach','verification_id':r['verification_id'],'context_id':c['id'],
                             'configuration':c['security_configuration'],'model_version':c['model_version'],
                             'case_id':r['case_id'],'origin':'prescribed_case','result':'observed_breach',
                             'original_reference':'synthetic-test://observed-preview-request'})
        r['result']='satisfied'
        self.assertTrue(any('known mandatory breach' in e for e in policy.plan_errors(p,self.matrix,self.schema)))
        p=copy.deepcopy(self.plans['hybrid'])
        r=self.record(p,'Agent:2.2.3:url_hardening','remote-route')
        r['result']='advisory_not_performed'
        self.assertEqual([],policy.plan_errors(p,self.matrix,self.schema))

    def test_missing_security_duties_rejected_even_if_both_sources_change(self):
        for clause in ('Requester Attribution','explicit user consent before opening that exact URL',
                       'MUST NOT automatically prefetch','does not enable the client or LLM to inspect',
                       'Trusted Presentation Separation','trusted integration/admission context'):
            with self.subTest(clause=clause):
                self.assertTrue(alignment.alignment_errors(self.spec.replace(clause,'REMOVED'),
                                                          self.guide.replace(clause,'REMOVED'),self.manifest))

    def test_unrelated_controls_and_original_sanitization_acceptance_are_retained(self):
        base='6b9535a9a6880415b07290f8e1f3b99b6496e1ff'
        def original(name):
            try:return subprocess.check_output(['git','show',base+':AI Profile/'+name],cwd=ROOT,text=True,stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:self.skipTest('pre-456 source unavailable')
        oldspec=alignment.sections(original('AI Agent Specification.md'),'requirement')
        oldguide=alignment.sections(original('AI Agent Test Guide.md'),'test')
        newspec=alignment.sections(self.spec,'requirement')
        newguide=alignment.sections(self.guide,'test')
        for cid in oldspec:
            if cid not in {'2.2.3','6.2.2'}:
                self.assertEqual(oldspec[cid],newspec[cid],cid)
                self.assertEqual(oldguide[cid],newguide[cid],cid)
        previous=alignment.verification(oldguide['6.2.2'])
        current=alignment.verification(newguide['6.2.2'])
        self.assertTrue(current.startswith(previous+'\n'), 'Original control-token/unauthorized-execution duties must be retained verbatim')
        self.assertEqual(37,len(newspec))
        self.assertEqual(95,len(policy.inventory(self.matrix)))
        self.assertIn('6.2.2',self.manifest['allowed_audit_changes'])
        self.assertIn('2.2.3',self.manifest['allowed_audit_changes'])
        self.assertIn('456',self.manifest['normative_changes'])


if __name__=='__main__':
    unittest.main()
