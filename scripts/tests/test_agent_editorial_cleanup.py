"""Editorial-only #546 preservation and link checks; no product tests."""
from pathlib import Path
import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
AI=ROOT/'AI Profile'
BASE='6adc64fdcf4f5739ccb2196aaf4b85f651959f2a'
sys.path.insert(0,str(ROOT/'scripts'))
import agent_policy_alignment as alignment
import ai_assessment_lint as ai_lint
from ai_document_set import DOCUMENTS, ASSETS, INDEXES, errors


def original(path):
    return subprocess.check_output(['git','show',BASE+':'+path],cwd=ROOT,text=True,stderr=subprocess.DEVNULL)


GUIDE_NAVIGATION_EDITS = {
    'See section 3.1 for mandatory Input Validation and Sanitization requriements.':
        'See [§3.1 Input Validation and Sanitization](#31-input-validation-and-sanitization) for the mandatory requirements.',
    'See section 3.1 for mandatory Input Validation and Sanitization and section 3.2 for madatory Output Validation and Sanitization requirements.':
        'See [§3.1 Input Validation and Sanitization](#31-input-validation-and-sanitization) and [§3.2 Output Validation and Sanitization](#32-output-validation-and-sanitization) for the mandatory requirements.',
}


def guide_navigation(text):
    for old, new in GUIDE_NAVIGATION_EDITS.items():
        text = text.replace(old, new)
    return text


def typography(text):
    """Word spacing/hyphenation only: identifiers, numbers and letter order stay."""
    return re.sub(r'[^\w]', '', text)


def canonical(value):
    if isinstance(value,dict):return {k:canonical(v) for k,v in value.items()}
    if isinstance(value,list):return [canonical(v) for v in value]
    if isinstance(value,str):return typography(value)
    return value


class EditorialCleanupTests(unittest.TestCase):
    def test_no_contributor_placeholders_and_no_broken_local_links(self):
        self.assertEqual([],errors(ROOT))
        for name in DOCUMENTS:
            text=(AI/name).read_text()
            self.assertNotRegex(text,r'(?im)^\s*[-*]\s+(?:TBD|TODO)(?:\s|$)')
        for name in ('AI Tool Specification.md','AI Tool Testing Guide.md'):
            text=(AI/name).read_text()
            self.assertIn('## Acknowledgements',text)
            self.assertEqual(1,text.count('### Contributors\n'))
        self.assertIn('AI%20Agent%20Test%20Guide.md#3-production-equivalent-fixture-approval',
                      (AI/'AI Agent Specification.md').read_text())
        guide=(AI/'AI Agent Test Guide.md').read_text()
        self.assertIn('#31-input-validation-and-sanitization',guide)
        self.assertIn('#32-output-validation-and-sanitization',guide)
        for name in ('AI Tool Specification.md','AI Agent-Tool Identity and Consent Wire Format.md'):
            text=(AI/name).read_text()
            self.assertIn('/whitepapers/model-context-protocol-security.md',text)
            self.assertNotIn('/main/model-context-protocol-security.md',text)

    def test_placeholder_and_support_index_link_regressions_are_rejected(self):
        with tempfile.TemporaryDirectory() as dirname:
            root=Path(dirname)
            for rel in ['AI Profile/'+n for n in DOCUMENTS]+list(ASSETS)+list(INDEXES)+['CONTRIBUTING.md']:
                target=root/rel
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((ROOT/rel).read_bytes())
            self.assertEqual([],errors(root))
            p=root/'AI Profile/AI Tool Specification.md'
            p.write_text(p.read_text()+'\n* TBD\n')
            self.assertTrue(any('placeholder' in e for e in errors(root)))
            p=root/'assessment/ai/README.md'
            p.write_text(p.read_text()+'\n[missing record](missing-record.json)\n')
            self.assertTrue(any('missing local link target missing-record.json' in e for e in errors(root)))

    def test_agent_acceptance_and_mode_scope_are_unchanged(self):
        for name,role in [('AI Agent Specification.md','requirement'),('AI Agent Test Guide.md','test')]:
            previous=alignment.sections(original('AI Profile/'+name),role)
            current=alignment.sections((AI/name).read_text(),role)
            self.assertEqual(list(previous),list(current))
            for cid in previous:
                before=alignment.table_assertions(previous[cid]) if role=='requirement' else alignment.verification(previous[cid])
                after=alignment.table_assertions(current[cid]) if role=='requirement' else alignment.verification(current[cid])
                self.assertEqual(before,after,cid+' acceptance changed during editorial cleanup')
        rel='assessment/ai/AI Agent Assessment Applicability.json'
        before=json.loads(original(rel))
        after=json.loads((ROOT/rel).read_text())
        # Only a new immutable source snapshot is allowed after this check.
        for field in ('source_baseline',):before[field]=after[field]
        for field in ('source_revision','reference'):before['procedure_catalog'][field]=after['procedure_catalog'][field]
        self.assertEqual(before,after,'Agent scope, populations and evidence changed')
        for rel in ('assessment/ai/AI Agent Assessment Plan.schema.json','scripts/tests/fixtures/ai/AI Agent Assessment Examples.json'):
            self.assertEqual(json.loads(original(rel)),json.loads((ROOT/rel).read_text()))

    def test_tool_scope_tiers_and_assertions_allow_only_word_spacing(self):
        for name,role in [('AI Tool Specification.md',False),('AI Tool Testing Guide.md',True)]:
            before,errs=ai_lint.extract(original('AI Profile/'+name),'Tool',role,'before')
            after,errs2=ai_lint.extract((AI/name).read_text(),'Tool',role,'after')
            self.assertEqual([],errs+errs2)
            self.assertEqual(set(before),set(after))
            for cid in before:
                def control_body(text):
                    return re.split(r'(?m)^## (?:References|Contributors|Acknowledgements|Local Android and excluded standalone variants)\b', text)[0]
                self.assertEqual(typography(control_body(before[cid]['body'])),typography(control_body(after[cid]['body'])),cid)
        for rel in ('assessment/ai/AI Tool Assessment Cases.json','assessment/ai/AI Tool Minimum Security Register.json'):
            self.assertEqual(canonical(json.loads(original(rel))),canonical(json.loads((ROOT/rel).read_text())),
                             'Tool requirements/scope/tier values changed beyond whitespace')
        rel='AI Profile/AI Tool Local Android Requirements.md'
        self.assertEqual(original(rel),(ROOT/rel).read_text(),'Retained Android source must remain byte-identical')

    def test_contract_and_wire_keep_authority_and_requirement_text(self):
        for name in ('AI Agent-Tool Interface Contract.md','AI Agent-Tool Identity and Consent Wire Format.md'):
            old=original('AI Profile/'+name)
            new=(AI/name).read_text()
            # Linked references and introduction navigation are outside normative bodies.
            if name.endswith('Wire Format.md'):
                old=old.split('## References\n',1)[0]
                new=new.split('## References\n',1)[0]
            strip=lambda t:re.sub(r'\[([^\]]+)\]\([^)]+\)',r'\1',t)
            old=strip(old).replace('The paired candidate records','The paired documents record')
            self.assertEqual(typography(old),typography(strip(new)),name)


if __name__=='__main__':
    unittest.main()
