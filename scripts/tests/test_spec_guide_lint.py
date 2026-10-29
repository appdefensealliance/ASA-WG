"""Regressions for demonstrated parser, authority and assessment risks."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import ai_assessment_lint as ai
import spec_guide_lint as lint


class AssessmentLintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = SCRIPTS.parent
        cls.register = json.loads((root/'AI Profile/AI Tool Minimum Security Register.json').read_text())
        cls.ledger = json.loads((root/'AI Profile/AI Tool Assessment Cases.json').read_text())
        cls.spec, _ = ai.extract((root/'AI Profile/AI Tool Specification.md').read_text(), 'Tool', False, 'spec')
        cls.guide, _ = ai.extract((root/'AI Profile/AI Tool Testing Guide.md').read_text(), 'Tool', True, 'guide')
        cls.agent, _ = ai.extract((root/'AI Profile/AI Agent Test Guide.md').read_text(), 'Agent', True, 'agent')

    def metadata_errors(self, ledger=None, register=None):
        return ai.tool_metadata(self.spec,self.guide,register or self.register,ledger or self.ledger)

    def test_zero_parse_rejected(self):
        records, errors = ai.extract('# A document\nNo assessment IDs.', 'Tool', False, 'spec')
        self.assertEqual(records,{})
        self.assertTrue(any('zero' in e for e in errors))

    def test_unmarked_requirement_rejected(self):
        _, errors = ai.extract('### 1.1.1 Authority\nA required control.', 'Tool', False, 'spec')
        self.assertTrue(any('exactly one' in e for e in errors))

    def test_duplicate_heading_not_silently_collapsed(self):
        text = '### 1.1.1 Authority\n<!-- ada:requirement Tool:1.1.1 -->\n'*2
        _, errors = ai.extract(text,'Tool',False,'spec')
        self.assertTrue(any('duplicate' in e for e in errors))

    def test_same_title_keeps_distinct_ids(self):
        text = '### 1.1.1 Isolation\n<!-- ada:requirement Tool:1.1.1 -->\n### 8.2.1 Isolation\n<!-- ada:requirement Tool:8.2.1 -->\n'
        records, errors = ai.extract(text,'Tool',False,'spec')
        self.assertEqual(set(records),{'Tool:1.1.1','Tool:8.2.1'})
        self.assertEqual(errors,[])

    def test_wrong_actor_mapping_rejected(self):
        text = '## 1.1 Identity\n<!-- ada:test Tool:1.1 covers=Agent:6.1.1 -->\n'
        _, errors = ai.extract(text,'Tool',True,'guide')
        self.assertTrue(any('wrong-actor' in e for e in errors))

    def test_casa_criterion_changed_with_same_id_count_rejected(self):
        register = copy.deepcopy(self.register)
        register['CASA_floor'][0]['verification'] = 'weakened criterion'
        self.assertTrue(any('CASA' in e for e in self.metadata_errors(register=register)))

    def test_missing_source_case_rejected(self):
        ledger = copy.deepcopy(self.ledger)
        ledger['tests'][0]['cases'].pop()
        self.assertTrue(any('210' in e for e in self.metadata_errors(ledger=ledger)))

    def test_local_android_demotion_rejected(self):
        ledger = copy.deepcopy(self.ledger)
        ledger['tests'][0]['cases'][0]['gate_by_variant']['local_android_tool'] = 'ADVISORY'
        self.assertTrue(any('Android' in e for e in self.metadata_errors(ledger=ledger)))

    def test_mixed_case_requires_atom_split(self):
        ledger = copy.deepcopy(self.ledger)
        case = next(c for t in ledger['tests'] for c in t['cases'] if c['proposed_disposition']=='MIXED_BASELINE_AND_ADVISORY')
        case['requires_atom_split'] = False
        self.assertTrue(any('split' in e for e in self.metadata_errors(ledger=ledger)))

    def test_duplicate_case_rejected(self):
        ledger = copy.deepcopy(self.ledger)
        ledger['tests'][0]['cases'][1]['case_id'] = ledger['tests'][0]['cases'][0]['case_id']
        self.assertTrue(any('Duplicate case' in e for e in self.metadata_errors(ledger=ledger)))

    def test_research_reference_must_resolve(self):
        register = copy.deepcopy(self.register)
        register['research_sources'] = []
        self.assertTrue(any('research reference' in e for e in self.metadata_errors(register=register)))

    def test_log_evidence_requires_named_attestation(self):
        agent = copy.deepcopy(self.agent)
        agent['Agent:5.2.1']['body'] = agent['Agent:5.2.1']['body'].replace('Evidence type: Attestation','Evidence type: Functional Observation')
        self.assertTrue(any('5.2.1' in e for e in ai.agent_evidence(agent)))

    def test_baseline_cannot_hide_assessment_errors(self):
        result = {'spec_count':1,'guide_count':1,'untested':{},'orphans':{},'errors':['invalid authority mapping']}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(lint.render('AI Tool',result,{'AI Tool':{}},False))

    def test_legacy_zero_and_duplicate_id_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(lint,'ROOT',directory):
            file = Path(directory)/'sample.md'
            file.write_text('no IDs\n')
            with self.assertRaisesRegex(ValueError,'zero'):
                lint.extract('sample.md',r'^### (\d+\.\d+\.\d+)','id')
            file.write_text('### 1.1.1 First\n### 1.1.1 Second\n')
            with self.assertRaisesRegex(ValueError,'duplicate'):
                lint.extract('sample.md',r'^### (\d+\.\d+\.\d+)','id')


if __name__ == '__main__':
    unittest.main()
