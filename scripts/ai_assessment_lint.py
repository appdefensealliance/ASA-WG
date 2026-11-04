"""Stable AI requirement mappings, assessment gates and evidence types.

Structural and assessment failures are never accepted baseline debt.
"""
import hashlib
import json
from pathlib import Path
import re
from tool_case_render import CONTEXT_FIELDS, RULE_FIELDS, render_case, render_context, render_rules, summary

ID = r'[A-Za-z0-9.-]+'
REQ = re.compile(r'^<!-- ada:requirement ('+ID+':'+ID+r') -->$')
TEST = re.compile(r'^<!-- ada:test ('+ID+':'+ID+r') covers=('+ID+':'+ID+r'(?:,'+ID+':'+ID+r')*) -->$')
CLASSES = {'BASELINE_GATE', 'ADVISORY', 'MIXED_BASELINE_AND_ADVISORY',
           'CURRENT_UNCHANGED_OUTSIDE_TARGET_VARIANT'}
CASA_PIN = '7ad3cce0cbb8d6ece5a096afe4a669c1604af583'
# Exact original v2.1.1 floor, including criteria, exceptions and alternatives.
CASA_DIGEST = 'cbd96693460e37854063da93970e45082886bcf468f5ede64285f24892066f49'
# Case IDs, text and tiers retained from the existing PR #538 source snapshot.
TOOL_SOURCE_PIN = '34705233b5f249d3fd4e8fc82cbb5e765ef94b81'
TOOL_CASE_SOURCE_DIGEST = 'c17b0522600298b0e00ea3d93edad1093cd8c295e000f20dd87d98d187eb5f1e'


def extract(text, namespace, guide, label):
    if namespace == 'Agent':
        heading = r'^#{1,6}\s+(\d+\.\d+\.\d+)\b'
    elif guide:
        heading = r'^#{1,6}\s+(\d+\.\d+(?:\.\d+)?|MIN-S\d{2})\b'
    else:
        heading = r'^#{1,6}\s+(\d+\.\d+\.\d+|TG-\d+\.\d+|MIN-S\d{2})\b'
    lines = text.splitlines()
    headings = [(i, re.match(heading,line).group(1)) for i,line in enumerate(lines)
                if re.match(heading,line)]
    records, errors, consumed, seen = {}, [], set(), set()
    tag = TEST if guide else REQ
    for index, (start, hid) in enumerate(headings):
        end = headings[index+1][0] if index+1<len(headings) else len(lines)
        if hid in seen:
            errors.append(f'{label}:{start+1}: duplicate heading {hid}')
        seen.add(hid)
        matches = [(i, tag.fullmatch(lines[i])) for i in range(start+1,end)
                   if tag.fullmatch(lines[i])]
        if len(matches) != 1:
            errors.append(f'{label}:{start+1}: {hid} requires exactly one assessment tag')
            continue
        lineno, match = matches[0]
        consumed.add(lineno)
        key = match.group(1)
        if key != f'{namespace}:{hid}':
            errors.append(f'{label}:{lineno+1}: tag {key} differs from heading/actor {hid}')
        if key in records:
            errors.append(f'{label}:{lineno+1}: duplicate tag {key}')
        row = {'label':hid,'line':start+1,'body':'\n'.join(lines[start+1:end])}
        if guide:
            targets = match.group(2).split(',')
            if len(set(targets)) != len(targets):
                errors.append(f'{label}:{lineno+1}: duplicate coverage target')
            if any(not t.startswith(namespace+':') for t in targets):
                errors.append(f'{label}:{lineno+1}: wrong-actor coverage target')
            row['covers'] = set(targets)
        records[key] = row
    for i,line in enumerate(lines):
        if '<!-- ada:' in line and i not in consumed:
            errors.append(f'{label}:{i+1}: malformed, misplaced or wrong-role tag')
    if not records:
        errors.append(f'{label}: parsed zero assessment tags')
    return records, errors


def tool_metadata(spec, guide, register, ledger):
    errors = []
    floor = register.get('CASA_floor',[])
    floor_ids = {x.get('id') for x in floor}
    digest = hashlib.sha256(json.dumps(floor,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    if len(floor)!=48 or len(floor_ids)!=48 or digest!=CASA_DIGEST:
        errors.append('Published CASA 48-ID criteria/scope/alternatives snapshot changed')
    if register.get('source_pins',{}).get('CASA')!=CASA_PIN:
        errors.append('Published CASA source pin changed')
    props = register.get('leading_practices',[])
    expected = {f'MIN-S{i:02d}' for i in range(1,22)}
    if len(props)!=21 or {x.get('id') for x in props}!=expected:
        errors.append('Leading-practice register needs 21 unique MIN-S properties')
    sources = {s.get('id') for s in register.get('research_sources',[])}
    for prop in props:
        pid = prop.get('id')
        if f'Tool:{pid}' not in spec or f'Tool:{pid}' not in guide:
            errors.append(f'{pid}: missing minimum coverage')
        for field in ['scope','interface_condition','publication_condition','actor_condition']:
            if not prop.get(field):
                errors.append(f'{pid}: missing {field}')
        for item in prop.get('market_research_evidence',[]):
            if not item.get('references') or set(item['references'])-sources:
                errors.append(f'{pid}: unresolved research reference')
        if set(prop.get('CASA_ids',[]))-floor_ids:
            errors.append(f'{pid}: unknown CASA relationship')
    if ledger.get('schema_version') != 2:
        errors.append('Tool case ledger requires assessment schema version 2')
    rules = ledger.get('assessment_rules', {})
    if not isinstance(rules, dict):
        rules = {}
    for field in RULE_FIELDS:
        if not isinstance(rules.get(field), str) or not rules[field].strip():
            errors.append(f'Tool case ledger: missing assessment rule {field}')
    if rules.get('target_variant') != 'remote_http_tool':
        errors.append('Tool assessment overlay must target only remote_http_tool')
    tests = ledger.get('tests',[])
    test_ids, case_ids = set(),set()
    for test in tests:
        tid = test.get('id')
        if tid in test_ids:
            errors.append(f'Duplicate Tool test {tid}')
        test_ids.add(tid)
        row = guide.get(f'Tool:{tid}')
        context = test.get('assessment_context', {})
        if not isinstance(context, dict):
            context = {}
        context_valid = context.get('id') == tid and context.get('variant') == 'remote_http_tool'
        for field in CONTEXT_FIELDS:
            if not isinstance(context.get(field), str) or not context[field].strip():
                context_valid = False
        if not context_valid:
            errors.append(f'Tool {tid}: missing/invalid actor, applicability, fixture or observation context')
        elif row and render_context(test) not in row['body']:
            errors.append(f'Tool {tid}: Guide and ledger assessment context differ')
        targets = {f'Tool:{x}' for x in test.get('requirement_ids',[])}
        if not targets or not targets <= set(spec):
            errors.append(f'Tool {tid}: unknown/missing requirement target')
        if row is None or row['covers']!=targets:
            errors.append(f'Tool {tid}: Guide and ledger coverage differ')
        if row:
            for field in ['mandatory_outcome','advisory_outcome']:
                if not test.get(field) or test[field] not in row['body']:
                    errors.append(f'Tool {tid}: Guide and ledger outcome/enhancement text differ')
        if test.get('gate_class') not in CLASSES:
            errors.append(f'Tool {tid}: invalid test gate')
        if set(test.get('CASA_floor_ids',[]))-floor_ids:
            errors.append(f'Tool {tid}: unknown CASA reference')
        if {f'MIN-{x}' for x in test.get('shared_group_ids',[])}-expected:
            errors.append(f'Tool {tid}: unknown minimum reference')
        for case in test.get('cases',[]):
            cid = case.get('case_id')
            if cid in case_ids:
                errors.append(f'Duplicate case {cid}')
            case_ids.add(cid)
            if not isinstance(cid,str) or not cid.startswith(str(tid)+'/V'):
                errors.append(f'{cid}: wrong test ownership')
            for field in ['current_text','requirement_text','original_assurance_tier']:
                if not case.get(field):
                    errors.append(f'{cid}: missing source/proposed text or tier')
            gate = case.get('disposition')
            if gate not in CLASSES:
                errors.append(f'{cid}: invalid case gate')
            if case.get('requires_atom_split') != (gate=='MIXED_BASELINE_AND_ADVISORY'):
                errors.append(f'{cid}: mixed case must split mandatory/advisory atoms')
            assessment = case.get('assessment', {})
            assessment_valid = isinstance(assessment, dict) and assessment.get('context_id') == tid
            if not assessment_valid:
                errors.append(f'{cid}: missing/invalid case assessment context')
                assessment = {}
            mandatory = assessment.get('mandatory_assertions')
            advisory = assessment.get('advisory_assertions')
            for assertions, key, prefix in [(mandatory, 'mandatory_assertions', 'M'),
                                             (advisory, 'advisory_assertions', 'S')]:
                if not isinstance(assertions, list):
                    errors.append(f'{cid}: missing structured {key}')
                    assessment_valid = False
                    continue
                seen_assertions = set()
                for assertion in assertions:
                    if not isinstance(assertion, dict):
                        errors.append(f'{cid}: invalid {key} assertion')
                        assessment_valid = False
                        continue
                    aid = assertion.get('id')
                    if not isinstance(aid, str) or not re.fullmatch(re.escape(str(cid)) + '/' + prefix + r'\d{2}', aid) or aid in seen_assertions:
                        errors.append(f'{cid}: invalid/duplicate {key} assertion ID')
                        assessment_valid = False
                    if isinstance(aid, str):
                        seen_assertions.add(aid)
                    for field in ['exercise', 'expected']:
                        value = assertion.get(field)
                        if not isinstance(value, str) or not value.strip() or re.search(r'mandatory outcome in|required security outcome for|meet the above baseline scope', value, re.I):
                            errors.append(f'{cid}: missing/generic {key} {field}')
                            assessment_valid = False
                    refs = assertion.get('requirement_ids')
                    if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) for ref in refs) or not set(refs) <= targets or len(set(refs)) != len(refs):
                        errors.append(f'{cid}: unresolved/wrong-case {key} requirement references')
                        assessment_valid = False
            has_mandatory = isinstance(mandatory, list) and bool(mandatory)
            has_advisory = isinstance(advisory, list) and bool(advisory)
            expected_shape = {
                'BASELINE_GATE': (True, False),
                'ADVISORY': (False, True),
                'MIXED_BASELINE_AND_ADVISORY': (True, True),
                'CURRENT_UNCHANGED_OUTSIDE_TARGET_VARIANT': (False, False),
            }.get(gate)
            if expected_shape != (has_mandatory, has_advisory):
                errors.append(f'{cid}: gate requires actual separate mandatory/advisory assertions')
                assessment_valid = False
            if gate == 'CURRENT_UNCHANGED_OUTSIDE_TARGET_VARIANT' and not assessment.get('retained_source'):
                errors.append(f'{cid}: retained variant requires original-source assessment basis')
                assessment_valid = False
            if assessment_valid:
                if summary(case) != case.get('requirement_text'):
                    errors.append(f'{cid}: proposed text differs from structured assertions')
                if row and render_case(case) not in row['body']:
                    errors.append(f'{cid}: Guide and ledger assertion exercises/references differ')
            variants = case.get('gate_by_variant',{})
            if variants.get('remote_http_tool')!=gate:
                errors.append(f'{cid}: remote gate differs from declared disposition')
            if variants.get('local_android_tool')!='RETAIN_CURRENT_TEST_GATE_IF_ORIGINALLY_APPLICABLE':
                errors.append(f'{cid}: local Android test strength changed')
            if variants.get('other_local_mobile')!='OUTSIDE_STANDALONE_TOOL_SCOPE':
                errors.append(f'{cid}: excluded standalone local/desktop/iOS Tool variant acquired an assessment gate')
            if row and f'**{cid} — {gate}:**' not in row['body']:
                errors.append(f'{cid}: Guide case missing or gate differs')
            if row and (not case.get('requirement_text') or case['requirement_text'] not in row['body']):
                errors.append(f'{cid}: Guide and ledger proposed case text differ')
    if len(tests)!=40 or len(test_ids)!=40 or len(case_ids)!=210:
        errors.append('Case ledger must retain 40 unique tests and 210 unique source cases')
    retained_source = [{'test_id': test.get('id'), 'case_id': case.get('case_id'),
                        'tier': case.get('original_assurance_tier'), 'text': case.get('current_text')}
                       for test in tests for case in test.get('cases', [])]
    source_digest = hashlib.sha256(json.dumps(retained_source, sort_keys=True,
                                              separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    if source_digest != TOOL_CASE_SOURCE_DIGEST or ledger.get('source_pin') != TOOL_SOURCE_PIN:
        errors.append('Retained Tool source case IDs/text/tiers or source pin changed')
    if {x.split(':',1)[1] for x in guide if not x.startswith('Tool:MIN-')}!=test_ids:
        errors.append('Guide and ledger test inventories differ')
    if len(register.get('legacy_PR_324_topics',[]))!=6:
        errors.append('All six earlier governance topics require a disposition')
    return errors


def agent_evidence(guide):
    errors = []
    required = {'Agent:2.4.2':'Attestation','Agent:5.2.1':'Attestation',
                'Agent:3.1.3':'Attestation','Agent:5.2.2':'Document Review'}
    for key,row in guide.items():
        block = re.search(r'^#### Evidence\s*\n(.*?)(?=^#### Test Procedure)',row['body'],re.M|re.S)
        if not block:
            errors.append(f'{key}: Evidence/Test Procedure block missing')
            continue
        evidence = block.group(1)
        if 'Evidence type: Functional Observation' not in evidence:
            errors.append(f'{key}: Functional Observation type missing')
        for kind in ['Attestation','Document Review']:
            for tag in re.finditer(r'\*\*Evidence type: '+kind+r'.*?\*\*([^\n]*)',evidence):
                if 'Named artifact:' not in tag.group(1) or not tag.group(1).split('Named artifact:',1)[1].strip():
                    errors.append(f'{key}: {kind} must name an artifact')
        if key in required and f'Evidence type: {required[key]}' not in evidence:
            errors.append(f'{key}: required {required[key]} missing')
        if 'AL0/AL1 static evidence' in row['body']:
            errors.append(f'{key}: stale static-evidence instruction in Agent AL2 guide')
    if len(guide)!=37:
        errors.append('Agent Guide must retain all 37 source audit IDs')
    return errors


def lint_pair(root, name, cfg):
    root = Path(root)
    spec, e1 = extract((root/cfg['spec']).read_text(),cfg['namespace'],False,cfg['spec'])
    guide,e2 = extract((root/cfg['guide']).read_text(),cfg['namespace'],True,cfg['guide'])
    covered = set().union(*(row['covers'] for row in guide.values())) if guide else set()
    errors = e1+e2
    if name=='AI Tool':
        register = json.loads((root/'assessment/ai/AI Tool Minimum Security Register.json').read_text())
        ledger = json.loads((root/'assessment/ai/AI Tool Assessment Cases.json').read_text())
        errors += tool_metadata(spec,guide,register,ledger)
        if isinstance(ledger.get('assessment_rules'), dict) and all(isinstance(ledger['assessment_rules'].get(field), str) for field in RULE_FIELDS):
            if render_rules(ledger) not in (root/cfg['guide']).read_text():
                errors.append('Tool Guide and ledger individual grading rules differ')
    elif name=='AI Agent':
        errors += agent_evidence(guide)
    return {'spec_count':len(spec),'guide_count':len(guide),'errors':errors,
            'untested':{k:spec[k] for k in set(spec)-covered},
            'orphans':{k:v for k,v in guide.items() if v['covers']-set(spec)}}
