"""Stable AI requirement mappings, assessment gates and evidence types.

Structural and assessment failures are never accepted baseline debt.
"""
import hashlib
import json
from pathlib import Path
import re

ID = r'[A-Za-z0-9.-]+'
REQ = re.compile(r'^<!-- ada:requirement ('+ID+':'+ID+r') -->$')
TEST = re.compile(r'^<!-- ada:test ('+ID+':'+ID+r') covers=('+ID+':'+ID+r'(?:,'+ID+':'+ID+r')*) -->$')
CLASSES = {'BASELINE_GATE', 'ADVISORY', 'MIXED_BASELINE_AND_ADVISORY',
           'CURRENT_UNCHANGED_OUTSIDE_TARGET_VARIANT'}
CASA_PIN = '7ad3cce0cbb8d6ece5a096afe4a669c1604af583'
# Exact original v2.1.1 floor, including criteria, exceptions and alternatives.
CASA_DIGEST = 'cbd96693460e37854063da93970e45082886bcf468f5ede64285f24892066f49'


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
    tests = ledger.get('tests',[])
    test_ids, case_ids = set(),set()
    for test in tests:
        tid = test.get('id')
        if tid in test_ids:
            errors.append(f'Duplicate Tool test {tid}')
        test_ids.add(tid)
        row = guide.get(f'Tool:{tid}')
        targets = {f'Tool:{x}' for x in test.get('requirement_ids',[])}
        if not targets or not targets <= set(spec):
            errors.append(f'Tool {tid}: unknown/missing requirement target')
        if row is None or row['covers']!=targets:
            errors.append(f'Tool {tid}: Guide and ledger coverage differ')
        if row:
            for field in ['proposed_MUST_atoms','proposed_SHOULD_atoms']:
                if not test.get(field) or test[field] not in row['body']:
                    errors.append(f'Tool {tid}: Guide and ledger outcome/enhancement text differ')
        if test.get('proposed_gate_class') not in CLASSES:
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
            for field in ['current_text','proposed_text','original_assurance_tier']:
                if not case.get(field):
                    errors.append(f'{cid}: missing source/proposed text or tier')
            gate = case.get('proposed_disposition')
            if gate not in CLASSES:
                errors.append(f'{cid}: invalid case gate')
            if case.get('requires_atom_split') != (gate=='MIXED_BASELINE_AND_ADVISORY'):
                errors.append(f'{cid}: mixed case must split mandatory/advisory atoms')
            variants = case.get('gate_by_variant',{})
            if variants.get('remote_http_tool')!=gate:
                errors.append(f'{cid}: remote gate differs from declared disposition')
            if variants.get('local_android_tool')!='RETAIN_CURRENT_TEST_GATE_IF_ORIGINALLY_APPLICABLE':
                errors.append(f'{cid}: local Android test strength changed')
            if variants.get('other_local_mobile')!='CURRENT_UNCHANGED_OR_UNDECIDED':
                errors.append(f'{cid}: other retained variant changed')
            if row and f'**{cid} — {gate}:**' not in row['body']:
                errors.append(f'{cid}: Guide case missing or gate differs')
            if row and (not case.get('proposed_text') or case['proposed_text'] not in row['body']):
                errors.append(f'{cid}: Guide and ledger proposed case text differ')
    if len(tests)!=40 or len(test_ids)!=40 or len(case_ids)!=210:
        errors.append('Case ledger must retain 40 unique tests and 210 unique source cases')
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
        register = json.loads((root/'AI Profile/AI Tool Minimum Security Register.json').read_text())
        ledger = json.loads((root/'AI Profile/AI Tool Assessment Cases.json').read_text())
        errors += tool_metadata(spec,guide,register,ledger)
    elif name=='AI Agent':
        errors += agent_evidence(guide)
    return {'spec_count':len(spec),'guide_count':len(guide),'errors':errors,
            'untested':{k:spec[k] for k in set(spec)-covered},
            'orphans':{k:v for k,v in guide.items() if v['covers']-set(spec)}}
