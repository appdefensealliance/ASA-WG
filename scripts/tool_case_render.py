"""Render the proposed remote Tool case rubric from its structured ledger."""
import argparse
import json
from pathlib import Path
import re

LEDGER = Path('assessment/ai/AI Tool Assessment Cases.json')
GUIDE = Path('AI Profile/AI Tool Testing Guide.md')
CONTEXT_FIELDS = ('actor', 'applies_when', 'setup_and_controls', 'observe')
RULE_FIELDS = ('source_precedence', 'tiers', 'minimum_result', 'enhancement_result',
               'mandatory_breach_from_advisory', 'positive_controls',
               'result_record', 'retained_variants')


def render_rules(ledger):
    rules = ledger['assessment_rules']
    lines = ['<!-- assessment-rules -->', '## Individual case grading', '']
    lines.extend('- **' + key.replace('_', ' ').capitalize() + ':** ' + rules[key]
                 for key in RULE_FIELDS)
    lines.append('<!-- /assessment-rules -->')
    return '\n'.join(lines)


def summary(case):
    assessment = case['assessment']
    parts = []
    for key, strength in [('mandatory_assertions', 'MUST'),
                          ('advisory_assertions', 'SHOULD')]:
        parts.extend(strength + ': ' + item['expected'] for item in assessment[key])
    return ' '.join(parts) if parts else assessment['retained_source']


def render_context(test):
    context = test['assessment_context']
    labels = ('Actor', 'Applicability', 'Setup and positive/negative controls', 'Observe')
    lines = [f'<!-- assessment-context:{test["id"]} -->',
             '**Case assessment context — remote HTTP Tool:**', '']
    lines.extend(f'- **{label}:** {context[field]}'
                 for field, label in zip(CONTEXT_FIELDS, labels))
    lines.append(f'<!-- /assessment-context:{test["id"]} -->')
    return '\n'.join(lines)


def render_case(case):
    lines = [f'- **{case["case_id"]} — {case["disposition"]}:** {summary(case)}']
    assessment = case['assessment']
    for key in ('mandatory_assertions', 'advisory_assertions'):
        for item in assessment[key]:
            lines.append(f'  - **{item["id"]} exercise:** {item["exercise"]}')
            lines.append(f'  - **{item["id"]} source requirements:** ' + ', '.join(item['requirement_ids']) + '.')
    return '\n'.join(lines)


def render_guide(text, ledger):
    rules = render_rules(ledger)
    marker = re.compile(r'^<!-- assessment-rules -->\n.*?^<!-- /assessment-rules -->', re.M | re.S)
    if marker.search(text):
        text = marker.sub(lambda _: rules, text)
    else:
        first = re.search(r'^## 1\.1\b', text, re.M)
        if not first:
            raise ValueError('Missing first Tool test heading')
        text = text[:first.start()] + rules + '\n\n' + text[first.start():]
    for test in ledger['tests']:
        context = render_context(test)
        marker = re.compile(r'^<!-- assessment-context:' + re.escape(test['id'])
                            + r' -->\n.*?^<!-- /assessment-context:'
                            + re.escape(test['id']) + r' -->', re.M | re.S)
        if marker.search(text):
            text = marker.sub(lambda _: context, text)
        else:
            first = test['cases'][0]['case_id']
            start = re.search(r'^- \*\*' + re.escape(first) + r' — ', text, re.M)
            if not start:
                raise ValueError(f'Missing Guide case {first}')
            text = text[:start.start()] + context + '\n\n' + text[start.start():]
        for case in test['cases']:
            pattern = re.compile(r'^- \*\*' + re.escape(case['case_id'])
                                 + r' — [^\n]*(?:\n[ \t]+[^\n]*)*', re.M)
            text, count = pattern.subn(lambda _: render_case(case), text)
            if count != 1:
                raise ValueError(f'{case["case_id"]}: expected exactly one Guide case, found {count}')
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Update derived case text and Guide blocks')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    ledger_path, guide_path = args.root / LEDGER, args.root / GUIDE
    original = ledger_path.read_text()
    ledger = json.loads(original)
    for test in ledger['tests']:
        for case in test['cases']:
            case['requirement_text'] = summary(case)
    rendered_ledger = json.dumps(ledger, indent=2, ensure_ascii=False) + '\n'
    text = guide_path.read_text()
    rendered_guide = render_guide(text, ledger)
    if args.write:
        ledger_path.write_text(rendered_ledger)
        guide_path.write_text(rendered_guide)
    elif rendered_ledger != original or rendered_guide != text:
        parser.exit(1, 'Tool case ledger/Guide rendering differs; run scripts/tool_case_render.py --write\n')
    print('Tool cases: 40 contexts and 210 case rubrics synchronized.')


if __name__ == '__main__':
    main()
