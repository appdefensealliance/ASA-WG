"""Maintained AI document inventory and supporting-asset link validation.

This validates repository structure, not governance approval, real security
results, or authority to issue certificates. Versioning follows CONTRIBUTING.
"""
from pathlib import Path
import json
import re
from urllib.parse import unquote, urlsplit

DOCUMENTS = (
    'AI Agent Specification.md', 'AI Agent Test Guide.md',
    'AI Tool Specification.md', 'AI Tool Testing Guide.md',
    'AI Agent-Tool Interface Contract.md', 'AI Agent-Tool Identity and Consent Wire Format.md',
    'AI Tool Local Android Requirements.md', 'AI Tool Minimum Security Register.md',
)
ASSETS = (
    'assessment/ai/AI Agent Assessment Applicability.json',
    'assessment/ai/AI Agent Assessment Plan.schema.json',
    'assessment/ai/AI Tool Assessment Cases.json',
    'assessment/ai/AI Tool Minimum Security Register.json',
    'scripts/tests/fixtures/ai/AI Agent Assessment Examples.json',
    'scripts/data/ai/AI Agent Migration Coverage.json',
    'scripts/data/ai/AI Agent Policy Alignment.json',
)


def anchors(path):
    text = Path(path).read_text()
    values = set(re.findall(r'<[^>]+(?:id|name)=["\']([^"\']+)', text))
    counts = {}
    for heading in re.findall(r'^#{1,6} (.+)$', text, re.M):
        heading = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', heading)
        heading = heading.replace('`', '').replace('*', '').strip().lower()
        key = re.sub(r'[^\w\- ]', '', heading).replace(' ', '-')
        duplicate = counts.get(key, 0)
        counts[key] = duplicate + 1
        values.add(key + ('-' + str(duplicate) if duplicate else ''))
    return values


def errors(root):
    root = Path(root)
    ai = root / 'AI Profile'
    problems = []
    actual = {p.name for p in ai.iterdir() if p.is_file()}
    if actual != set(DOCUMENTS):
        problems.append('Primary AI documents differ from the maintained eight-file inventory')
    for name in DOCUMENTS:
        p = ai / name
        if not p.is_file():
            problems.append(name + ': missing')
            continue
        text = p.read_text()
        if re.search(r'(?i)alpha[\s-]+pilot|pilot[\s-]+alpha|pilot-only|0\.1\.0-alpha\.1|ai-profile-version:|ai-alpha-preview:', text):
            problems.append(name + ': session publication/pilot framing remains')
        if re.search(r'(?im)^\*{0,2}(?:Draft proposal|Proposed (?:alpha|pilot|source))\b', text):
            problems.append(name + ': current requirement has a proposal-status wrapper')
        for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)\)', text):
            target = target.strip('<>')
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or target.startswith('/'):
                continue
            filename = unquote(parsed.path)
            target_path = p.parent / filename if filename else p
            if not target_path.exists():
                problems.append(name + ': missing local link target ' + filename)
            elif parsed.fragment and target_path.suffix == '.md' and unquote(parsed.fragment) not in anchors(target_path):
                problems.append(name + ': missing local link anchor ' + parsed.fragment)
    for rel in ASSETS:
        p = root / rel
        if not p.is_file():
            problems.append(rel + ': supporting asset missing')
            continue
        data = json.loads(p.read_text())
        if 'x_profile_release' in data or 'x_alpha_preview' in data:
            problems.append(rel + ': session release-state metadata remains')
    register_path = root / 'assessment/ai/AI Tool Minimum Security Register.json'
    if register_path.exists():
        register = json.loads(register_path.read_text())
        floor = register.get('CASA_floor', {})
        ids = [x['id'] for x in floor] if isinstance(floor,list) else list(floor)
        if len(ids) != 48:
            problems.append('Independent published CASA floor must retain 48 audit IDs')
    return problems


def main():
    root = Path(__file__).resolve().parents[1]
    problems = errors(root)
    if problems:
        raise SystemExit('\n'.join(problems))
    print('AI documents: eight primary files; supporting assets linked; no session publication framing')


if __name__ == '__main__':
    main()
