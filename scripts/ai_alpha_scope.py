"""Uniform AI-only alpha preview authority and immutable baseline checks.

This packages pilot documents; it neither releases underlying profiles nor
permits ADA certificate issuance. --stamp regenerates only preview metadata.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREVIEW_ID = "AI-profiles-0.1.0-alpha.1"
MARKER = "<!-- ai-alpha-preview: " + PREVIEW_ID + " -->"
BANNER = "**AI profiles 0.1.0-alpha.1 — proposed WG alpha for pilot assessment; not a basis for ADA certificates.**"
NOTICE = "This candidate's prospective requirements do not authorize certificate issuance. [AI-only publication scope and exact released baseline references](AI%20Alpha%20Publication%20Scope.md) govern the pilot; WG/SC adoption and release preparation remain outstanding."
FILES = (
    "AI Agent Specification.md", "AI Agent Test Guide.md",
    "AI Agent-Tool Interface Contract.md", "AI Agent-Tool Identity and Consent Wire Format.md",
    "AI Tool Specification.md", "AI Tool Testing Guide.md", "AI Tool Local Android Requirements.md",
    "AI Tool Minimum Security Register.md", "AI Tool Local Android Applicability.md", "AI Agent Assessment Protocol.md",
    "AI Agent Assessment Applicability.md", "AI Agent Assessment Plans.md", "AI Alpha Publication Scope.md", "AI Alpha Pilot Worksheet.md",
    "AI Agent Migration Coverage.json", "AI Agent Policy Alignment.json",
    "AI Tool Minimum Security Register.json", "AI Tool Assessment Cases.json",
    "AI Agent Assessment Applicability.json", "AI Agent Assessment Plan.schema.json",
    "AI Agent Assessment Examples.json", "AI Alpha Publication Scope.json",
)


def errors(ai):
    problems = []
    for name in FILES:
        path = ai / name
        if not path.is_file():
            problems.append(name + ": preview document missing")
            continue
        if name.endswith(".md"):
            text = path.read_text()
            if MARKER not in "\n".join(text.splitlines()[:8]) or text.count(MARKER) != 1 or BANNER not in text:
                problems.append(name + ": missing/duplicate uniform pilot-only alpha banner")
        else:
            record = json.loads(path.read_text())
            preview = record.get("x_alpha_preview", {})
            if preview.get("id") != PREVIEW_ID or preview.get("certification_authority") is not False:
                problems.append(name + ": missing/unsafe alpha metadata")
    scope = json.loads((ai / "AI Alpha Publication Scope.json").read_text())
    if scope.get("certification_authority") is not False:
        problems.append("Alpha cannot authorize ADA certificates")
    if scope.get("underlying_versions") != {"mobile_MASA": "2.1.1", "web_CASA": "2.1.1", "desktop_DASA": "2.2.0"}:
        problems.append("Pilot underlying baseline versions changed without scope update")
    floor = scope.get("tool_CASA_floor", {})
    if floor != {"version": "2.1.1", "audit_ids": 48, "document_pin": "7ad3cce0cbb8d6ece5a096afe4a669c1604af583"}:
        problems.append("AI alpha must not silently replace the published Tool CASA floor")
    if scope.get("underlying_profiles_are_references_not_released_by_this_alpha") is not True:
        problems.append("AI-only publication must not release pending underlying-profile changes")
    return problems


def stamp(ai):
    preview = {"id": PREVIEW_ID, "status": "proposed WG alpha for pilot assessment; not a basis for ADA certificates", "certification_authority": False}
    for name in FILES:
        path = ai / name
        if name.endswith(".md"):
            text = path.read_text()
            if MARKER in text:
                continue
            first, rest = text.split("\n", 1)
            path.write_text(first + "\n\n" + MARKER + "\n" + BANNER + "\n\n" + NOTICE + "\n" + rest)
        else:
            raw = path.read_text()
            data = json.loads(raw)
            if "x_alpha_preview" not in data:
                start = raw.index("{") + 1
                field = "\n  \"x_alpha_preview\": " + json.dumps(preview, ensure_ascii=False, separators=(",", ":")) + ","
                path.write_text(raw[:start] + field + raw[start:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--stamp", action="store_true")
    args = parser.parse_args()
    ai = args.root / "AI Profile"
    if args.stamp:
        stamp(ai)
    problems = errors(ai)
    if problems:
        raise SystemExit("\n".join(problems))
    print("AI alpha scope: pilot-only; exact released baselines retained; no certificate authority")


if __name__ == "__main__":
    main()
