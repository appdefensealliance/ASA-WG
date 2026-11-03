"""Versioned AI-only alpha document and metadata validation.

The feature/release PR carries the intended post-approval text. A version label
never grants lab authorization, certificate authority or evidence admission.
--stamp migrates only version headers and explicit publication metadata.
"""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0-alpha.1"
PREVIEW_ID = "AI-profiles-" + VERSION  # Compatibility name; value is a version ID.
MARKER = "<!-- ai-profile-version: " + PREVIEW_ID + " -->"
BANNER = "Version " + VERSION + " — 2026-11-03"
NOTICE = "This alpha defines AI security requirements and assessment procedures within the [AI-only publication scope](AI%20Alpha%20Publication%20Scope.md). A document version alone does not grant assessor authorization or authority to issue ADA certificates."
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
TOOL_FIELDS = {
    "proposed_gate_class": "gate_class", "proposed_MUST_atoms": "mandatory_outcome",
    "proposed_SHOULD_atoms": "advisory_outcome", "proposed_disposition": "disposition",
    "proposed_text": "requirement_text",
}


def renamed_tool_fields(value):
    if isinstance(value, list):
        return [renamed_tool_fields(v) for v in value]
    if isinstance(value, dict):
        return {TOOL_FIELDS.get(k, k): renamed_tool_fields(v) for k, v in value.items()}
    return value


def errors(ai):
    problems = []
    for name in FILES:
        path = ai / name
        if not path.is_file():
            problems.append(name + ": versioned document missing")
            continue
        if name.endswith(".md"):
            text = path.read_text()
            if MARKER not in "\n".join(text.splitlines()[:8]) or text.count(MARKER) != 1 or text.count(BANNER) != 1:
                problems.append(name + ": missing/duplicate uniform alpha version stamp")
            if re.search(r"(?im)^\*{0,2}(?:draft(?:\s+(?:proposal|retention|\d))?|proposed(?:\s+(?:alpha|pilot|source)))\b", text) or re.search(r"(?i)DRAFT proposal|draft proposal for Working Group", text):
                problems.append(name + ": current document/requirement still labeled draft or proposed")
            if "ai-alpha-preview:" in text:
                problems.append(name + ": obsolete preview metadata remains")
        else:
            record = json.loads(path.read_text())
            publication = record.get("x_profile_release", {})
            if publication != {"id": PREVIEW_ID, "version": VERSION, "document_state": "alpha", "certification_authority": False}:
                problems.append(name + ": missing/unsafe versioned-alpha metadata")
            if "x_alpha_preview" in record:
                problems.append(name + ": obsolete preview metadata remains")
            if re.search(r"(?i)draft|propos|pending.*WG|WG.*pending", str(record.get("status", ""))):
                problems.append(name + ": current top-level status is not final alpha text")
    scope = json.loads((ai / "AI Alpha Publication Scope.json").read_text())
    if scope.get("certification_authority") is not False:
        problems.append("A publication label cannot authorize ADA certificates")
    if scope.get("underlying_versions") != {"mobile_MASA": "2.1.1", "web_CASA": "2.1.1", "desktop_DASA": "2.2.0"}:
        problems.append("Underlying baseline versions changed without a scope change")
    if scope.get("tool_CASA_floor") != {"version": "2.1.1", "audit_ids": 48, "document_pin": "7ad3cce0cbb8d6ece5a096afe4a669c1604af583"}:
        problems.append("Versioning must preserve the independent published Tool CASA floor")
    if scope.get("underlying_profiles_are_references_not_released_by_this_alpha") is not True:
        problems.append("AI-only publication must not release underlying-profile changes")
    return problems


def stamp(ai):
    publication = {"id": PREVIEW_ID, "version": VERSION, "document_state": "alpha", "certification_authority": False}
    for name in FILES:
        path = ai / name
        if name.endswith(".md"):
            text = path.read_text()
            # Remove exactly the generated old preview block, not quoted source.
            text = re.sub(r"\n\n<!-- ai-alpha-preview: [^\n]+ -->\n[^\n]+\n\n[^\n]+\n", "\n", text, count=1)
            if MARKER in text:
                continue
            first, rest = text.split("\n", 1)
            path.write_text(first + "\n\n" + MARKER + "\n" + BANNER + "\n\n" + NOTICE + "\n" + rest)
        else:
            data = json.loads(path.read_text())
            data.pop("x_alpha_preview", None)
            data["x_profile_release"] = publication
            if name in {"AI Tool Assessment Cases.json", "AI Tool Minimum Security Register.json"}:
                data = renamed_tool_fields(data)
                data["status"] = "ALPHA"
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


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
    print("AI alpha: clean versioned text; exact baselines preserved; label does not grant certificate authority")


if __name__ == "__main__":
    main()
