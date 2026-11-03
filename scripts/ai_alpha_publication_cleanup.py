"""Editorial publication transition for parent-owned AI documents.

This changes status vocabulary and descriptive wrappers, not security strength.
Companion files are independently migrated; retained source bodies and external
pre-release specifications are not globally rewritten.
"""
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
AI = ROOT / "AI Profile"
PARENT_MD = (
    "AI Agent Specification.md", "AI Agent Test Guide.md",
    "AI Agent-Tool Interface Contract.md", "AI Agent-Tool Identity and Consent Wire Format.md",
    "AI Tool Specification.md", "AI Tool Testing Guide.md", "AI Tool Minimum Security Register.md",
    "AI Tool Local Android Requirements.md", "AI Tool Local Android Applicability.md",
)
REPLACEMENTS = {
    "This proposal does not introduce a blanket": "This profile does not introduce a blanket",
    "The proposed minimum is": "The Tool minimum is",
    "Proposed interpretation": "Interpretation",
    "Proposed two-stage verification": "Two-stage verification",
    "Public remote MCP profile applicability (DRAFT proposal)": "Public remote MCP profile applicability",
    "not draft underlying-profile requirements": "not unreleased underlying-profile requirements",
    "does not release draft CASA 2.x/3.0 or MASA changes": "does not release unreleased CASA 2.x/3.0 or MASA changes",
    "These proposed assessment/lifecycle rules require WG review and do not waive": "These assessment/lifecycle rules do not waive",
    "proposed single certificate": "single certificate, when issuance is independently authorized",
    "This alpha does not adopt the formerly proposed 25-step fallback.": "No generic 25-step fallback applies to this alpha.",
    "#5-proposed-111-task-appropriate-amendment": "#5-111-task-appropriate-outcomes",
    "their individually proposed gate and variant disposition": "their individual gate and variant disposition",
    "referenced proposed Tool requirements": "versioned Tool requirements",
    "current draft CASA changes": "unreleased CASA changes",
    "Disposition of earlier retention/governance proposal": "Historical retention/governance scope dispositions",
    "Proposed disposition": "Disposition",
    "this proposal does not certify jurisdictional compliance": "this profile does not certify jurisdictional compliance",
    "inform the proposed technical properties": "inform the technical properties",
    "not the remote proposed disposition": "not the remote-HTTP disposition",
}


def main():
    for name in PARENT_MD:
        path = AI / name
        text = path.read_text()
        text = re.sub(r"(?m)^\*\*(?:Draft proposal for Working Group review[^\n]*|Draft retention annex\.|Proposed alpha planning map[^\n]*)\*\*\n\n?", "", text)
        for old, new in REPLACEMENTS.items():
            text = text.replace(old, new)
        path.write_text(text)
    # Canonical Tool ledger remains synchronized by tool_case_render --write.
    ledger = AI / "AI Tool Assessment Cases.json"
    data = json.loads(ledger.read_text())
    data["assessment_rules"]["source_precedence"] = data["assessment_rules"]["source_precedence"].replace("referenced proposed Tool requirements", "versioned Tool requirements")
    ledger.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    register = AI / "AI Tool Minimum Security Register.json"
    raw = register.read_text().replace("this proposal does not certify jurisdictional compliance", "this profile does not certify jurisdictional compliance")
    register.write_text(raw)
    print("Parent-owned publication wrappers normalized; invariants must still validate.")


if __name__ == "__main__":
    main()
