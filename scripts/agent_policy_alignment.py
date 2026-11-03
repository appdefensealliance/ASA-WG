"""Check and regenerate the explicit Agent decision-amendment record.

Only named normative amendments may differ from the pinned pre-amendment
controls. These are document regressions, not evidence that an Agent is secure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASELINE = "3302bdb2d8c2637e2c76b80f9ed81d97d578ae65"
BASELINE_MAP_SHA = "01f8e9af9ddd06fa081978ce13005caee79effebadef6eaf9ea7bd9b27e1ce7b"
ALLOWED = {"1.1.1", "1.2.1", "1.3.1", "2.1.1", "2.1.2", "2.2.2", "3.1.3", "3.3.1", "4.1.1", "5.1.1", "5.1.2", "5.2.1", "6.1.3"}
MANIFEST = "AI Agent Policy Alignment.json"


def normalize(text):
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


def hash_text(text):
    return hashlib.sha256(normalize(text).encode()).hexdigest()


def sections(text, role):
    rows = {}
    for block in re.split(r"(?=^#{1,3} )", text, flags=re.M):
        match = re.search(r"<!-- ada:" + role + r" Agent:(\d+\.\d+\.\d+)", block)
        if match:
            if match[1] in rows:
                raise ValueError("Duplicate Agent control: " + match[1])
            rows[match[1]] = block
    return rows


def verification(block):
    return normalize(block.split("#### Verification\n", 1)[1])


def baseline_maps(spec, guide):
    return {
        "baseline_spec_blocks": {key: hash_text(block) for key, block in sections(spec, "requirement").items()},
        "baseline_guide_verification": {key: hash_text(verification(block)) for key, block in sections(guide, "test").items()},
    }


def baseline_digest(manifest):
    maps = {key: manifest[key] for key in ("baseline_spec_blocks", "baseline_guide_verification")}
    return hashlib.sha256(json.dumps(maps, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compact(text):
    return re.sub(r"\s+", " ", text).strip()


def table_assertions(block):
    row = next(line for line in block.splitlines() if re.match(r"^\| \d+\.\d+\.\d+ \|", line))
    return row.split("|", 2)[2].rsplit("|", 1)[0].replace("<br>", "\n")


def alignment_errors(spec, guide, manifest, contract=None):
    errors = []
    sr, gr = sections(spec, "requirement"), sections(guide, "test")
    if len(sr) != 37 or list(sr) != list(gr):
        return ["Agent audit IDs/order must remain the same 37 controls"]
    if baseline_digest(manifest) != BASELINE_MAP_SHA:
        errors.append("Pinned pre-amendment baseline maps changed")
    if len(manifest.get("allowed_audit_changes", [])) != len(ALLOWED) or set(manifest.get("allowed_audit_changes", [])) != ALLOWED:
        errors.append("Normative change inventory differs from the explicit amendment")
    for key in sr:
        if key not in ALLOWED:
            if hash_text(sr[key]) != manifest["baseline_spec_blocks"].get(key):
                errors.append(key + ": unrelated Specification control changed")
            if hash_text(verification(gr[key])) != manifest["baseline_guide_verification"].get(key):
                errors.append(key + ": unrelated acceptance criterion changed")
        else:
            if compact(table_assertions(sr[key])) != compact(verification(gr[key])):
                errors.append(key + ": Specification/Guide acceptance assertions differ")
    required = {
        "1.1.1": ["Task-appropriate Evasion Resistance", "meaning-preserving perturbations", "not exact prose", "remains unresolved"],
        "3.1.3": ["one qualified assessor person-day (8 person-hours)", "Exclude setup, report writing and unattended tool runtime", "not an independent pass prerequisite", "unauthorized disclosure of private data"],
        "1.2.1": ["diagnostic logs, error messages and shared operational caches", "separately declared and permitted user-scoped protected memory/cache", "does not establish that exception", "no-secret-logging/output protections", "other contexts"],
        "3.3.1": ["Sensitive Actions and explicit Tool/product-policy confirmation requirements", "Privilege level alone shall not require", "Every plugin action shall be validated", "All plugin invocations, including the arguments"],
        "1.3.1": ["shall never be replayed as instructions", "injected directive shall not survive", "authorized user/context"],
        "2.1.1": ["shall refuse harmful or out-of-scope actions", "shall use only permitted tools", "shall enforce step, time, token, and cost limits", "valid user/resource authority"],
        "2.1.2": ["Agent-managed Tool execution", "not a claim about the independent server's filesystem", "Agent-controlled runtime", "Logged Disposition"],
        "2.2.2": ["fresh per-action user consent", "Explicit Tool consent requests", "Before dispatch", "one execution", "bounded validity period", "expired, consumed, mismatched, replayed"],
        "4.1.1": ["Enforce Rate Limiting", "Enforce Input Size Limits", "hard limits and pre-limit usage alerts", "restrict/refuse the operation", "a request-count limit alone does not establish the bound"],
        "5.1.1": ["access, purpose and recipient are authorized", "not a blanket secret-disclosure exception", "cross-user/context disclosure", "A user request alone does not establish access rights"],
        "5.1.2": ["separately permitted persistence", "Task authorization does not by itself authorize", "encoded or obfuscated content", "retention, withdrawal and deletion"],
        "6.1.3": ["SHOULD use a supported", "absence alone does not prohibit", "MUST satisfy a selected interface", "MUST preserve and correctly reuse", "MUST NOT replace or remint", "indeterminate outcome without initiating another action", "unique nonce or accurate timestamp", "securely re-initiate", "MUST stop new actions and uncommitted queued work", "invalidate every stateful session/refresh token", "MUST NOT reuse revoked"],
    }
    for key, clauses in required.items():
        for clause in clauses:
            if clause not in gr[key]:
                errors.append(key + ": missing policy guard: " + clause)
    for text, label in [(spec, "Specification"), (guide, "Guide")]:
        for clause in ["Remote Tools MUST be treated as untrusted dependencies", "A Tool certificate is not a prerequisite for Agent certification", "first-party remote execution services and runtime subprocessors", "remote HTTP/MCP transport does not remove those duties"]:
            if clause not in text:
                errors.append(label + ": missing independent-Agent boundary")
        if "unless the separate optional Agent relaxation" in text or "Only if optional Agent relaxations" in text:
            errors.append(label + ": unpublished option selector remains")
        if "execution strictly mandates isolation sandboxing and explicit per-action user consent" in text:
            errors.append(label + ": blanket capability-based consent remains")
    if contract is not None:
        definition = "**Sensitive Action:** An operation that is irreversible, transfers value or money, mutates or shares user data beyond the scope of the current task, or grants or expands access."
        if contract.count(definition) != 1:
            errors.append("Contract must contain exactly one canonical Sensitive Action definition")
        if "General Agent use of supported stable action-intent/idempotency mechanisms is SHOULD" not in contract:
            errors.append("Contract general action-ID strength is not aligned")
        if "Agent stable-ID obligations remain MUST" in contract:
            errors.append("Contract retains unconditional Agent ID obligation")
    return errors


def refresh_coverage(ai, guide, manifest):
    path = ai / "AI Agent Migration Coverage.json"
    coverage = json.loads(path.read_text())
    rows = sections(guide, "test")
    if [control["id"] for control in coverage["controls"]] != list(rows):
        raise ValueError("Refusing to regenerate a changed audit inventory")
    for control in coverage["controls"]:
        control["verification"] = verification(rows[control["id"]])
    coverage["baseline_scenario"] = "A"
    coverage["scenario"] = "owner-aligned normative control amendments; WG review pending"
    coverage["stable_ID_relaxations_included"] = True
    coverage["source_pin_role"] = manifest["source_pin_role"]
    if "upstream_revocation_candidate" in manifest:
        coverage["upstream_revocation_candidate"] = manifest["upstream_revocation_candidate"]
        coverage["evidence_sufficiency_amendment"]["Agent_PR_537_base"] = manifest["baseline_agent_head"]
    coverage["assessment_policy"] = {
        "status": "proposed; owner aligned, WG review pending",
        "default_independent_stochastic_executions_per_case": 10,
        "specific_applicable_procedure_overrides_preserved": True,
        "actual_red_team_person_hours_initial_or_full": 8,
        "excluded_effort": ["setup", "report writing", "unattended tool runtime"],
        "quarterly": "designated automated reruns and findings review; not automatically full manual exercise",
        "major_model_change_or_new_agent_product": "full review",
        "minor_update": "impact review and affected regressions; not automatically full review",
        "protocol": "AI Agent Assessment Protocol.md",
        "applicability_matrix": "AI Agent Assessment Applicability.json"
    }
    coverage["owner_decision_amendment"] = {
        "status": "proposed; owner aligned, WG review pending",
        "issues": manifest["issues"],
        "allowed_audit_changes": manifest["allowed_audit_changes"],
        "baseline_evidence_head": BASELINE,
        "general_supported_ID_strength": "SHOULD",
        "required_interface_and_correct_ID_use_strength": "MUST",
        "safe_outcome_strength": "MUST",
        "tool_certificate_prerequisite": False,
        "new_numbered_audits": 0,
    }
    path.write_text(json.dumps(coverage, indent=2, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--bootstrap", action="store_true", help="Create the pinned baseline manifest once")
    parser.add_argument("--rebase-baseline", action="store_true", help="Apply only the explicitly pinned upstream PR 528 baseline migration")
    parser.add_argument("--refresh", action="store_true", help="Regenerate derived verification/migration records")
    args = parser.parse_args()
    ai = args.root / "AI Profile"
    path = ai / MANIFEST
    prior = None
    if args.bootstrap or args.rebase_baseline:
        if path.exists() and not args.rebase_baseline:
            parser.error("Manifest already exists; refusing to replace the baseline")
        if args.rebase_baseline:
            prior = json.loads(path.read_text())
            if baseline_digest(prior) != "dd9d0b33d3291f7917cd9c16d9021240ceccf0c24f5a402a0d2853be9647ad65":
                parser.error("Refusing an unrecognized prior baseline")
        originals = {}
        for name in ("AI Agent Specification.md", "AI Agent Test Guide.md"):
            originals[name] = subprocess.check_output(["git", "show", BASELINE + ":AI Profile/" + name], cwd=args.root, text=True)
        original_coverage = json.loads(subprocess.check_output(["git", "show", BASELINE + ":AI Profile/AI Agent Migration Coverage.json"], cwd=args.root, text=True))
        manifest = {
            "status": "owner-aligned proposal; WG review pending",
            "baseline_agent_head": "07bfda43f4c3974b9dbd6c333e76de8be9cb058b",
            "baseline_evidence_head": BASELINE,
            "issues": [539, 540, 541, 410, 542, 544],
            "allowed_audit_changes": sorted(ALLOWED, key=lambda key: tuple(map(int, key.split(".")))),
            **baseline_maps(originals["AI Agent Specification.md"], originals["AI Agent Test Guide.md"]),
            "source_pin_role": "historical migration baseline; the actual assessed draft/release bundle must be pinned separately",
            "normative_changes": {
                "539": "Operation-based fresh confirmation; explicit Tool/product requirements remain binding.",
                "540": "Agent-owned managed-runtime and independent remote-integration boundaries; no Tool-cert prerequisite or provider-honesty guarantee.",
                "541": "Per-verification applicability, production-equivalent fixtures and worked plans; missing mandatory protections/evidence are not N/A.",
                "410": "Default ten stochastic executions unless explicit applicable guidance differs; eight qualified actual red-team hours; pilot/full/remediation and quarterly automated maintenance; task-appropriate evasion and supporting-only comparators.",
                "542": "Authorized private tasks and separately permitted persistence; strict secrets, isolation, retention/deletion preserved.",
                "544": "General supported-ID use SHOULD; required-interface/correct-use and uncertainty safeguards MUST.",
            },
        }
        if baseline_digest(manifest) != BASELINE_MAP_SHA:
            raise ValueError("The pinned baseline does not reproduce the reviewed hashes")
        manifest["upstream_revocation_candidate"] = original_coverage["upstream_revocation_candidate"]
        if prior is not None:
            for field in ("baseline_spec_blocks", "baseline_guide_verification"):
                changed = {key for key in manifest[field] if manifest[field][key] != prior[field].get(key)}
                if changed != {"2.4.2"}:
                    raise ValueError("Baseline migration must change only the pinned revocation control")
        path.write_text(json.dumps(manifest, indent=2) + "\n")
    manifest = json.loads(path.read_text())
    spec = (ai / "AI Agent Specification.md").read_text()
    guide = (ai / "AI Agent Test Guide.md").read_text()
    contract = (ai / "AI Agent-Tool Interface Contract.md").read_text()
    errors = alignment_errors(spec, guide, manifest, contract)
    if errors:
        raise SystemExit("\n".join(errors))
    if args.refresh:
        refresh_coverage(ai, guide, manifest)
    print("Agent decision alignment: 37 controls; explicit scoped amendments and retained guards verified")


if __name__ == "__main__":
    main()
