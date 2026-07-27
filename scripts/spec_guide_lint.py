#!/usr/bin/env python3
"""Specification <-> Test Guide consistency lint for ADA ASA-WG profiles.

Every ADA profile ships as a *Specification* (defines requirements) paired with a
*Test Guide* (defines how a lab tests them). The two must stay in lockstep. This
lint fails when they diverge, i.e. when:

  * a Specification requirement has **no** corresponding test in its Guide, or
  * a Guide test maps to **no** Specification requirement (an orphan/undocumented
    requirement).

It is generic across profiles via a small per-pair adapter. Only three things
vary per pair, so each adapter is a few lines:

  * the file paths of the Spec and the Guide,
  * how a requirement ID is extracted from each document (a regex), and
  * the *join strategy*:
      - "id"    : Spec and Guide share a stable numeric ID (MASA, CASA).
      - "title" : requirements are matched on normalized title (AI Tool) --
                  a bootstrap until explicit `covers:` tags are added, at which
                  point that pair can switch to the far more robust "id" strategy.

Known, already-accepted divergences are recorded in
`scripts/spec_guide_lint_baseline.json` so CI blocks *new* drift without being
held hostage by pre-existing debt (a ratchet). Burn the baseline down as the
reconciliation lands; regenerate it with `--update-baseline`.

Usage:
  python3 scripts/spec_guide_lint.py                 # lint every pair
  python3 scripts/spec_guide_lint.py --pair MASA     # one pair
  python3 scripts/spec_guide_lint.py --strict        # ignore the baseline (report all debt)
  python3 scripts/spec_guide_lint.py --update-baseline

Exit codes: 0 = clean (modulo baseline) · 1 = new divergence · 2 = usage/IO error.
No third-party dependencies (standard library only).
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "spec_guide_lint_baseline.json")

# --- Per-pair adapters -------------------------------------------------------
# spec_re / guide_re: the capture group (1) is the requirement ID for "id"
# strategy, or the requirement title for "title" strategy.
PAIRS = {
    "AI Tool": {
        "spec": "AI Profile/AI Tool Specification.md",
        "guide": "AI Profile/AI Tool Testing Guide.md",
        "strategy": "title",
        # Spec requirements are `### X.Y.Z Title` (tolerate a trailing `.`/`:`, e.g. `### 1.2.2:` or `### 10.1.1.`)
        "spec_re": r"^###\s+\d+\.\d+\.\d+[.:]?\s+(.*\S)\s*$",
        # Guide tests are `## X.Y Title`
        "guide_re": r"^##\s+\d+\.\d+[.:]?\s+(.*\S)\s*$",
    },
    "MASA": {
        "spec": "MASA/MASA Specification.md",
        "guide": "MASA/MASA Test Guide.md",
        "strategy": "id",
        # Spec audit items are table rows `| X.Y.Z.W | ... |`
        "spec_re": r"^\|\s*(\d+\.\d+\.\d+\.\d+)\s*\|",
        # Guide tests are `#### X.Y.Z.W ...`
        "guide_re": r"^####\s+(\d+\.\d+\.\d+\.\d+)\b",
    },
    "CASA": {
        "spec": "CASA/CASA Specification.md",
        "guide": "CASA/CASA Test Guide.md",
        "strategy": "id",
        # Spec audit items are table rows `| [N.M.K](url) | ... |`
        "spec_re": r"^\|\s*\[(\d+\.\d+\.\d+)\]",
        # Guide tests are `### N.M.K ...`
        "guide_re": r"^###\s+(\d+\.\d+\.\d+)\b",
    },
}

_FILLER = re.compile(r"\b(mandatory|ensure|shall|the app)\b")


def norm_title(text: str) -> str:
    """Normalize a requirement title into a fuzzy join key."""
    t = text.lower()
    t = re.sub(r"\(duplicate\)", "", t)
    t = re.sub(r"[^a-z0-9 ]", " ", t)   # drop markdown/punctuation
    t = _FILLER.sub(" ", t)             # drop filler adjectives that drift
    return " ".join(t.split())


def _read(rel_path: str) -> str:
    path = os.path.join(ROOT, rel_path)
    if not os.path.exists(path):
        print(f"ERROR: file not found: {rel_path}", file=sys.stderr)
        raise SystemExit(2)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def extract(rel_path: str, regex: str, strategy: str) -> dict:
    """Return {join_key: {"label": raw, "line": n}} for a document."""
    rx = re.compile(regex)
    out: dict = {}
    for lineno, line in enumerate(_read(rel_path).splitlines(), 1):
        m = rx.match(line)
        if not m:
            continue
        raw = m.group(1).strip()
        key = norm_title(raw) if strategy == "title" else raw
        if not key:
            continue
        out.setdefault(key, {"label": raw, "line": lineno})
    return out


def lint_pair(name: str, cfg: dict) -> dict:
    spec = extract(cfg["spec"], cfg["spec_re"], cfg["strategy"])
    guide = extract(cfg["guide"], cfg["guide_re"], cfg["strategy"])
    untested = {k: spec[k] for k in (set(spec) - set(guide))}   # requirement w/ no test
    orphans = {k: guide[k] for k in (set(guide) - set(spec))}   # test w/ no requirement
    return {
        "spec_count": len(spec),
        "guide_count": len(guide),
        "untested": untested,
        "orphans": orphans,
    }


def load_baseline() -> dict:
    if not os.path.exists(BASELINE_PATH):
        return {}
    with open(BASELINE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _baseline_keys(entry: dict, kind: str) -> set:
    return {row["id"] for row in entry.get(kind, [])}


def render(name: str, result: dict, baseline: dict, strict: bool) -> bool:
    """Print a report for one pair. Return True if it has NEW divergence."""
    b = baseline.get(name, {})
    base_untested = set() if strict else _baseline_keys(b, "untested")
    base_orphans = set() if strict else _baseline_keys(b, "orphans")

    new_untested = {k: v for k, v in result["untested"].items() if k not in base_untested}
    new_orphans = {k: v for k, v in result["orphans"].items() if k not in base_orphans}
    n_base = len(result["untested"]) - len(new_untested) + len(result["orphans"]) - len(new_orphans)

    status = "FAIL" if (new_untested or new_orphans) else "ok"
    print(f"\n[{status}] {name}: {result['spec_count']} requirements / "
          f"{result['guide_count']} tests"
          + (f"  ({n_base} known-debt suppressed)" if n_base and not strict else ""))

    if new_untested:
        print(f"  Requirements with NO test ({len(new_untested)}):")
        for k, v in sorted(new_untested.items(), key=lambda kv: kv[1]["line"]):
            print(f"    - {v['label']}   (spec:{v['line']})")
    if new_orphans:
        print(f"  Tests with NO matching requirement ({len(new_orphans)}):")
        for k, v in sorted(new_orphans.items(), key=lambda kv: kv[1]["line"]):
            print(f"    - {v['label']}   (guide:{v['line']})")

    return bool(new_untested or new_orphans)


def build_baseline(names) -> dict:
    out = {}
    for name in names:
        r = lint_pair(name, PAIRS[name])
        out[name] = {
            "untested": [{"id": k, "label": v["label"], "spec_line": v["line"]}
                         for k, v in sorted(r["untested"].items(), key=lambda kv: kv[1]["line"])],
            "orphans": [{"id": k, "label": v["label"], "guide_line": v["line"]}
                        for k, v in sorted(r["orphans"].items(), key=lambda kv: kv[1]["line"])],
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pair", choices=list(PAIRS), help="lint only this pair")
    ap.add_argument("--strict", action="store_true",
                    help="ignore the baseline and report ALL divergence")
    ap.add_argument("--update-baseline", action="store_true",
                    help="regenerate the baseline from the current documents")
    args = ap.parse_args()

    names = [args.pair] if args.pair else list(PAIRS)

    if args.update_baseline:
        current = load_baseline()
        current.update(build_baseline(names))
        with open(BASELINE_PATH, "w", encoding="utf-8") as fh:
            json.dump(current, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        total = sum(len(v["untested"]) + len(v["orphans"]) for v in current.values())
        print(f"Wrote baseline for {', '.join(names)} -> {os.path.relpath(BASELINE_PATH, ROOT)} "
              f"({total} known-debt entries total).")
        return 0

    baseline = load_baseline()
    failed = False
    for name in names:
        result = lint_pair(name, PAIRS[name])
        if render(name, result, baseline, args.strict):
            failed = True

    print()
    if failed:
        print("RESULT: FAIL - Spec/Guide divergence introduced. Add the missing test, "
              "fix the requirement mapping, or (if intentional) update the baseline.")
        return 1
    print("RESULT: ok - no new Spec/Guide divergence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
