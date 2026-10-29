# Spec ↔ Test Guide consistency lint

Every ADA profile ships as a **Specification** (defines requirements) paired with a
**Test Guide** (defines how a lab tests them). They must stay in lockstep.
`scripts/spec_guide_lint.py` fails CI when a pair drifts:

- a **requirement with no test** in its Guide, or
- a **test with no requirement** (an orphan / undocumented requirement).

It runs in CI via [`.github/workflows/spec-guide-consistency.yml`](../.github/workflows/spec-guide-consistency.yml)
on any PR that touches a paired document, and locally with no third-party dependencies.

## Usage

```bash
python3 scripts/spec_guide_lint.py                 # lint every pair (CI default)
python3 scripts/spec_guide_lint.py --pair MASA     # one pair
python3 scripts/spec_guide_lint.py --strict        # ignore the baseline; show ALL debt
python3 scripts/spec_guide_lint.py --update-baseline
```

Exit codes: `0` clean (modulo baseline) · `1` new divergence · `2` usage/IO error.

## Pairs covered

| Pair | Spec | Test Guide | Join strategy |
| --- | --- | --- | --- |
| MASA | `MASA/MASA Specification.md` | `MASA/MASA Test Guide.md` | **id** — shared `X.Y.Z.W` audit IDs |
| CASA | `CASA/CASA Specification.md` | `CASA/CASA Test Guide.md` | **id** — shared `N.M.K` audit IDs |
| AI Tool | `AI Profile/AI Tool Specification.md` | `AI Profile/AI Tool Testing Guide.md` | **explicit assessment tags** |
| AI Agent | `AI Profile/AI Agent Specification.md` | `AI Profile/AI Agent Test Guide.md` | **explicit assessment tags** |

MASA and CASA share stable numeric IDs. The AI pairs use explicit namespaced tags,
preserving their independently numbered tests and multiple mappings. Duplicate
titles do not collapse distinct controls.

## Stable AI assessment tags

Every numbered AI requirement and test heading requires exactly one corresponding
tag. Requirement and test IDs must be unique and must match their heading and actor.

```html
<!-- ada:requirement Tool:2.2.1 -->
<!-- ada:test Tool:5.1 covers=Tool:2.2.1,Tool:8.2.1 -->
<!-- ada:requirement Agent:2.4.2 -->
<!-- ada:test Agent:2.4.2 covers=Agent:2.4.2 -->
```

These examples illustrate the syntax. They are not requirements in this lint guide.
`scripts/ai_assessment_lint.py` checks AI tags and metadata. The original lint retains
numeric adapters for MASA and CASA. Empty parses and duplicate IDs fail for all pairs.

## The baseline (a ratchet, not a snooze)

Pre-existing drift is recorded in `scripts/spec_guide_lint_baseline.json` so CI blocks
**new** divergence without being blocked by existing debt. The baseline file *is* the
debt register — each entry lists the requirement/test label and its line. Burn it down
as reconciliation lands (issue #400):

1. Add the missing test / fix the mapping in the documents.
2. Remove the corresponding entry from `spec_guide_lint_baseline.json` (or run
   `--update-baseline` to regenerate), so the item can never silently regress.

Run `--strict` any time to see the full current debt regardless of the baseline.

## Assessment metadata

The AI Tool case ledger retains 40 source tests and 210 source cases. The register
retains 48 published CASA IDs and 21 conditional supplemental properties. These counts
are different inventories: the Tool pair has 62 requirement mappings (35 original,
six reconciled Guide-only outcomes/enhancements and 21 supplemental properties) and
61 tests (40 original plus 21 coverage entries).

The lint rejects:

- Unresolved requirement, CASA or research references.
- Differences between Guide and ledger mappings, gate labels or proposed case text.
- Mixed cases without separate mandatory/advisory adjudication.
- Changes to retained local Android or other local/mobile test strength.
- Changes to the pinned published CASA criteria/scope/alternatives snapshot.
- Missing Agent evidence types or unnamed Attestation/Document Review artifacts.

Structural and assessment errors cannot be added to the accepted-debt baseline.
The lint verifies documentary consistency and the preserved CASA snapshot; it does
not prove implementation security or determine semantic applicability for a product.
Assessors still record the correct actor, deployment, protocol and applicable outcome.

## Focused regressions

```bash
python3 -m unittest discover -s scripts/tests -p test_spec_guide_lint.py
```

The regressions cover empty parses, duplicate headings, same-title controls,
wrong-actor mappings, retained CASA criteria, missing/duplicate source cases,
mixed gates, local Android demotion, evidence artifacts and baseline bypass.
