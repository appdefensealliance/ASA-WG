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
| AI Tool | `AI Profile/AI Tool Specification.md` | `AI Profile/AI Tool Testing Guide.md` | **title** (bootstrap) |

MASA and CASA already share stable numeric IDs between Spec and Guide, so their join is
exact. The AI Tool pair numbers the two documents independently, so it is matched on
**normalized requirement title** as a bootstrap — this is fuzzy and should be upgraded
(see "Upgrading the AI Tool pair" below).

## How join strategies work

Each pair is a small adapter in `PAIRS` inside `spec_guide_lint.py` — only three things
vary: the two file paths, a regex that captures the requirement ID (or title) from each
document, and the strategy (`id` or `title`). Adding a new pair is ~6 lines.

- **`id`** — the capture group is a stable ID present in *both* documents. Robust.
- **`title`** — the capture group is a human title, normalized (lowercased, punctuation
  and filler words like "mandatory"/"shall" removed) into a fuzzy key. Fragile to
  rewording; use only until a shared ID/tag exists.

## The baseline (a ratchet, not a snooze)

Pre-existing drift is recorded in `scripts/spec_guide_lint_baseline.json` so CI blocks
**new** divergence without being blocked by existing debt. The baseline file *is* the
debt register — each entry lists the requirement/test label and its line. Burn it down
as reconciliation lands (issue #400):

1. Add the missing test / fix the mapping in the documents.
2. Remove the corresponding entry from `spec_guide_lint_baseline.json` (or run
   `--update-baseline` to regenerate), so the item can never silently regress.

Run `--strict` any time to see the full current debt regardless of the baseline.

## Upgrading the AI Tool pair to `id`

To make the AI Tool pair as robust as MASA/CASA, give each Guide test an explicit,
machine-readable reference to the Spec requirement it covers — e.g. a line
`Spec: §6.1.1` (or an HTML comment `<!-- covers: 6.1.1 -->`) under each `## X.Y` test.
Then change its adapter `strategy` to `id` and point `guide_re` at that tag. This removes
all fuzzy title-matching. Standardizing that `covers:` convention across every profile
would let all pairs share one robust code path.
