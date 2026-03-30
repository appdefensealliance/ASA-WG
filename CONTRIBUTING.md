# Contributing to ASA-WG Standards

This document describes the standards management lifecycle for the App Security Assessment Working Group (ASA-WG). It defines how standards are drafted, achieve WG consensus, get referred to the Steering Committee (SC), and are officially released.

## Branching Model

| Branch | Purpose |
|--------|---------|
| `main` | Latest SC-approved text. Tagged with semver (e.g., `v1.0.0`). |
| `develop` | Integration branch for WG-approved changes. Default branch. |
| `<issue#>-<short-description>` | Feature branches for individual requirements. |
| `release/vX.Y.Z` | Release candidate branches cut from `develop` for SC review. |

## Standards Lifecycle

### Stage 0 — Starting Point

`main` contains the latest Steering Committee–approved text, tagged with a semantic version (e.g., `v1.0.0`). The `develop` branch is the default branch and the target for all WG work.

### Stage 1 — Intake

Each new requirement or change is tracked as a **GitHub Issue**.

- Use the [New Requirement issue template](/.github/ISSUE_TEMPLATE/new_requirement.md).
- Apply the appropriate labels:
  - **Profile:** `profile:mobile`, `profile:web`, or `profile:cloud`
  - **Change type:** `change:add`, `change:modify`, or `change:remove`
  - **Target release:** e.g., `release:v2.0`
  - **Stage:** `needs-wg`
- Assign the issue to the target milestone (e.g., `v2.0.0`).

### Stage 2 — Drafting & WG Consensus

1. **Create a feature branch** from `develop`, named after the issue (e.g., `42-add-api-security-requirement`).
2. **Open a Pull Request** targeting `develop`.
   - Reference the issue in the PR description (e.g., `Closes #42`).
   - Apply the label `stage:wg-consensus`.
3. **WG review and discussion** happens in the PR.
   - WG members review, comment, and request changes.
   - For contentious items, open a **GitHub Discussion** and link it from the PR.
4. **WG Chair calls consensus:**
   - If consensus is reached via PR discussion, the chair records the decision in a PR comment and merges.
   - If a formal vote is needed, the chair opens a `[VOTE]` issue, applies the label `stage:wg-vote`, and records the outcome.
5. **Merge to `develop`** once WG consensus is achieved.
   - WG approvals are recorded via PR approvals.
   - Optionally, a governance decision record can be created at `governance/decisions/YYYY-MM-DD-<topic>.md`.

### Stage 3 — Batch for Steering Committee

When the WG is ready to propose a release:

1. **Cut a release branch** from `develop`: `release/vX.Y.Z`.
2. **Update `CHANGELOG.md`** on the release branch:
   - Move items from `[Unreleased]` to the new version section.
   - Include the date and a summary of all changes.
3. **Open a PR targeting `main`** from the release branch.
   - Title: `Release vX.Y.Z`
   - Body: Summary of all included WG PRs and their issue references.
   - Apply the label `stage:sc-consensus`.
4. **SC review:**
   - SC comments focus on scope, risk, stakeholder concerns, and release readiness.
   - If a formal SC vote is needed, the chair opens a `[VOTE]` issue with the label `stage:sc-vote`.
5. **SC consensus or vote** is recorded on the PR.

### Stage 4 — Release

Once the SC approves:

1. **Merge the SC PR** to `main`.
2. **Create an annotated tag:**
   ```
   git tag -a vX.Y.Z -m "Release vX.Y.Z — <brief description>"
   ```
3. **Create a GitHub Release** from the tag, using the CHANGELOG.md notes as the release body.

### Stage 5 — Post-Release

1. **Merge `main` back into `develop`** to incorporate any release-branch changes.
2. **Close the milestone** for the released version.
3. **Celebrate** the new release with the WG and SC.

## Versioning

This project uses [Semantic Versioning](https://semver.org/):

- **Major** (e.g., `v2.0.0`): Significant changes to profiles, new profiles, or breaking changes to existing requirements.
- **Minor** (e.g., `v1.1.0`): New requirements added, non-breaking modifications to existing requirements.
- **Patch** (e.g., `v1.0.1`): Clarifications, typo fixes, editorial corrections that do not change the substance of any requirement.

## Consensus & Voting

- **Default:** Consensus is reached via PR discussion and recorded by the WG Chair.
- **Formal vote:** When consensus cannot be reached through discussion, the chair opens a dedicated `[VOTE]` issue. The voting process and outcome are documented in the issue.
- **Decision records:** Optionally, significant decisions can be documented at `governance/decisions/YYYY-MM-DD-vX.Y.Z.md`.

## Labels

See [`labels-reference.md`](labels-reference.md) for the full set of recommended GitHub labels and their purposes.

## Code of Conduct

All participants in the ASA-WG are expected to engage respectfully and constructively. Focus discussions on technical merit and the goal of improving application security standards.