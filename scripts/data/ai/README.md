# AI maintainer regression and provenance records

These records support maintenance of the standards and their tests. They are not requirements for an assessor to perform additional procedures or evidence that a product meets the standards.

- [Agent migration coverage](AI%20Agent%20Migration%20Coverage.json): original source mapping, historical split/evidence deltas and derived current verification text. Historical flags describe their named migration delta, not the complete current document set.
- [Agent policy alignment](AI%20Agent%20Policy%20Alignment.json): immutable pre-amendment baseline hashes, explicitly scoped control changes and upstream merge provenance. `scripts/agent_policy_alignment.py` guards against unrelated security weakening and refreshes derived records.

The controlling documents are the [Agent Specification](../../../AI%20Profile/AI%20Agent%20Specification.md) and [Test Guide](../../../AI%20Profile/AI%20Agent%20Test%20Guide.md). An actual assessment records its own applicable source/configuration/evidence; a maintainer baseline hash is not approval, release status or conformity evidence.
