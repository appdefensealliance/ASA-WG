# ADA Cloud Assessment Tool — Claude Context

## Project Overview

This repo (`ASA-WG`) contains the ADA (App Defense Alliance) security assessment
profiles, submission templates, and the `cloud-assessment` automation tool.

The `cloud-assessment/` directory is a Python package (`ada-cloud-audit`) that
automates the security checks from the ADA Cloud App and Config Test Guide. It
runs against a live cloud tenant and produces JSON + DOCX compliance reports.

## Architecture

```
cloud-assessment/
  ada_cloud_audit/
    models.py          # RequirementResult, AssessmentReport, Provider enum, SECTIONS/DOMAINS dicts
    cli.py             # CLI entry point (argparse)
    checks/
      base.py          # make_result() helper, AWS-specific utils (run_multi_region, etc.)
      registry.py      # Provider -> {spec_id: check_fn} mapping, conditional imports
      aws/             # 40 AWS checks across 5 modules
        account.py, compute.py, database.py, iam.py, logging.py, storage.py
      gcp/             # 48 GCP checks across 6 modules
        base.py        # GCPSession dataclass, list_all_instances, list_sql_instances helpers
        compute.py, database.py, iam.py, logging.py, networking.py, storage.py
    report/
      json_report.py, compliance_report.py, developer_report.py
  tests/
    conftest.py        # AWS mock fixtures (moto-based)
    test_checks/
      test_aws/        # 42 AWS tests (all passing)
      test_gcp/        # GCP tests (written, not yet validated with pytest)
        conftest.py    # sys.modules mocking for google-cloud packages
```

## Key Patterns

- Each check function takes a session object (`boto3.Session` for AWS,
  `GCPSession` for GCP) and returns a `RequirementResult`.
- `make_result(spec_id, title, platform, verdict, evidence)` auto-populates
  section/domain from the SECTIONS/DOMAINS dicts in `models.py`.
- GCP check modules use inline imports (`from google.cloud import compute_v1`)
  inside function bodies to avoid import-time dependency on google-cloud packages.
- The database module uses a `_make_flag_check()` factory to generate 10+
  checks from configuration.
- All source files use `from __future__ import annotations` for Python 3.9 compat.
- AWS and GCP dependencies are conditionally imported in `registry.py` so only
  the needed provider's packages must be installed.

## Pending Work

- **GCP tests not yet run with pytest.** The test files exist in
  `tests/test_checks/test_gcp/` but haven't been executed in a proper test
  environment. Manual verification confirmed all 48 checks produce correct
  PASS/FAIL/INCONCLUSIVE verdicts. To run: `pip install -e ".[gcp,dev]"` then
  `pytest tests/ -v`.
- **DOCX report generation for GCP** has not been end-to-end tested.
- Python version requirement is `>=3.9` (`pyproject.toml`).

## Provider Check Counts

| Provider | Checks | Test Status |
|----------|--------|-------------|
| AWS      | 40     | 42 tests, all passing |
| GCP      | 48     | Tests written, not yet validated |

## Reference Documents

- `Cloud App and Config Profile/Cloud App and Config Test Guide.md` — verification steps
- `Cloud App and Config Profile/Cloud Profile and Config Audit Summary.md` — requirements list
