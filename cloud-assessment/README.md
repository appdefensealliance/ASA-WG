# ADA Cloud Audit

> **Alpha** -- This tool is under active development. Check implementations, report
> formats, and CLI options may change without notice.

`ada-cloud-audit` automates security checks from the
[ADA Cloud App and Config Test Guide](https://appdefensealliance.dev/cloud).
It runs against a live cloud tenant, evaluates each requirement, and produces
JSON and DOCX compliance reports.

**Supported providers:**

| Provider | Requirements | Status |
|----------|-------------|--------|
| AWS      | 40          | Complete |
| GCP      | 48          | Complete |

## Installation

Requires Python 3.10+.

```bash
# AWS only (default)
pip install -e ./cloud-assessment

# AWS + GCP
pip install -e "./cloud-assessment[gcp]"

# With dev/test dependencies
pip install -e "./cloud-assessment[gcp,dev]"
```

## Configuration

### AWS

The tool uses [boto3 credential resolution](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html).
Any of the following will work:

- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- AWS CLI named profile (`~/.aws/credentials`)
- IAM role (when running on EC2/ECS/Lambda)

The authenticated principal needs **read-only** access across the account.
The AWS managed policy `ReadOnlyAccess` is sufficient for all 40 checks.

### GCP

The tool uses [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials).
Set up credentials with one of:

```bash
# Interactive login (development)
gcloud auth application-default login

# Service account key (CI / automation)
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
```

The authenticated principal needs the **Viewer** (`roles/viewer`) role on the
target project. Some checks also require `roles/cloudasset.viewer` and
`roles/dns.reader`.

## Usage

```bash
# Run AWS assessment (default provider)
ada-cloud-audit --output-dir ./results

# Use a specific AWS profile
ada-cloud-audit --profile my-profile --output-dir ./results

# Run GCP assessment
ada-cloud-audit --provider gcp --project my-gcp-project --output-dir ./results

# JSON output only (skip DOCX report generation)
ada-cloud-audit --provider gcp --project my-gcp-project --json-only

# Verbose output (prints each check result to the console)
ada-cloud-audit --verbose --output-dir ./results
```

### Report metadata

These optional flags populate the header fields in the DOCX compliance reports:

```bash
ada-cloud-audit \
  --lab-name "Example Security Lab" \
  --app-name "My Application" \
  --app-version "2.1.0" \
  --company "Example Corp" \
  --output-dir ./results
```

### All options

```
usage: ada-cloud-audit [-h] [--provider {aws,gcp}] [--profile PROFILE]
                       [--project PROJECT] [--regions [REGIONS ...]]
                       [--output-dir OUTPUT_DIR] [--lab-name LAB_NAME]
                       [--app-name APP_NAME] [--app-version APP_VERSION]
                       [--company COMPANY] [--json-only] [--verbose]
```

## Output

Each run produces:

- `assessment_results.json` -- machine-readable results for every requirement
- `Cloud App and Config Compliance Report.docx` -- formatted compliance report
  (unless `--json-only` is used)
- `Cloud App and Config Developer Test Report.docx` -- developer-facing test
  report (unless `--json-only` is used)

DOCX generation requires the report templates in
`Submission Forms and Templates/Lab Templates/`.

## Running tests

```bash
pip install -e "./cloud-assessment[gcp,dev]"
pytest cloud-assessment/tests/ -v
```
