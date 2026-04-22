"""GCP BigQuery checks for ADA Cloud assessment.

Covers 1 requirement:
- 5.5.4: BigQuery datasets not publicly accessible
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.gcp.base import GCPSession
from ada_cloud_audit.models import RequirementResult, Verdict


def check_bigquery_public_access(session: GCPSession) -> RequirementResult:
    """ADA 5.5.4: Ensure BigQuery datasets are not publicly accessible."""
    spec_id = "5.5.4"
    title = "Ensure That BigQuery Datasets Are Not Anonymously or Publicly Accessible"

    try:
        from google.cloud import bigquery

        client = bigquery.Client(
            project=session.project_id, credentials=session.credentials
        )
        datasets = list(client.list_datasets())

        if not datasets:
            return make_result(
                spec_id, title, "GCP", Verdict.PASS,
                "No BigQuery datasets found in the project",
            )

        non_compliant = []
        for dataset_ref in datasets:
            dataset = client.get_dataset(dataset_ref.reference)
            for entry in dataset.access_entries:
                entity_id = getattr(entry, "entity_id", "") or ""
                if entity_id in ("allUsers", "allAuthenticatedUsers"):
                    non_compliant.append(
                        f"{dataset.dataset_id} (grants {entry.role} to {entity_id})"
                    )

        if non_compliant:
            return make_result(
                spec_id, title, "GCP", Verdict.FAIL,
                "BigQuery datasets with public access:\n" + "\n".join(non_compliant),
                {"non_compliant": non_compliant, "total": len(datasets)},
            )
        return make_result(
            spec_id, title, "GCP", Verdict.PASS,
            f"All {len(datasets)} BigQuery datasets are not publicly accessible",
            {"total": len(datasets)},
        )
    except Exception as e:
        return make_result(
            spec_id, title, "GCP", Verdict.INCONCLUSIVE,
            f"Error checking BigQuery datasets: {e}",
        )
