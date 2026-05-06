"""GCP Storage checks for ADA Cloud assessment.

Covers 2 requirements:
- 5.5.3: Cloud Storage buckets not publicly accessible
- 5.5.6: Cloud Storage buckets have uniform bucket-level access enabled
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.gcp.base import GCPSession
from ada_cloud_audit.models import RequirementResult, Verdict


def check_bucket_public_access(session: GCPSession) -> RequirementResult:
    """ADA 5.5.3: Ensure Cloud Storage buckets are not anonymously or publicly accessible."""
    spec_id = "5.5.3"
    title = "Ensure Cloud Storage buckets are not anonymously or publicly accessible"

    try:
        from google.cloud import storage

        client = storage.Client(project=session.project_id,
                                credentials=session.credentials)
        buckets = list(client.list_buckets())

        if not buckets:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No Cloud Storage buckets found")

        public_buckets = []
        compliant = []
        for bucket in buckets:
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                is_public = False
                for binding in policy.bindings:
                    members = binding.get("members", set())
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public_buckets.append(
                            f"{bucket.name} ({', '.join(m for m in members if m in ('allUsers', 'allAuthenticatedUsers'))} "
                            f"has {binding['role']})"
                        )
                        is_public = True
                        break
                if not is_public:
                    compliant.append(bucket.name)
            except Exception as e:
                public_buckets.append(f"{bucket.name} (error checking IAM: {e})")

        if public_buckets:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Publicly accessible buckets:\n" + "\n".join(public_buckets),
                             {"public_buckets": public_buckets, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {len(compliant)} Cloud Storage buckets are not publicly accessible",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking Cloud Storage buckets: {e}")


def check_uniform_bucket_access(session: GCPSession) -> RequirementResult:
    """ADA 5.5.6: Ensure Cloud Storage buckets have uniform bucket-level access enabled."""
    spec_id = "5.5.6"
    title = "Ensure That Cloud Storage Buckets Have Uniform Bucket-Level Access Enabled"

    try:
        from google.cloud import storage

        client = storage.Client(project=session.project_id,
                                credentials=session.credentials)
        buckets = list(client.list_buckets())

        if not buckets:
            return make_result(spec_id, title, "Google", Verdict.PASS,
                             "No Cloud Storage buckets found")

        non_compliant = []
        compliant = []
        for bucket in buckets:
            iam_config = bucket.iam_configuration
            if iam_config.uniform_bucket_level_access_enabled:
                compliant.append(bucket.name)
            else:
                non_compliant.append(f"{bucket.name} (uniform bucket-level access not enabled)")

        if non_compliant:
            return make_result(spec_id, title, "Google", Verdict.FAIL,
                             "Buckets without uniform bucket-level access:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "Google", Verdict.PASS,
                         f"All {len(compliant)} Cloud Storage buckets have uniform bucket-level access enabled",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "Google", Verdict.INCONCLUSIVE,
                         f"Error checking Cloud Storage buckets: {e}")
