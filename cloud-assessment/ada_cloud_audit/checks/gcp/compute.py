"""GCP Compute checks for ADA Cloud assessment.

Covers 7 requirements:
- 1.2.7: Cloud Functions use current runtimes
- 1.3.4: Block Project-Wide SSH Keys enabled for VM instances
- 1.5.1: IP Forwarding not enabled on instances
- 1.6.1: Instances not using default service account
- 1.6.2: Instances not using default SA with full access scope
- 1.7.1: Serial port connection not enabled for VM instances
- 1.8.2: OS Login enabled for the project
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.gcp.base import GCPSession, list_all_instances
from ada_cloud_audit.models import RequirementResult, Verdict

# Deprecated Cloud Functions runtimes
DEPRECATED_RUNTIMES = {
    "nodejs6", "nodejs8", "nodejs10", "nodejs12", "nodejs14", "nodejs16",
    "python37", "python38",
    "go111", "go113", "go116",
    "java11",
    "dotnet3",
    "ruby26", "ruby27",
    "php74",
}


def check_cloud_functions_runtimes(session: GCPSession) -> RequirementResult:
    """ADA 1.2.7: Ensure Cloud Functions use current (not deprecated) runtimes."""
    spec_id = "1.2.7"
    title = "Ensure that all Cloud Functions are configured to use a current runtime"

    try:
        from google.cloud.functions_v2 import FunctionServiceClient
        from google.cloud.functions_v2.types import ListFunctionsRequest

        client = FunctionServiceClient(credentials=session.credentials)
        parent = f"projects/{session.project_id}/locations/-"
        request = ListFunctionsRequest(parent=parent)

        deprecated_functions = []
        total = 0
        for func in client.list_functions(request=request):
            total += 1
            runtime = func.build_config.runtime if func.build_config else ""
            if runtime in DEPRECATED_RUNTIMES:
                deprecated_functions.append(f"{func.name} (runtime: {runtime})")

        if total == 0:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No Cloud Functions found")

        if deprecated_functions:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Functions with deprecated runtimes:\n" + "\n".join(deprecated_functions),
                             {"deprecated_functions": deprecated_functions, "total": total})

        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {total} Cloud Functions use current runtimes",
                         {"total": total})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking Cloud Functions runtimes: {e}")


def _get_instance_metadata_value(instance, key: str) -> str | None:
    """Get a value from instance metadata items."""
    metadata = instance.metadata
    if metadata and metadata.items:
        for item in metadata.items:
            if item.key == key:
                return item.value
    return None


def check_block_project_ssh_keys(session: GCPSession) -> RequirementResult:
    """ADA 1.3.4: Ensure 'Block Project-Wide SSH Keys' is enabled for VM instances."""
    spec_id = "1.3.4"
    title = "Ensure 'Block Project-Wide SSH Keys' is enabled for VM instances"

    try:
        instances = list_all_instances(session)
        if not instances:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No VM instances found")

        non_compliant = []
        compliant = []
        for inst in instances:
            name = inst.name
            value = _get_instance_metadata_value(inst, "block-project-ssh-keys")
            if value and value.lower() == "true":
                compliant.append(name)
            else:
                non_compliant.append(f"{name} (block-project-ssh-keys not enabled)")

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Instances without Block Project-Wide SSH Keys:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {len(compliant)} instances have Block Project-Wide SSH Keys enabled",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking VM instances: {e}")


def check_ip_forwarding(session: GCPSession) -> RequirementResult:
    """ADA 1.5.1: Ensure IP Forwarding is not enabled on instances."""
    spec_id = "1.5.1"
    title = "Ensure IP Forwarding is not enabled on instances"

    try:
        instances = list_all_instances(session)
        if not instances:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No VM instances found")

        non_compliant = []
        compliant = []
        for inst in instances:
            name = inst.name
            if inst.can_ip_forward:
                non_compliant.append(f"{name} (IP forwarding enabled)")
            else:
                compliant.append(name)

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Instances with IP forwarding enabled:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {len(compliant)} instances have IP forwarding disabled",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking VM instances: {e}")


def check_default_service_account(session: GCPSession) -> RequirementResult:
    """ADA 1.6.1: Ensure instances are not configured to use default service account."""
    spec_id = "1.6.1"
    title = "Ensure instances are not configured to use the default service account"

    try:
        instances = list_all_instances(session)
        if not instances:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No VM instances found")

        non_compliant = []
        compliant = []
        for inst in instances:
            name = inst.name
            for sa in inst.service_accounts:
                if sa.email and sa.email.endswith("-compute@developer.gserviceaccount.com"):
                    non_compliant.append(f"{name} (uses default service account: {sa.email})")
                    break
            else:
                compliant.append(name)

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Instances using default service account:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {len(compliant)} instances use non-default service accounts",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking VM instances: {e}")


def check_default_sa_full_access(session: GCPSession) -> RequirementResult:
    """ADA 1.6.2: Ensure instances are not configured to use default SA with full access to all Cloud APIs."""
    spec_id = "1.6.2"
    title = "Ensure instances are not configured to use the default service account with full access to all Cloud APIs"

    try:
        instances = list_all_instances(session)
        if not instances:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No VM instances found")

        non_compliant = []
        compliant = []
        for inst in instances:
            name = inst.name
            found_issue = False
            for sa in inst.service_accounts:
                if sa.email and sa.email.endswith("-compute@developer.gserviceaccount.com"):
                    scopes = list(sa.scopes) if sa.scopes else []
                    if "https://www.googleapis.com/auth/cloud-platform" in scopes:
                        non_compliant.append(
                            f"{name} (default SA with full cloud-platform scope)"
                        )
                        found_issue = True
                        break
            if not found_issue:
                compliant.append(name)

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Instances with default SA and full access:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {len(compliant)} instances do not use default SA with full access scope",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking VM instances: {e}")


def check_serial_port(session: GCPSession) -> RequirementResult:
    """ADA 1.7.1: Ensure 'Enable connecting to serial ports' is not enabled for VM Instance."""
    spec_id = "1.7.1"
    title = "Ensure 'Enable connecting to serial ports' is not enabled for VM Instance"

    try:
        instances = list_all_instances(session)
        if not instances:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No VM instances found")

        non_compliant = []
        compliant = []
        for inst in instances:
            name = inst.name
            value = _get_instance_metadata_value(inst, "serial-port-enable")
            if value and value.lower() == "true":
                non_compliant.append(f"{name} (serial port connection enabled)")
            else:
                compliant.append(name)

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Instances with serial port enabled:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {len(compliant)} instances have serial port connection disabled",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking VM instances: {e}")


def check_oslogin(session: GCPSession) -> RequirementResult:
    """ADA 1.8.2: Ensure OS Login is enabled for the project."""
    spec_id = "1.8.2"
    title = "Ensure OS Login is enabled for a project"

    try:
        from google.cloud import compute_v1

        client = compute_v1.ProjectsClient(credentials=session.credentials)
        project = client.get(project=session.project_id)

        # Check project-level metadata for enable-oslogin
        if project.common_instance_metadata and project.common_instance_metadata.items:
            for item in project.common_instance_metadata.items:
                if item.key == "enable-oslogin" and item.value.lower() == "true":
                    return make_result(spec_id, title, "GCP", Verdict.PASS,
                                     "OS Login is enabled at project level (enable-oslogin=TRUE)",
                                     {"enable_oslogin": True})

        return make_result(spec_id, title, "GCP", Verdict.FAIL,
                         "OS Login is not enabled at the project level. "
                         "Project metadata does not contain 'enable-oslogin=TRUE'.",
                         {"enable_oslogin": False})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking project metadata: {e}")
