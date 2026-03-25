"""GCP Logging and Monitoring checks for ADA Cloud assessment.

Covers 8 requirements:
- 3.1.1: Cloud Asset Inventory enabled
- 3.9.10: Cloud Audit Logging configured properly
- 3.9.11: Cloud DNS logging enabled for all VPC networks
- 3.10.1: Sinks configured for all log entries
- 3.10.2: Log metric filter + alerts for project ownership changes
- 3.10.3: Log metric filter + alerts for audit config changes
- 3.10.4: Log metric filter + alerts for custom role changes
- 3.10.5: Audit logs retained >= 90 days
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.gcp.base import GCPSession
from ada_cloud_audit.models import RequirementResult, Verdict


def check_cloud_asset_inventory(session: GCPSession) -> RequirementResult:
    """ADA 3.1.1: Ensure Cloud Asset Inventory is enabled."""
    spec_id = "3.1.1"
    title = "Ensure Cloud Asset Inventory is enabled"

    try:
        from google.cloud import asset_v1

        client = asset_v1.AssetServiceClient(credentials=session.credentials)
        parent = f"projects/{session.project_id}"

        # Try to search resources -- if the API is enabled, this will succeed
        request = asset_v1.SearchAllResourcesRequest(
            scope=parent,
            page_size=1,
        )
        results = list(client.search_all_resources(request=request))

        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         "Cloud Asset Inventory API is enabled and accessible",
                         {"api_enabled": True})
    except Exception as e:
        error_str = str(e)
        if "PERMISSION_DENIED" in error_str and "cloudasset.assets.searchAllResources" in error_str:
            return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                             f"Insufficient permissions to verify Cloud Asset Inventory: {e}")
        if "403" in error_str or "not been used" in error_str or "disabled" in error_str:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Cloud Asset Inventory API appears to be disabled: {e}",
                             {"api_enabled": False})
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking Cloud Asset Inventory: {e}")


def check_audit_logging(session: GCPSession) -> RequirementResult:
    """ADA 3.9.10: Ensure Cloud Audit Logging is configured properly."""
    spec_id = "3.9.10"
    title = "Ensure Cloud Audit Logging is configured properly"

    try:
        from google.cloud import resourcemanager_v3
        from google.iam.v1 import iam_policy_pb2

        client = resourcemanager_v3.ProjectsClient(credentials=session.credentials)
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{session.project_id}",
            options=iam_policy_pb2.GetPolicyOptions(requested_policy_version=3),
        )
        policy = client.get_iam_policy(request=request)

        if not policy.audit_configs:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "No audit logging configuration found. Default audit logging "
                             "only covers Admin Activity. Data Access audit logs should be enabled.",
                             {"audit_configs": []})

        # Check for allServices config
        all_services_config = None
        configs_summary = []
        for config in policy.audit_configs:
            log_types = [str(lc.log_type) for lc in config.audit_log_configs]
            configs_summary.append(f"{config.service}: {', '.join(log_types)}")
            if config.service == "allServices":
                all_services_config = config

        if all_services_config:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             f"Cloud Audit Logging configured:\n" + "\n".join(configs_summary),
                             {"audit_configs": configs_summary})
        else:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Audit logging is configured for specific services but not for 'allServices'. "
                             f"Current config:\n" + "\n".join(configs_summary),
                             {"audit_configs": configs_summary})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking audit logging: {e}")


def check_dns_logging(session: GCPSession) -> RequirementResult:
    """ADA 3.9.11: Ensure Cloud DNS logging is enabled for all VPC networks."""
    spec_id = "3.9.11"
    title = "Ensure Cloud DNS logging is enabled for all VPC networks"

    try:
        from google.cloud import dns
        from google.cloud import compute_v1

        # Get all VPC networks
        networks_client = compute_v1.NetworksClient(credentials=session.credentials)
        networks = list(networks_client.list(project=session.project_id))

        if not networks:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No VPC networks found")

        # Get DNS policies
        dns_client = dns.Client(project=session.project_id, credentials=session.credentials)
        policies = list(dns_client.list_policies())

        # Build map of networks with DNS logging enabled
        networks_with_logging = set()
        for policy in policies:
            if policy.enable_logging:
                for network in policy.networks:
                    # Extract network name from URL
                    network_name = network.get("networkUrl", "").split("/")[-1]
                    networks_with_logging.add(network_name)

        networks_without_logging = []
        networks_with = []
        for network in networks:
            if network.name in networks_with_logging:
                networks_with.append(network.name)
            else:
                networks_without_logging.append(network.name)

        if networks_without_logging:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"VPC networks without DNS logging:\n"
                             + "\n".join(networks_without_logging),
                             {"without_logging": networks_without_logging,
                              "with_logging": networks_with})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"DNS logging enabled for all {len(networks_with)} VPC networks",
                         {"with_logging": networks_with})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking DNS logging: {e}")


def check_log_sinks(session: GCPSession) -> RequirementResult:
    """ADA 3.10.1: Ensure sinks are configured for all log entries."""
    spec_id = "3.10.1"
    title = "Ensure sinks are configured for all log entries"

    try:
        from google.cloud import logging_v2

        client = logging_v2.Client(project=session.project_id,
                                   credentials=session.credentials)
        sinks = list(client.list_sinks())

        if not sinks:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "No log sinks configured",
                             {"sinks": []})

        # Check for a catch-all sink (empty filter or no filter)
        catch_all_sinks = []
        filtered_sinks = []
        for sink in sinks:
            if not sink.filter_:
                catch_all_sinks.append(sink.name)
            else:
                filtered_sinks.append(f"{sink.name} (filter: {sink.filter_})")

        if catch_all_sinks:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             f"Catch-all log sink(s) configured: {', '.join(catch_all_sinks)}. "
                             f"Total sinks: {len(sinks)}",
                             {"catch_all_sinks": catch_all_sinks,
                              "filtered_sinks": filtered_sinks})
        else:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"No catch-all log sink found. {len(sinks)} sink(s) exist but all have filters:\n"
                             + "\n".join(filtered_sinks),
                             {"filtered_sinks": filtered_sinks})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking log sinks: {e}")


def _check_log_metric_and_alert(
    session: GCPSession,
    spec_id: str,
    title: str,
    description: str,
    filter_keywords: list[str],
) -> RequirementResult:
    """Common helper for 3.10.2-3.10.4: verify log metric filter + alert policy.

    filter_keywords: substrings that should appear in a log-based metric filter.
    """
    try:
        from google.cloud import logging_v2
        from google.cloud import monitoring_v3

        log_client = logging_v2.Client(project=session.project_id,
                                       credentials=session.credentials)
        metrics = list(log_client.list_metrics())

        # Find a metric whose filter contains the required keywords
        matching_metric = None
        for metric in metrics:
            filter_str = metric.filter_ or ""
            if all(kw.lower() in filter_str.lower() for kw in filter_keywords):
                matching_metric = metric
                break

        if not matching_metric:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"No log-based metric found for {description}. "
                             "Create a metric filter matching the required pattern.",
                             {"metric_found": False})

        # Check for alert policy referencing this metric
        alert_client = monitoring_v3.AlertPolicyServiceClient(
            credentials=session.credentials
        )
        project_name = f"projects/{session.project_id}"
        alert_policies = list(alert_client.list_alert_policies(name=project_name))

        matching_alert = None
        metric_type = f"logging.googleapis.com/user/{matching_metric.name}"
        for policy in alert_policies:
            if not policy.enabled:
                continue
            for condition in policy.conditions:
                cond_filter = ""
                if condition.condition_threshold:
                    cond_filter = condition.condition_threshold.filter
                if metric_type in cond_filter or matching_metric.name in cond_filter:
                    matching_alert = policy
                    break
            if matching_alert:
                break

        if not matching_alert:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Log-based metric found for {description} "
                             f"(metric: {matching_metric.name}), but no alert policy is configured.",
                             {"metric_name": matching_metric.name, "alert_found": False})

        # Check notification channels
        channels = matching_alert.notification_channels
        if not channels:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Metric and alert found for {description}, "
                             "but alert has no notification channels configured.",
                             {"metric_name": matching_metric.name,
                              "alert_name": matching_alert.display_name})

        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"Log metric, alert, and notification configured for {description}. "
                         f"Metric: {matching_metric.name}, "
                         f"Alert: {matching_alert.display_name}, "
                         f"Channels: {len(channels)}",
                         {"metric_name": matching_metric.name,
                          "alert_name": matching_alert.display_name,
                          "notification_channels": len(channels)})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking log metric and alert: {e}")


def check_ownership_changes(session: GCPSession) -> RequirementResult:
    """ADA 3.10.2: Ensure log metric filter and alerts exist for project ownership assignments/changes."""
    return _check_log_metric_and_alert(
        session,
        "3.10.2",
        "Ensure log metric filter and alerts exist for project ownership assignments/changes",
        "project ownership changes",
        ["SetIamPolicy", "roles/owner"],
    )


def check_audit_config_changes(session: GCPSession) -> RequirementResult:
    """ADA 3.10.3: Ensure log metric filter and alerts exist for audit configuration changes."""
    return _check_log_metric_and_alert(
        session,
        "3.10.3",
        "Ensure log metric filter and alerts exist for audit configuration changes",
        "audit configuration changes",
        ["SetIamPolicy", "auditConfigDelta"],
    )


def check_custom_role_changes(session: GCPSession) -> RequirementResult:
    """ADA 3.10.4: Ensure log metric filter and alerts exist for custom role changes."""
    return _check_log_metric_and_alert(
        session,
        "3.10.4",
        "Ensure log metric filter and alerts exist for custom role changes",
        "custom role changes",
        ["CreateRole", "DeleteRole", "UpdateRole"],
    )


def check_log_retention(session: GCPSession) -> RequirementResult:
    """ADA 3.10.5: Ensure audit logs are retained for at least 90 days."""
    spec_id = "3.10.5"
    title = "Ensure that audit logs are retained for a minimum of 90 days"

    try:
        from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client

        client = ConfigServiceV2Client(credentials=session.credentials)
        parent = f"projects/{session.project_id}/locations/-"

        buckets_info = []
        non_compliant = []
        compliant = []

        for bucket in client.list_buckets(parent=parent):
            retention_days = bucket.retention_days
            bucket_name = bucket.name.split("/")[-1]
            buckets_info.append(f"{bucket_name}: {retention_days} days")

            if bucket_name == "_Default" or bucket_name == "_Required":
                if retention_days < 90:
                    non_compliant.append(
                        f"{bucket_name} (retention: {retention_days} days, required >= 90)"
                    )
                else:
                    compliant.append(f"{bucket_name} ({retention_days} days)")

        if not buckets_info:
            return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                             "No logging buckets found")

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Logging buckets with insufficient retention:\n"
                             + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant,
                              "all_buckets": buckets_info})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All logging buckets meet 90-day retention requirement:\n"
                         + "\n".join(compliant),
                         {"compliant": compliant, "all_buckets": buckets_info})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking log retention: {e}")
