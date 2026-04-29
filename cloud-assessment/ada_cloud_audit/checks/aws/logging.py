"""AWS Logging and Monitoring checks for ADA Cloud assessment.

Covers 12 requirements:
- 3.4.1: CloudTrail S3 bucket access logging
- 3.9.1-3.9.9: CloudWatch metric filter monitoring (9 checks)
- 3.10.6: Audit logs retained >= 90 days
- 3.11.1: CloudTrail enabled in all regions
- 3.11.2: CloudTrail integrated with CloudWatch Logs
- 3.11.18: Web front-end access logging enabled
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.models import Verdict


def _find_multi_region_trail(session: boto3.Session) -> dict | None:
    """Find an active multi-region CloudTrail with management events."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]

    for trail in trails:
        if not trail.get("IsMultiRegionTrail", False):
            continue
        name = trail.get("TrailARN") or trail.get("Name")
        try:
            status = ct.get_trail_status(Name=name)
            if not status.get("IsLogging", False):
                continue
        except ClientError:
            continue

        # Check event selectors
        try:
            selectors = ct.get_event_selectors(TrailName=name)
            # Check standard event selectors
            for sel in selectors.get("EventSelectors", []):
                if (
                    sel.get("IncludeManagementEvents", False)
                    and sel.get("ReadWriteType") == "All"
                ):
                    return trail
            # Check advanced event selectors
            for sel in selectors.get("AdvancedEventSelectors", []):
                # Advanced selectors with management events
                for field_sel in sel.get("FieldSelectors", []):
                    if field_sel.get("Field") == "eventCategory" and "Management" in field_sel.get("Equals", []):
                        return trail
        except ClientError:
            continue
    return None


def _get_log_group_name(trail: dict) -> str | None:
    """Extract CloudWatch Logs log group name from a trail."""
    arn = trail.get("CloudWatchLogsLogGroupArn", "")
    if not arn:
        return None
    # Format: arn:aws:logs:region:account:log-group:NAME:*
    match = re.search(r":log-group:([^:]+)", arn)
    return match.group(1) if match else None


def _check_metric_filter_and_alarm(
    session: boto3.Session,
    log_group_name: str,
    filter_pattern_keywords: list[str],
    spec_id: str,
    title: str,
    description: str,
) -> "RequirementResult":
    """Common helper for 3.9.x checks: verify metric filter + alarm + SNS subscriber.

    filter_pattern_keywords: list of event names or patterns that must appear in the filter.
    """
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    sns = session.client("sns")

    try:
        # Get all metric filters for the log group
        filters = []
        paginator = logs.get_paginator("describe_metric_filters")
        for page in paginator.paginate(logGroupName=log_group_name):
            filters.extend(page["metricFilters"])

        # Find a filter that matches the required pattern
        matching_filter = None
        for mf in filters:
            fp = mf.get("filterPattern", "")
            # Check if the filter pattern contains the required keywords
            if all(kw.lower() in fp.lower() for kw in filter_pattern_keywords):
                matching_filter = mf
                break

        if not matching_filter:
            return make_result(
                spec_id, title, "AWS", Verdict.FAIL,
                f"No metric filter found for {description}. "
                f"Log group '{log_group_name}' does not have a filter matching required pattern.",
                {"log_group": log_group_name, "filter_found": False},
            )

        # Check for CloudWatch alarm on this metric
        metric_name = matching_filter["metricTransformations"][0]["metricName"]
        metric_ns = matching_filter["metricTransformations"][0].get(
            "metricNamespace", ""
        )

        alarms = cloudwatch.describe_alarms(
            MetricName=metric_name, Namespace=metric_ns if metric_ns else None
        ).get("MetricAlarms", []) if metric_ns else cloudwatch.describe_alarms()["MetricAlarms"]

        if not metric_ns:
            alarms = [a for a in alarms if a.get("MetricName") == metric_name]

        if not alarms:
            return make_result(
                spec_id, title, "AWS", Verdict.FAIL,
                f"Metric filter found for {description} (metric: {metric_name}), "
                f"but no CloudWatch alarm is configured for this metric.",
                {"metric_name": metric_name, "alarm_found": False},
            )

        # Check for SNS subscriber
        alarm = alarms[0]
        alarm_actions = alarm.get("AlarmActions", [])
        sns_topics = [a for a in alarm_actions if ":sns:" in a]

        if not sns_topics:
            return make_result(
                spec_id, title, "AWS", Verdict.FAIL,
                f"Metric filter and alarm found for {description}, "
                f"but alarm has no SNS topic action configured.",
                {"metric_name": metric_name, "alarm_name": alarm["AlarmName"]},
            )

        # Check at least one subscriber
        topic_arn = sns_topics[0]
        try:
            subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
            active_subs = [
                s for s in subs["Subscriptions"]
                if s["SubscriptionArn"] != "PendingConfirmation"
                and "arn:aws:" in s.get("SubscriptionArn", "")
            ]
            if active_subs:
                return make_result(
                    spec_id, title, "AWS", Verdict.PASS,
                    f"Metric filter, alarm, and SNS subscriber configured for {description}. "
                    f"Metric: {metric_name}, Alarm: {alarm['AlarmName']}, "
                    f"SNS topic: {topic_arn} ({len(active_subs)} active subscriber(s)).",
                    {
                        "metric_name": metric_name,
                        "alarm_name": alarm["AlarmName"],
                        "sns_topic": topic_arn,
                        "subscribers": len(active_subs),
                    },
                )
            else:
                return make_result(
                    spec_id, title, "AWS", Verdict.FAIL,
                    f"Metric filter and alarm found for {description}, "
                    f"but SNS topic {topic_arn} has no active subscribers.",
                    {"metric_name": metric_name, "sns_topic": topic_arn},
                )
        except ClientError:
            return make_result(
                spec_id, title, "AWS", Verdict.FAIL,
                f"Could not verify SNS subscribers for topic {topic_arn}.",
                {"metric_name": metric_name, "sns_topic": topic_arn},
            )

    except ClientError as e:
        return make_result(
            spec_id, title, "AWS", Verdict.INCONCLUSIVE,
            f"Error checking metric filters: {e}",
        )


def check_cloudtrail_s3_access_logging(session: boto3.Session) -> "RequirementResult":
    """ADA 3.4.1: Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket."""
    ct = session.client("cloudtrail")
    s3 = session.client("s3")
    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            return make_result(
                "3.4.1",
                "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
                "AWS",
                Verdict.FAIL,
                "No CloudTrail trails configured",
            )

        failing_buckets = []
        passing_buckets = []
        for trail in trails:
            bucket = trail.get("S3BucketName", "")
            if not bucket:
                continue
            try:
                logging_config = s3.get_bucket_logging(Bucket=bucket)
                if logging_config.get("LoggingEnabled"):
                    passing_buckets.append(bucket)
                else:
                    failing_buckets.append(bucket)
            except ClientError:
                failing_buckets.append(f"{bucket} (access denied)")

        if not failing_buckets:
            return make_result(
                "3.4.1",
                "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
                "AWS",
                Verdict.PASS,
                f"Access logging enabled on CloudTrail S3 bucket(s): {', '.join(passing_buckets)}",
                {"passing_buckets": passing_buckets},
            )
        else:
            return make_result(
                "3.4.1",
                "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
                "AWS",
                Verdict.FAIL,
                f"Access logging NOT enabled on CloudTrail S3 bucket(s): {', '.join(failing_buckets)}",
                {"failing_buckets": failing_buckets, "passing_buckets": passing_buckets},
            )
    except ClientError as e:
        return make_result(
            "3.4.1",
            "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking CloudTrail S3 bucket logging: {e}",
        )


# 3.9.x Metric filter checks - each uses the common helper

_METRIC_FILTER_CHECKS = {
    "3.9.1": {
        "title": "Ensure management console sign-in without MFA is monitored",
        "description": "console sign-in without MFA",
        "keywords": ["ConsoleLogin", "MFAUsed"],
    },
    "3.9.2": {
        "title": "Ensure usage of 'root' account is monitored",
        "description": "root account usage",
        "keywords": ["Root", "userIdentity.type"],
    },
    "3.9.3": {
        "title": "Ensure IAM policy changes are monitored",
        "description": "IAM policy changes",
        "keywords": ["DeleteGroupPolicy", "CreatePolicy"],
    },
    "3.9.4": {
        "title": "Ensure CloudTrail configuration changes are monitored",
        "description": "CloudTrail configuration changes",
        "keywords": ["CreateTrail", "DeleteTrail"],
    },
    "3.9.5": {
        "title": "Ensure S3 bucket policy changes are monitored",
        "description": "S3 bucket policy changes",
        "keywords": ["PutBucketAcl", "PutBucketPolicy"],
    },
    "3.9.6": {
        "title": "Ensure changes to network gateways are monitored",
        "description": "network gateway changes",
        "keywords": ["CreateCustomerGateway", "AttachInternetGateway"],
    },
    "3.9.7": {
        "title": "Ensure route table changes are monitored",
        "description": "route table changes",
        "keywords": ["CreateRoute", "CreateRouteTable"],
    },
    "3.9.8": {
        "title": "Ensure VPC changes are monitored",
        "description": "VPC changes",
        "keywords": ["CreateVpc", "DeleteVpc"],
    },
    "3.9.9": {
        "title": "Ensure AWS Organizations changes are monitored",
        "description": "AWS Organizations changes",
        "keywords": ["organizations.amazonaws.com", "AcceptHandshake"],
    },
}


def _make_metric_filter_check(spec_id: str, config: dict):
    """Factory to create a check function for a specific 3.9.x requirement."""

    def check_fn(session: boto3.Session) -> "RequirementResult":
        trail = _find_multi_region_trail(session)
        if not trail:
            return make_result(
                spec_id,
                config["title"],
                "AWS",
                Verdict.FAIL,
                f"No active multi-region CloudTrail found. Cannot verify monitoring for {config['description']}.",
            )

        log_group = _get_log_group_name(trail)
        if not log_group:
            return make_result(
                spec_id,
                config["title"],
                "AWS",
                Verdict.FAIL,
                f"Multi-region CloudTrail exists but has no CloudWatch Logs integration. "
                f"Cannot verify monitoring for {config['description']}.",
            )

        return _check_metric_filter_and_alarm(
            session, log_group, config["keywords"], spec_id, config["title"], config["description"]
        )

    check_fn.__doc__ = f"ADA {spec_id}: {config['title']}"
    return check_fn


# Generate the 9 metric filter check functions
check_console_signin_no_mfa = _make_metric_filter_check("3.9.1", _METRIC_FILTER_CHECKS["3.9.1"])
check_root_account_usage = _make_metric_filter_check("3.9.2", _METRIC_FILTER_CHECKS["3.9.2"])
check_iam_policy_changes = _make_metric_filter_check("3.9.3", _METRIC_FILTER_CHECKS["3.9.3"])
check_cloudtrail_config_changes = _make_metric_filter_check("3.9.4", _METRIC_FILTER_CHECKS["3.9.4"])
check_s3_policy_changes = _make_metric_filter_check("3.9.5", _METRIC_FILTER_CHECKS["3.9.5"])
check_network_gateway_changes = _make_metric_filter_check("3.9.6", _METRIC_FILTER_CHECKS["3.9.6"])
check_route_table_changes = _make_metric_filter_check("3.9.7", _METRIC_FILTER_CHECKS["3.9.7"])
check_vpc_changes = _make_metric_filter_check("3.9.8", _METRIC_FILTER_CHECKS["3.9.8"])
check_organizations_changes = _make_metric_filter_check("3.9.9", _METRIC_FILTER_CHECKS["3.9.9"])


def check_audit_log_retention(session: boto3.Session) -> "RequirementResult":
    """ADA 3.10.6: Ensure that audit logs are retained for a minimum of 90 days."""
    logs = session.client("logs")
    try:
        # Find CloudTrail log groups
        trail = _find_multi_region_trail(session)
        if not trail:
            return make_result(
                "3.10.6",
                "Ensure That Audit Logs are retained for a Minimum of 90 Days",
                "AWS",
                Verdict.INCONCLUSIVE,
                "No active multi-region CloudTrail found to determine audit log group.",
            )

        log_group_name = _get_log_group_name(trail)
        if not log_group_name:
            return make_result(
                "3.10.6",
                "Ensure That Audit Logs are retained for a Minimum of 90 Days",
                "AWS",
                Verdict.FAIL,
                "CloudTrail is not integrated with CloudWatch Logs; no log group to check retention.",
            )

        groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
        if not groups:
            return make_result(
                "3.10.6",
                "Ensure That Audit Logs are retained for a Minimum of 90 Days",
                "AWS",
                Verdict.FAIL,
                f"Log group '{log_group_name}' not found.",
            )

        group = groups[0]
        retention = group.get("retentionInDays")
        if retention is None:
            # None means "Never expire" which is valid
            return make_result(
                "3.10.6",
                "Ensure That Audit Logs are retained for a Minimum of 90 Days",
                "AWS",
                Verdict.PASS,
                f"Log group '{log_group_name}' retention is set to 'Never expire'.",
                {"retentionInDays": "Never expire"},
            )
        elif retention >= 90:
            return make_result(
                "3.10.6",
                "Ensure That Audit Logs are retained for a Minimum of 90 Days",
                "AWS",
                Verdict.PASS,
                f"Log group '{log_group_name}' retention is {retention} days (>= 90).",
                {"retentionInDays": retention},
            )
        else:
            return make_result(
                "3.10.6",
                "Ensure That Audit Logs are retained for a Minimum of 90 Days",
                "AWS",
                Verdict.FAIL,
                f"Log group '{log_group_name}' retention is {retention} days (required >= 90).",
                {"retentionInDays": retention},
            )
    except ClientError as e:
        return make_result(
            "3.10.6",
            "Ensure That Audit Logs are retained for a Minimum of 90 Days",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking log retention: {e}",
        )


def check_cloudtrail_all_regions(session: boto3.Session) -> "RequirementResult":
    """ADA 3.11.1: Ensure CloudTrail is enabled in all regions."""
    trail = _find_multi_region_trail(session)
    if trail:
        name = trail.get("Name", trail.get("TrailARN", "unknown"))
        return make_result(
            "3.11.1",
            "Ensure CloudTrail is enabled in all regions",
            "AWS",
            Verdict.PASS,
            f"Active multi-region CloudTrail found: {name}. "
            f"IsMultiRegionTrail=True, IsLogging=True, management events capture all read/write.",
            {"trail_name": name, "trail_arn": trail.get("TrailARN", "")},
        )
    else:
        return make_result(
            "3.11.1",
            "Ensure CloudTrail is enabled in all regions",
            "AWS",
            Verdict.FAIL,
            "No active multi-region CloudTrail with management event logging found.",
        )


def check_cloudtrail_cloudwatch_integration(session: boto3.Session) -> "RequirementResult":
    """ADA 3.11.2: Ensure CloudTrail trails are integrated with CloudWatch Logs."""
    ct = session.client("cloudtrail")
    try:
        trails = ct.describe_trails()["trailList"]
        if not trails:
            return make_result(
                "3.11.2",
                "Ensure CloudTrail trails are integrated with CloudWatch Logs",
                "AWS",
                Verdict.FAIL,
                "No CloudTrail trails configured",
            )

        integrated_trails = []
        non_integrated = []

        for trail in trails:
            name = trail.get("Name", "unknown")
            cw_arn = trail.get("CloudWatchLogsLogGroupArn", "")
            if cw_arn:
                # Check if delivery is recent
                try:
                    status = ct.get_trail_status(Name=trail.get("TrailARN") or name)
                    last_delivery = status.get("LatestCloudWatchLogsDeliveryTime")
                    if last_delivery:
                        age = datetime.now(timezone.utc) - last_delivery
                        if age < timedelta(days=2):
                            integrated_trails.append(
                                f"{name} (last delivery: {last_delivery.isoformat()})"
                            )
                        else:
                            non_integrated.append(
                                f"{name} (stale delivery: {last_delivery.isoformat()})"
                            )
                    else:
                        non_integrated.append(f"{name} (no delivery timestamp)")
                except ClientError:
                    integrated_trails.append(f"{name} (CloudWatch ARN set)")
            else:
                non_integrated.append(f"{name} (no CloudWatch Logs integration)")

        if integrated_trails and not non_integrated:
            return make_result(
                "3.11.2",
                "Ensure CloudTrail trails are integrated with CloudWatch Logs",
                "AWS",
                Verdict.PASS,
                f"CloudTrail integrated with CloudWatch Logs:\n" + "\n".join(integrated_trails),
                {"integrated": integrated_trails},
            )
        elif integrated_trails:
            return make_result(
                "3.11.2",
                "Ensure CloudTrail trails are integrated with CloudWatch Logs",
                "AWS",
                Verdict.PASS,
                f"At least one trail integrated:\n" + "\n".join(integrated_trails)
                + f"\nNon-integrated:\n" + "\n".join(non_integrated),
                {"integrated": integrated_trails, "non_integrated": non_integrated},
            )
        else:
            return make_result(
                "3.11.2",
                "Ensure CloudTrail trails are integrated with CloudWatch Logs",
                "AWS",
                Verdict.FAIL,
                f"No CloudTrail trails integrated with CloudWatch Logs:\n" + "\n".join(non_integrated),
                {"non_integrated": non_integrated},
            )
    except ClientError as e:
        return make_result(
            "3.11.2",
            "Ensure CloudTrail trails are integrated with CloudWatch Logs",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Error checking CloudTrail CloudWatch integration: {e}",
        )


def check_web_frontend_logging(session: boto3.Session) -> "RequirementResult":
    """ADA 3.11.15: Ensure all AWS-managed web front-end services have access logging enabled."""
    findings = []
    services_checked = []

    # Check CloudFront distributions
    try:
        cf = session.client("cloudfront")
        dists = cf.list_distributions()
        items = dists.get("DistributionList", {}).get("Items", [])
        services_checked.append("CloudFront")
        for dist in items:
            dist_id = dist["Id"]
            domain = dist.get("DomainName", "")
            logging_cfg = dist.get("DefaultCacheBehavior", {})
            # Need full config for logging
            try:
                full = cf.get_distribution(Id=dist_id)
                log_enabled = full["Distribution"]["DistributionConfig"].get("Logging", {}).get("Enabled", False)
                if not log_enabled:
                    findings.append(f"CloudFront {dist_id} ({domain}): access logging disabled")
            except ClientError:
                findings.append(f"CloudFront {dist_id}: unable to check logging config")
    except ClientError:
        findings.append("CloudFront: unable to list distributions")

    # Check ALB/NLB
    try:
        elbv2 = session.client("elbv2")
        paginator = elbv2.get_paginator("describe_load_balancers")
        services_checked.append("ELBv2")
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                lb_arn = lb["LoadBalancerArn"]
                lb_name = lb.get("LoadBalancerName", "")
                try:
                    attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                    log_enabled = False
                    for attr in attrs.get("Attributes", []):
                        if attr["Key"] == "access_logs.s3.enabled" and attr["Value"] == "true":
                            log_enabled = True
                    if not log_enabled:
                        findings.append(f"{lb.get('Type', 'LB')} {lb_name}: access logging disabled")
                except ClientError:
                    findings.append(f"LB {lb_name}: unable to check attributes")
    except ClientError:
        findings.append("ELBv2: unable to list load balancers")

    if not findings:
        return make_result(
            "3.11.18",
            "Ensure all AWS-managed web front-end services have access logging enabled",
            "AWS",
            Verdict.INCONCLUSIVE,
            f"Services checked ({', '.join(services_checked)}): no issues found. "
            "Manual review required for API Gateway stages.",
            {"services_checked": services_checked},
        )
    else:
        return make_result(
            "3.11.18",
            "Ensure all AWS-managed web front-end services have access logging enabled",
            "AWS",
            Verdict.FAIL,
            "Web front-end services without access logging:\n" + "\n".join(findings),
            {"findings": findings, "services_checked": services_checked},
        )
