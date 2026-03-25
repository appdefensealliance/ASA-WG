"""Tests for GCP Logging checks."""

from unittest.mock import patch, MagicMock

import pytest

from ada_cloud_audit.checks.gcp.logging import (
    check_cloud_asset_inventory,
    check_audit_logging,
    check_dns_logging,
    check_log_sinks,
    check_ownership_changes,
    check_audit_config_changes,
    check_custom_role_changes,
    check_log_retention,
)
from ada_cloud_audit.models import Verdict


def test_check_cloud_asset_inventory_pass(gcp_session, mock_google_modules):
    mock_asset = mock_google_modules["google.cloud.asset_v1"]
    mock_client = MagicMock()
    mock_asset.AssetServiceClient.return_value = mock_client
    mock_client.search_all_resources.return_value = [MagicMock()]

    result = check_cloud_asset_inventory(gcp_session)
    assert result.spec_id == "3.1.1"
    assert result.verdict == Verdict.PASS


def test_check_audit_logging_pass(gcp_session, mock_google_modules):
    mock_rm = mock_google_modules["google.cloud.resourcemanager_v3"]
    mock_client = MagicMock()
    mock_rm.ProjectsClient.return_value = mock_client

    mock_policy = MagicMock()
    mock_config = MagicMock()
    mock_config.service = "allServices"
    mock_log_config = MagicMock()
    mock_log_config.log_type = 1
    mock_config.audit_log_configs = [mock_log_config]
    mock_policy.audit_configs = [mock_config]
    mock_client.get_iam_policy.return_value = mock_policy

    result = check_audit_logging(gcp_session)
    assert result.spec_id == "3.9.10"
    assert result.verdict == Verdict.PASS


def test_check_audit_logging_fail_no_config(gcp_session, mock_google_modules):
    mock_rm = mock_google_modules["google.cloud.resourcemanager_v3"]
    mock_client = MagicMock()
    mock_rm.ProjectsClient.return_value = mock_client

    mock_policy = MagicMock()
    mock_policy.audit_configs = []
    mock_client.get_iam_policy.return_value = mock_policy

    result = check_audit_logging(gcp_session)
    assert result.verdict == Verdict.FAIL


def test_check_log_sinks_pass(gcp_session, mock_google_modules):
    mock_logging = mock_google_modules["google.cloud.logging_v2"]
    mock_client = MagicMock()
    mock_logging.Client.return_value = mock_client

    mock_sink = MagicMock()
    mock_sink.name = "catch-all-sink"
    mock_sink.filter_ = ""
    mock_client.list_sinks.return_value = [mock_sink]

    result = check_log_sinks(gcp_session)
    assert result.spec_id == "3.10.1"
    assert result.verdict == Verdict.PASS


def test_check_log_sinks_fail_no_sinks(gcp_session, mock_google_modules):
    mock_logging = mock_google_modules["google.cloud.logging_v2"]
    mock_client = MagicMock()
    mock_logging.Client.return_value = mock_client
    mock_client.list_sinks.return_value = []

    result = check_log_sinks(gcp_session)
    assert result.verdict == Verdict.FAIL


def test_check_log_sinks_fail_only_filtered(gcp_session, mock_google_modules):
    mock_logging = mock_google_modules["google.cloud.logging_v2"]
    mock_client = MagicMock()
    mock_logging.Client.return_value = mock_client

    mock_sink = MagicMock()
    mock_sink.name = "filtered-sink"
    mock_sink.filter_ = 'resource.type = "gce_instance"'
    mock_client.list_sinks.return_value = [mock_sink]

    result = check_log_sinks(gcp_session)
    assert result.verdict == Verdict.FAIL


def test_check_log_retention_pass(gcp_session, mock_google_modules):
    mock_config = mock_google_modules["google.cloud.logging_v2.services.config_service_v2"]
    mock_client = MagicMock()
    mock_config.ConfigServiceV2Client.return_value = mock_client

    mock_bucket = MagicMock()
    mock_bucket.name = "projects/test/locations/global/buckets/_Default"
    mock_bucket.retention_days = 365
    mock_client.list_buckets.return_value = [mock_bucket]

    result = check_log_retention(gcp_session)
    assert result.spec_id == "3.10.5"
    assert result.verdict == Verdict.PASS


def test_check_log_retention_fail(gcp_session, mock_google_modules):
    mock_config = mock_google_modules["google.cloud.logging_v2.services.config_service_v2"]
    mock_client = MagicMock()
    mock_config.ConfigServiceV2Client.return_value = mock_client

    mock_bucket = MagicMock()
    mock_bucket.name = "projects/test/locations/global/buckets/_Default"
    mock_bucket.retention_days = 30
    mock_client.list_buckets.return_value = [mock_bucket]

    result = check_log_retention(gcp_session)
    assert result.verdict == Verdict.FAIL


def test_check_ownership_changes_fail_no_metric(gcp_session, mock_google_modules):
    mock_logging = mock_google_modules["google.cloud.logging_v2"]
    mock_log_client = MagicMock()
    mock_logging.Client.return_value = mock_log_client
    mock_log_client.list_metrics.return_value = []

    result = check_ownership_changes(gcp_session)
    assert result.spec_id == "3.10.2"
    assert result.verdict == Verdict.FAIL


def test_check_audit_config_changes_fail_no_metric(gcp_session, mock_google_modules):
    mock_logging = mock_google_modules["google.cloud.logging_v2"]
    mock_log_client = MagicMock()
    mock_logging.Client.return_value = mock_log_client
    mock_log_client.list_metrics.return_value = []

    result = check_audit_config_changes(gcp_session)
    assert result.spec_id == "3.10.3"
    assert result.verdict == Verdict.FAIL


def test_check_custom_role_changes_fail_no_metric(gcp_session, mock_google_modules):
    mock_logging = mock_google_modules["google.cloud.logging_v2"]
    mock_log_client = MagicMock()
    mock_logging.Client.return_value = mock_log_client
    mock_log_client.list_metrics.return_value = []

    result = check_custom_role_changes(gcp_session)
    assert result.spec_id == "3.10.4"
    assert result.verdict == Verdict.FAIL
