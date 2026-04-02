"""Tests for GCP Storage checks."""

from unittest.mock import patch, MagicMock

import pytest

from ada_cloud_audit.checks.gcp.storage import check_bucket_public_access
from ada_cloud_audit.models import Verdict


def test_check_bucket_public_access_pass_no_buckets(gcp_session, mock_google_modules):
    mock_storage = mock_google_modules["google.cloud.storage"]
    mock_client = MagicMock()
    mock_storage.Client.return_value = mock_client
    mock_client.list_buckets.return_value = []

    result = check_bucket_public_access(gcp_session)
    assert result.spec_id == "5.5.3"
    assert result.verdict == Verdict.PASS


def test_check_bucket_public_access_pass(gcp_session, mock_google_modules):
    mock_storage = mock_google_modules["google.cloud.storage"]
    mock_client = MagicMock()
    mock_storage.Client.return_value = mock_client

    mock_bucket = MagicMock()
    mock_bucket.name = "private-bucket"
    mock_policy = MagicMock()
    mock_policy.bindings = [
        {"role": "roles/storage.objectViewer", "members": {"user:admin@company.com"}},
    ]
    mock_bucket.get_iam_policy.return_value = mock_policy
    mock_client.list_buckets.return_value = [mock_bucket]

    result = check_bucket_public_access(gcp_session)
    assert result.verdict == Verdict.PASS


def test_check_bucket_public_access_fail(gcp_session, mock_google_modules):
    mock_storage = mock_google_modules["google.cloud.storage"]
    mock_client = MagicMock()
    mock_storage.Client.return_value = mock_client

    mock_bucket = MagicMock()
    mock_bucket.name = "public-bucket"
    mock_policy = MagicMock()
    mock_policy.bindings = [
        {"role": "roles/storage.objectViewer", "members": {"allUsers"}},
    ]
    mock_bucket.get_iam_policy.return_value = mock_policy
    mock_client.list_buckets.return_value = [mock_bucket]

    result = check_bucket_public_access(gcp_session)
    assert result.verdict == Verdict.FAIL
    assert "public-bucket" in result.evidence
