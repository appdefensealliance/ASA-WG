"""Tests for GCP IAM checks."""

from unittest.mock import patch, MagicMock

import pytest

from ada_cloud_audit.checks.gcp.iam import (
    check_essential_contacts,
    check_secrets_in_functions,
    check_sa_user_role,
    check_kms_public_access,
    check_sa_admin_privileges,
    check_corporate_credentials,
    check_mfa_non_service,
)
from ada_cloud_audit.models import Verdict


def test_check_mfa_non_service_inconclusive(gcp_session):
    result = check_mfa_non_service(gcp_session)
    assert result.spec_id == "2.14.7"
    assert result.verdict == Verdict.INCONCLUSIVE


@patch("ada_cloud_audit.checks.gcp.iam._get_project_iam_policy")
def test_check_corporate_credentials_pass(mock_policy, gcp_session):
    mock_binding = MagicMock()
    mock_binding.role = "roles/viewer"
    mock_binding.members = ["user:admin@company.com"]
    mock_policy.return_value.bindings = [mock_binding]

    result = check_corporate_credentials(gcp_session)
    assert result.spec_id == "2.12.1"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.iam._get_project_iam_policy")
def test_check_corporate_credentials_fail(mock_policy, gcp_session):
    mock_binding = MagicMock()
    mock_binding.role = "roles/viewer"
    mock_binding.members = ["user:someone@gmail.com"]
    mock_policy.return_value.bindings = [mock_binding]

    result = check_corporate_credentials(gcp_session)
    assert result.verdict == Verdict.FAIL
    assert "gmail.com" in result.evidence


@patch("ada_cloud_audit.checks.gcp.iam._get_project_iam_policy")
def test_check_sa_user_role_pass(mock_policy, gcp_session):
    mock_binding = MagicMock()
    mock_binding.role = "roles/viewer"
    mock_binding.members = ["user:admin@company.com"]
    mock_policy.return_value.bindings = [mock_binding]

    result = check_sa_user_role(gcp_session)
    assert result.spec_id == "2.7.5"
    assert result.verdict == Verdict.PASS


@patch("ada_cloud_audit.checks.gcp.iam._get_project_iam_policy")
def test_check_sa_user_role_fail(mock_policy, gcp_session):
    mock_binding = MagicMock()
    mock_binding.role = "roles/iam.serviceAccountUser"
    mock_binding.members = ["user:dev@company.com"]
    mock_policy.return_value.bindings = [mock_binding]

    result = check_sa_user_role(gcp_session)
    assert result.verdict == Verdict.FAIL


@patch("ada_cloud_audit.checks.gcp.iam._get_project_iam_policy")
def test_check_sa_admin_privileges_pass(mock_policy, gcp_session):
    mock_binding = MagicMock()
    mock_binding.role = "roles/viewer"
    mock_binding.members = ["serviceAccount:my-sa@test-project-123.iam.gserviceaccount.com"]
    mock_policy.return_value.bindings = [mock_binding]

    result = check_sa_admin_privileges(gcp_session)
    assert result.spec_id == "2.11.5"
    assert result.verdict == Verdict.PASS


def test_check_secrets_in_functions_pass_no_functions(gcp_session, mock_google_modules):
    mock_functions = mock_google_modules["google.cloud.functions_v2"]
    mock_client = MagicMock()
    mock_functions.FunctionServiceClient.return_value = mock_client
    mock_client.list_functions.return_value = []

    result = check_secrets_in_functions(gcp_session)
    assert result.spec_id == "2.6.1"
    assert result.verdict == Verdict.PASS


def test_check_secrets_in_functions_fail(gcp_session, mock_google_modules):
    mock_functions = mock_google_modules["google.cloud.functions_v2"]
    mock_client = MagicMock()
    mock_functions.FunctionServiceClient.return_value = mock_client

    mock_func = MagicMock()
    mock_func.name = "projects/test/locations/us-central1/functions/my-func"
    mock_func.service_config.environment_variables = {"DB_PASSWORD": "secret123"}
    mock_func.build_config.environment_variables = {}
    mock_client.list_functions.return_value = [mock_func]

    result = check_secrets_in_functions(gcp_session)
    assert result.verdict == Verdict.FAIL
    assert "DB_PASSWORD" in result.evidence


def test_check_essential_contacts_pass(gcp_session, mock_google_modules):
    mock_contacts = mock_google_modules["google.cloud.essential_contacts_v1"]
    mock_client = MagicMock()
    mock_contacts.EssentialContactsServiceClient.return_value = mock_client

    mock_contact = MagicMock()
    mock_contact.notification_category_subscriptions = [1, 2]
    mock_client.list_contacts.return_value = [mock_contact]

    result = check_essential_contacts(gcp_session)
    assert result.spec_id == "2.3.5"
    assert result.verdict == Verdict.PASS


def test_check_essential_contacts_fail(gcp_session, mock_google_modules):
    mock_contacts = mock_google_modules["google.cloud.essential_contacts_v1"]
    mock_client = MagicMock()
    mock_contacts.EssentialContactsServiceClient.return_value = mock_client
    mock_client.list_contacts.return_value = []

    result = check_essential_contacts(gcp_session)
    assert result.verdict == Verdict.FAIL
