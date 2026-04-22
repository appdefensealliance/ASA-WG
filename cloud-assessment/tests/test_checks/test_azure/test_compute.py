"""Tests for Azure Compute (App Service) checks."""

from unittest.mock import MagicMock

from ada_cloud_audit.checks.azure.compute import (
    check_functions_runtime,
    check_https_only,
    check_tls_version,
    check_ftp_disabled,
    check_http_version,
    check_app_service_auth,
)
from ada_cloud_audit.models import Verdict


def _mock_web_app(name="test-app", https_only=True):
    app = MagicMock()
    app.name = name
    app.id = f"/subscriptions/00000000/resourceGroups/test-rg/providers/Microsoft.Web/sites/{name}"
    app.https_only = https_only
    return app


def _mock_config(min_tls="1.2", ftp_state="Disabled", http20=True,
                 php_version="", python_version="", java_version=""):
    config = MagicMock()
    config.min_tls_version = min_tls
    config.ftp_state = ftp_state
    config.http20_enabled = http20
    config.php_version = php_version
    config.python_version = python_version
    config.java_version = java_version
    return config


def test_functions_runtime_inconclusive(azure_session, mock_azure_modules):
    result = check_functions_runtime(azure_session)
    assert result.spec_id == "1.2.2"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_https_only_pass(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app(https_only=True)]
    mock_client.web_apps.get_configuration.return_value = _mock_config()

    result = check_https_only(azure_session)
    assert result.spec_id == "1.3.1"
    assert result.verdict == Verdict.PASS


def test_https_only_fail(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app(https_only=False)]
    mock_client.web_apps.get_configuration.return_value = _mock_config()

    result = check_https_only(azure_session)
    assert result.verdict == Verdict.FAIL


def test_https_only_no_apps(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = []

    result = check_https_only(azure_session)
    assert result.verdict == Verdict.PASS


def test_tls_version_pass(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app()]
    mock_client.web_apps.get_configuration.return_value = _mock_config(min_tls="1.2")

    result = check_tls_version(azure_session)
    assert result.spec_id == "1.3.2"
    assert result.verdict == Verdict.PASS


def test_tls_version_fail(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app()]
    mock_client.web_apps.get_configuration.return_value = _mock_config(min_tls="1.0")

    result = check_tls_version(azure_session)
    assert result.verdict == Verdict.FAIL


def test_ftp_disabled_pass(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app()]
    mock_client.web_apps.get_configuration.return_value = _mock_config(ftp_state="Disabled")

    result = check_ftp_disabled(azure_session)
    assert result.spec_id == "1.3.3"
    assert result.verdict == Verdict.PASS


def test_ftp_disabled_pass_ftps_only(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app()]
    mock_client.web_apps.get_configuration.return_value = _mock_config(ftp_state="FtpsOnly")

    result = check_ftp_disabled(azure_session)
    assert result.verdict == Verdict.PASS


def test_ftp_disabled_fail(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app()]
    mock_client.web_apps.get_configuration.return_value = _mock_config(ftp_state="AllAllowed")

    result = check_ftp_disabled(azure_session)
    assert result.verdict == Verdict.FAIL


def test_http_version_pass(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app()]
    mock_client.web_apps.get_configuration.return_value = _mock_config(http20=True)

    result = check_http_version(azure_session)
    assert result.spec_id == "1.2.6"
    assert result.verdict == Verdict.PASS


def test_http_version_fail(azure_session, mock_azure_modules):
    mock_web = mock_azure_modules["azure.mgmt.web"]
    mock_client = MagicMock()
    mock_web.WebSiteManagementClient.return_value = mock_client
    mock_client.web_apps.list.return_value = [_mock_web_app()]
    mock_client.web_apps.get_configuration.return_value = _mock_config(http20=False)

    result = check_http_version(azure_session)
    assert result.verdict == Verdict.FAIL
