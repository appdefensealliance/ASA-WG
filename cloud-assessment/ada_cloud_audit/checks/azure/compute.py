"""Azure Compute checks for ADA Cloud assessment.

Covers 9 requirements (maps to CIS Azure Compute Services Benchmark v2.0.0):
- 1.2.2: Azure Functions current runtime
- 1.2.3: PHP version latest
- 1.2.4: Python version latest
- 1.2.5: Java version latest
- 1.2.6: HTTP Version latest
- 1.3.1: Web App HTTPS redirect
- 1.3.2: Web App latest TLS
- 1.3.3: FTP deployments disabled
- 1.8.1: Register with Azure AD on App Service
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict


def _list_web_apps(session: AzureSession) -> list:
    """List all web apps in the subscription."""
    from azure.mgmt.web import WebSiteManagementClient

    client = WebSiteManagementClient(session.credential, session.subscription_id)
    return list(client.web_apps.list())


def _get_web_app_config(session: AzureSession, rg: str, name: str):
    """Get web app configuration."""
    from azure.mgmt.web import WebSiteManagementClient

    client = WebSiteManagementClient(session.credential, session.subscription_id)
    return client.web_apps.get_configuration(rg, name)


def _check_web_app_property(session: AzureSession, spec_id: str, title: str,
                             check_fn) -> RequirementResult:
    """Common helper for web app configuration checks."""
    try:
        apps = _list_web_apps(session)
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                         f"Error listing web apps: {e}")

    if not apps:
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         "No web apps found")

    non_compliant = []
    compliant = []
    for app in apps:
        rg = app.id.split("/")[4]
        try:
            config = _get_web_app_config(session, rg, app.name)
            result = check_fn(app, config)
            if result:
                non_compliant.append(f"{app.name}: {result}")
            else:
                compliant.append(app.name)
        except Exception as e:
            non_compliant.append(f"{app.name}: error ({e})")

    if non_compliant:
        return make_result(spec_id, title, "Azure", Verdict.FAIL,
                         "Non-compliant apps:\n" + "\n".join(non_compliant))
    return make_result(spec_id, title, "Azure", Verdict.PASS,
                     f"All {len(compliant)} web apps are compliant")


def check_functions_runtime(session: AzureSession) -> RequirementResult:
    """ADA 1.2.2: Ensure Azure Functions use a current runtime."""
    return make_result("1.2.2",
        "Ensure that all Azure Functions are configured to use a current (not deprecated) runtime",
        "Azure", Verdict.INCONCLUSIVE,
        "Function app runtime version checking requires inspecting each function app's "
        "configuration. Manual verification recommended via Azure Portal or CLI.")


def check_php_version(session: AzureSession) -> RequirementResult:
    """ADA 1.2.3: Ensure 'PHP version' is the latest."""
    def _check(app, config):
        php = getattr(config, "php_version", "")
        if php and php not in ("", "Off"):
            # PHP 8.2+ is current as of 2025
            try:
                major = int(php.split(".")[0])
                if major < 8:
                    return f"PHP version {php} (should be 8.x+)"
            except (ValueError, IndexError):
                pass
        return None

    return _check_web_app_property(session, "1.2.3",
        "Ensure That 'PHP version' is the Latest, If Used to Run the Web App", _check)


def check_python_version(session: AzureSession) -> RequirementResult:
    """ADA 1.2.4: Ensure 'Python version' is the latest."""
    def _check(app, config):
        python = getattr(config, "python_version", "")
        if python and python not in ("", "Off"):
            try:
                parts = python.split(".")
                major = int(parts[0])
                minor = int(parts[1]) if len(parts) > 1 else 0
                if major < 3 or (major == 3 and minor < 10):
                    return f"Python version {python} (should be 3.10+)"
            except (ValueError, IndexError):
                pass
        return None

    return _check_web_app_property(session, "1.2.4",
        "Ensure that 'Python version' is the Latest Stable Version, if Used to Run the Web App",
        _check)


def check_java_version(session: AzureSession) -> RequirementResult:
    """ADA 1.2.5: Ensure 'Java version' is the latest."""
    def _check(app, config):
        java = getattr(config, "java_version", "")
        if java and java not in ("", "Off"):
            try:
                major = int(java.split(".")[0])
                if major < 17:
                    return f"Java version {java} (should be 17+)"
            except (ValueError, IndexError):
                pass
        return None

    return _check_web_app_property(session, "1.2.5",
        "Ensure that 'Java version' is the latest, if used to run the Web App", _check)


def check_http_version(session: AzureSession) -> RequirementResult:
    """ADA 1.2.6: Ensure 'HTTP Version' is the latest."""
    def _check(app, config):
        http20 = getattr(config, "http20_enabled", False)
        if not http20:
            return "HTTP/2.0 not enabled"
        return None

    return _check_web_app_property(session, "1.2.6",
        "Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App", _check)


def check_https_only(session: AzureSession) -> RequirementResult:
    """ADA 1.3.1: Ensure Web App Redirects All HTTP traffic to HTTPS."""
    def _check(app, config):
        if not getattr(app, "https_only", False):
            return "HTTPS Only not enabled"
        return None

    return _check_web_app_property(session, "1.3.1",
        "Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service", _check)


def check_tls_version(session: AzureSession) -> RequirementResult:
    """ADA 1.3.2: Ensure Web App is using the latest version of TLS encryption."""
    def _check(app, config):
        min_tls = getattr(config, "min_tls_version", "")
        if min_tls and min_tls < "1.2":
            return f"min TLS version is {min_tls}"
        return None

    return _check_web_app_property(session, "1.3.2",
        "Ensure Web App is using the latest version of TLS encryption", _check)


def check_ftp_disabled(session: AzureSession) -> RequirementResult:
    """ADA 1.3.3: Ensure FTP deployments are Disabled."""
    def _check(app, config):
        ftp_state = getattr(config, "ftp_state", "AllAllowed")
        if ftp_state not in ("Disabled", "FtpsOnly"):
            return f"FTP state is {ftp_state}"
        return None

    return _check_web_app_property(session, "1.3.3",
        "Ensure FTP deployments are Disabled", _check)


def check_app_service_auth(session: AzureSession) -> RequirementResult:
    """ADA 1.8.1: Ensure Register with Azure Active Directory is enabled on App Service."""
    try:
        from azure.mgmt.web import WebSiteManagementClient

        client = WebSiteManagementClient(session.credential, session.subscription_id)
        apps = list(client.web_apps.list())

        if not apps:
            return make_result("1.8.1",
                "Ensure that Register with Azure Active Directory is enabled on App Service",
                "Azure", Verdict.PASS, "No web apps found")

        non_compliant = []
        for app in apps:
            rg = app.id.split("/")[4]
            try:
                auth = client.web_apps.get_auth_settings_v2(rg, app.name)
                platform = getattr(auth, "platform", None)
                enabled = platform and getattr(platform, "enabled", False)
                if not enabled:
                    non_compliant.append(app.name)
            except Exception:
                non_compliant.append(f"{app.name} (unable to check)")

        if non_compliant:
            return make_result("1.8.1",
                "Ensure that Register with Azure Active Directory is enabled on App Service",
                "Azure", Verdict.FAIL,
                "Apps without authentication:\n" + "\n".join(non_compliant))
        return make_result("1.8.1",
            "Ensure that Register with Azure Active Directory is enabled on App Service",
            "Azure", Verdict.PASS,
            f"All {len(apps)} web apps have authentication enabled")
    except Exception as e:
        return make_result("1.8.1",
            "Ensure that Register with Azure Active Directory is enabled on App Service",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")
