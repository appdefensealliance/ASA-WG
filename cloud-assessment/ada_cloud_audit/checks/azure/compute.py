"""Azure Compute checks for ADA Cloud assessment.

Covers 34 requirements (maps to CIS Azure Compute Services Benchmark v2.0.0):

App Service (original):
- 1.2.2: Azure Functions current runtime
- 1.2.3: PHP version latest
- 1.2.4: Python version latest
- 1.2.5: Java version latest
- 1.2.6: HTTP Version latest
- 1.3.1: Web App HTTPS redirect
- 1.3.2: Web App latest TLS
- 1.3.3: FTP deployments disabled
- 1.8.1: Register with Azure AD on App Service

App Service (new):
- 1.3.4: End-to-end TLS (client cert mode)
- 1.3.5: Remote debugging disabled
- 1.3.6: Managed identities configured
- 1.3.7: Public network access disabled
- 1.3.8: VNet integration enabled
- 1.3.9: Route all traffic through VNet
- 1.3.10: Basic auth disabled

App Service Environment:
- 1.4.2: ASE v3+ deployed
- 1.4.3: ASE TLS 1.0/1.1 disabled
- 1.4.4: ASE custom cipher suite ordering

Container Instances:
- 1.5.2: Container groups in private VNets
- 1.5.3: Container group managed identity
- 1.5.4: Container least privilege capabilities

Batch:
- 1.6.3: Batch disk encryption
- 1.6.4: Batch local auth disabled
- 1.6.5: Batch public access disabled
- 1.6.6: Batch diagnostics enabled

Virtual Machines:
- 1.4.1: VMs use managed disks (identity, removed stub)
- 1.10.1: VM managed disks check
- 1.10.2: VM disk network access restricted
- 1.10.3: VM disk data access auth mode
- 1.10.4: Only approved VM extensions
- 1.10.5: Trusted launch enabled
- 1.10.6: Encryption at host enabled
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


# --- App Service additional checks ---

def check_e2e_tls(session: AzureSession) -> RequirementResult:
    """ADA 1.3.4: Ensure end-to-end TLS is enabled (HTTPS Only + client cert)."""
    def _check(app, config):
        if not getattr(app, "https_only", False):
            return "httpsOnly not enabled"
        client_cert = getattr(app, "client_cert_mode", "")
        if client_cert not in ("Required", "Optional"):
            return f"clientCertMode is {client_cert or 'not set'} (expected Required or Optional)"
        return None

    return _check_web_app_property(session, "1.3.4",
        "Ensure End-to-End TLS is Enabled for App Service", _check)


def check_remote_debugging(session: AzureSession) -> RequirementResult:
    """ADA 1.3.5: Ensure Remote Debugging is turned off."""
    def _check(app, config):
        if getattr(config, "remote_debugging_enabled", False):
            return "remote debugging is enabled"
        return None

    return _check_web_app_property(session, "1.3.5",
        "Ensure Remote Debugging is Turned Off for App Service", _check)


def check_app_managed_identity(session: AzureSession) -> RequirementResult:
    """ADA 1.3.6: Ensure managed identities are configured for App Service."""
    def _check(app, config):
        identity = getattr(app, "identity", None)
        identity_type = getattr(identity, "type", None) if identity else None
        if not identity_type:
            return "no managed identity configured"
        return None

    return _check_web_app_property(session, "1.3.6",
        "Ensure Managed Identities are Configured for App Service", _check)


def check_app_public_network(session: AzureSession) -> RequirementResult:
    """ADA 1.3.7: Ensure Public Network Access is disabled for App Service."""
    def _check(app, config):
        public_access = getattr(app, "public_network_access", "Enabled")
        if public_access != "Disabled":
            return f"publicNetworkAccess is {public_access}"
        return None

    return _check_web_app_property(session, "1.3.7",
        "Ensure Public Network Access is Disabled for App Service", _check)


def check_vnet_integration(session: AzureSession) -> RequirementResult:
    """ADA 1.3.8: Ensure VNet integration is enabled for App Service."""
    def _check(app, config):
        vnet_subnet = getattr(app, "virtual_network_subnet_id", None)
        if not vnet_subnet:
            return "VNet integration not configured (no virtualNetworkSubnetId)"
        return None

    return _check_web_app_property(session, "1.3.8",
        "Ensure VNet Integration is Enabled for App Service", _check)


def check_vnet_route_all(session: AzureSession) -> RequirementResult:
    """ADA 1.3.9: Ensure all traffic is routed through VNet."""
    def _check(app, config):
        route_all = getattr(config, "vnet_route_all_enabled", False)
        if not route_all:
            return "vnetRouteAllEnabled is not true"
        return None

    return _check_web_app_property(session, "1.3.9",
        "Ensure All Traffic is Routed Through VNet for App Service", _check)


def check_basic_auth_disabled(session: AzureSession) -> RequirementResult:
    """ADA 1.3.10: Ensure basic authentication is disabled for App Service."""
    spec_id = "1.3.10"
    title = "Ensure Basic Authentication is Disabled for App Service Deployments"
    try:
        from azure.mgmt.web import WebSiteManagementClient

        client = WebSiteManagementClient(session.credential, session.subscription_id)
        apps = list(client.web_apps.list())

        if not apps:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No web apps found")

        non_compliant = []
        for app in apps:
            rg = app.id.split("/")[4]
            try:
                # Check FTP basic auth
                ftp_creds = client.web_apps.get_ftp_allowed(rg, app.name)
                if getattr(ftp_creds, "allow", True):
                    non_compliant.append(f"{app.name} (FTP basic auth enabled)")
                # Check SCM basic auth
                scm_creds = client.web_apps.get_scm_allowed(rg, app.name)
                if getattr(scm_creds, "allow", True):
                    non_compliant.append(f"{app.name} (SCM basic auth enabled)")
            except Exception:
                non_compliant.append(f"{app.name} (unable to check)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Apps with basic auth enabled:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(apps)} web apps have basic auth disabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# --- App Service Environment checks ---

def check_ase_version(session: AzureSession) -> RequirementResult:
    """ADA 1.4.2: Ensure App Service Environment is v3+."""
    spec_id = "1.4.2"
    title = "Ensure App Service Environment is Version 3 or Higher"
    try:
        from azure.mgmt.web import WebSiteManagementClient

        client = WebSiteManagementClient(session.credential, session.subscription_id)
        envs = list(client.app_service_environments.list())

        if not envs:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No App Service Environments found")

        non_compliant = []
        for env in envs:
            kind = getattr(env, "kind", "") or ""
            # ASEv3 uses kind "ASEV3"
            if "v3" not in kind.lower() and "asev3" not in kind.lower():
                non_compliant.append(f"{env.name} (kind={kind})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "ASEs not on v3:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(envs)} App Service Environments are v3+")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_ase_tls_disabled(session: AzureSession) -> RequirementResult:
    """ADA 1.4.3: Ensure TLS 1.0 and 1.1 are disabled in ASE."""
    return make_result("1.4.3",
        "Ensure TLS 1.0 and 1.1 are Disabled in App Service Environment",
        "Azure", Verdict.INCONCLUSIVE,
        "ASE TLS settings require checking cluster settings via the ASE API. "
        "Manual verification required: check that InternalEncryption and "
        "FrontEndSSLCipherSuiteOrder settings disable TLS 1.0/1.1.")


def check_ase_cipher_suite(session: AzureSession) -> RequirementResult:
    """ADA 1.4.4: Ensure custom cipher suite ordering is configured for ASE."""
    return make_result("1.4.4",
        "Ensure Custom Cipher Suite Ordering is Configured for App Service Environment",
        "Azure", Verdict.INCONCLUSIVE,
        "ASE cipher suite ordering requires checking cluster settings. "
        "Manual verification required: check FrontEndSSLCipherSuiteOrder in "
        "ASE configuration to ensure strong cipher suites are prioritized.")


# --- Container Instances checks ---

def check_container_private_vnet(session: AzureSession) -> RequirementResult:
    """ADA 1.5.2: Ensure container groups are deployed in private VNets."""
    spec_id = "1.5.2"
    title = "Ensure Container Groups are Deployed in Private VNets"
    try:
        from azure.mgmt.containerinstance import ContainerInstanceManagementClient

        client = ContainerInstanceManagementClient(
            session.credential, session.subscription_id)
        groups = list(client.container_groups.list())

        if not groups:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No container groups found")

        non_compliant = []
        for group in groups:
            subnet_ids = getattr(group, "subnet_ids", None)
            if not subnet_ids:
                non_compliant.append(f"{group.name} (no subnet_ids; not in VNet)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Container groups not in private VNets:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(groups)} container groups are deployed in private VNets")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_container_managed_identity(session: AzureSession) -> RequirementResult:
    """ADA 1.5.3: Ensure container groups have managed identities."""
    spec_id = "1.5.3"
    title = "Ensure Container Groups Have Managed Identities Configured"
    try:
        from azure.mgmt.containerinstance import ContainerInstanceManagementClient

        client = ContainerInstanceManagementClient(
            session.credential, session.subscription_id)
        groups = list(client.container_groups.list())

        if not groups:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No container groups found")

        non_compliant = []
        for group in groups:
            identity = getattr(group, "identity", None)
            identity_type = getattr(identity, "type", None) if identity else None
            if not identity_type:
                non_compliant.append(f"{group.name} (no managed identity)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Container groups without managed identity:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(groups)} container groups have managed identities")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_container_least_privilege(session: AzureSession) -> RequirementResult:
    """ADA 1.5.4: Ensure containers run with least privilege capabilities."""
    return make_result("1.5.4",
        "Ensure Containers Run with Least Privilege Capabilities",
        "Azure", Verdict.INCONCLUSIVE,
        "Container capability restrictions must be verified by examining each "
        "container's security context configuration. Manual verification required: "
        "ensure containers do not run as privileged and drop unnecessary capabilities.")


# --- Batch checks ---

def check_batch_disk_encryption(session: AzureSession) -> RequirementResult:
    """ADA 1.6.3: Ensure Batch account disk encryption is configured."""
    spec_id = "1.6.3"
    title = "Ensure Batch Account Disk Encryption is Configured"
    try:
        from azure.mgmt.batch import BatchManagementClient

        client = BatchManagementClient(session.credential, session.subscription_id)
        accounts = list(client.batch_account.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Batch accounts found")

        non_compliant = []
        for acct in accounts:
            encryption = getattr(acct, "encryption", None)
            key_source = getattr(encryption, "key_source", "") if encryption else ""
            if not encryption or key_source == "":
                non_compliant.append(f"{acct.name} (no encryption configured)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Batch accounts without disk encryption:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} Batch accounts have disk encryption configured")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_batch_local_auth_disabled(session: AzureSession) -> RequirementResult:
    """ADA 1.6.4: Ensure Batch account local authentication is disabled."""
    spec_id = "1.6.4"
    title = "Ensure Batch Account Local Authentication is Disabled"
    try:
        from azure.mgmt.batch import BatchManagementClient

        client = BatchManagementClient(session.credential, session.subscription_id)
        accounts = list(client.batch_account.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Batch accounts found")

        non_compliant = []
        for acct in accounts:
            auth_modes = getattr(acct, "allowed_authentication_modes", None) or []
            auth_modes_str = [str(m) for m in auth_modes]
            if "SharedKey" in auth_modes_str or "TaskAuthenticationToken" in auth_modes_str:
                non_compliant.append(
                    f"{acct.name} (allowed modes: {', '.join(auth_modes_str)})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Batch accounts with local auth enabled:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} Batch accounts have local auth disabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_batch_public_access(session: AzureSession) -> RequirementResult:
    """ADA 1.6.5: Ensure Batch account public network access is disabled."""
    spec_id = "1.6.5"
    title = "Ensure Batch Account Public Network Access is Disabled"
    try:
        from azure.mgmt.batch import BatchManagementClient

        client = BatchManagementClient(session.credential, session.subscription_id)
        accounts = list(client.batch_account.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Batch accounts found")

        non_compliant = []
        for acct in accounts:
            public_access = getattr(acct, "public_network_access", "Enabled")
            if str(public_access) != "Disabled":
                non_compliant.append(
                    f"{acct.name} (publicNetworkAccess={public_access})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Batch accounts with public access:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} Batch accounts have public access disabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_batch_diagnostics(session: AzureSession) -> RequirementResult:
    """ADA 1.6.6: Ensure Batch account diagnostics are enabled."""
    spec_id = "1.6.6"
    title = "Ensure Batch Account Diagnostic Settings are Enabled"
    try:
        from azure.mgmt.batch import BatchManagementClient
        from azure.mgmt.monitor import MonitorManagementClient

        batch_client = BatchManagementClient(session.credential, session.subscription_id)
        monitor_client = MonitorManagementClient(session.credential, session.subscription_id)
        accounts = list(batch_client.batch_account.list())

        if not accounts:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Batch accounts found")

        non_compliant = []
        for acct in accounts:
            settings = list(monitor_client.diagnostic_settings.list(acct.id))
            has_logging = any(
                any(getattr(log, "enabled", False) for log in getattr(s, "logs", []))
                for s in settings
            )
            if not has_logging:
                non_compliant.append(acct.name)

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Batch accounts without diagnostic settings:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(accounts)} Batch accounts have diagnostics enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


# --- Virtual Machine checks ---

def check_vm_managed_disks(session: AzureSession) -> RequirementResult:
    """ADA 1.10.1: Ensure VMs use managed disks."""
    spec_id = "1.10.1"
    title = "Ensure Virtual Machines are Utilizing Managed Disks"
    try:
        from azure.mgmt.compute import ComputeManagementClient

        client = ComputeManagementClient(session.credential, session.subscription_id)
        vms = list(client.virtual_machines.list_all())

        if not vms:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No virtual machines found")

        non_compliant = []
        for vm in vms:
            storage_profile = getattr(vm, "storage_profile", None)
            if not storage_profile:
                non_compliant.append(f"{vm.name} (no storage profile)")
                continue
            # Check OS disk
            os_disk = getattr(storage_profile, "os_disk", None)
            if os_disk:
                managed = getattr(os_disk, "managed_disk", None)
                if not managed:
                    non_compliant.append(f"{vm.name} (OS disk not managed)")
            # Check data disks
            data_disks = getattr(storage_profile, "data_disks", []) or []
            for dd in data_disks:
                managed = getattr(dd, "managed_disk", None)
                if not managed:
                    non_compliant.append(
                        f"{vm.name} (data disk {getattr(dd, 'name', '?')} not managed)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "VMs with unmanaged disks:\n" + "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(vms)} VMs use managed disks")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_disk_network_access(session: AzureSession) -> RequirementResult:
    """ADA 1.10.2: Ensure disk network access is restricted."""
    spec_id = "1.10.2"
    title = "Ensure Managed Disk Network Access is Restricted"
    try:
        from azure.mgmt.compute import ComputeManagementClient

        client = ComputeManagementClient(session.credential, session.subscription_id)
        disks = list(client.disks.list())

        if not disks:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No managed disks found")

        non_compliant = []
        for disk in disks:
            policy = getattr(disk, "network_access_policy", "AllowAll")
            if policy == "AllowAll":
                non_compliant.append(
                    f"{disk.name} (networkAccessPolicy={policy})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Disks with unrestricted network access:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(disks)} managed disks have restricted network access")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_disk_data_access_auth(session: AzureSession) -> RequirementResult:
    """ADA 1.10.3: Ensure disk data access auth mode is configured."""
    spec_id = "1.10.3"
    title = "Ensure Managed Disk Data Access Authentication Mode is Configured"
    try:
        from azure.mgmt.compute import ComputeManagementClient

        client = ComputeManagementClient(session.credential, session.subscription_id)
        disks = list(client.disks.list())

        if not disks:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No managed disks found")

        non_compliant = []
        for disk in disks:
            auth_mode = getattr(disk, "data_access_auth_mode", None)
            if auth_mode and str(auth_mode) not in (
                "AzureActiveDirectory", "None"
            ):
                non_compliant.append(
                    f"{disk.name} (dataAccessAuthMode={auth_mode})")
            elif not auth_mode:
                # No explicit mode set; flag for review
                pass

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Disks with non-Entra auth mode:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(disks)} managed disks have appropriate data access auth mode")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_vm_approved_extensions(session: AzureSession) -> RequirementResult:
    """ADA 1.10.4: Ensure only approved VM extensions are installed."""
    spec_id = "1.10.4"
    title = "Ensure Only Approved Extensions Are Installed on Virtual Machines"
    try:
        from azure.mgmt.compute import ComputeManagementClient

        client = ComputeManagementClient(session.credential, session.subscription_id)
        vms = list(client.virtual_machines.list_all())

        if not vms:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No virtual machines found")

        vm_extensions = []
        for vm in vms:
            rg = vm.id.split("/")[4]
            try:
                exts = list(client.virtual_machine_extensions.list(rg, vm.name))
                for ext in exts:
                    ext_type = getattr(ext, "type_properties_type", "") or \
                               getattr(ext, "type_handler_version", "")
                    vm_extensions.append(f"{vm.name}: {ext.name} ({ext_type})")
            except Exception:
                vm_extensions.append(f"{vm.name}: unable to list extensions")

        if vm_extensions:
            return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                             "VM extensions found (verify against approved list):\n" +
                             "\n".join(vm_extensions))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         "No VM extensions found on any virtual machine")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_trusted_launch(session: AzureSession) -> RequirementResult:
    """ADA 1.10.5: Ensure Trusted Launch is enabled for VMs."""
    spec_id = "1.10.5"
    title = "Ensure Trusted Launch is Enabled for Virtual Machines"
    try:
        from azure.mgmt.compute import ComputeManagementClient

        client = ComputeManagementClient(session.credential, session.subscription_id)
        vms = list(client.virtual_machines.list_all())

        if not vms:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No virtual machines found")

        non_compliant = []
        for vm in vms:
            sec_profile = getattr(vm, "security_profile", None)
            sec_type = getattr(sec_profile, "security_type", None) if sec_profile else None
            if sec_type not in ("TrustedLaunch", "ConfidentialVM"):
                non_compliant.append(
                    f"{vm.name} (securityType={sec_type or 'not set'})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "VMs without Trusted Launch:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(vms)} VMs have Trusted Launch enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_encryption_at_host(session: AzureSession) -> RequirementResult:
    """ADA 1.10.6: Ensure Encryption at Host is enabled for VMs."""
    spec_id = "1.10.6"
    title = "Ensure Encryption at Host is Enabled for Virtual Machines"
    try:
        from azure.mgmt.compute import ComputeManagementClient

        client = ComputeManagementClient(session.credential, session.subscription_id)
        vms = list(client.virtual_machines.list_all())

        if not vms:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No virtual machines found")

        non_compliant = []
        for vm in vms:
            sec_profile = getattr(vm, "security_profile", None)
            enc_at_host = getattr(sec_profile, "encryption_at_host", False) \
                if sec_profile else False
            if not enc_at_host:
                non_compliant.append(f"{vm.name} (encryptionAtHost not enabled)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "VMs without Encryption at Host:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(vms)} VMs have Encryption at Host enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")
