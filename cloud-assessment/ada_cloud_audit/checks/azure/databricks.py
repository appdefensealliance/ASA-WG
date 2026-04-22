"""Azure Databricks checks for ADA Cloud assessment.

Covers 8 requirements:
- 1.9.1: Databricks workspace deployed in VNet
- 1.9.2: NSG on Databricks subnets
- 1.9.3: Entra ID identity sync (SCIM)
- 1.9.4: Unity Catalog configured
- 1.9.5: PAT token restrictions
- 1.9.6: Diagnostic logs enabled
- 1.9.7: No Public IP for clusters
- 1.9.8: Public network access disabled
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict


def _list_databricks_workspaces(session: AzureSession) -> list:
    """List all Databricks workspaces in the subscription."""
    from azure.mgmt.databricks import AzureDatabricksManagementClient

    client = AzureDatabricksManagementClient(session.credential, session.subscription_id)
    return list(client.workspaces.list_by_subscription())


def check_vnet_deployment(session: AzureSession) -> RequirementResult:
    """ADA 1.9.1: Ensure Databricks workspace is deployed in a VNet."""
    spec_id = "1.9.1"
    title = "Ensure Databricks Workspace is Deployed in a Customer-Managed VNet"
    try:
        workspaces = _list_databricks_workspaces(session)

        if not workspaces:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Databricks workspaces found")

        non_compliant = []
        for ws in workspaces:
            params = getattr(ws, "parameters", None)
            if params:
                custom_vnet = getattr(params, "custom_virtual_network_id", None)
                vnet_value = getattr(custom_vnet, "value", None) if custom_vnet else None
                if not vnet_value:
                    non_compliant.append(f"{ws.name} (no custom VNet configured)")
            else:
                non_compliant.append(f"{ws.name} (no parameters found)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Workspaces not deployed in customer VNet:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(workspaces)} Databricks workspaces are deployed in customer VNets")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_nsg_on_subnets(session: AzureSession) -> RequirementResult:
    """ADA 1.9.2: Ensure NSGs are associated with Databricks subnets."""
    spec_id = "1.9.2"
    title = "Ensure NSGs are Associated with Databricks Subnets"
    try:
        from azure.mgmt.network import NetworkManagementClient

        workspaces = _list_databricks_workspaces(session)

        if not workspaces:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Databricks workspaces found")

        net_client = NetworkManagementClient(session.credential, session.subscription_id)
        non_compliant = []
        checked = 0

        for ws in workspaces:
            params = getattr(ws, "parameters", None)
            if not params:
                continue
            # Check public and private subnet NSGs
            for subnet_param_name in ("custom_public_subnet_name", "custom_private_subnet_name"):
                subnet_param = getattr(params, subnet_param_name, None)
                subnet_name = getattr(subnet_param, "value", None) if subnet_param else None
                if not subnet_name:
                    continue

                custom_vnet = getattr(params, "custom_virtual_network_id", None)
                vnet_id = getattr(custom_vnet, "value", None) if custom_vnet else None
                if not vnet_id:
                    continue

                checked += 1
                try:
                    # Parse VNet resource group and name from the ID
                    parts = vnet_id.split("/")
                    vnet_rg = parts[4]
                    vnet_name = parts[8]
                    subnet = net_client.subnets.get(vnet_rg, vnet_name, subnet_name)
                    if not subnet.network_security_group:
                        non_compliant.append(
                            f"{ws.name}/{subnet_name} (no NSG associated)")
                except Exception:
                    non_compliant.append(
                        f"{ws.name}/{subnet_name} (unable to check)")

        if checked == 0:
            return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                             "No Databricks subnets found to check. "
                             "Workspaces may not use custom VNets.")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Databricks subnets without NSGs:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {checked} Databricks subnets have NSGs associated")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_entra_id_sync(session: AzureSession) -> RequirementResult:
    """ADA 1.9.3: Ensure Entra ID identity sync is configured via SCIM."""
    return make_result("1.9.3",
        "Ensure Entra ID Identity Sync (SCIM) is Configured for Databricks",
        "Azure", Verdict.INCONCLUSIVE,
        "SCIM provisioning configuration requires access to the Databricks workspace "
        "admin console or SCIM API. Manual verification required: check that SCIM "
        "provisioning is set up via Entra ID Enterprise Applications.")


def check_unity_catalog(session: AzureSession) -> RequirementResult:
    """ADA 1.9.4: Ensure Unity Catalog is configured for data governance."""
    return make_result("1.9.4",
        "Ensure Unity Catalog is Configured for Databricks Data Governance",
        "Azure", Verdict.INCONCLUSIVE,
        "Unity Catalog configuration requires access to the Databricks account "
        "console or workspace APIs. Manual verification required: check that Unity "
        "Catalog is enabled and a metastore is assigned to the workspace.")


def check_pat_restrictions(session: AzureSession) -> RequirementResult:
    """ADA 1.9.5: Ensure PAT token management policies are enforced."""
    return make_result("1.9.5",
        "Ensure Personal Access Token (PAT) Restrictions are Configured",
        "Azure", Verdict.INCONCLUSIVE,
        "PAT token management policies require access to the Databricks workspace "
        "admin settings. Manual verification required: check that token lifetime "
        "restrictions and creation permissions are properly configured.")


def check_diagnostic_logs(session: AzureSession) -> RequirementResult:
    """ADA 1.9.6: Ensure diagnostic logs are enabled for Databricks."""
    spec_id = "1.9.6"
    title = "Ensure Diagnostic Logs are Enabled for Databricks Workspaces"
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        workspaces = _list_databricks_workspaces(session)

        if not workspaces:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Databricks workspaces found")

        monitor_client = MonitorManagementClient(session.credential, session.subscription_id)
        non_compliant = []

        for ws in workspaces:
            settings = list(monitor_client.diagnostic_settings.list(ws.id))
            has_logging = any(
                any(getattr(log, "enabled", False) for log in getattr(s, "logs", []))
                for s in settings
            )
            if not has_logging:
                non_compliant.append(ws.name)

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Databricks workspaces without diagnostic logs:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(workspaces)} Databricks workspaces have diagnostic logs enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_no_public_ip(session: AzureSession) -> RequirementResult:
    """ADA 1.9.7: Ensure 'No Public IP' is enabled for Databricks clusters."""
    spec_id = "1.9.7"
    title = "Ensure No Public IP (NPIP) is Enabled for Databricks Clusters"
    try:
        workspaces = _list_databricks_workspaces(session)

        if not workspaces:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Databricks workspaces found")

        non_compliant = []
        for ws in workspaces:
            params = getattr(ws, "parameters", None)
            if params:
                npip = getattr(params, "enable_no_public_ip", None)
                npip_value = getattr(npip, "value", None) if npip else None
                if npip_value is not True:
                    non_compliant.append(f"{ws.name} (enableNoPublicIp is not true)")
            else:
                non_compliant.append(f"{ws.name} (no parameters found)")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Workspaces without No Public IP:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(workspaces)} Databricks workspaces have No Public IP enabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_public_network_access(session: AzureSession) -> RequirementResult:
    """ADA 1.9.8: Ensure public network access is disabled for Databricks."""
    spec_id = "1.9.8"
    title = "Ensure Public Network Access is Disabled for Databricks Workspaces"
    try:
        workspaces = _list_databricks_workspaces(session)

        if not workspaces:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No Databricks workspaces found")

        non_compliant = []
        for ws in workspaces:
            public_access = getattr(ws, "public_network_access", "Enabled")
            if public_access != "Disabled":
                non_compliant.append(f"{ws.name} (publicNetworkAccess={public_access})")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             "Workspaces with public network access:\n" +
                             "\n".join(non_compliant))
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"All {len(workspaces)} Databricks workspaces have public network access disabled")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")
