"""Azure Networking checks for ADA Cloud assessment.

Covers 8 requirements:
- 4.3.1: RDP access restricted from internet
- 4.3.2: SSH access restricted from internet
- 4.3.9: UDP access restricted from internet
- 4.3.10: HTTP(S) access restricted from internet
- 4.3.11: Subnets associated with NSGs
- 4.3.12: App Gateway SSL policy min TLSv1_2
- 4.3.13: App Gateway HTTP2 enabled
- 4.3.14: Public IP addresses evaluation
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.azure.base import AzureSession
from ada_cloud_audit.models import RequirementResult, Verdict


def _check_nsg_port(session: AzureSession, spec_id: str, title: str,
                    port: int, protocol_name: str) -> RequirementResult:
    """Common helper for NSG port restriction checks."""
    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(session.credential, session.subscription_id)
        nsgs = list(client.network_security_groups.list_all())

        non_compliant = []
        for nsg in nsgs:
            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                # Check if rule allows the target port from internet
                src = rule.source_address_prefix or ""
                src_list = rule.source_address_prefixes or []
                is_internet = src in ("*", "Internet", "0.0.0.0/0") or \
                              any(s in ("*", "Internet", "0.0.0.0/0") for s in src_list)
                if not is_internet:
                    continue

                # Check port range
                dst_port = rule.destination_port_range or ""
                dst_ports = rule.destination_port_ranges or []
                port_match = False
                for p in [dst_port] + list(dst_ports):
                    if p == "*" or p == str(port):
                        port_match = True
                    elif "-" in p:
                        try:
                            lo, hi = p.split("-")
                            if int(lo) <= port <= int(hi):
                                port_match = True
                        except ValueError:
                            pass

                if port_match:
                    non_compliant.append(
                        f"NSG '{nsg.name}' rule '{rule.name}' allows {protocol_name} "
                        f"(port {port}) from {src or src_list}")

        if non_compliant:
            return make_result(spec_id, title, "Azure", Verdict.FAIL,
                             f"NSG rules allowing {protocol_name} from internet:\n"
                             + "\n".join(non_compliant),
                             {"non_compliant": non_compliant})
        return make_result(spec_id, title, "Azure", Verdict.PASS,
                         f"No NSG rules allow unrestricted {protocol_name} access from the internet")
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                         f"Error checking NSG rules: {e}")


def check_rdp_restricted(session: AzureSession) -> RequirementResult:
    """ADA 4.3.1: Ensure RDP access from the Internet is restricted."""
    return _check_nsg_port(session, "4.3.1",
        "Ensure that RDP access from the Internet is evaluated and restricted",
        3389, "RDP")


def check_ssh_restricted(session: AzureSession) -> RequirementResult:
    """ADA 4.3.2: Ensure SSH access from the Internet is restricted."""
    return _check_nsg_port(session, "4.3.2",
        "Ensure that SSH access from the Internet is evaluated and restricted",
        22, "SSH")


def check_udp_restricted(session: AzureSession) -> RequirementResult:
    """ADA 4.3.9: Ensure UDP access from the Internet is restricted."""
    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(session.credential, session.subscription_id)
        nsgs = list(client.network_security_groups.list_all())

        non_compliant = []
        for nsg in nsgs:
            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                protocol = (rule.protocol or "").upper()
                if protocol not in ("UDP", "*"):
                    continue
                src = rule.source_address_prefix or ""
                if src in ("*", "Internet", "0.0.0.0/0"):
                    non_compliant.append(
                        f"NSG '{nsg.name}' rule '{rule.name}' allows UDP from {src}")

        if non_compliant:
            return make_result("4.3.9",
                "Ensure that UDP access from the Internet is evaluated and restricted",
                "Azure", Verdict.FAIL,
                "NSG rules allowing UDP from internet:\n" + "\n".join(non_compliant))
        return make_result("4.3.9",
            "Ensure that UDP access from the Internet is evaluated and restricted",
            "Azure", Verdict.PASS,
            "No NSG rules allow unrestricted UDP access from the internet")
    except Exception as e:
        return make_result("4.3.9",
            "Ensure that UDP access from the Internet is evaluated and restricted",
            "Azure", Verdict.INCONCLUSIVE, f"Error checking NSG rules: {e}")


def check_https_restricted(session: AzureSession) -> RequirementResult:
    """ADA 4.3.10: Ensure HTTP(S) access from the Internet is restricted."""
    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(session.credential, session.subscription_id)
        nsgs = list(client.network_security_groups.list_all())

        non_compliant = []
        http_ports = {80, 443, 8080, 8443}
        for nsg in nsgs:
            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                src = rule.source_address_prefix or ""
                if src not in ("*", "Internet", "0.0.0.0/0"):
                    continue
                dst_port = rule.destination_port_range or ""
                dst_ports = rule.destination_port_ranges or []
                for p in [dst_port] + list(dst_ports):
                    if p == "*":
                        non_compliant.append(
                            f"NSG '{nsg.name}' rule '{rule.name}' allows all ports from {src}")
                        break
                    try:
                        if int(p) in http_ports:
                            non_compliant.append(
                                f"NSG '{nsg.name}' rule '{rule.name}' allows port {p} from {src}")
                    except ValueError:
                        pass

        if non_compliant:
            return make_result("4.3.10",
                "Ensure that HTTP(S) access from the Internet is evaluated and restricted",
                "Azure", Verdict.FAIL,
                "NSG rules allowing HTTP(S) from internet:\n" + "\n".join(non_compliant))
        return make_result("4.3.10",
            "Ensure that HTTP(S) access from the Internet is evaluated and restricted",
            "Azure", Verdict.PASS,
            "No NSG rules allow unrestricted HTTP(S) access from the internet")
    except Exception as e:
        return make_result("4.3.10",
            "Ensure that HTTP(S) access from the Internet is evaluated and restricted",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_subnets_have_nsgs(session: AzureSession) -> RequirementResult:
    """ADA 4.3.11: Ensure subnets are associated with NSGs."""
    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(session.credential, session.subscription_id)
        vnets = list(client.virtual_networks.list_all())

        non_compliant = []
        total_subnets = 0
        skip_subnets = {"GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet"}
        for vnet in vnets:
            for subnet in (vnet.subnets or []):
                if subnet.name in skip_subnets:
                    continue
                total_subnets += 1
                if not subnet.network_security_group:
                    non_compliant.append(f"{vnet.name}/{subnet.name}")

        if total_subnets == 0:
            return make_result("4.3.11",
                "Ensure subnets are associated with network security groups",
                "Azure", Verdict.PASS, "No applicable subnets found")

        if non_compliant:
            return make_result("4.3.11",
                "Ensure subnets are associated with network security groups",
                "Azure", Verdict.FAIL,
                "Subnets without NSGs:\n" + "\n".join(non_compliant))
        return make_result("4.3.11",
            "Ensure subnets are associated with network security groups",
            "Azure", Verdict.PASS,
            f"All {total_subnets} subnets have NSGs associated")
    except Exception as e:
        return make_result("4.3.11",
            "Ensure subnets are associated with network security groups",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_app_gateway_tls(session: AzureSession) -> RequirementResult:
    """ADA 4.3.12: Ensure App Gateway SSL policy min TLSv1_2."""
    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(session.credential, session.subscription_id)
        gateways = list(client.application_gateways.list_all())

        if not gateways:
            return make_result("4.3.12",
                "Ensure the SSL policy min protocol version is set to TLSv1_2 or higher on Azure Application Gateway",
                "Azure", Verdict.PASS, "No Application Gateways found")

        non_compliant = []
        for gw in gateways:
            ssl_policy = getattr(gw, "ssl_policy", None)
            if ssl_policy:
                min_ver = getattr(ssl_policy, "min_protocol_version", "")
                if min_ver and min_ver not in ("TLSv1_2", "TLSv1_3"):
                    non_compliant.append(f"{gw.name} (min TLS: {min_ver})")
            else:
                non_compliant.append(f"{gw.name} (no SSL policy configured)")

        if non_compliant:
            return make_result("4.3.12",
                "Ensure the SSL policy min protocol version is set to TLSv1_2 or higher on Azure Application Gateway",
                "Azure", Verdict.FAIL,
                "App Gateways with weak TLS:\n" + "\n".join(non_compliant))
        return make_result("4.3.12",
            "Ensure the SSL policy min protocol version is set to TLSv1_2 or higher on Azure Application Gateway",
            "Azure", Verdict.PASS,
            f"All {len(gateways)} Application Gateways use TLSv1_2 or higher")
    except Exception as e:
        return make_result("4.3.12",
            "Ensure the SSL policy min protocol version is set to TLSv1_2 or higher on Azure Application Gateway",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_app_gateway_http2(session: AzureSession) -> RequirementResult:
    """ADA 4.3.13: Ensure HTTP2 is enabled on Azure Application Gateway."""
    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(session.credential, session.subscription_id)
        gateways = list(client.application_gateways.list_all())

        if not gateways:
            return make_result("4.3.13",
                "Ensure HTTP2 is set to Enabled on Azure Application Gateway",
                "Azure", Verdict.PASS, "No Application Gateways found")

        non_compliant = []
        for gw in gateways:
            if not getattr(gw, "enable_http2", False):
                non_compliant.append(gw.name)

        if non_compliant:
            return make_result("4.3.13",
                "Ensure HTTP2 is set to Enabled on Azure Application Gateway",
                "Azure", Verdict.FAIL,
                "App Gateways without HTTP2:\n" + "\n".join(non_compliant))
        return make_result("4.3.13",
            "Ensure HTTP2 is set to Enabled on Azure Application Gateway",
            "Azure", Verdict.PASS,
            f"All {len(gateways)} Application Gateways have HTTP2 enabled")
    except Exception as e:
        return make_result("4.3.13",
            "Ensure HTTP2 is set to Enabled on Azure Application Gateway",
            "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")


def check_public_ip_evaluation(session: AzureSession) -> RequirementResult:
    """ADA 4.3.14: Evaluate all public IP addresses."""
    spec_id = "4.3.14"
    title = "Ensure All Public IP Addresses are Evaluated for Necessity"
    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(session.credential, session.subscription_id)
        public_ips = list(client.public_ip_addresses.list_all())

        if not public_ips:
            return make_result(spec_id, title, "Azure", Verdict.PASS,
                             "No public IP addresses found in the subscription")

        ip_list = []
        for pip in public_ips:
            ip_addr = getattr(pip, "ip_address", "N/A") or "not allocated"
            assoc = getattr(pip, "ip_configuration", None)
            assoc_id = getattr(assoc, "id", "unassociated") if assoc else "unassociated"
            ip_list.append(
                f"{pip.name}: {ip_addr} (associated: {assoc_id})")

        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE,
                         f"Found {len(public_ips)} public IP address(es). "
                         f"Manual review required to confirm necessity:\n" +
                         "\n".join(ip_list))
    except Exception as e:
        return make_result(spec_id, title, "Azure", Verdict.INCONCLUSIVE, f"Error: {e}")
