"""GCP Networking checks for ADA Cloud assessment.

Covers 5 requirements:
- 4.1.1: No HTTPS/SSL proxy LBs with weak cipher suites
- 4.2.1: No legacy networks exist
- 4.2.2: DNSSEC enabled for Cloud DNS
- 4.2.3: RSASHA1 not used for key-signing key in DNSSEC
- 4.2.4: RSASHA1 not used for zone-signing key in DNSSEC
"""

from __future__ import annotations

from ada_cloud_audit.checks.base import make_result
from ada_cloud_audit.checks.gcp.base import GCPSession
from ada_cloud_audit.models import RequirementResult, Verdict


def check_ssl_policies(session: GCPSession) -> RequirementResult:
    """ADA 4.1.1: Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites."""
    spec_id = "4.1.1"
    title = "Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites"

    try:
        from google.cloud import compute_v1

        ssl_client = compute_v1.SslPoliciesClient(credentials=session.credentials)
        target_https_client = compute_v1.TargetHttpsProxiesClient(credentials=session.credentials)
        target_ssl_client = compute_v1.TargetSslProxiesClient(credentials=session.credentials)

        # Get all SSL policies
        ssl_policies = {}
        for policy in ssl_client.list(project=session.project_id):
            ssl_policies[policy.self_link] = policy

        weak_proxies = []
        total_proxies = 0

        # Check HTTPS proxies
        for proxy in target_https_client.list(project=session.project_id):
            total_proxies += 1
            if proxy.ssl_policy:
                policy = ssl_policies.get(proxy.ssl_policy)
                if policy and policy.min_tls_version != "TLS_1_2":
                    weak_proxies.append(
                        f"HTTPS proxy '{proxy.name}' uses SSL policy '{policy.name}' "
                        f"with min TLS version {policy.min_tls_version}"
                    )
            else:
                weak_proxies.append(
                    f"HTTPS proxy '{proxy.name}' has no SSL policy (uses GCP default)"
                )

        # Check SSL proxies
        for proxy in target_ssl_client.list(project=session.project_id):
            total_proxies += 1
            if proxy.ssl_policy:
                policy = ssl_policies.get(proxy.ssl_policy)
                if policy and policy.min_tls_version != "TLS_1_2":
                    weak_proxies.append(
                        f"SSL proxy '{proxy.name}' uses SSL policy '{policy.name}' "
                        f"with min TLS version {policy.min_tls_version}"
                    )
            else:
                weak_proxies.append(
                    f"SSL proxy '{proxy.name}' has no SSL policy (uses GCP default)"
                )

        if total_proxies == 0:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No HTTPS or SSL proxy load balancers found")

        if weak_proxies:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "Proxies with weak SSL policies:\n" + "\n".join(weak_proxies),
                             {"weak_proxies": weak_proxies, "total_proxies": total_proxies})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"All {total_proxies} proxies use SSL policies with TLS 1.2+",
                         {"total_proxies": total_proxies})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking SSL policies: {e}")


def check_legacy_networks(session: GCPSession) -> RequirementResult:
    """ADA 4.2.1: Ensure legacy networks do not exist for older projects."""
    spec_id = "4.2.1"
    title = "Ensure legacy networks do not exist for older projects"

    try:
        from google.cloud import compute_v1

        client = compute_v1.NetworksClient(credentials=session.credentials)
        networks = list(client.list(project=session.project_id))

        if not networks:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No VPC networks found")

        legacy_networks = []
        for network in networks:
            # Legacy networks don't have subnets and have IPv4Range set
            if hasattr(network, 'I_pv4_range') and network.I_pv4_range:
                legacy_networks.append(network.name)
            elif not network.subnetworks and not network.auto_create_subnetworks:
                # Another indicator of legacy network
                legacy_networks.append(network.name)

        if legacy_networks:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Legacy networks found: {', '.join(legacy_networks)}",
                             {"legacy_networks": legacy_networks})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"No legacy networks found. All {len(networks)} networks use VPC mode.",
                         {"network_count": len(networks)})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking networks: {e}")


def _check_dns_zones(session: GCPSession):
    """Get all public managed DNS zones."""
    from google.cloud import dns

    client = dns.Client(project=session.project_id, credentials=session.credentials)
    zones = list(client.list_zones())
    # Filter to public zones only
    return [z for z in zones if z.dns_name and not getattr(z, 'visibility', None) == 'private']


def check_dnssec(session: GCPSession) -> RequirementResult:
    """ADA 4.2.2: Ensure DNSSEC is enabled for Cloud DNS."""
    spec_id = "4.2.2"
    title = "Ensure that DNSSEC is enabled for Cloud DNS"

    try:
        zones = _check_dns_zones(session)
        if not zones:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No public Cloud DNS managed zones found")

        non_compliant = []
        compliant = []
        for zone in zones:
            dnssec_config = getattr(zone, 'dnssec_config', None)
            if dnssec_config and dnssec_config.get('state') == 'on':
                compliant.append(zone.name)
            else:
                non_compliant.append(f"{zone.name} (DNSSEC not enabled)")

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             "DNS zones without DNSSEC:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"DNSSEC enabled for all {len(compliant)} public DNS zones",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking DNSSEC: {e}")


def _check_dnssec_algorithm(session: GCPSession, spec_id: str, title: str,
                            key_type: str) -> RequirementResult:
    """Common helper for DNSSEC algorithm checks."""
    try:
        zones = _check_dns_zones(session)
        if not zones:
            return make_result(spec_id, title, "GCP", Verdict.PASS,
                             "No public Cloud DNS managed zones found")

        non_compliant = []
        compliant = []
        for zone in zones:
            dnssec_config = getattr(zone, 'dnssec_config', None)
            if not dnssec_config or dnssec_config.get('state') != 'on':
                continue  # DNSSEC not enabled, checked by 4.2.2

            key_specs = dnssec_config.get('defaultKeySpecs', [])
            for spec in key_specs:
                if spec.get('keyType') == key_type:
                    algorithm = spec.get('algorithm', '')
                    if algorithm == 'RSASHA1':
                        non_compliant.append(
                            f"{zone.name} ({key_type} uses RSASHA1)"
                        )
                    else:
                        compliant.append(f"{zone.name} ({key_type}: {algorithm})")

        if non_compliant:
            return make_result(spec_id, title, "GCP", Verdict.FAIL,
                             f"Zones using RSASHA1 for {key_type}:\n" + "\n".join(non_compliant),
                             {"non_compliant": non_compliant, "compliant": compliant})
        return make_result(spec_id, title, "GCP", Verdict.PASS,
                         f"No zones use RSASHA1 for {key_type}",
                         {"compliant": compliant})
    except Exception as e:
        return make_result(spec_id, title, "GCP", Verdict.INCONCLUSIVE,
                         f"Error checking DNSSEC algorithms: {e}")


def check_dnssec_key_signing(session: GCPSession) -> RequirementResult:
    """ADA 4.2.3: Ensure RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC."""
    return _check_dnssec_algorithm(
        session,
        "4.2.3",
        "Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC",
        "keySigning",
    )


def check_dnssec_zone_signing(session: GCPSession) -> RequirementResult:
    """ADA 4.2.4: Ensure RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC."""
    return _check_dnssec_algorithm(
        session,
        "4.2.4",
        "Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC",
        "zoneSigning",
    )


