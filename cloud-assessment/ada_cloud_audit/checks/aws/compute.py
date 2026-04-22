"""AWS Compute and Networking checks for ADA Cloud assessment.

Covers 4 requirements:
- 1.2.1: Lambda functions use current runtimes
- 4.2.5: EC2 Metadata Service only allows IMDSv2
- 4.3.5: WITHDRAWN (auto NA)
- 4.3.6: No security groups allow 0.0.0.0/0 ingress to admin ports
- 4.3.7: No security groups allow ::/0 ingress to admin ports
- 4.3.8: CIFS access restricted to trusted networks
"""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ada_cloud_audit.checks.base import make_result, run_multi_region
from ada_cloud_audit.models import Verdict

# Deprecated Lambda runtimes as of late 2024
# See: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
DEPRECATED_RUNTIMES = {
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
    "dotnet5.0", "dotnet6",
    "go1.x",
    "java8", "java8.al2",
    "nodejs", "nodejs4.3", "nodejs4.3-edge", "nodejs6.10", "nodejs8.10",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "python2.7", "python3.6", "python3.7", "python3.8",
    "ruby2.5", "ruby2.7",
    "provided",
}

# Admin ports to check for unrestricted access
ADMIN_PORTS = {22, 3389}


def check_lambda_runtimes(session: boto3.Session) -> "RequirementResult":
    """ADA 1.2.1: Ensure that all AWS Lambda functions are configured to use a current runtime."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        lam = session.client("lambda", region_name=region)
        deprecated_functions = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate(FunctionVersion="ALL"):
                for fn in page["Functions"]:
                    runtime = fn.get("Runtime", "")
                    if runtime in DEPRECATED_RUNTIMES:
                        deprecated_functions.append(
                            f"{fn['FunctionName']} (runtime: {runtime})"
                        )
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDeniedException",):
                return True, "Lambda service not accessible", {}
            raise

        if deprecated_functions:
            return (
                False,
                f"Functions with deprecated runtimes: {', '.join(deprecated_functions)}",
                {"deprecated_functions": deprecated_functions},
            )
        return True, "No functions with deprecated runtimes", {}

    return run_multi_region(
        session,
        "1.2.1",
        "Ensure that all AWS Lambda functions are configured to use a current (not deprecated) runtime",
        "AWS",
        _check_region,
    )


def check_ec2_imdsv2(session: boto3.Session) -> "RequirementResult":
    """ADA 4.2.5: Ensure that EC2 Metadata Service only allows IMDSv2."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        ec2 = session.client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_instances")
            non_compliant = []
            for page in paginator.paginate(
                Filters=[
                    {"Name": "metadata-options.http-tokens", "Values": ["optional"]},
                    {"Name": "metadata-options.state", "Values": ["applied"]},
                ]
            ):
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        state = instance.get("State", {}).get("Name", "")
                        if state == "terminated":
                            continue
                        non_compliant.append(instance["InstanceId"])
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if non_compliant:
            return (
                False,
                f"Instances not requiring IMDSv2: {', '.join(non_compliant)}",
                {"non_compliant_instances": non_compliant},
            )
        return True, "All instances require IMDSv2 (or no instances found)", {}

    return run_multi_region(
        session,
        "4.2.5",
        "Ensure that EC2 Metadata Service only allows IMDSv2",
        "AWS",
        _check_region,
    )


def check_nacl_admin_ports_withdrawn(session: boto3.Session) -> "RequirementResult":
    """ADA 4.3.5: WITHDRAWN in favor of 4.3.6 and 4.3.7."""
    return make_result(
        "4.3.5",
        "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports",
        "AWS",
        Verdict.NOT_APPLICABLE,
        "Requirement withdrawn in favor of 4.3.6 and 4.3.7",
    )


def _port_in_range(port_range_from: int, port_range_to: int, target_port: int) -> bool:
    """Check if a target port falls within a port range."""
    return port_range_from <= target_port <= port_range_to


def _check_security_groups_admin_ports(
    session: boto3.Session, cidr_key: str, cidr_value: str, spec_id: str, title: str
) -> "RequirementResult":
    """Common logic for 4.3.6 and 4.3.7: check security groups for unrestricted admin port access."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        ec2 = session.client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            non_compliant = []
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "")
                    for rule in sg.get("IpPermissions", []):
                        ip_protocol = rule.get("IpProtocol", "")
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 65535)

                        # -1 means all traffic
                        if ip_protocol == "-1":
                            from_port = 0
                            to_port = 65535

                        # Only check TCP/UDP/all protocols
                        if ip_protocol not in ("-1", "tcp", "udp", "6", "17"):
                            continue

                        # Check if any admin port is in range
                        admin_port_exposed = any(
                            _port_in_range(from_port, to_port, p)
                            for p in ADMIN_PORTS
                        )
                        if not admin_port_exposed:
                            continue

                        # Check for the unrestricted CIDR
                        ranges = (
                            rule.get("IpRanges", [])
                            if cidr_key == "CidrIp"
                            else rule.get("Ipv6Ranges", [])
                        )
                        for ip_range in ranges:
                            if ip_range.get(cidr_key) == cidr_value:
                                exposed_ports = [
                                    p for p in ADMIN_PORTS
                                    if _port_in_range(from_port, to_port, p)
                                ]
                                non_compliant.append(
                                    f"{sg_id} ({sg_name}): ports {exposed_ports} "
                                    f"open to {cidr_value}"
                                )
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if non_compliant:
            return (
                False,
                f"Security groups with unrestricted admin port access: {'; '.join(non_compliant)}",
                {"non_compliant": non_compliant},
            )
        return True, f"No security groups allow {cidr_value} ingress to admin ports", {}

    return run_multi_region(session, spec_id, title, "AWS", _check_region)


def check_sg_ipv4_admin_ports(session: boto3.Session) -> "RequirementResult":
    """ADA 4.3.6: Ensure no security groups allow ingress from 0.0.0.0/0 to admin ports."""
    return _check_security_groups_admin_ports(
        session,
        "CidrIp",
        "0.0.0.0/0",
        "4.3.6",
        "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
    )


def check_sg_ipv6_admin_ports(session: boto3.Session) -> "RequirementResult":
    """ADA 4.3.7: Ensure no security groups allow ingress from ::/0 to admin ports."""
    return _check_security_groups_admin_ports(
        session,
        "CidrIpv6",
        "::/0",
        "4.3.7",
        "Ensure no security groups allow ingress from ::/0 to remote server administration ports",
    )


# Port 445 (CIFS) restriction
CIFS_PORTS = {445}


def _check_security_groups_cifs(
    session: boto3.Session, cidr_key: str, cidr_value: str, spec_id: str, title: str
) -> "RequirementResult":
    """Check security groups for unrestricted CIFS port 445 access."""

    def _check_region(session: boto3.Session, region: str) -> tuple[bool, str, dict]:
        ec2 = session.client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            non_compliant = []
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "")
                    for rule in sg.get("IpPermissions", []):
                        ip_protocol = rule.get("IpProtocol", "")
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 65535)

                        if ip_protocol == "-1":
                            from_port = 0
                            to_port = 65535

                        if ip_protocol not in ("-1", "tcp", "udp", "6", "17"):
                            continue

                        cifs_exposed = any(
                            _port_in_range(from_port, to_port, p) for p in CIFS_PORTS
                        )
                        if not cifs_exposed:
                            continue

                        ranges = (
                            rule.get("IpRanges", [])
                            if cidr_key == "CidrIp"
                            else rule.get("Ipv6Ranges", [])
                        )
                        for ip_range in ranges:
                            if ip_range.get(cidr_key) == cidr_value:
                                non_compliant.append(
                                    f"{sg_id} ({sg_name}): port 445 open to {cidr_value}"
                                )
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AuthFailure", "OptInRequired"):
                return True, "Region not accessible", {}
            raise

        if non_compliant:
            return (
                False,
                f"Security groups with unrestricted CIFS access: {'; '.join(non_compliant)}",
                {"non_compliant": non_compliant},
            )
        return True, f"No security groups allow {cidr_value} ingress to port 445", {}

    return run_multi_region(session, spec_id, title, "AWS", _check_region)


def check_cifs_restricted(session: boto3.Session) -> "RequirementResult":
    """ADA 4.3.8: Ensure CIFS access is restricted to trusted networks."""
    # Check both IPv4 and IPv6
    result_v4 = _check_security_groups_cifs(
        session, "CidrIp", "0.0.0.0/0", "4.3.8",
        "Ensure CIFS access is restricted to trusted networks to prevent unauthorized access",
    )
    if result_v4.verdict == Verdict.FAIL:
        return result_v4

    result_v6 = _check_security_groups_cifs(
        session, "CidrIpv6", "::/0", "4.3.8",
        "Ensure CIFS access is restricted to trusted networks to prevent unauthorized access",
    )
    if result_v6.verdict == Verdict.FAIL:
        return result_v6

    return make_result(
        "4.3.8",
        "Ensure CIFS access is restricted to trusted networks to prevent unauthorized access",
        "AWS",
        Verdict.PASS,
        "No security groups allow unrestricted CIFS access (port 445) from 0.0.0.0/0 or ::/0",
    )
