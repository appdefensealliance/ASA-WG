"""Tests for AWS Compute checks."""

import json

import boto3
import pytest
from moto import mock_aws

from ada_cloud_audit.checks.aws.compute import (
    check_lambda_runtimes,
    check_ec2_imdsv2,
    check_nacl_admin_ports_withdrawn,
    check_sg_ipv4_admin_ports,
    check_sg_ipv6_admin_ports,
)
from ada_cloud_audit.models import Verdict


@mock_aws
def test_check_nacl_admin_ports_withdrawn():
    session = boto3.Session(region_name="us-east-1")
    result = check_nacl_admin_ports_withdrawn(session)
    assert result.verdict == Verdict.NOT_APPLICABLE
    assert "withdrawn" in result.evidence.lower()


@mock_aws
def test_check_lambda_runtimes_pass_no_functions():
    session = boto3.Session(region_name="us-east-1")
    result = check_lambda_runtimes(session)
    # With no functions, should pass in each region
    assert result.spec_id == "1.2.1"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_lambda_runtimes_fail_deprecated():
    session = boto3.Session(region_name="us-east-1")
    lam = session.client("lambda", region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")

    # Create IAM role for Lambda
    role = iam.create_role(
        RoleName="lambda-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
    )

    # Create function with deprecated runtime
    lam.create_function(
        FunctionName="deprecated-func",
        Runtime="python3.6",
        Role=role["Role"]["Arn"],
        Handler="handler.handler",
        Code={"ZipFile": b"fake code"},
    )

    result = check_lambda_runtimes(session)
    assert result.spec_id == "1.2.1"
    assert result.verdict == Verdict.FAIL
    assert "deprecated-func" in result.evidence


@mock_aws
def test_check_sg_ipv4_admin_ports_pass():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    # Default VPC security group doesn't allow admin ports from 0.0.0.0/0
    result = check_sg_ipv4_admin_ports(session)
    assert result.spec_id == "4.3.6"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_sg_ipv4_admin_ports_fail():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    # Create a security group with SSH open to the world
    vpc = ec2.describe_vpcs()["Vpcs"][0]
    sg = ec2.create_security_group(
        GroupName="insecure-sg",
        Description="Test SG with open SSH",
        VpcId=vpc["VpcId"],
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    result = check_sg_ipv4_admin_ports(session)
    assert result.spec_id == "4.3.6"
    assert result.verdict == Verdict.FAIL


@mock_aws
def test_check_sg_ipv6_admin_ports_pass():
    session = boto3.Session(region_name="us-east-1")
    result = check_sg_ipv6_admin_ports(session)
    assert result.spec_id == "4.3.7"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_ec2_imdsv2_pass_no_instances():
    session = boto3.Session(region_name="us-east-1")
    result = check_ec2_imdsv2(session)
    assert result.spec_id == "4.2.5"
    assert result.verdict == Verdict.PASS
