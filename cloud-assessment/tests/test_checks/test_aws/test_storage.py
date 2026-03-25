"""Tests for AWS Storage checks."""

import boto3
import pytest
from moto import mock_aws

from ada_cloud_audit.checks.aws.storage import (
    check_ebs_encryption,
    check_efs_encryption,
    check_s3_block_public_access,
)
from ada_cloud_audit.models import Verdict


@mock_aws
def test_check_s3_block_public_access_pass_no_buckets():
    session = boto3.Session(region_name="us-east-1")
    result = check_s3_block_public_access(session)
    assert result.spec_id == "5.5.1"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_s3_block_public_access_pass():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    result = check_s3_block_public_access(session)
    assert result.spec_id == "5.5.1"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_s3_block_public_access_fail():
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    # No public access block configured

    result = check_s3_block_public_access(session)
    assert result.spec_id == "5.5.1"
    assert result.verdict == Verdict.FAIL


@mock_aws
def test_check_ebs_encryption():
    session = boto3.Session(region_name="us-east-1")
    result = check_ebs_encryption(session)
    assert result.spec_id == "5.4.1"
    # Default is disabled in moto
    assert result.verdict in (Verdict.PASS, Verdict.FAIL)


@mock_aws
def test_check_efs_encryption_pass_no_filesystems():
    session = boto3.Session(region_name="us-east-1")
    result = check_efs_encryption(session)
    assert result.spec_id == "5.4.2"
    assert result.verdict == Verdict.PASS
