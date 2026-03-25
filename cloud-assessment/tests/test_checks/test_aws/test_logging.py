"""Tests for AWS Logging checks."""

import json

import boto3
import pytest
from moto import mock_aws

from ada_cloud_audit.checks.aws.logging import (
    check_cloudtrail_all_regions,
    check_cloudtrail_cloudwatch_integration,
    check_cloudtrail_s3_access_logging,
    check_cloudtrail_s3_not_public,
    check_audit_log_retention,
)
from ada_cloud_audit.models import Verdict


@mock_aws
def test_check_cloudtrail_all_regions_fail_no_trail():
    session = boto3.Session(region_name="us-east-1")
    result = check_cloudtrail_all_regions(session)
    assert result.spec_id == "3.11.1"
    assert result.verdict == Verdict.FAIL


@mock_aws
def test_check_cloudtrail_all_regions_pass():
    session = boto3.Session(region_name="us-east-1")
    ct = session.client("cloudtrail", region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    # Create S3 bucket for trail
    s3.create_bucket(Bucket="my-trail-bucket")

    # Create multi-region trail
    ct.create_trail(
        Name="multi-region-trail",
        S3BucketName="my-trail-bucket",
        IsMultiRegionTrail=True,
    )
    ct.start_logging(Name="multi-region-trail")

    # Configure event selectors to capture all management events
    ct.put_event_selectors(
        TrailName="multi-region-trail",
        EventSelectors=[{
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
        }],
    )

    result = check_cloudtrail_all_regions(session)
    assert result.spec_id == "3.11.1"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_cloudtrail_s3_access_logging_fail():
    session = boto3.Session(region_name="us-east-1")
    ct = session.client("cloudtrail", region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    s3.create_bucket(Bucket="trail-bucket")
    ct.create_trail(Name="test-trail", S3BucketName="trail-bucket")

    result = check_cloudtrail_s3_access_logging(session)
    assert result.spec_id == "3.4.1"
    assert result.verdict == Verdict.FAIL


@mock_aws
def test_check_cloudtrail_s3_not_public_pass():
    session = boto3.Session(region_name="us-east-1")
    ct = session.client("cloudtrail", region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    s3.create_bucket(Bucket="trail-bucket")
    ct.create_trail(Name="test-trail", S3BucketName="trail-bucket")

    result = check_cloudtrail_s3_not_public(session)
    assert result.spec_id == "3.5.1"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_cloudtrail_cloudwatch_integration_fail_no_trails():
    session = boto3.Session(region_name="us-east-1")
    result = check_cloudtrail_cloudwatch_integration(session)
    assert result.spec_id == "3.11.2"
    assert result.verdict == Verdict.FAIL
