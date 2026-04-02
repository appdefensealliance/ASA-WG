"""Tests for AWS Database checks."""

import boto3
import pytest
from moto import mock_aws

from ada_cloud_audit.checks.aws.database import (
    check_rds_encryption,
    check_rds_public_access,
    check_rds_auto_minor_upgrade,
    check_rds_logging_enabled,
)
from ada_cloud_audit.models import Verdict


@mock_aws
def test_check_rds_encryption_pass_no_instances():
    session = boto3.Session(region_name="us-east-1")
    result = check_rds_encryption(session)
    assert result.spec_id == "6.4.1"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_rds_public_access_pass_no_instances():
    session = boto3.Session(region_name="us-east-1")
    result = check_rds_public_access(session)
    assert result.spec_id == "6.5.1"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_rds_auto_minor_upgrade_pass_no_instances():
    session = boto3.Session(region_name="us-east-1")
    result = check_rds_auto_minor_upgrade(session)
    assert result.spec_id == "6.12.1"
    assert result.verdict == Verdict.PASS


@mock_aws
def test_check_rds_logging_pass_no_instances():
    session = boto3.Session(region_name="us-east-1")
    result = check_rds_logging_enabled(session)
    assert result.spec_id == "6.15.8"
    assert result.verdict == Verdict.PASS
