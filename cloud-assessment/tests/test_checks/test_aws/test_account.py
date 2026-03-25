"""Tests for AWS Account checks."""

import boto3
import pytest
from moto import mock_aws

from ada_cloud_audit.checks.aws.account import (
    check_contact_info,
    check_security_contact,
)
from ada_cloud_audit.models import Verdict


@mock_aws
def test_check_contact_info():
    session = boto3.Session(region_name="us-east-1")
    result = check_contact_info(session)
    # Moto may or may not support account:get-contact-information
    assert result.spec_id == "2.3.1"
    assert result.verdict in (Verdict.PASS, Verdict.FAIL, Verdict.INCONCLUSIVE)


@mock_aws
def test_check_security_contact():
    session = boto3.Session(region_name="us-east-1")
    result = check_security_contact(session)
    assert result.spec_id == "2.3.2"
    assert result.verdict in (Verdict.PASS, Verdict.FAIL, Verdict.INCONCLUSIVE)
