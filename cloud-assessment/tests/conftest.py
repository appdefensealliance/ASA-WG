"""Shared fixtures for ADA Cloud Audit tests."""

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def aws_session():
    """Create a mocked AWS session using moto."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        # Create default EC2 regions
        yield session
