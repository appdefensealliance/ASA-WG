"""Shared fixtures for GCP check tests.

Since GCP doesn't have a moto-equivalent and google-cloud packages may not be installed
in the test environment, we use sys.modules mocking for inline imports and
unittest.mock.patch for module-level references.
"""

import sys
from unittest.mock import MagicMock

import pytest

from ada_cloud_audit.checks.gcp.base import GCPSession


@pytest.fixture
def gcp_session():
    """Create a GCPSession with mock credentials and test project ID."""
    mock_credentials = MagicMock()
    return GCPSession(credentials=mock_credentials, project_id="test-project-123")


@pytest.fixture(autouse=True)
def mock_google_modules():
    """Pre-populate sys.modules with mock google-cloud modules.

    This allows inline 'from google.cloud import X' imports to work
    even when google-cloud packages aren't installed.
    """
    mocks = {}
    modules_to_mock = [
        "google",
        "google.auth",
        "google.auth.credentials",
        "google.api_core",
        "google.api_core.exceptions",
        "google.cloud",
        "google.cloud.compute_v1",
        "google.cloud.compute_v1.types",
        "google.cloud.functions_v2",
        "google.cloud.functions_v2.types",
        "google.cloud.resourcemanager_v3",
        "google.cloud.kms_v1",
        "google.cloud.essential_contacts_v1",
        "google.cloud.essential_contacts_v1.types",
        "google.cloud.asset_v1",
        "google.cloud.logging_v2",
        "google.cloud.logging_v2.services",
        "google.cloud.logging_v2.services.config_service_v2",
        "google.cloud.monitoring_v3",
        "google.cloud.dns",
        "google.cloud.dns.client",
        "google.cloud.storage",
        "google.cloud.sql_v1beta4",
        "google.iam",
        "google.iam.v1",
        "google.iam.v1.iam_policy_pb2",
        "googleapiclient",
        "googleapiclient.discovery",
    ]

    # Save originals and insert mocks
    saved = {}
    for mod_name in modules_to_mock:
        saved[mod_name] = sys.modules.get(mod_name)
        mocks[mod_name] = MagicMock()
        sys.modules[mod_name] = mocks[mod_name]

    # Wire up the hierarchy so 'from google.cloud import X' works
    sys.modules["google"].cloud = sys.modules["google.cloud"]
    sys.modules["google"].auth = sys.modules["google.auth"]
    sys.modules["google"].iam = sys.modules["google.iam"]

    gc = sys.modules["google.cloud"]
    gc.compute_v1 = sys.modules["google.cloud.compute_v1"]
    gc.functions_v2 = sys.modules["google.cloud.functions_v2"]
    gc.resourcemanager_v3 = sys.modules["google.cloud.resourcemanager_v3"]
    gc.kms_v1 = sys.modules["google.cloud.kms_v1"]
    gc.essential_contacts_v1 = sys.modules["google.cloud.essential_contacts_v1"]
    gc.asset_v1 = sys.modules["google.cloud.asset_v1"]
    gc.logging_v2 = sys.modules["google.cloud.logging_v2"]
    gc.monitoring_v3 = sys.modules["google.cloud.monitoring_v3"]
    gc.dns = sys.modules["google.cloud.dns"]
    gc.storage = sys.modules["google.cloud.storage"]

    yield mocks

    # Restore originals
    for mod_name in modules_to_mock:
        if saved[mod_name] is None:
            sys.modules.pop(mod_name, None)
        else:
            sys.modules[mod_name] = saved[mod_name]


@pytest.fixture
def mock_sql_instances():
    """Factory to create mock Cloud SQL instances."""
    def _create(instances_data):
        result = []
        for data in instances_data:
            instance = {
                "name": data.get("name", "test-instance"),
                "databaseVersion": data.get("databaseVersion", "MYSQL_8_0"),
                "settings": data.get("settings", {}),
                "ipAddresses": data.get("ipAddresses", []),
            }
            result.append(instance)
        return result
    return _create


@pytest.fixture
def mock_vm_instance():
    """Factory to create mock Compute Engine VM instances."""
    def _create(name="test-vm", metadata_items=None, can_ip_forward=False,
                service_accounts=None):
        inst = MagicMock()
        inst.name = name
        inst.can_ip_forward = can_ip_forward

        if metadata_items:
            items = []
            for key, value in metadata_items.items():
                item = MagicMock()
                item.key = key
                item.value = value
                items.append(item)
            inst.metadata.items = items
        else:
            inst.metadata.items = []

        if service_accounts:
            sa_mocks = []
            for sa in service_accounts:
                sa_mock = MagicMock()
                sa_mock.email = sa.get("email", "")
                sa_mock.scopes = sa.get("scopes", [])
                sa_mocks.append(sa_mock)
            inst.service_accounts = sa_mocks
        else:
            inst.service_accounts = []

        return inst
    return _create
