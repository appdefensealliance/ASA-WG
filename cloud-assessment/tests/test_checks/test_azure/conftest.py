"""Shared fixtures for Azure check tests.

Since Azure SDK packages may not be installed in the test environment,
we use sys.modules mocking for inline imports and unittest.mock for
Azure management client responses.
"""

import sys
from unittest.mock import MagicMock

import pytest

from ada_cloud_audit.checks.azure.base import AzureSession


@pytest.fixture
def azure_session():
    """Create an AzureSession with mock credential and test subscription ID."""
    mock_credential = MagicMock()
    return AzureSession(credential=mock_credential, subscription_id="00000000-0000-0000-0000-000000000000")


@pytest.fixture(autouse=True)
def mock_azure_modules():
    """Pre-populate sys.modules with mock Azure SDK modules.

    This allows inline 'from azure.mgmt.X import Y' imports to work
    even when azure packages aren't installed.
    """
    mocks = {}
    modules_to_mock = [
        "azure",
        "azure.identity",
        "azure.mgmt",
        "azure.mgmt.storage",
        "azure.mgmt.network",
        "azure.mgmt.keyvault",
        "azure.mgmt.monitor",
        "azure.mgmt.security",
        "azure.mgmt.sql",
        "azure.mgmt.web",
        "azure.mgmt.rdbms",
        "azure.mgmt.rdbms.postgresql_flexibleservers",
        "azure.mgmt.rdbms.mysql_flexibleservers",
        "azure.keyvault",
        "azure.keyvault.keys",
        "azure.keyvault.secrets",
    ]

    saved = {}
    for mod_name in modules_to_mock:
        saved[mod_name] = sys.modules.get(mod_name)
        mocks[mod_name] = MagicMock()
        sys.modules[mod_name] = mocks[mod_name]

    # Wire up the hierarchy
    sys.modules["azure"].mgmt = sys.modules["azure.mgmt"]
    sys.modules["azure"].identity = sys.modules["azure.identity"]
    sys.modules["azure"].keyvault = sys.modules["azure.keyvault"]

    mgmt = sys.modules["azure.mgmt"]
    mgmt.storage = sys.modules["azure.mgmt.storage"]
    mgmt.network = sys.modules["azure.mgmt.network"]
    mgmt.keyvault = sys.modules["azure.mgmt.keyvault"]
    mgmt.monitor = sys.modules["azure.mgmt.monitor"]
    mgmt.security = sys.modules["azure.mgmt.security"]
    mgmt.sql = sys.modules["azure.mgmt.sql"]
    mgmt.web = sys.modules["azure.mgmt.web"]
    mgmt.rdbms = sys.modules["azure.mgmt.rdbms"]

    rdbms = sys.modules["azure.mgmt.rdbms"]
    rdbms.postgresql_flexibleservers = sys.modules["azure.mgmt.rdbms.postgresql_flexibleservers"]
    rdbms.mysql_flexibleservers = sys.modules["azure.mgmt.rdbms.mysql_flexibleservers"]

    kv = sys.modules["azure.keyvault"]
    kv.keys = sys.modules["azure.keyvault.keys"]
    kv.secrets = sys.modules["azure.keyvault.secrets"]

    yield mocks

    for mod_name in modules_to_mock:
        if saved[mod_name] is None:
            sys.modules.pop(mod_name, None)
        else:
            sys.modules[mod_name] = saved[mod_name]


@pytest.fixture
def mock_storage_account():
    """Factory to create mock Azure Storage Account objects."""
    def _create(name="teststorage", **kwargs):
        acct = MagicMock()
        acct.name = name
        acct.id = f"/subscriptions/00000000/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/{name}"
        acct.enable_https_traffic_only = kwargs.get("https_only", True)
        acct.minimum_tls_version = kwargs.get("min_tls", "TLS1_2")
        acct.allow_blob_public_access = kwargs.get("allow_blob_public", False)
        acct.allow_shared_key_access = kwargs.get("allow_shared_key", True)
        acct.public_network_access = kwargs.get("public_network_access", "Enabled")

        net_rules = MagicMock()
        net_rules.default_action = kwargs.get("default_action", "Allow")
        acct.network_rule_set = net_rules

        key_policy = MagicMock()
        key_policy.key_expiration_period_in_days = kwargs.get("key_expiration_days", None)
        acct.key_policy = key_policy

        return acct
    return _create


@pytest.fixture
def mock_nsg():
    """Factory to create mock Network Security Group objects."""
    def _create(name="test-nsg", rules=None):
        nsg = MagicMock()
        nsg.name = name
        if rules is None:
            nsg.security_rules = []
        else:
            mock_rules = []
            for r in rules:
                rule = MagicMock()
                rule.name = r.get("name", "rule1")
                rule.direction = r.get("direction", "Inbound")
                rule.access = r.get("access", "Allow")
                rule.protocol = r.get("protocol", "TCP")
                rule.source_address_prefix = r.get("source", "*")
                rule.source_address_prefixes = r.get("sources", [])
                rule.destination_port_range = r.get("dest_port", "*")
                rule.destination_port_ranges = r.get("dest_ports", [])
                mock_rules.append(rule)
            nsg.security_rules = mock_rules
        return nsg
    return _create
