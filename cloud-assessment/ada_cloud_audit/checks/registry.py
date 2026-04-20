"""Provider-scoped registry mapping (provider, spec_id) -> check function."""

from __future__ import annotations

import logging
from typing import Any, Callable

from ada_cloud_audit.models import Provider, RequirementResult

logger = logging.getLogger(__name__)


PROVIDER_REGISTRIES: dict[Provider, dict[str, Callable[[Any], RequirementResult]]] = {}


def _register_aws_checks() -> None:
    """Register AWS checks if boto3 is installed."""
    try:
        from ada_cloud_audit.checks.aws import (
            iam,
            account,
            compute,
            logging as logging_checks,
            storage,
            database,
        )
    except ImportError:
        logger.debug("AWS dependencies not installed, skipping AWS check registration")
        return

    PROVIDER_REGISTRIES[Provider.AWS] = {
        # Compute
        "1.2.1": compute.check_lambda_runtimes,

        # IAM
        "2.2.1": iam.check_support_role,
        "2.3.1": account.check_contact_info,
        "2.3.2": account.check_security_contact,
        "2.7.1": iam.check_root_access_keys,
        "2.7.3": iam.check_no_full_admin_policies,
        "2.8.2": iam.check_password_policy_length,
        "2.8.4": iam.check_access_keys_rotated,
        "2.9.1": iam.check_password_reuse_prevention,
        "2.10.1": iam.check_credentials_unused,
        "2.11.1": iam.check_root_usage,
        "2.16.1": iam.check_root_mfa,
        "2.18.1": iam.check_users_permissions_through_groups,
        "2.14.9": iam.check_iam_mfa_all_users,

        # Logging & Monitoring
        "3.4.1": logging_checks.check_cloudtrail_s3_access_logging,
        "3.9.1": logging_checks.check_console_signin_no_mfa,
        "3.9.2": logging_checks.check_root_account_usage,
        "3.9.3": logging_checks.check_iam_policy_changes,
        "3.9.4": logging_checks.check_cloudtrail_config_changes,
        "3.9.5": logging_checks.check_s3_policy_changes,
        "3.9.6": logging_checks.check_network_gateway_changes,
        "3.9.7": logging_checks.check_route_table_changes,
        "3.9.8": logging_checks.check_vpc_changes,
        "3.9.9": logging_checks.check_organizations_changes,
        "3.10.6": logging_checks.check_audit_log_retention,
        "3.11.1": logging_checks.check_cloudtrail_all_regions,

        # Networking
        "4.2.5": compute.check_ec2_imdsv2,
        "4.3.5": compute.check_nacl_admin_ports_withdrawn,
        "4.3.6": compute.check_sg_ipv4_admin_ports,
        "4.3.7": compute.check_sg_ipv6_admin_ports,
        "4.3.8": compute.check_cifs_restricted,

        # Data Protection - Storage
        "5.4.1": storage.check_ebs_encryption,
        "5.4.2": storage.check_efs_encryption,
        "5.5.1": storage.check_s3_block_public_access,

        # Database Services
        "6.4.1": database.check_rds_encryption,
        "6.5.1": database.check_rds_public_access,
        "6.12.1": database.check_rds_auto_minor_upgrade,
        "6.15.8": database.check_rds_logging_enabled,
        "6.1.2": database.check_rds_multi_az,
    }


def _register_gcp_checks() -> None:
    """Register GCP checks if google-cloud packages are installed."""
    try:
        from ada_cloud_audit.checks.gcp import (
            compute as gcp_compute,
            iam as gcp_iam,
            logging as gcp_logging,
            networking as gcp_networking,
            storage as gcp_storage,
            database as gcp_database,
        )
    except ImportError:
        logger.debug("GCP dependencies not installed, skipping GCP check registration")
        return

    PROVIDER_REGISTRIES[Provider.GCP] = {
        # Compute (7 checks)
        "1.2.6": gcp_compute.check_cloud_functions_runtimes,
        "1.3.4": gcp_compute.check_block_project_ssh_keys,
        "1.5.1": gcp_compute.check_ip_forwarding,
        "1.6.1": gcp_compute.check_default_service_account,
        "1.6.2": gcp_compute.check_default_sa_full_access,
        "1.7.1": gcp_compute.check_serial_port,
        "1.8.2": gcp_compute.check_oslogin,

        # IAM (7 checks)
        "2.3.5": gcp_iam.check_essential_contacts,
        "2.6.1": gcp_iam.check_secrets_in_functions,
        "2.7.5": gcp_iam.check_sa_user_role,
        "2.7.6": gcp_iam.check_kms_public_access,
        "2.11.5": gcp_iam.check_sa_admin_privileges,
        "2.12.1": gcp_iam.check_corporate_credentials,
        "2.14.7": gcp_iam.check_mfa_non_service,
        "2.8.6": gcp_iam.check_gcp_managed_sa_keys,

        # Logging (8 checks)
        "3.1.1": gcp_logging.check_cloud_asset_inventory,
        "3.9.10": gcp_logging.check_audit_logging,
        "3.9.11": gcp_logging.check_dns_logging,
        "3.10.1": gcp_logging.check_log_sinks,
        "3.10.2": gcp_logging.check_ownership_changes,
        "3.10.3": gcp_logging.check_audit_config_changes,
        "3.10.4": gcp_logging.check_custom_role_changes,
        "3.10.5": gcp_logging.check_log_retention,

        # Networking (7 checks)
        "4.1.1": gcp_networking.check_ssl_policies,
        "4.2.1": gcp_networking.check_legacy_networks,
        "4.2.2": gcp_networking.check_dnssec,
        "4.2.3": gcp_networking.check_dnssec_key_signing,
        "4.2.4": gcp_networking.check_dnssec_zone_signing,

        # Storage (1 check)
        "5.5.3": gcp_storage.check_bucket_public_access,

        # Database (19 checks)
        "6.1.1": gcp_database.check_local_infile,
        "6.2.1": gcp_database.check_external_scripts,
        "6.3.4": gcp_database.check_ssl_required,
        "6.5.3": gcp_database.check_no_public_ip_whitelist,
        "6.5.4": gcp_database.check_skip_show_database,
        "6.5.5": gcp_database.check_cross_db_ownership,
        "6.5.6": gcp_database.check_contained_db_auth,
        "6.6.1": gcp_database.check_user_options,
        "6.6.2": gcp_database.check_trace_flag_3625,
        "6.8.1": gcp_database.check_private_ip,
        "6.9.1": gcp_database.check_mysql_admin_access,
        "6.10.1": gcp_database.check_remote_access,
        "6.15.2": gcp_database.check_log_connections,
        "6.15.3": gcp_database.check_log_disconnections,
        "6.15.4": gcp_database.check_log_min_messages,
        "6.15.5": gcp_database.check_log_min_error_statement,
        "6.15.6": gcp_database.check_log_min_duration_statement,
        "6.15.7": gcp_database.check_pgaudit,
    }


_register_aws_checks()
_register_gcp_checks()


def get_checks_for_provider(
    provider: Provider,
) -> dict[str, Callable[[Any], RequirementResult]]:
    """Return the check registry for a given provider."""
    return PROVIDER_REGISTRIES.get(provider, {})
