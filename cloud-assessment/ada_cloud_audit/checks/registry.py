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
        "3.8.2": iam.check_access_analyzer,
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
        "3.11.2": logging_checks.check_cloudtrail_cloudwatch_integration,
        "3.11.15": logging_checks.check_web_frontend_logging,

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


def _register_azure_checks() -> None:
    """Register Azure checks if azure packages are installed."""
    try:
        from ada_cloud_audit.checks.azure import (
            compute as az_compute,
            database as az_database,
            identity as az_identity,
            logging as az_logging,
            networking as az_networking,
            security as az_security,
            storage as az_storage,
        )
    except ImportError:
        logger.debug("Azure dependencies not installed, skipping Azure check registration")
        return

    PROVIDER_REGISTRIES[Provider.AZURE] = {
        # Removed checks (return NOT_APPLICABLE)
        "1.1.1": az_identity.check_approved_extensions,
        "1.4.1": az_identity.check_managed_disks,

        # Compute / App Service (9 checks)
        "1.2.2": az_compute.check_functions_runtime,
        "1.2.3": az_compute.check_php_version,
        "1.2.4": az_compute.check_python_version,
        "1.2.5": az_compute.check_java_version,
        "1.2.6": az_compute.check_http_version,
        "1.3.1": az_compute.check_https_only,
        "1.3.2": az_compute.check_tls_version,
        "1.3.3": az_compute.check_ftp_disabled,
        "1.8.1": az_compute.check_app_service_auth,

        # Identity / Entra ID (21 checks — INCONCLUSIVE stubs, requires Microsoft Graph)
        "2.4.1": az_identity.check_user_consent,
        "2.4.2": az_identity.check_gallery_apps,
        "2.4.3": az_identity.check_register_apps,
        "2.7.4": az_identity.check_guest_access_restrictions,
        "2.8.1": az_identity.check_security_defaults,
        "2.9.2": az_identity.check_bad_password_list,
        "2.10.2": az_identity.check_guest_users_reviewed,
        "2.11.2": az_identity.check_notify_admin_password_reset,
        "2.11.3": az_identity.check_restrict_admin_portal,
        "2.11.4": az_identity.check_no_custom_sub_admin_roles,
        "2.13.1": az_identity.check_reconfirm_auth_info,
        "2.14.1": az_identity.check_reset_methods,
        "2.14.2": az_identity.check_mfa_register_devices,
        "2.14.3": az_identity.check_mfa_privileged,
        "2.14.4": az_identity.check_mfa_remember_disabled,
        "2.14.5": az_identity.check_mfa_policy_all_users,
        "2.14.6": az_identity.check_mfa_risky_signins,
        "2.14.8": az_identity.check_mfa_non_privileged,
        "2.15.1": az_identity.check_mfa_admin_groups,
        "2.15.2": az_identity.check_mfa_azure_management,
        "2.17.1": az_identity.check_notify_password_resets,

        # Security - Key Vault (7 checks)
        "2.1.1": az_security.check_key_vault_recoverable,
        "2.1.2": az_security.check_key_vault_public_access,
        "2.5.1": az_security.check_key_expiry_rbac,
        "2.5.2": az_security.check_key_expiry_non_rbac,
        "2.5.3": az_security.check_secret_expiry_rbac,
        "2.5.4": az_security.check_secret_expiry_non_rbac,
        "2.5.5": az_security.check_cert_validity,

        # Security - Defender (6 checks)
        "3.2.1": az_security.check_notify_severity_high,
        "3.2.2": az_security.check_notify_attack_paths,
        "3.3.1": az_security.check_owner_role_notifications,
        "3.3.2": az_security.check_additional_email,
        "3.5.2": az_identity.check_storage_activity_logs,
        "3.6.1": az_security.check_security_benchmark_policies,
        "3.7.1": az_security.check_defender_vm_updates,
        "3.8.1": az_identity.check_auto_provisioning,

        # Logging (16 checks)
        "3.10.7": az_logging.check_audit_log_retention,
        "3.11.3": az_logging.check_resource_logging,
        "3.11.4": az_logging.check_key_vault_logging,
        "3.11.5": az_logging.check_alert_create_policy,
        "3.11.6": az_logging.check_alert_delete_policy,
        "3.11.7": az_logging.check_alert_create_nsg,
        "3.11.8": az_logging.check_alert_delete_nsg,
        "3.11.9": az_logging.check_alert_create_security,
        "3.11.10": az_logging.check_alert_delete_security,
        "3.11.11": az_logging.check_alert_create_sql_fw,
        "3.11.12": az_logging.check_alert_delete_sql_fw,
        "3.11.13": az_logging.check_alert_create_public_ip,
        "3.11.14": az_logging.check_alert_delete_public_ip,
        "3.11.15": az_logging.check_diagnostic_setting_exists,
        "3.11.16": az_logging.check_diagnostic_categories,
        "3.11.17": az_logging.check_alert_service_health,

        # Networking (7 checks)
        "4.3.1": az_networking.check_rdp_restricted,
        "4.3.2": az_networking.check_ssh_restricted,
        "4.3.9": az_networking.check_udp_restricted,
        "4.3.10": az_networking.check_https_restricted,
        "4.3.11": az_networking.check_subnets_have_nsgs,
        "4.3.12": az_networking.check_app_gateway_tls,
        "4.3.13": az_networking.check_app_gateway_http2,

        # Storage (14 checks)
        "5.1.1": az_storage.check_blob_soft_delete,
        "5.1.2": az_storage.check_file_share_soft_delete,
        "5.1.3": az_storage.check_smb_protocol_version,
        "5.1.4": az_storage.check_smb_encryption,
        "5.1.5": az_storage.check_container_soft_delete,
        "5.2.1": az_storage.check_default_network_deny,
        "5.2.2": az_storage.check_public_network_access_disabled,
        "5.3.1": az_storage.check_secure_transfer,
        "5.3.2": az_storage.check_min_tls_version,
        "5.5.2": az_storage.check_blob_public_access_disabled,
        "5.6.1": az_storage.check_key_rotation_reminders,
        "5.7.1": az_storage.check_access_keys_regenerated,
        "5.7.2": az_storage.check_storage_key_access_disabled,
        "5.8.1": az_storage.check_sas_expiry,

        # Database (11 checks)
        "6.3.1": az_database.check_pg_ssl,
        "6.3.2": az_database.check_mysql_ssl,
        "6.3.3": az_database.check_mysql_tls,
        "6.4.2": az_database.check_sql_encryption,
        "6.5.2": az_database.check_sql_firewall,
        "6.7.1": az_identity.check_pg_allow_azure_services,
        "6.11.1": az_database.check_sql_ad_admin,
        "6.13.1": az_database.check_pg_log_checkpoints,
        "6.13.2": az_database.check_pg_log_connections,
        "6.13.3": az_database.check_pg_log_disconnections,
        "6.14.1": az_database.check_pg_log_retention,
        "6.15.1": az_database.check_sql_auditing,
    }


def _register_gcp_checks() -> None:
    """Register GCP checks if google-cloud packages are installed."""
    try:
        from ada_cloud_audit.checks.gcp import (
            bigquery as gcp_bigquery,
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
        "1.2.7": gcp_compute.check_cloud_functions_runtimes,
        "1.3.4": gcp_compute.check_block_project_ssh_keys,
        "1.5.1": gcp_compute.check_ip_forwarding,
        "1.6.1": gcp_compute.check_default_service_account,
        "1.6.2": gcp_compute.check_default_sa_full_access,
        "1.7.1": gcp_compute.check_serial_port,
        "1.8.2": gcp_compute.check_oslogin,

        # IAM (10 checks)
        "2.3.5": gcp_iam.check_essential_contacts,
        "2.6.1": gcp_iam.check_secrets_in_functions,
        "2.7.5": gcp_iam.check_sa_user_role,
        "2.7.6": gcp_iam.check_kms_public_access,
        "2.7.9": gcp_iam.check_kms_key_rotation,
        "2.8.6": gcp_iam.check_gcp_managed_sa_keys,
        "2.10.3": gcp_iam.check_sa_key_rotation,
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

        # Storage (2 checks)
        "5.5.3": gcp_storage.check_bucket_public_access,
        "5.5.4": gcp_bigquery.check_bigquery_public_access,

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
        "6.6.3": gcp_database.check_user_connections,
        "6.12.2": gcp_database.check_automated_backups,
    }


_register_aws_checks()
_register_azure_checks()
_register_gcp_checks()


def get_checks_for_provider(
    provider: Provider,
) -> dict[str, Callable[[Any], RequirementResult]]:
    """Return the check registry for a given provider."""
    return PROVIDER_REGISTRIES.get(provider, {})
