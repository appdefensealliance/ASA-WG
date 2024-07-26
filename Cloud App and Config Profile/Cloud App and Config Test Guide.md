# Cloud Config and App Profile - Test Plan

Version 0.5 - April 8, 2024




# Table of Contents
[1 Compute](#1-compute)

[1.1 Establish and Maintain a Software Inventory](#11-establish-and-maintain-a-software-inventory)

[1.1.1 Ensure that Only Approved Extensions Are Installed](#111-ensure-that-only-approved-extensions-are-installed)

[1.2 Ensure Authorized Software is Currently Supported](#12-ensure-authorized-software-is-currently-supported)

[1.2.1 Ensure that all AWS Lambda functions are configured to use a current (not deprecated) runtime](#121-ensure-that-all-aws-lambda-functions-are-configured-to-use-a-current-not-deprecated-runtime)

[1.2.2 Ensure that all Azure Functions are configured to use a current (not deprecated) runtime](#122-ensure-that-all-azure-functions-are-configured-to-use-a-current-not-deprecated-runtime)

[1.2.3 Ensure That 'PHP version' is the Latest, If Used to Run the Web App](#123-ensure-that-php-version-is-the-latest-if-used-to-run-the-web-app)

[1.2.4 Ensure that 'Python version' is the Latest Stable Version, if Used to Run the Web App](#124-ensure-that-python-version-is-the-latest-stable-version-if-used-to-run-the-web-app)

[1.2.5 Ensure that 'Java version' is the latest, if used to run the Web App ](#125-ensure-that-java-version-is-the-latest-if-used-to-run-the-web-app)

[1.2.6 Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App ](#126-ensure-that-http-version-is-the-latest-if-used-to-run-the-web-app)

[1.2.6 Ensure that all GCP Cloud functions are configured to use a current (not deprecated) runtime ](#126-ensure-that-all-gcp-cloud-functions-are-configured-to-use-a-current-not-deprecated-runtime)

[1.3 Encrypt Sensitive Data in Transit](#13-encrypt-sensitive-data-in-transit)

[1.3.1 Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service ](#131-ensure-web-app-redirects-all-http-traffic-to-https-in-azure-app-service)

[1.3.2 Ensure Web App is using the latest version of TLS encryption](#132-ensure-web-app-is-using-the-latest-version-of-tls-encryption)

[1.3.3 Ensure FTP deployments are Disabled ](#133-ensure-ftp-deployments-are-disabled)

[1.3.4 Ensure “Block Project-Wide SSH Keys” Is Enabled for VM Instances ](#134-ensure-block-project-wide-ssh-keys-is-enabled-for-vm-instances)

[1.4 Encrypt Sensitive Data at Rest](#14-encrypt-sensitive-data-at-rest)

[1.4.1 Ensure Virtual Machines are utilizing Managed Disks](#141-ensure-virtual-machines-are-utilizing-managed-disks)

[1.5 Implement and Manage a Firewall on Servers](#15-implement-and-manage-a-firewall-on-servers)

[1.5.1 Ensure That IP Forwarding Is Not Enabled on Instances](#151-ensure-that-ip-forwarding-is-not-enabled-on-instances)

[1.6 Manage Default Accounts on Enterprise Assets and Software ](#16-manage-default-accounts-on-enterprise-assets-and-software)

[1.6.1 Ensure That Instances Are Not Configured To Use the Default Service Account](#161-ensure-that-instances-are-not-configured-to-use-the-default-service-account)

[1.6.2 Ensure That Instances Are Not Configured To Use the Default Service Account With Full Access to All Cloud APIs](#162-ensure-that-instances-are-not-configured-to-use-the-default-service-account-with-full-access-to-all-cloud-apis)

[1.7 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software](#17-uninstall-or-disable-unnecessary-services-on-enterprise-assets-and-software)

[1.7.1 Ensure ‘Enable Connecting to Serial Ports’ Is Not Enabled for VM Instance](#171-ensure-enable-connecting-to-serial-ports-is-not-enabled-for-vm-instance)

[1.8 Centralize Account Management](#18-centralize-account-management)

[1.8.1 Ensure that Register with Azure Active Directory is enabled on App Service](#181-ensure-that-register-with-azure-active-directory-is-enabled-on-app-service)

[1.8.2 Ensure Oslogin Is Enabled for a Project](#182-ensure-oslogin-is-enabled-for-a-project)

[2 Identity and Access Management](#2-identity-and-access-management)

[2.1 Establish and Maintain a Data Recovery Process](#21-establish-and-maintain-a-data-recovery-process)

[2.1.1 Ensure the Key Vault is Recoverable](#211-ensure-the-key-vault-is-recoverable)

[2.2 Designate Personnel to Manage Incident Handling](#22-designate-personnel-to-manage-incident-handling)

[2.2.1 Ensure a support role has been created to manage incidents with AWS Support](#221-ensure-a-support-role-has-been-created-to-manage-incidents-with-aws-support)

[2.3 Establish and Maintain Contact Information for Reporting Security Incidents](#23-establish-and-maintain-contact-information-for-reporting-security-incidents)

[2.3.1 Maintain current contact details](#231-maintain-current-contact-details)

[2.3.2 Ensure security contact information is registered](#232-ensure-security-contact-information-is-registered)

[2.3.5 Ensure Essential Contacts is Configured for Organization](#235-ensure-essential-contacts-is-configured-for-organization)

[2.4 Address Unauthorized Software](#24-address-unauthorized-software)

[2.4.1 Ensure User consent for applications is set to Do not allow user consent](#241-ensure-user-consent-for-applications-is-set-to-do-not-allow-user-consent)

[2.4.2 Ensure that 'Users can add gallery apps to My Apps' is set to 'No'](#242-ensure-that-users-can-add-gallery-apps-to-my-apps-is-set-to-no)

[2.4.3 Ensure That ‘Users Can Register Applications’ Is Set to ‘No’](#243-ensure-that-users-can-register-applications-is-set-to-no)

[2.5 Establish and Maintain a Data Management Process](#25-establish-and-maintain-a-data-management-process)

[2.5.1 Ensure that the Expiration Date that is no more than 90 days in the future is set for all Keys in RBAC Key Vaults](#251-ensure-that-the-expiration-date-that-is-no-more-than-90-days-in-the-future-is-set-for-all-keys-in-rbac-key-vaults)

[2.5.2 Ensure that the Expiration Date that is no more than 90 days in the future is set for all Keys in Non-RBAC Key Vaults.](#252-ensure-that-the-expiration-date-that-is-no-more-than-90-days-in-the-future-is-set-for-all-keys-in-non-rbac-key-vaults)

[2.5.3 Ensure that the Expiration Date that is no more than 90 days in the future is set for all Secrets in RBAC Key Vaults](#253-ensure-that-the-expiration-date-that-is-no-more-than-90-days-in-the-future-is-set-for-all-secrets-in-rbac-key-vaults)

[2.5.4 Ensure that the Expiration Date that is no more than 90 days in the future is set for all Secrets in Non-RBAC Key Vaults](#254-ensure-that-the-expiration-date-that-is-no-more-than-90-days-in-the-future-is-set-for-all-secrets-in-non-rbac-key-vaults)

[2.6 Encrypt Sensitive Data at Rest](#26-encrypt-sensitive-data-at-rest)

[2.6.1 Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager](#261-ensure-secrets-are-not-stored-in-cloud-functions-environment-variables-by-using-secret-manager)

[2.7 Configure Data Access Control Lists](#27-configure-data-access-control-lists)

[2.7.1 Ensure no 'root' user account access key exists](#271-ensure-no-root-user-account-access-key-exists)

[2.7.2 Do not setup access keys during initial user setup for all IAM users that have a console password](#272-do-not-setup-access-keys-during-initial-user-setup-for-all-iam-users-that-have-a-console-password)

[2.7.3 Ensure IAM policies that allow full  "\*:\*"  administrative privileges are not attached](#273-ensure-iam-policies-that-allow-full--administrative-privileges-are-not-attached)

[2.7.4 Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'](#274-ensure-that-guest-users-access-restrictions-is-set-to-guest-user-access-is-restricted-to-properties-and-memberships-of-their-own-directory-objects)

[2.7.5 Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level](#275-ensure-that-iam-users-are-not-assigned-the-service-account-user-or-service-account-token-creator-roles-at-project-level)

[2.7.6 Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible](#276-ensure-that-cloud-kms-cryptokeys-are-not-anonymously-or-publicly-accessible)

[2.8 Establish and Maintain a Secure Configuration Process](#28-establish-and-maintain-a-secure-configuration-process)

[2.8.1 Ensure Security Defaults is enabled on Azure Active Directory](#281-ensure-security-defaults-is-enabled-on-azure-active-directory)

[2.8.2 Ensure IAM password policy requires minimum length of 14 or greater](#282-ensure-iam-password-policy-requires-minimum-length-of-14-or-greater)

[2.8.3 Ensure there is only one active access key available for any single IAM user](#283-ensure-there-is-only-one-active-access-key-available-for-any-single-iam-user)

[2.8.4 Ensure access keys are rotated every 90 days or less](#284-ensure-access-keys-are-rotated-every-90-days-or-less)

[2.9 Use Unique Passwords](#29-use-unique-passwords)

[2.9.1 Ensure IAM password policy prevents password reuse](#291-ensure-iam-password-policy-prevents-password-reuse)

[2.9.2 Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization](#292-ensure-that-a-custom-bad-password-list-is-set-to-enforce-for-your-organization)

[2.10 Disable Dormant Accounts](#210-disable-dormant-accounts)

[2.10.1 Ensure credentials unused for 45 days or greater are disabled ](#2101-ensure-credentials-unused-for-45-days-or-greater-are-disabled)

[2.10.2 Ensure Guest Users Are Reviewed on a Regular Basis ](#2102-ensure-guest-users-are-reviewed-on-a-regular-basis)

[2.11 Restrict Administrator Privileges to Dedicated Administrator Accounts](#211-restrict-administrator-privileges-to-dedicated-administrator-accounts)

[2.11.1 Eliminate use of the 'root' user for administrative and daily tasks](#2111-eliminate-use-of-the-root-user-for-administrative-and-daily-tasks)

[2.11.2 Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes'](#2112-ensure-that-notify-all-admins-when-other-admins-reset-their-password-is-set-to-yes)

[2.11.3 Ensure That 'Restrict access to Azure AD administration portal' is Set to 'Yes'](#2113-ensure-that-restrict-access-to-azure-ad-administration-portal-is-set-to-yes)

[2.11.4 Ensure That No Custom Subscription Administrator Roles Exist](#2114-ensure-that-no-custom-subscription-administrator-roles-exist)

[2.11.5 Ensure That Service Account Has No Admin Privileges](#2115-ensure-that-service-account-has-no-admin-privileges)

[2.12 Centralize Account Management](#212-centralize-account-management)

[2.12.1 Ensure that Corporate Login Credentials are Used ](#2121-ensure-that-corporate-login-credentials-are-used)

[2.13 Establish an Access Revoking Process](#213-establish-an-access-revoking-process)

[2.13.1 Ensure that 'Number of days before users are asked to re-confirm their authentication information' is set to '90'](#2131-ensure-that-number-of-days-before-users-are-asked-to-re-confirm-their-authentication-information-is-set-to-90)

[2.14 Require MFA for Externally-Exposed Applications](#214-require-mfa-for-externally-exposed-applications)

[2.14.1 Ensure That 'Number of methods required to reset' is set to '2'](#2141-ensure-that-number-of-methods-required-to-reset-is-set-to-2)

[2.14.2 Ensure that 'Require Multi-Factor Authentication to register or join devices with Azure AD' is set to 'Yes' ](#2142-ensure-that-require-multi-factor-authentication-to-register-or-join-devices-with-azure-ad-is-set-to-yes)

[2.14.3 Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users](#2143-ensure-that-multi-factor-auth-status-is-enabled-for-all-privileged-users)

[2.14.4 Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled ](#2144-ensure-that-allow-users-to-remember-multi-factor-authentication-on-devices-they-trust-is-disabled)

[2.14.5 Ensure that A Multi-factor Authentication Policy Exists for All Users ](#2145-ensure-that-a-multi-factor-authentication-policy-exists-for-all-users)

[2.14.6 Ensure Multi-factor Authentication is Required for Risky Sign-ins ](#2146-ensure-multi-factor-authentication-is-required-for-risky-sign-ins)

[2.14.7 Ensure that Multi-Factor Authentication is 'Enabled' for All Non-Service Accounts ](#2147-ensure-that-multi-factor-authentication-is-enabled-for-all-non-service-accounts)

[2.14.8 Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users ](#2148-ensure-that-multi-factor-auth-status-is-enabled-for-all-non-privileged-users)

[2.15 Require MFA for Remote Network Access](#215-require-mfa-for-remote-network-access)

[2.15.1 Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups ](#2151-ensure-that-a-multi-factor-authentication-policy-exists-for-administrative-groups)

[2.15.2 Ensure Multi-factor Authentication is Required for Azure Management](#2152-ensure-multi-factor-authentication-is-required-for-azure-management)

[2.16 Require MFA for Administrative Access](#216-require-mfa-for-administrative-access)

[2.16.1 Ensure MFA is enabled for the 'root' user account ](#2161-ensure-mfa-is-enabled-for-the-root-user-account)

[2.17 Centralize Access Control](#217-centralize-access-control)

[2.17.1 Ensure that 'Notify users on password resets?' is set to 'Yes'](#2171-ensure-that-notify-users-on-password-resets-is-set-to-yes)

[2.18 Define and Maintain Role-Based Access Control](#218-define-and-maintain-role-based-access-control)

[2.18.1 Ensure IAM Users Receive Permissions Only Through Groups](#2181-ensure-iam-users-receive-permissions-only-through-groups)

[3.1 Establish and Maintain Detailed Enterprise Asset Inventory](#31-establish-and-maintain-detailed-enterprise-asset-inventory)

[3.1.1 Ensure Cloud Asset Inventory Is Enabled](#311-ensure-cloud-asset-inventory-is-enabled)

[3.2 Tune Security Event Alerting Thresholds](#32-tune-security-event-alerting-thresholds)

[3.2.1 Ensure That 'Notify about alerts with the following severity' is Set to 'High'](#321-ensure-that-notify-about-alerts-with-the-following-severity-is-set-to-high)

[3.3 Establish and Maintain Contact Information for Reporting Security Incidents](#33-establish-and-maintain-contact-information-for-reporting-security-incidents)

[3.3.1 Ensure That 'All users with the following roles' is set to 'Owner'](#331-ensure-that-all-users-with-the-following-roles-is-set-to-owner)

[3.3.2 Ensure 'Additional email addresses' is Configured with a Security Contact Email](#332-ensure-additional-email-addresses-is-configured-with-a-security-contact-email)

[3.4 Log Sensitive Data Access](#34-log-sensitive-data-access)

[3.4.1 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket](#341-ensure-s3-bucket-access-logging-is-enabled-on-the-cloudtrail-s3-bucket)

[3.5 Configure Data Access Control Lists](#35-configure-data-access-control-lists)

[3.5.1 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible](#351-ensure-the-s3-bucket-used-to-store-cloudtrail-logs-is-not-publicly-accessible)

[3.5.2 Ensure the Storage Container Storing the Activity Logs is not Publicly Accessible](#352-ensure-the-storage-container-storing-the-activity-logs-is-not-publicly-accessible)

[3.6 Establish and Maintain a Secure Configuration Process](#36-establish-and-maintain-a-secure-configuration-process)

[3.6.1 Ensure Any of the ASC Default Policy Settings are Not Set to 'Disabled'](#361-ensure-any-of-the-asc-default-policy-settings-are-not-set-to-disabled)

[3.7 Perform Automated Operating System Patch Management](#37-perform-automated-operating-system-patch-management)

[3.7.1 Ensure that Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed'](#371-ensure-that-microsoft-defender-recommendation-for-apply-system-updates-status-is-completed)

[3.8 Perform Automated Vulnerability Scans of Internal Enterprise Assets](#38-perform-automated-vulnerability-scans-of-internal-enterprise-assets)

[3.8.1 Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'](#381-ensure-that-auto-provisioning-of-log-analytics-agent-for-azure-vms-is-set-to-on)

[3.9 Conduct Audit Log Reviews](#39-conduct-audit-log-reviews)

[3.9.1 Ensure management console sign-in without MFA is monitored](#391-ensure-management-console-sign-in-without-mfa-is-monitored)

[3.9.2 Ensure usage of 'root' account is monitored](#392-ensure-usage-of-root-account-is-monitored)

[3.9.3 Ensure IAM policy changes are monitored](#393-ensure-iam-policy-changes-are-monitored)

[3.9.4 Ensure CloudTrail configuration changes are monitored](#394-ensure-cloudtrail-configuration-changes-are-monitored)

[3.9.5 Ensure S3 bucket policy changes are monitored](#395-ensure-s3-bucket-policy-changes-are-monitored)

[3.9.6 Ensure changes to network gateways are monitored](#396-ensure-changes-to-network-gateways-are-monitored)

[3.9.7 Ensure route table changes are monitored](#397-ensure-route-table-changes-are-monitored)

[3.9.8 Ensure VPC changes are monitored](#398-ensure-vpc-changes-are-monitored)

[3.9.9 Ensure AWS Organizations changes are monitored](#399-ensure-aws-organizations-changes-are-monitored)

[3.9.10 Ensure That Cloud Audit Logging Is Configured Properly](#3910-ensure-that-cloud-audit-logging-is-configured-properly)

[3.9.11 Ensure That Cloud DNS Logging Is Enabled for All VPC Networks](#3911-ensure-that-cloud-dns-logging-is-enabled-for-all-vpc-networks)

[3.10 Collect Audit Logs](#310-collect-audit-logs)

[3.10.1 Ensure That Sinks Are Configured for All Log Entries](#3101-ensure-that-sinks-are-configured-for-all-log-entries)

[3.10.2 Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes](#3102-ensure-log-metric-filter-and-alerts-exist-for-project-ownership-assignmentschanges)

[3.10.3 Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes](#3103-ensure-that-the-log-metric-filter-and-alerts-exist-for-audit-configuration-changes)

[3.10.4 Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes](#3104-ensure-that-the-log-metric-filter-and-alerts-exist-for-custom-role-changes)

[3.11 Collect Detailed Audit Logs](#311-collect-detailed-audit-logs)

[3.11.1 Ensure CloudTrail is enabled in all regions](#3111-ensure-cloudtrail-is-enabled-in-all-regions)

[3.11.2 Ensure CloudTrail trails are integrated with CloudWatch Logs](#3112-ensure-cloudtrail-trails-are-integrated-with-cloudwatch-logs)

[3.11.3 Ensure that Azure Monitor Resource Logging is Enabled for All Services that Manage, Store, or Secure Sensitive Data](#3113-ensure-that-azure-monitor-resource-logging-is-enabled-for-all-services-that-manage-store-or-secure-sensitive-data)

[3.11.4 Ensure that logging for Azure Key Vault is 'Enabled'](#3114-ensure-that-logging-for-azure-key-vault-is-enabled)

[3.11.5 Ensure that Activity Log Alert exists for Create Policy Assignment](#3115-ensure-that-activity-log-alert-exists-for-create-policy-assignment)

[3.11.6 Ensure that Activity Log Alert exists for Delete Policy Assignment](#3116-ensure-that-activity-log-alert-exists-for-delete-policy-assignment)

[3.11.7 Ensure that Activity Log Alert exists for Create or Update Network Security Group ](#3117-ensure-that-activity-log-alert-exists-for-create-or-update-network-security-group)

[3.11.8 Ensure that Activity Log Alert exists for Delete Network Security Group](#3118-ensure-that-activity-log-alert-exists-for-delete-network-security-group)

[3.11.9 Ensure that Activity Log Alert exists for Create or Update Security Solution](#3119-ensure-that-activity-log-alert-exists-for-create-or-update-security-solution)

[3.11.10 Ensure that Activity Log Alert exists for Delete Security Solution](#31110-ensure-that-activity-log-alert-exists-for-delete-security-solution)

[3.11.11 Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule ](#31111-ensure-that-activity-log-alert-exists-for-create-or-update-sql-server-firewall-rule)

[3.11.12 Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule](#31112-ensure-that-activity-log-alert-exists-for-delete-sql-server-firewall-rule)

[3.11.13 Ensure that Activity Log Alert exists for Create or Update Public IP Address rule](#31113-ensure-that-activity-log-alert-exists-for-create-or-update-public-ip-address-rule)

[3.11.14 Ensure that Activity Log Alert exists for Delete Public IP Address rule](#31114-ensure-that-activity-log-alert-exists-for-delete-public-ip-address-rule)

[4 Networking](#4-networking)

[4.1 Encrypt Sensitive Data in Transit](#41-encrypt-sensitive-data-in-transit)

[4.1.1 Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites](#411-ensure-no-https-or-ssl-proxy-load-balancers-permit-ssl-policies-with-weak-cipher-suites)

[4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure](#42-establish-and-maintain-a-secure-configuration-process-for-network-infrastructure)

[4.2.1 Ensure Legacy Networks Do Not Exist for Older Projects](#421-ensure-legacy-networks-do-not-exist-for-older-projects)

[4.2.2 Ensure That DNSSEC Is Enabled for Cloud DNS](#422-ensure-that-dnssec-is-enabled-for-cloud-dns)

[4.2.3 Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC](#423-ensure-that-rsasha1-is-not-used-for-the-key-signing-key-in-cloud-dns-dnssec)

[4.2.4 Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC](#424-ensure-that-rsasha1-is-not-used-for-the-zone-signing-key-in-cloud-dns-dnssec)

[4.2.5 Ensure that EC2 Metadata Service only allows IMDSv2](#425-ensure-that-ec2-metadata-service-only-allows-imdsv2)

[4.3 Implement and Manage a Firewall on Servers](#43-implement-and-manage-a-firewall-on-servers)

[4.3.1 Ensure that RDP access from the Internet is evaluated and restricted](#431-ensure-that-rdp-access-from-the-internet-is-evaluated-and-restricted)

[4.3.2 Ensure that SSH access from the Internet is evaluated and restricted](#432-ensure-that-ssh-access-from-the-internet-is-evaluated-and-restricted)

[4.3.3 Ensure That SSH Access Is Restricted From the Internet](#433-ensure-that-ssh-access-is-restricted-from-the-internet)

[4.3.4 Ensure That RDP Access Is Restricted From the Internet](#434-ensure-that-rdp-access-is-restricted-from-the-internet)

[4.3.5 Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports](#435-ensure-no-network-acls-allow-ingress-from-00000-to-remote-server-administration-ports)

[4.3.6 Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports](#436-ensure-no-security-groups-allow-ingress-from-00000-to-remote-server-administration-ports)

[4.3.7 Ensure no security groups allow ingress from ::/0 to remote server administration ports](#437-ensure-no-security-groups-allow-ingress-from-0-to-remote-server-administration-ports)


[5 Storage](#5-storage)

[5.1 Establish and Maintain a Data Recovery Process](#51-establish-and-maintain-a-data-recovery-process)

[5.1.1 Ensure Soft Delete is Enabled for Azure Containers and Blob Storage](#511-ensure-soft-delete-is-enabled-for-azure-containers-and-blob-storage)

[5.2 Establish and Maintain a Secure Network Architecture](#52-establish-and-maintain-a-secure-network-architecture)

[5.2.1 Ensure Default Network Access Rule for Storage Accounts is Set to Deny](#521-ensure-default-network-access-rule-for-storage-accounts-is-set-to-deny)

[5.3 Encrypt Sensitive Data in Transit](#53-encrypt-sensitive-data-in-transit)

[5.3.1 Ensure that 'Secure transfer required' is set to 'Enabled'](#531-ensure-that-secure-transfer-required-is-set-to-enabled)

[5.3.2 Ensure the "Minimum TLS version" for storage accounts is set to "Version 1.2"](#532-ensure-the-minimum-tls-version-for-storage-accounts-is-set-to-version-12)

[5.4 Encrypt Sensitive Data at Rest](#54-encrypt-sensitive-data-at-rest)

[5.4.1 Ensure EBS Volume Encryption is Enabled in all Regions](#541-ensure-ebs-volume-encryption-is-enabled-in-all-regions)

[5.4.2 Ensure that encryption is enabled for EFS file systems](#542-ensure-that-encryption-is-enabled-for-efs-file-systems)

[5.5 Configure Data Access Control Lists](#55-configure-data-access-control-lists)

[5.5.1 Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'](#551-ensure-that-s3-buckets-are-configured-with-block-public-access-bucket-settings)

[5.5.2 Ensure that 'Public access level' is disabled for storage accounts with blob containers](#552-ensure-that-public-access-level-is-disabled-for-storage-accounts-with-blob-containers)

[5.5.3 Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible](#553-ensure-that-cloud-storage-bucket-is-not-anonymously-or-publicly-accessible)

[5.6 Establish and Maintain a Secure Configuration Process](#56-establish-and-maintain-a-secure-configuration-process)

[5.6.1 Ensure that 'Enable key rotation reminders' is enabled for each Storage Account](#561-ensure-that-enable-key-rotation-reminders-is-enabled-for-each-storage-account)

[5.7 Securely Manage Enterprise Assets and Software](#57-securely-manage-enterprise-assets-and-software)

[5.7.1 Ensure that Storage Account Access Keys are Periodically Regenerated](#571-ensure-that-storage-account-access-keys-are-periodically-regenerated)

[5.8 Establish an Access Revoking Process](#58-establish-an-access-revoking-process)

[5.8.1 Ensure that Shared Access Signature Tokens Expire Within an Hour](#581-ensure-that-shared-access-signature-tokens-expire-within-an-hour)

[6 Database Services](#6-database-services)

[6.1 Use Standard Hardening Configuration Templates for Application Infrastructure](#61-use-standard-hardening-configuration-templates-for-application-infrastructure)

[6.1.1 Ensure That the ‘Local_infile’ Database Flag for a Cloud SQL MySQL Instance Is Set to ‘Off’](#611-ensure-that-the-local_infile-database-flag-for-a-cloud-sql-mysql-instance-is-set-to-off)

[6.2 Allowlist Authorized Scripts](#62-allowlist-authorized-scripts)

[6.2.1 Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'](#621-ensure-external-scripts-enabled-database-flag-for-cloud-sql-sql-server-instance-is-set-to-off)

[6.3 Encrypt Sensitive Data in Transit](#63-encrypt-sensitive-data-in-transit)

[6.3.1 Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server](#631-ensure-enforce-ssl-connection-is-set-to-enabled-for-postgresql-database-server)

[6.3.2 Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server](#632-ensure-enforce-ssl-connection-is-set-to-enabled-for-standard-mysql-database-server)

[6.3.3 Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server](#633-ensure-tls-version-is-set-to-tlsv12-for-mysql-flexible-database-server)

[6.3.4 Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL](#634-ensure-that-the-cloud-sql-database-instance-requires-all-incoming-connections-to-use-ssl)

[6.4 Encrypt Sensitive Data at Rest](#64-encrypt-sensitive-data-at-rest)

[6.4.1 Ensure that encryption-at-rest is enabled for RDS Instances](#641-ensure-that-encryption-at-rest-is-enabled-for-rds-instances)

[6.4.2 Ensure that 'Data encryption' is set to 'On' on a SQL Database](#642-ensure-that-data-encryption-is-set-to-on-on-a-sql-database)

[6.5 Configure Data Access Control Lists](#65-configure-data-access-control-lists)

[6.5.1 Ensure that public access is not given to RDS Instance](#651-ensure-that-public-access-is-not-given-to-rds-instance)

[6.5.2 Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)](#652-ensure-no-azure-sql-databases-allow-ingress-from-00000-any-ip)

[6.5.3 Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses](#653-ensure-that-cloud-sql-database-instances-do-not-implicitly-whitelist-all-public-ip-addresses)

[6.5.4 Ensure ‘Skip_show_database’ Database Flag for Cloud SQL MySQL Instance Is Set to ‘On’](#654-ensure-skip_show_database-database-flag-for-cloud-sql-mysql-instance-is-set-to-on)

[6.5.5 Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'](#655-ensure-that-the-cross-db-ownership-chaining-database-flag-for-cloud-sql-sql-server-instance-is-set-to-off)

[6.5.6 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'](#656-ensure-that-the-contained-database-authentication-database-flag-for-cloud-sql-on-the-sql-server-instance-is-set-to-off)

[6.6 Establish and Maintain a Secure Configuration Process](#66-establish-and-maintain-a-secure-configuration-process)

[6.6.1 Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured](#661-ensure-user-options-database-flag-for-cloud-sql-sql-server-instance-is-not-configured)

[6.6.2 Ensure '3625 (trace flag)' database flag for all Cloud SQL Server instances is set to 'on'](#662-ensure-3625-trace-flag-database-flag-for-all-cloud-sql-server-instances-is-set-to-on)

[6.7 Implement and Manage a Firewall on Servers](#67-implement-and-manage-a-firewall-on-servers)

[6.7.1 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled](#671-ensure-allow-access-to-azure-services-for-postgresql-database-server-is-disabled)

[6.8 Securely Manage Enterprise Assets and Software](#68-securely-manage-enterprise-assets-and-software)

[6.8.1 Ensure Instance IP assignment is set to private](#681-ensure-instance-ip-assignment-is-set-to-private)

[6.9 Manage Default Accounts on Enterprise Assets and Software](#69-manage-default-accounts-on-enterprise-assets-and-softwar)

[6.9.1 Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges](#691-ensure-that-a-mysql-database-instance-does-not-allow-anyone-to-connect-with-administrative-privileges)

[6.10 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software](#610-uninstall-or-disable-unnecessary-services-on-enterprise-assets-and-software)

[6.10.1 Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'](#6101-ensure-remote-access-database-flag-for-cloud-sql-sql-server-instance-is-set-to-off)

[6.11 Centralize Account Management](#611-centralize-account-management)

[6.11.1 Ensure that Azure Active Directory Admin is Configured for SQL Servers](#6111-ensure-that-azure-active-directory-admin-is-configured-for-sql-servers)

[6.12 Perform Automated Application Patch Management](#612-perform-automated-application-patch-management)

[6.12.1 Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances](#6121-ensure-auto-minor-version-upgrade-feature-is-enabled-for-rds-instances)

[6.13 Collect Audit Logs](#613-collect-audit-logs)

[6.13.1 Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server](#6131-ensure-server-parameter-log_checkpoints-is-set-to-on-for-postgresql-database-server)

[6.13.2 Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server](#6132-ensure-server-parameter-log_connections-is-set-to-on-for-postgresql-database-server)

[6.13.3 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server](#6133-ensure-server-parameter-log_disconnections-is-set-to-on-for-postgresql-database-server)

[6.14 Ensure Adequate Audit Log Storage](#614-ensure-adequate-audit-log-storage)

[6.14.1 Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server](#6141-ensure-server-parameter-log_retention_days-is-greater-than-3-days-for-postgresql-database-server)

[6.15 Collect Detailed Audit Logs](#615-collect-detailed-audit-logs)

[6.15.1 Ensure that 'Auditing' is set to 'On'](#6151-ensure-that-auditing-is-set-to-on)

[6.15.2 Ensure That the ‘Log_connections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’](#6152-ensure-that-the-log_connections-database-flag-for-cloud-sql-postgresql-instance-is-set-to-on)

[6.15.3 Ensure That the ‘Log_disconnections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’](#6153-ensure-that-the-log_disconnections-database-flag-for-cloud-sql-postgresql-instance-is-set-to-on)

[6.15.4 Ensure that the ‘Log_min_messages’ Flag for a Cloud SQL PostgreSQL Instance is set at minimum to 'Warning'](#6154-ensure-that-the-log_min_messages-flag-for-a-cloud-sql-postgresql-instance-is-set-at-minimum-to-warning)

[6.15.5 Ensure ‘Log_min_error_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘Error’ or Stricter](#6155-ensure-log_min_error_statement-database-flag-for-cloud-sql-postgresql-instance-is-set-to-error-or-stricter)

[6.15.6 Ensure That the ‘Log_min_duration_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘-1′ (Disabled)](#6156-ensure-that-the-log_min_duration_statement-database-flag-for-cloud-sql-postgresql-instance-is-set-to-1-disabled)

[6.15.7 Ensure That 'cloudsql.enable_pgaudit' Database Flag for each Cloud Sql Postgresql Instance Is Set to 'on' For Centralized Logging](#6157-ensure-that-cloudsqlenable_pgaudit-database-flag-for-each-cloud-sql-postgresql-instance-is-set-to-on-for-centralized-logging)



# Overview

This document provides prescriptive guidance for configuring security options for a subset of cloud services offered by Amazon Web Services, Google Cloud Platform, and Microsoft Azure. This profile emphasizes foundational, testable, and architecture agnostic settings that are suitable for applications that process sensitive data such as Personally Identifiable Information (PII) or other types of confidential information.


# Applicability

This document is intended for system and application administrators, security specialists, auditors, help desk, platform deployment, and/or DevOps personnel who plan to develop, deploy, assess, or secure solutions in the cloud.


# Acknowledgements

This profile builds upon the work of the Center for Internet Security (CIS), specifically their cloud foundations benchmarks.

1. [CIS Amazon Web Services Foundations Benchmark v2.0.0](https://workbench.cisecurity.org/benchmarks/14207)
2. [CIS Google Cloud Platform Foundation Benchmark v2.0.0](https://workbench.cisecurity.org/benchmarks/9562)
3. [CIS Microsoft Azure Foundations Benchmark v2.0.0](https://workbench.cisecurity.org/benchmarks/10624)


# 1 Compute
## 1.1 Establish and Maintain a Software Inventory

### Description

Establish and maintain a detailed inventory of all licensed software installed on enterprise assets. The software inventory must document the title, publisher, initial install/use date, and business purpose for each entry; where appropriate, include the Uniform Resource Locator (URL), app store(s), version(s), deployment mechanism, and decommission date. Review and update the software inventory bi-annually, or more frequently.


### Rationale

It is necessary to first identify the software that needs to be secured before taking additional steps towards achieving a suitable security baseline.


### Audit


---

### 1.1.1 Ensure that Only Approved Extensions Are Installed
**Platform:** Azure

**Rationale:** Azure virtual machine extensions are small applications that provide post-deployment configuration and automation tasks on Azure virtual machines. These extensions run with administrative privileges and could potentially access anything on a virtual machine. The Azure Portal and community provide several such extensions. Each organization should carefully evaluate these extensions and ensure that only those that are approved for use are actually implemented.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 7.5

**Evidence**

**From Azure Portal**

1. Go to `Virtual machines`.
2. For each virtual machine, click on the server name to select it go to
3. In the new column menu, under `Settings` Click on `Extensions + applications`.
4. Ensure that all the listed extensions are approved by your organization for use.

**From Azure CLI**

Use the below command to list the extensions attached to a VM, and ensure the listed extensions are approved for use.


```
az vm extension list --vm-name <vmName> --resource-group <sourceGroupName> --query [*].name
```


**From PowerShell**

Get a list of VMs.


```
Get-AzVM
```


For each VM run the following command.


```
Get-AzVMExtension -ResourceGroupName <VM Resource Group> -VMName <VM Name>
```


Review each `Name`, `ExtensionType`, and `ProvisioningState` to make sure no unauthorized extensions are installed on any virtual machines.

**Verification**

Developer states that they have reviewed the list of extensions and that each one of them is approved for use.


---


## 1.2 Ensure Authorized Software is Currently Supported


### Description

Ensure that only currently supported software is designated as authorized in the software inventory for enterprise assets. If software is unsupported, yet necessary for the fulfillment of the enterprise’s mission, document an exception detailing mitigating controls and residual risk acceptance. For any unsupported software without an exception documentation, designate as unauthorized. Review the software list to verify software support at least monthly, or more frequently.


### Rationale

When software ceases to be supported, the maintainer of that software will no longer issue patches to remediate security vulnerabilities that are discovered in it. This leaves any organization relying on that software at a high risk of a security incident.


### Audit


---

### 1.2.1 Ensure that all AWS Lambda functions are configured to use a current (not deprecated) runtime
**Platform:** AWS

**Rationale:** Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.

**External Reference:** [AWS Security Hub Lambda.2](https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-2)

**Evidence**

**From Command Line:**



1. For each [deprecated runtime](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html#runtimes-deprecated) according to the AWS documentation
2. Use the `list-functions` command to query for the existence of any lambda function in each in-use region that uses the runtime:


```
aws lambda list-functions --function-version ALL --region <region> --output text --query "Functions[?Runtime=='<RUNTIME_IDENTIFIER>'].FunctionArn"
```


**Using Trusted Advisor**

This procedure can be used if Trusted Advisor is enabled in the tenant.



1. Open the AWS Console
2. Go to Trusted Advisor
3. Open the Recommendations > Security section
4. Search by keyword “lambda”
5. Open the section entitled “AWS Lambda Functions Using Deprecated Runtimes”
6. If there are any lambda functions listed in the table contained within this section, this requirement is not met

**Verification**

Evidence or test output indicates that no Lambda function is configured to use a deprecated runtime (i.e, a runtime that appears in the “Deprecated runtimes” section of [the AWS documentation)](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html#runtimes-deprecated).


---

### 1.2.2 Ensure that all Azure Functions are configured to use a current (not deprecated) runtime
**Platform:** Azure

**Rationale:** Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.

**External Reference:** Todo

**Evidence**

Todo

**Verification**

Evidence or test output indicates that all Azure Functions are:



1. Configured to use a supported (i.e., not unsupported) runtime host version
2. Using a language version that is not past its EOL date

Microsoft documentation contains the specific dates and version for supported languages and runtime modes: https://learn.microsoft.com/en-us/azure/azure-functions/functions-versions


---

### 1.2.3 Ensure That 'PHP version' is the Latest, If Used to Run the Web App
**Platform:** Azure

**Rationale:** Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 9.6

**Evidence**

**From Azure Portal**



1. From Azure Home open the Portal Menu in the top left
2. Go to `App Services`
3. Click on each App
4. Under `Settings` section, click on `Configuration`
5. Click on the `General settings` pane, ensure that for a `Stack` of `PHP` the `Major Version` and `Minor Version` reflect the latest stable and supported release.

**The latest stable version can be confirmed by going to php.net. Navigate to the downloads, and then find the most recent version that is marked by `Current Stable PHP [version_number]`.**

_NOTE:_ No action is required If the PHP` version` is set to `Off` as PHP is not used by your web app.

**From Azure CLI**

To check PHP version for an existing app, run the following command,


```
az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query "{LinuxFxVersion:linuxFxVersion,PHP_Version:phpVersion}"
```


**From PowerShell**


```
$application = Get-AzWebApp -ResourceGroupName <resource group name> -Name <app name>
$application.SiteConfig | select-object LinuxFXVersion, phpVersion
```


The output should return the latest available version of PHP. Any other version of PHP would be considered a finding.

**NOTE:** No action is required, If the output is empty as PHP is not used by your web app.

**Verification**

Evidence or test output indicates that the developer has configured App Service to use the latest PHP version supported by Azure. See: [https://github.com/Azure/app-service-linux-docs/blob/master/Runtime_Support/php_support.md#support-timeline](https://github.com/Azure/app-service-linux-docs/blob/master/Runtime_Support/php_support.md#support-timeline)


---

### 1.2.4 Ensure that 'Python version' is the Latest Stable Version, if Used to Run the Web App
**Platform:** Azure

**Rationale:** Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected. Using the latest full version will keep your stack secure to vulnerabilities and exploits.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 9.7

**Evidence**

**From Azure Console**



1. From Azure Home open the Portal Menu in the top left
2. Go to `App Services`
3. Click on each App
4. Under `Settings` section, click on `Configuration`
5. Click on the General settings pane and ensure that for a Stack of Python, with Major Version of Python 3, that the Minor Version is set to the latest stable version available (Python 3.11, at the time of writing)

NOTE: No action is required if the Python` version` is set to `Off`, as Python is not used by your web app.

**From Azure CLI**

To check Python version for an existing app, run the following command


```
az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query "{LinuxFxVersion:linuxFxVersion,WindowsFxVersion:windowsFxVersion,PythonVersion:pythonVersion}
```


The output should return the latest stable version of Python.

_NOTE:_ No action is required if the output is empty, as Python is not used by your web app.

**From PowerShell**


```
$app = Get-AzWebApp -Name <app name> -ResourceGroup <resource group name>
$app.SiteConfig |Select-Object LinuxFXVersion, WindowsFxVersion, PythonVersion
```


Ensure the output of the above command shows the latest version of Python.

_NOTE:_ No action is required if the output is empty, as Python is not used by your web app.

**Verification**

Evidence or test output indicates that -- if used to run the web app -- the developer is using the latest stable Python version supported by Azure. See: [https://github.com/Azure/app-service-linux-docs/blob/master/Runtime_Support/python_support.md](https://github.com/Azure/app-service-linux-docs/blob/master/Runtime_Support/python_support.md)


---

### 1.2.5 Ensure that 'Java version' is the latest, if used to run the Web App
**Platform:** Azure

**Rationale:** Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 9.8

**Evidence**

**From Azure Portal**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/)
2. Go to `App Services`
3. Click on each App
4. Under `Settings` section, click on `Configuration`
5. Click on the `General settings` pane and ensure that for a `Stack` of `Java` the `Major Version` and `Minor Version` reflect the latest stable and supported release, and that the `Java web server version` is set to the `auto-update` option.

NOTE: No action is required if the Java` version` is set to `Off`, as Java is not used by your web app.

**From Azure CLI**

To check Java version for an existing app, run the following command,


```
az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query "{LinuxFxVersion:linuxFxVersion, WindowsFxVersion:windowsFxVersion, JavaVersion:javaVersion, JavaContainerVersion:javaContainerVersion, JavaContainer:javaContainer}"
```


The output should return the latest available version of Java (if java is being used for the web application being audited).

**From PowerShell**

For each application, store the application information within an object, and then interrogate the `SiteConfig` information for that application object.


```
$app = Get-AzWebApp -Name <app name> -ResourceGroup <resource group name>

$app.SiteConfig |Select-Object LinuxFXVersion, WindowsFxVersion, JavaVersion, JavaContainerVersion, JavaContainer
```


Ensure the Java version used within the application is a currently supported version (if java is being used for the web application being audited).

**Verification**

Evidence or test output indicates that -- if used to run the web app -- the developer is using the latest stable Java version supported by Azure. See: [https://learn.microsoft.com/en-us/azure/app-service/language-support-policy?tabs=linux#jdk-versions-and-maintenance](https://learn.microsoft.com/en-us/azure/app-service/language-support-policy?tabs=linux#jdk-versions-and-maintenance)


---

### 1.2.6 Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App
**Platform:** Azure

**Rationale:** Newer versions may contain security enhancements and additional functionality. Using the latest version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.

HTTP 2.0 has additional performance improvements on the head-of-line blocking problem present in HTTP 1.1, along with improved header compression and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.\
External Reference: CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 9.9

**Evidence**

**From Azure Portal**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/)
2. Go to `App Services`
3. Click on each App
4. Under `Setting` section, Click on `Configuration`
5. Ensure that `HTTP Version` set to `2.0` version under `General settings`

NOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third party certificate.

**From Azure CLI**

To check HTTP 2.0 version status for an existing app, run the following command,


```
az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query http20Enabled
```


The output should return `true` if HTTPS 2.0 traffic value is set to `On`.

**From PowerShell**

For each application, run the following command:


```
Get-AzWebApp -ResourceGroupName <app resource group> -Name <app name> |Select-Object -ExpandProperty SiteConfig
```


If the value of the **Http20Enabled** setting is **true**, the application is compliant. Otherwise if the value of the **Http20Enabled** setting is **false**, the application is non-compliant.

**Verification**

Evidence or test output indicates that HTTP 2.0 is enabled for each webapp.


---

### 1.2.6 Ensure that all GCP Cloud functions are configured to use a current (not deprecated) runtime
**Platform:** Google

**Rationale:** Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.

**External Reference:** Todo

**Evidence**

Todo

**Verification**

Evidence or test output indicates that all Cloud Functions are configured to run on a runtime that is not beyond its published deprecation date. See the [GCP documentation for specific runtime version deprecation dates](https://cloud.google.com/functions/docs/runtime-support).


---
## 1.3 Encrypt Sensitive Data in Transit
### Description
Encrypt sensitive data in transit. Example implementations can include: Transport Layer Security (TLS) and Open Secure Shell (OpenSSH).


### Rationale
Encryption protects sensitive data when transmitted over untrusted network connections.


### Audit


---

### 1.3.1 Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service
**Platform:** Azure

**Rationale:** Enabling HTTPS-only traffic will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the TLS/SSL protocol to provide a secure connection which is both encrypted and authenticated. It is therefore important to support HTTPS for the security benefits.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 9.2

**Evidence**

**From Azure Portal**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/)
2. Go to `App Services`
3. Click on each App
4. Under `Setting` section, click on `TLS/SSL settings`
5. Under the `Bindings` pane, ensure that `HTTPS Only` set to `On` under `Protocol Settings`

**From Azure CLI**

To check HTTPS-only traffic value for an existing app, run the following command,


```
az webapp show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query httpsOnly
```


The output should return `true` if HTTPS-only traffic value is set to `On`.

**From PowerShell**

List all the web apps configured within the subscription.


```
Get-AzWebApp | Select-Object ResourceGroup, Name, HttpsOnly
```


For each web app review the `HttpsOnly` setting and make sure it is set to `True`.

**Verification**

Evidence or test output indicates that each Azure App Service webapp is configured to redirect all HTTP traffic to HTTPS.


---

### 1.3.2 Ensure Web App is using the latest version of TLS encryption
**Platform:** Azure

**Rationale:** App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app secure connections.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 9.3

**Evidence**

**From Azure Portal**

1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/)
2. Go to `App Services`
3. Click on each App
4. Under `Setting` section, Click on `TLS/SSL settings`
5. Under the `Bindings` pane, ensure that `Minimum TLS Version` set to `1.2` under `Protocol Settings`

**From Azure CLI**

To check TLS Version for an existing app, run the following command,


```
az webapp config show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query minTlsVersion
```


The output should return `1.2` if TLS Version is set to `1.2` (Which is currently the latest version).

**From PowerShell**

List all web apps.


```
Get-AzWebApp
```


For each web app run the following command.


```
Get-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> |Select-Object -ExpandProperty SiteConfig
```


Make sure the `minTlsVersion` is set to at least `1.2`.

**Verification**

Evidence or test output indicates that each webapp is configured to require TLS 1.2 or higher.


---
### 1.3.3 Ensure FTP deployments are Disabled
**Platform:** Azure

**Rationale:** Azure FTP deployment endpoints are public. An attacker listening to traffic on a wifi network used by a remote employee or a corporate network could see login traffic in clear-text which would then grant them full control of the code base of the app or service. This finding is more severe if User Credentials for deployment are set at the subscription level rather than using the default Application Credentials which are unique per App.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 9.10

**Evidence**

**From Azure Portal**


1. Go to the Azure Portal
2. Select `App Services`
3. Click on an app
4. Select `Settings` and then `Configuration`
5. Under `General Settings`, for the `Platform Settings`, the `FTP state` should not be set to `All allowed`

**From Azure CLI**

List webapps to obtain the ids.


```
az webapp list
```


List the publish profiles to obtain the username, password and ftp server url.


```
az webapp deployment list-publishing-profiles --ids <ids>
{
 "publishUrl": <URL_FOR_WEB_APP>,
 "userName": <USER_NAME>,
 "userPWD": <USER_PASSWORD>,
}
```


**From PowerShell**

List all Web Apps:


```
Get-AzWebApp
```


For each app:


```
Get-AzWebApp -ResourceGroupName <resource group name> -Name <app name> | Select-Object -ExpandProperty SiteConfig
```


In the output, look for the value of **FtpsState**. If its value is **AllAllowed** the setting is out of compliance. Any other value is considered in compliance with this check.

**Verification**

Evidence or test output indicates that no webapp is deployed with FtpsState of AllAllowed.


---

### 1.3.4 Ensure “Block Project-Wide SSH Keys” Is Enabled for VM Instances
**Platform:** Google

**Rationale:** Project-wide SSH keys are stored in Compute/Project-meta-data. Project wide SSH keys can be used to login into all the instances within the project. Using project-wide SSH keys eases the SSH key management but if compromised, poses the security risk which can impact all the instances within the project. It is recommended to use Instance specific SSH keys which can limit the attack surface if the SSH keys are compromised.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 4.3

**Evidence**

**From Google Cloud Console**



1. Go to the `VM instances` page by visiting [https://console.cloud.google.com/compute/instances](https://console.cloud.google.com/compute/instances). It will list all the instances in your project.
2. For every instance, click on the name of the instance.
3. Under `SSH Keys`, ensure `Block project-wide SSH keys` is selected.

**From Google Cloud CLI**



1. List the instances in your project and get details on each instance:

  ```
  gcloud compute instances list --format=json
  ```

2. Ensure `key: block-project-ssh-keys` is set to `value: 'true'`.

**Verification**

Evidence or test output indicates that every compute instance is configured to block project ssh keys.


---


## 1.4 Encrypt Sensitive Data at Rest


### Description

Encrypt sensitive data at rest on servers, applications, and databases containing sensitive data. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard. Additional encryption methods may include application-layer encryption, also known as client-side encryption, where access to the data storage device(s) does not permit access to the plain-text data.


### Rationale

Encryption at rest protects against some risks of unauthorized access to data, for example insecure disposal and reuse of storage media.


### Audit


---

### 1.4.1 Ensure Virtual Machines are utilizing Managed Disks
**Platform:** Azure

**Rationale:** Managed disks are by default encrypted on the underlying hardware, so no additional encryption is required for basic protection. It is available if additional encryption is required. Managed disks are by design more resilient than storage accounts.

For ARM-deployed Virtual Machines, Azure Adviser will at some point recommend moving VHDs to managed disks both from a security and cost management perspective.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 7.2

**Evidence**

**From Azure Portal**



1. Using the search feature, go to `Virtual Machines`
2. Click the `Manage view` dropdown, then select `Edit columns`
3. Add `Uses managed disks` to the selected columns
4. Select `Save`
5. Ensure all virtual machines listed are using managed disks

**From PowerShell**


```
Get-AzVM | ForEach-Object {"Name: " + $_.Name;"ManagedDisk Id: " + $_.StorageProfile.OsDisk.ManagedDisk.Id;""}
```


Example output:


```
Name: vm1
ManagedDisk Id: /disk1/id

Name: vm2
ManagedDisk Id: /disk2/id
```


If the 'ManagedDisk Id' field is empty the os disk for that vm is not managed.

**Verification**

Evidence or test output indicates that every VM is using a managed disk.


---


## 1.5 Implement and Manage a Firewall on Servers


### Description

Implement and manage a firewall on servers, where supported. Example implementations include a virtual firewall, operating system firewall, or a third-party firewall agent.


### Rationale

Firewalls help to prevent unauthorized users from accessing servers or sending malicious payloads to those servers.


### Audit


---

### 1.5.1 Ensure That IP Forwarding Is Not Enabled on Instances
**Platform:** Google

**Rationale:** Compute Engine instance cannot forward a packet unless the source IP address of the packet matches the IP address of the instance. Similarly, GCP won't deliver a packet whose destination IP address is different than the IP address of the instance receiving the packet. However, both capabilities are required if you want to use instances to help route packets. To enable this source and destination IP check, disable the `canIpForward` field, which allows an instance to send and receive packets with non-matching destination or source IPs.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 4.6

**Evidence**

**From Google Cloud Console**



1. Go to the `VM Instances` page by visiting: [https://console.cloud.google.com/compute/instances](https://console.cloud.google.com/compute/instances).
2. For every instance, click on its name to go to the `VM instance details` page.
3. Under the `Network interfaces` section, ensure that `IP forwarding` is set to `Off` for every network interface.

**From Google Cloud CLI**



1. List all instances:

  ```
  gcloud compute instances list --format='table(name,canIpForward)'

  ```

2. Ensure that the CAN_IP_FORWARD column in the output of above command does not contain `True` for any VM instance.

**Exception:** Instances created by GKE should be excluded because they need to have IP forwarding enabled and cannot be changed. Instances created by GKE have names that start with "gke-".

**Verification**

Evidence or test output indicates that no compute instance is configured with CAN_IP_FORWARD set to true, with the exception of instances that were created by GKE having names that start with “gke-”.


---


## 1.6 Manage Default Accounts on Enterprise Assets and Software
### Description

Manage default accounts on enterprise assets and software, such as root, administrator, and other pre-configured vendor accounts. Example implementations can include: disabling default accounts or making them unusable.


### Rationale

Products typically ship with insecure defaults that, if not configured securely, can be used by malicious users to take over a system.


### Audit


---

### 1.6.1 Ensure That Instances Are Not Configured To Use the Default Service Account
**Platform:** Google

**Rationale:** The default Compute Engine service account has the Editor role on the project, which allows read and write access to most Google Cloud Services. To defend against privilege escalations if your VM is compromised and prevent an attacker from gaining access to all of your project, it is recommended to not use the default Compute Engine service account. Instead, you should create a new service account and assign only the permissions needed by your instance.

The default Compute Engine service account is named `[PROJECT_NUMBER]-compute@developer.gserviceaccount.com`.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 4.1

**Evidence**

**From Google Cloud Console**



1. Go to the `VM instances` page by visiting: [https://console.cloud.google.com/compute/instances](https://console.cloud.google.com/compute/instances).
2. Click on each instance name to go to its `VM instance details` page.
3. Under the section `API and identity management`, ensure that the default Compute Engine service account is not used. This account is named `[PROJECT_NUMBER]-compute@developer.gserviceaccount.com`.

**From Google Cloud CLI**



1. List the instances in your project and get details on each instance:

  ```
  gcloud compute instances list --format=json | jq -r '. | "SA: \(.[].serviceAccounts[].email) Name: \(.[].name)"'

  ```

2. Ensure that the service account section has an email that does not match the pattern `[PROJECT_NUMBER]-compute@developer.gserviceaccount.com`.

**Exception:** VMs created by GKE should be excluded. These VMs have names that start with `gke-` and are labeled `goog-gke-node`.

**Verification**

Evidence or test output indicates that no VM instance is configured to use the default service account.


---

### 1.6.2 Ensure That Instances Are Not Configured To Use the Default Service Account With Full Access to All Cloud APIs
**Platform:** Google

**Rationale:** Along with the ability to optionally create, manage and use user managed custom service accounts, Google Compute Engine provides default service account `Compute Engine default service account` for an instance to access necessary cloud services. `Project Editor` role is assigned to `Compute Engine default service account` hence, this service account has almost all capabilities over all cloud services except billing. However, when `Compute Engine default service account` is assigned to an instance it can operate in 3 scopes.


```
1. Allow default access: Allows only minimum access required to run an Instance (Least Privileges)

2. Allow full access to all Cloud APIs: Allow full access to all the cloud APIs/Services (Too much access)

3. Set access for each API: Allows Instance administrator to choose only those APIs that are needed to perform specific business functionality expected by instance
```


When an instance is configured with `Compute Engine default service account` with Scope `Allow full access to all Cloud APIs`, based on IAM roles assigned to the user(s) accessing Instance, it may allow user to perform cloud operations/API calls that user is not supposed to perform leading to successful privilege escalation.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 4.2

**Evidence**

**From Google Cloud Console**



1. Go to the `VM instances` page by visiting: [https://console.cloud.google.com/compute/instances](https://console.cloud.google.com/compute/instances).
2. Click on each instance name to go to its `VM instance details` page.
3. Under the `API and identity management`, ensure that `Cloud API access scopes` are not set to `Allow full access to all Cloud APIs`.

**From Google Cloud CLI**



1. List the instances in your project and get details on each instance:

  ```
  gcloud compute instances list --format=json | jq -r '. | "SA Scopes: \(.[].serviceAccounts[].scopes) Name: \(.[].name) Email: \(.[].serviceAccounts[].email)"'

  ```

2. Ensure that the service account section has an email that does not match the pattern `[PROJECT_NUMBER]-compute@developer.gserviceaccount.com`.

**Exception:** VMs created by GKE should be excluded. These VMs have names that start with `gke-` and are labeled `goog-gke-node

**Verification**

Evidence or test output indicates that no instance is configured to use the default service account with full access to all Cloud APIs scope granted.


---


## 1.7 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software

### Description

Uninstall or disable unnecessary services on enterprise assets and software, such as an unused file sharing service, web application module, or service function.


### Rationale

Uninstalling and disabling unnecessary services reduces the target area of your systems.


### Audit


---

### 1.7.1 Ensure ‘Enable Connecting to Serial Ports’ Is Not Enabled for VM Instance
**Platform:** Google

**Rationale:** A virtual machine instance has four virtual serial ports. Interacting with a serial port is similar to using a terminal window, in that input and output is entirely in text mode and there is no graphical interface or mouse support. The instance's operating system, BIOS, and other system-level entities often write output to the serial ports, and can accept input such as commands or answers to prompts. Typically, these system-level entities use the first serial port (port 1) and serial port 1 is often referred to as the serial console.

The interactive serial console does not support IP-based access restrictions such as IP whitelists. If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. This allows anybody to connect to that instance if they know the correct SSH key, username, project ID, zone, and instance name.

Therefore interactive serial console support should be disabled.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 4.5

**Evidence**

**From Google Cloud CLI**



1. Login to Google Cloud console
2. Go to Computer Engine
3. Go to VM instances
4. Click on the Specific VM
5. Ensure `Enable connecting to serial ports` below `Remote access` block is unselected.

**From Google Cloud Console**

Ensure the below command's output shows `null`:


```
gcloud compute instances describe <vmName> --zone=<region> --format="json(metadata.items[].key,metadata.items[].value)"
```


or `key` and `value` properties from below command's json response are equal to `serial-port-enable` and `0` or `false` respectively.


```
 {
 "metadata": {
 "items": [
 {
 "key": "serial-port-enable",
 "value": "0"
 }
 ]
 }
 }
```


**Verification**

Evidence or test output indicates that no compute instance is configured to allow connecting via serial port.


---


## 1.8 Centralize Account Management


### Description

Centralize account management through a directory or identity service.


### Rationale

Centralizing makes administration simpler and therefore reduces risks related to unauthorized account creation or usage.


### Audit


---

### 1.8.1 Ensure that Register with Azure Active Directory is enabled on App Service
**Platform:** Azure

**Rationale:** App Service provides a highly scalable, self-patching web hosting service in Azure. It also provides a managed identity for apps, which is a turn-key solution for securing access to Azure SQL Database and other Azure services.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 9.5

**Evidence**

**From Azure Portal**



1. From Azure Portal open the Portal Menu in the top left
2. Go to `App Services`
3. Click on each App
4. Under the `Setting` section, Click on `Identity`
5. Under the `System assigned` pane, ensure that `Status` set to `On`

**From Azure CLI**

To check Register with Azure Active Directory feature status for an existing app, run the following command,


```
az webapp identity show --resource-group <RESOURCE_GROUP_NAME> --name <APP_NAME> --query principalId
```


The output should return a unique Principal ID. If no output for the above command then Register with Azure Active Directory is not set.

**From PowerShell**

List the web apps.


```
Get-AzWebApp
```


For each web app run the following command.


```
Get-AzWebapp -ResourceGroupName <app resource group> -Name <app name>
```


Make sure the `Identity` setting contains a unique Principal ID

**Verification**

Evidence or test output indicates that every web app is assigned a unique principal ID, indicating that register with Azure Active Directory is enabled.


---

### 1.8.2 Ensure Oslogin Is Enabled for a Project
**Platform:** Google

**Rationale:** Enabling osLogin ensures that SSH keys used to connect to instances are mapped with IAM users. Revoking access to an IAM user will revoke all the SSH keys associated with that particular user. It facilitates centralized and automated SSH key pair management which is useful in handling cases like response to compromised SSH key pairs and/or revocation of external/third-party/Vendor users.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 4.4

**Evidence**

**From Google Cloud Console**



1. Go to the VM compute metadata page by visiting [https://console.cloud.google.com/compute/metadata](https://console.cloud.google.com/compute/metadata).
2. Ensure that key `enable-oslogin` is present with value set to `TRUE`.
3. Because instances can override project settings, ensure that no instance has custom metadata with key `enable-oslogin` and value `FALSE`.

**From Google Cloud CLI**



1. List the instances in your project and get details on each instance:

  ```
  gcloud compute instances list --format=json

  ```

2. Verify that the section `commonInstanceMetadata` has a key `enable-oslogin` set to value `TRUE`. **Exception:** VMs created by GKE should be excluded. These VMs have names that start with `gke-` and are labeled `goog-gke-node`

**Verification**

Evidence or test output indicates that all compute instances are configured with enable-oslogin set to true.


---


# 2 Identity and Access Management


## 2.1 Establish and Maintain a Data Recovery Process

### Description

Establish and maintain a data recovery process. In the process, address the scope of data recovery activities, recovery prioritization, and the security of backup data. Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

"Organizations need to establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state."


### Audit


---

### 2.1.1 Ensure the Key Vault is Recoverable
**Platform:** Azure

**Rationale:** There could be scenarios where users accidentally run delete/purge commands on Key Vault or an attacker/malicious user deliberately does so in order to cause disruption. Deleting or purging a Key Vault leads to immediate data loss, as keys encrypting data and secrets/certificates allowing access/services will become non-accessible. There are 2 Key Vault properties that play a role in permanent unavailability of a Key Vault:



1. `enableSoftDelete`:

Setting this parameter to "true" for a Key Vault ensures that even if Key Vault is deleted, Key Vault itself or its objects remain recoverable for the next 90 days. Key Vault/objects can either be recovered or purged (permanent deletion) during those 90 days. If no action is taken, the key vault and its objects will subsequently be purged.



2. `enablePurgeProtection`:

enableSoftDelete only ensures that Key Vault is not deleted permanently and will be recoverable for 90 days from date of deletion. However, there are scenarios in which the Key Vault and/or its objects are accidentally purged and hence will not be recoverable. Setting enablePurgeProtection to "true" ensures that the Key Vault and its objects cannot be purged.

Enabling both the parameters on Key Vaults ensures that Key Vaults and their objects cannot be deleted/purged permanently.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 8.5

**Evidence**

**From Azure Portal**



1. Go to `Key Vaults`
2. For each Key Vault
3. Click `Properties`
4. Ensure the status of soft-delete reads `Soft delete has been enabled on this key vault`

**From Azure CLI**



1. List all Resources of type Key Vaults:

  ```
  az resource list --query "[?type=='Microsoft.KeyVault/vaults']"

  ```

2. For Every Key Vault ID ensure check parameters `enableSoftDelete` and `enablePurgeProtection` are set to enabled.


```
az resource show --id /subscriptions/xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/<resourceGroupName>/providers/Microsoft.KeyVault
/vaults/<keyVaultName>
```


**From PowerShell**

Get all Key Vaults.


```
Get-AzKeyVault
```


For each Key Vault run the following command.


```
Get-AzKeyVault -VaultName <Vault Name>
```


Examine the results of the above command for the `EnablePurgeProtection` setting and the `EnableSoftDelete` setting. Make sure both settings are set to `True`.

**Verification**

Evidence or test output indicates that the Key Vault is recoverable.


---


## 2.2 Designate Personnel to Manage Incident Handling

### Description

Designate one key person, and at least one backup, who will manage the enterprise’s incident handling process. Management personnel are responsible for the coordination and documentation of incident response and recovery efforts and can consist of employees internal to the enterprise, third-party vendors, or a hybrid approach. If using a third-party vendor, designate at least one person internal to the enterprise to oversee any third-party work. Review annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

Without an incident response plan, an enterprise may not discover an attack in the first place, or, if the attack is detected, the enterprise may not follow good procedures to contain damage, eradicate the attacker’s presence, and recover in a secure fashion.


### Audit


---

### 2.2.1 Ensure a support role has been created to manage incidents with AWS Support
**Platform:** AWS

**Rationale:** By implementing least privilege for access control, an IAM Role will require an appropriate IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.17

**Evidence**

**From Command Line:**



1. List IAM policies, filter for the 'AWSSupportAccess' managed policy, and note the "Arn" element value:


```
aws iam list-policies --query "Policies[?PolicyName == 'AWSSupportAccess']"

```



2. Check if the 'AWSSupportAccess' policy is attached to any role:


```
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess

```



3. In Output, Ensure `PolicyRoles` does not return empty. 'Example: Example: PolicyRoles: [ ]'

If it returns empty then refer to the remediation in the CIS Benchmark.

**Verification**

Evidence or test output indicates that a support role has been created to manage incidents with AWS Support.


---


## 2.3 Establish and Maintain Contact Information for Reporting Security Incidents

### Description

Establish and maintain contact information for parties that need to be informed of security incidents. Contacts may include internal staff, third-party vendors, law enforcement, cyber insurance providers, relevant government agencies, Information Sharing and Analysis Center (ISAC) partners, or other stakeholders. Verify contacts annually to ensure that information is up-to-date.


### Rationale

As time goes by -- and processes and people change within an organization -- it's important to keep contact information up to date so that information about a security incident reaches the right individuals promptly.


### Audit


---

### 2.3.1 Maintain current contact details
**Platform:** AWS

**Rationale:** If an AWS account is observed to be behaving in a prohibited or suspicious manner, AWS will attempt to contact the account owner by email and phone using the contact details listed. If this is unsuccessful and the account behavior needs urgent mitigation, proactive measures may be taken, including throttling of traffic between the account exhibiting suspicious behavior and the AWS API endpoints and the Internet. This will result in impaired service to and from the account in question, so it is in both the customers' and AWS' best interests that prompt contact can be established. This is best achieved by setting AWS account contact details to point to resources which have multiple individuals as recipients, such as email aliases and PABX hunt groups.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.1

**Evidence**

This activity can only be performed via the AWS Console, with a user who has permission to read and write Billing information (aws-portal:*Billing )



1. Sign in to the AWS Management Console and open the `Billing and Cost Management` console at [https://console.aws.amazon.com/billing/home#/](https://console.aws.amazon.com/billing/home#/).
2. On the navigation bar, choose your account name, and then choose `Account`.
3. On the `Account Settings` page, review and verify the current details.
4. Under `Contact Information`, review and verify the current details.

**Verification**

Evidence or test output indicates that the tenant is configured with contact information and the developer affirms that this contact information is current.


---

### 2.3.2 Ensure security contact information is registered
**Platform:** AWS

**Rationale:** Specifying security-specific contact information will help ensure that security advisories sent by AWS reach the team in your organization that is best equipped to respond to them.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.2

**Evidence**

Perform the following to determine if security contact information is present:

**From Console:**



1. Click on your account name at the top right corner of the console
2. From the drop-down menu Click `My Account`
3. Scroll down to the `Alternate Contacts` section
4. Ensure contact information is specified in the `Security` section

**From Command Line:**



1. Run the following command:


```
aws account get-alternate-contact --alternate-contact-type SECURITY

```



2. Ensure proper contact information is specified for the `Security` contact.

**Verification**

Evidence or test output indicates that the tenant is configured with security contact information and the developer affirms that this contact information is current.


---

### 2.3.5 Ensure Essential Contacts is Configured for Organization
**Platform:** Google

**Rationale:** Many Google Cloud services, such as Cloud Billing, send out notifications to share important information with Google Cloud users. By default, these notifications are sent to members with certain Identity and Access Management (IAM) roles. With Essential Contacts, you can customize who receives notifications by providing your own list of contacts.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 1.16

**Evidence**

**From Google Cloud Console**



1. Go to `Essential Contacts` by visiting [https://console.cloud.google.com/iam-admin/essential-contacts](https://console.cloud.google.com/iam-admin/essential-contacts)
2. Make sure the organization appears in the resource selector at the top of the page. The resource selector tells you what project, folder, or organization you are currently managing contacts for.
3. Ensure that appropriate email addresses are configured for each of the following notification categories:
   * `Legal`
   * `Security`
   * `Suspension`
   * `Technical`
   * `Technical Incidents`

Alternatively, appropriate email addresses can be configured for the `All` notification category to receive all possible important notifications.

**From Google Cloud CLI**



1. To list all configured organization Essential Contacts run a command:


```
gcloud essential-contacts list --organization=<ORGANIZATION_ID>

```



2. Ensure at least one appropriate email address is configured for each of the following notification categories:
   * `LEGAL`
   * `SECURITY`
   * `SUSPENSION`
   * `TECHNICAL`
   * `TECHNICAL_INCIDENTS`

Alternatively, appropriate email addresses can be configured for the `ALL` notification category to receive all possible important notifications.

**Verification**

Evidence or test output indicates that essential contacts are configured for the organization.


---


## 2.4 Address Unauthorized Software


### Description

Ensure that unauthorized software is either removed from use on enterprise assets or receives a documented exception. Review monthly, or more frequently.


### Rationale

Actively manage (inventory, track, and correct) all software (operating systems and applications) on the network so that only authorized software is installed and can execute, and that unauthorized and unmanaged software is found and prevented from installation or execution.


### Audit


---

### 2.4.1 Ensure User consent for applications is set to Do not allow user consent
**Platform:** Azure

**Rationale:** If Azure Active Directory is running as an identity provider for third-party applications, permissions and consent should be limited to administrators or pre-approved. Malicious applications may attempt to exfiltrate data or abuse privileged user accounts.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.11

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Select `Enterprise Applications`
4. Select `Consent and permissions`
5. Select `User consent settings`
6. Ensure `User consent for applications` is set to `Do not allow user consent`

**From PowerShell**


```
Connect-MsolService
Get-MsolCompanyInformation | Select-Object UsersPermissionToUserConsentToAppEnabled
```


Command should return `UsersPermissionToUserConsentToAppEnabled` with the value of `False`

**Verification**

Evidence or test output indicates that `User consent for applications` is set to `Do not allow user consent`.


---

### 2.4.2 Ensure that 'Users can add gallery apps to My Apps' is set to 'No'
**Platform:** Azure

**Rationale:** Unless Azure Active Directory is running as an identity provider for third-party applications, do not allow users to use their identity outside of your cloud environment. User profiles contain private information such as phone numbers and email addresses which could then be sold off to other third parties without requiring any further consent from the user.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.13

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Then `Users`
4. Select `User settings`
5. Then `Manage how end users launch and view their applications`, and ensure that `Users can add gallery apps to My Apps` is set to `No`

**Verification**

Evidence or test output indicates that `Users can add gallery apps to My Apps` is set to `No`.


---

### 2.4.3 Ensure That ‘Users Can Register Applications’ Is Set to ‘No’
**Platform:** Azure

**Rationale:** It is recommended to only allow an administrator to register custom-developed applications. This ensures that the application undergoes a formal security review and approval process prior to exposing Azure Active Directory data. Certain users like developers or other high-request users may also be delegated permissions to prevent them from waiting on an administrative user. Your organization should review your policies and decide your needs.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.14

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Select `Users`
4. Select `User settings`
5. Ensure that `Users can register applications` is set to `No`

**From PowerShell**


```
Connect-MsolService
Get-MsolCompanyInformation | Select-Object UsersPermissionToCreateLOBAppsEnabled
```


Command should return `UsersPermissionToCreateLOBAppsEnabled` with the value of `False`

**Verification**

Evidence or test output indicates that `Users can register applications` is set to `No`.


---


## 2.5 Establish and Maintain a Data Management Process

### Description

Establish and maintain a data management process. In the process, address data sensitivity, data owner, handling of data, data retention limits, and disposal requirements, based on sensitivity and retention standards for the enterprise. Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.


### Audit


---

### 2.5.1 Ensure that the Expiration Date that is no more than 90 days in the future is set for all Keys in RBAC Key Vaults
**Platform:** Azure

**Rationale:** Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The `exp` (expiration date) attribute identifies the expiration date on or after which the key MUST NOT be used for encryption of new data, wrapping of new keys, and signing. By default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration date for all keys to help enforce the key rotation. This ensures that the keys cannot be used beyond their assigned lifetimes.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 8.1

**Evidence**

**From Azure Portal:**



1. Go to `Key vaults`.
2. For each Key vault, click on `Keys`.
3. In the main pane, ensure that an appropriate `Expiration date` is set for any keys that are `Enabled`.

**From Azure CLI:**

Get a list of all the key vaults in your Azure environment by running the following command:


```
az keyvault list
```


Then for each key vault listed ensure that the output of the below command contains Key ID (kid), enabled status as `true` and Expiration date (expires) is not empty or null:


```
az keyvault key list --vault-name <VaultName> --query '[*].{"kid":kid,"enabled":attributes.enabled,"expires":attributes.expires}'
```


**From PowerShell:**

Retrieve a list of Azure Key vaults:


```
Get-AzKeyVault
```


For each Key vault run the following command to determine which vaults are configured to use RBAC.


```
Get-AzKeyVault -VaultName <VaultName>
```


For each Key vault with the `EnableRbacAuthorizatoin` setting set to `True`, run the following command.


```
Get-AzKeyVaultKey -VaultName <VaultName>
```


Make sure the `Expires` setting is configured with a value as appropriate wherever the `Enabled` setting is set to `True`.

**Verification**

Evidence or test output indicates that an expiration date is set for all keys in RBAC key vaults and none of the expiration dates are more than 90 days in the future.


---

### 2.5.2 Ensure that the Expiration Date that is no more than 90 days in the future is set for all Keys in Non-RBAC Key Vaults.
**Platform:** Azure

**Rationale:** Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The `exp` (expiration date) attribute identifies the expiration date on or after which the key MUST NOT be used for a cryptographic operation. By default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration date for all keys. This ensures that the keys cannot be used beyond their assigned lifetimes.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 8.2

**Evidence**

**From Azure Portal:**

1. Go to `Key vaults`.
2. For each Key vault, click on `Keys`.
3. In the main pane, ensure that the status of the key is `Enabled`.
4. For each enabled key, ensure that an appropriate `Expiration date` is set.

**From Azure CLI:**

Get a list of all the key vaults in your Azure environment by running the following command:


```
az keyvault list
```


For each key vault, ensure that the output of the below command contains Key ID (kid), enabled status as `true` and Expiration date (expires) is not empty or null:


```
az keyvault key list --vault-name <KEYVAULTNAME> --query '[*].{"kid":kid,"enabled":attributes.enabled,"expires":attributes.expires}'
```


**From PowerShell:**

Retrieve a list of Azure Key vaults:


```
Get-AzKeyVault
```


For each Key vault, run the following command to determine which vaults are configured to not use RBAC:


```
Get-AzKeyVault -VaultName <Vault Name>
```


For each Key vault with the `EnableRbacAuthorizatoin` setting set to `False` or empty, run the following command.


```
Get-AzKeyVaultKey -VaultName <Vault Name>
```


Make sure the `Expires` setting is configured with a value as appropriate wherever the `Enabled` setting is set to `True`.

**Verification**

Evidence or test output indicates that an expiration date is set for all keys in Non-RBAC key vaults and none of the expiration dates are more than 90 days in the future.


---

### 2.5.3 Ensure that the Expiration Date that is no more than 90 days in the future is set for all Secrets in RBAC Key Vaults
**Platform:** Azure

**Rationale:** The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The `exp` (expiration date) attribute identifies the expiration date on or after which the secret MUST NOT be used. By default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration date for all secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 8.3

**Evidence**

**From Azure Portal:**

1. Go to `Key vaults`.
2. For each Key vault, click on `Secrets`.
3. In the main pane, ensure that the status of the secret is `Enabled`.
4. For each enabled secret, ensure that an appropriate `Expiration date` is set.

**From Azure CLI:**

Ensure that the output of the below command contains ID (id), enabled status as `true` and Expiration date (expires) is not empty or null:


```
az keyvault secret list --vault-name <KEYVAULTNAME> --query '[*].{"kid":kid,"enabled":attributes.enabled,"expires":attributes.expires}'
```


**From PowerShell:**

Retrieve a list of Key vaults:


```
Get-AzKeyVault
```


For each Key vault, run the following command to determine which vaults are configured to use RBAC:


```
Get-AzKeyVault -VaultName <Vault Name>
```


For each Key vault with the `EnableRbacAuthorizatoin` setting set to `True`, run the following command:


```
Get-AzKeyVaultSecret -VaultName <Vault Name>
```


Make sure the `Expires` setting is configured with a value as appropriate wherever the `Enabled` setting is set to `True`.

**Verification**

Evidence or test output indicates that an expiration date is set for all secrets in RBAC key vaults and none of the expiration dates are more than 90 days in the future.


---

### 2.5.4 Ensure that the Expiration Date that is no more than 90 days in the future is set for all Secrets in Non-RBAC Key Vaults
**Platform:** Azure

**Rationale:** The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The `exp` (expiration date) attribute identifies the expiration date on or after which the secret MUST NOT be used. By default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration date for all secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 8.4

**Evidence**

**From Azure Portal:**



1. Go to `Key vaults`.
2. For each Key vault, click on `Secrets`.
3. In the main pane, ensure that the status of the secret is `Enabled`.
4. Set an appropriate `Expiration date` on all secrets.

**From Azure CLI:**

Get a list of all the key vaults in your Azure environment by running the following command:


```
az keyvault list
```


For each key vault, ensure that the output of the below command contains ID (id), enabled status as `true` and Expiration date (expires) is not empty or null:


```
az keyvault secret list --vault-name <KEYVALUTNAME> --query '[*].{"kid":kid,"enabled":attributes.enabled,"expires":attributes.expires}'
```


**From PowerShell:**

Retrieve a list of Key vaults:


```
Get-AzKeyVault
```


For each Key vault run the following command to determine which vaults are configured to use RBAC:


```
Get-AzKeyVault -VaultName <Vault Name>
```


For each Key Vault with the `EnableRbacAuthorization` setting set to `False` or empty, run the following command.


```
Get-AzKeyVaultSecret -VaultName <Vault Name>
```


Make sure the `Expires` setting is configured with a value as appropriate wherever the `Enabled` setting is set to `True`.

**Verification**

Evidence or test output indicates that an expiration date is set for all secrets in Non-RBAC key vaults and none of the expiration dates are more than 90 days in the future.


---


## 2.6 Encrypt Sensitive Data at Rest


### Description

Encrypt sensitive data at rest on servers, applications, and databases containing sensitive data. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard. Additional encryption methods may include application-layer encryption, also known as client-side encryption, where access to the data storage device(s) does not permit access to the plain-text data.


### Rationale

Encryption at rest protects against some risks of unauthorized access to data, for example insecure disposal and reuse of storage media.


### Audit


---

### 2.6.1 Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager
**Platform:** Google

**Rationale:** It is recommended to use the Secret Manager, because environment variables are stored unencrypted, and accessible for all users who have access to the code.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 1.18

**Evidence**

Determine if Confidential Information is Stored in your Functions in Cleartext

**From Google Cloud Console**



1. Within the project you wish to audit, select the Navigation hamburger menu in the top left. Scroll down to under the heading 'Serverless', then select 'Cloud Functions'
2. Click on a function name from the list
3. Open the Variables tab and you will see both buildEnvironmentVariables and environmentVariables
4. Review the variables whether they are secrets
5. Repeat step 3-5 until all functions are reviewed

**From Google Cloud CLI**



1. To view a list of your cloud functions run


```
gcloud functions list

```



2. For each cloud function in the list run the following command.


```
gcloud functions describe <function_name>

```



3. Review the settings of the buildEnvironmentVariables and environmentVariables. Determine if this is data that should not be publicly accessible.

Determine if Secret Manager API is 'Enabled' for your Project

**From Google Cloud Console**



1. Within the project you wish to audit, select the Navigation hamburger menu in the top left. Hover over 'APIs & Services' under the heading 'Serverless', then select 'Enabled APIs & Services' in the menu that opens up.
2. Click the button '+ Enable APIS and Services'
3. In the Search bar, search for 'Secret Manager API' and select it.
4. If it is enabled, the blue box that normally says 'Enable' will instead say 'Manage'.

**From Google Cloud CLI**



1. Within the project you wish to audit, run the following command.


```
gcloud services list

```



2. If 'Secret Manager API' is in the list, it is enabled.

**Verification**

Evidence or test output indicates that no secrets are stored in cloud functions environment variables.


---


## 2.7 Configure Data Access Control Lists


### Description

Configure data access control lists based on a user’s need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.


### Rationale

The principle of least privilege reduces the risk of unauthorized actions being taken in your systems.


### Audit


---

### 2.7.1 Ensure no 'root' user account access key exists
**Platform:** AWS

**Rationale:** Deleting access keys associated with the 'root' user account limits vectors by which the account can be compromised. Additionally, deleting the 'root' access keys encourages the creation and use of role based accounts that are least privileged.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.4

**Evidence**

Perform the following to determine if the 'root' user account has access keys:

**From Console:**

1. Login to the AWS Management Console.
2. Click `Services`.
3. Click `IAM`.
4. Click on `Credential Report`.
5. This will download a `.csv` file which contains credential usage for all IAM users within an AWS Account - open this file.
6. For the `<root_account>` user, ensure the `access_key_1_active` and `access_key_2_active` fields are set to `FALSE`.

**From Command Line:**

Run the following command:


```
aws iam get-account-summary | grep "AccountAccessKeysPresent"
```


If no 'root' access keys exist the output will show `"AccountAccessKeysPresent": 0,`.

If the output shows a "1", then 'root' keys exist and should be deleted.

**Verification**

Evidence or test output indicates that no root user account access key exists.


---

### 2.7.2 Do not setup access keys during initial user setup for all IAM users that have a console password
**Platform:** AWS

**Rationale:** Requiring the additional steps be taken by the user for programmatic access after their profile has been created will give a stronger indication of intent that access keys are [a] necessary for their work and [b] once the access key is established on an account that the keys may be in use somewhere in the organization.

Note: Even if it is known the user will need access keys, require them to create the keys themselves or put in a support ticket to have them created as a separate step from user creation.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.11

**Evidence**

Perform the following to determine if access keys were created upon user creation and are being used and rotated as prescribed:

**From Console:**



1. Login to the AWS Management Console
2. Click `Services`
3. Click `IAM`
4. Click on a User where column `Password age` and `Access key age` is not set to `None`
5. Click on `Security credentials` Tab
6. Compare the user `Creation time` to the Access Key `Created` date.
7. For any that match, the key was created during initial user setup.
* Keys that were created at the same time as the user profile and do not have a last used date should be deleted. Refer to the remediation below.

**From Command Line:**



1. Run the following command (OSX/Linux/UNIX) to generate a list of all IAM users along with their access keys utilization:


```
 aws iam generate-credential-report

 aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,9,11,14,16

```



2. The output of this command will produce a table similar to the following:


```
user,password_enabled,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date
 elise,false,true,2015-04-16T15:14:00+00:00,false,N/A
 brandon,true,true,N/A,false,N/A
 rakesh,false,false,N/A,false,N/A
 helene,false,true,2015-11-18T17:47:00+00:00,false,N/A
 paras,true,true,2016-08-28T12:04:00+00:00,true,2016-03-04T10:11:00+00:00
 anitha,true,true,2016-06-08T11:43:00+00:00,true,N/A

```



3. For any user having `password_enabled` set to `true` AND `access_key_last_used_date` set to `N/A` then refer to the remediation in the CIS Benchmark.

**Verification**

Evidence or test output indicates that no user exists for which: (1) password enabled is set to true, and (2) an access key that has never been used exists for that user.


---

### 2.7.3 Ensure IAM policies that allow full "\*:\*" administrative privileges are not attached
**Platform:** AWS

**Rationale:** It's more secure to start with a minimum set of permissions and grant additional permissions as necessary, rather than starting with permissions that are too lenient and then trying to tighten them later.

Providing full administrative privileges instead of restricting to the minimum set of permissions that the user is required to do exposes the resources to potentially unwanted actions.

IAM policies that have a statement with "Effect": "Allow" with "Action": "\*" over "Resource": "\*" should be removed.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.16, [AWS Security Hub IAM.1](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html#iam-1)

**Evidence**

Perform the following to determine what policies are created:

**From Command Line:**



1. Run the following to get a list of IAM policies:


```
 aws iam list-policies --only-attached --output text

```



2. For each policy returned, run the following command to determine if any policies is allowing full administrative privileges on the account:


```
 aws iam get-policy-version --policy-arn <policy_arn> --version-id <version>

```



3. In output ensure policy should not have any Statement block with `"Effect": "Allow"` and `Action` set to `"*"` and `Resource` set to `"*"`

**Verification**

Evidence or test output indicates that no customer-managed IAM policy that allows full administrative privileges are attached (i.e., in effect within the AWS account). Note that inline and AWS-managed policies are exempt from this requirement.


---

### 2.7.4 Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects'
**Platform:** Azure

**Rationale:** Limiting guest access ensures that guest accounts do not have permission for certain directory tasks, such as enumerating users, groups or other directory resources, and cannot be assigned to administrative roles in your directory. Guest access has three levels of restriction.



1. Guest users have the same access as members (most inclusive),
2. Guest users have limited access to properties and memberships of directory objects (default value),
3. Guest user access is restricted to properties and memberships of their own directory objects (most restrictive).

The recommended option is the 3rd, most restrictive: "Guest user access is restricted to their own directory object".

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.15

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Then `External Identities`
4. Select `External collaboration settings`
5. Under `Guest user access`, ensure that `Guest user access restrictions `is set to `Guest user access is restricted to properties and memberships of their own directory objects`

**From PowerShell**



1. Enter the following `Get-AzureADMSAuthorizationPolicy` Which will give a result like:


```
Id : authorizationPolicy
OdataType :
Description : Used to manage authorization related settings across the company.
DisplayName : Authorization Policy
EnabledPreviewFeatures : {}
GuestUserRoleId : 10dae51f-b6af-4016-8d66-8c2a99b929b3
PermissionGrantPolicyIdsAssignedToDefaultUserRole : {user-default-legacy}
```


If the GuestUserRoleID property does not equal `2af84b1e-32c8-42b7-82bc-daa82404023b` then it is not set to the most restrictive.

**Verification**

Evidence that `Guest users access restrictions` is set to `Guest user access is restricted to properties and memberships of their own directory objects`.


---

### 2.7.5 Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level
**Platform:** Google

**Rationale:** A service account is a special Google account that belongs to an application or a virtual machine (VM), instead of to an individual end-user. Application/VM-Instance uses the service account to call the service's Google API so that users aren't directly involved. In addition to being an identity, a service account is a resource that has IAM policies attached to it. These policies determine who can use the service account.

Users with IAM roles to update the App Engine and Compute Engine instances (such as App Engine Deployer or Compute Instance Admin) can effectively run code as the service accounts used to run these instances, and indirectly gain access to all the resources for which the service accounts have access. Similarly, SSH access to a Compute Engine instance may also provide the ability to execute code as that instance/Service account.

Based on business needs, there could be multiple user-managed service accounts configured for a project. Granting the `iam.serviceAccountUser` or `iam.serviceAccountTokenCreator` roles to a user for a project gives the user access to all service accounts in the project, including service accounts that may be created in the future. This can result in elevation of privileges by using service accounts and corresponding `Compute Engine instances`.

In order to implement `least privileges` best practices, IAM users should not be assigned the `Service Account User` or `Service Account Token Creator` roles at the project level. Instead, these roles should be assigned to a user for a specific service account, giving that user access to the service account. The `Service Account User` allows a user to bind a service account to a long-running job service, whereas the `Service Account Token Creator` role allows a user to directly impersonate (or assert) the identity of a service account.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 1.6

**Evidence**

**From Google Cloud Console**



1. Go to the IAM page in the GCP Console by visiting [https://console.cloud.google.com/iam-admin/iam](https://console.cloud.google.com/iam-admin/iam)
2. Click on the filter table text bar, Type `Role: Service Account User`.
3. Ensure no user is listed as a result of the filter.
4. Click on the filter table text bar, Type `Role: Service Account Token Creator`.
5. Ensure no user is listed as a result of the filter.

**From Google Cloud CLI**

To ensure IAM users are not assigned Service Account User role at the project level:


```
gcloud projects get-iam-policy PROJECT_ID --format json | jq '.bindings[].role' | grep "roles/iam.serviceAccountUser"

gcloud projects get-iam-policy PROJECT_ID --format json | jq '.bindings[].role' | grep "roles/iam.serviceAccountTokenCreator"
```


These commands should not return any output.

**Verification**

Evidence or test output indicates that IAM users are not assigned the service account user or service account token creator roles at project level.


---
### 2.7.6 Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible
**Platform:** Google

**Rationale:** Granting permissions to `allUsers` or `allAuthenticatedUsers` allows anyone to access the dataset. Such access might not be desirable if sensitive data is stored at the location. In this case, ensure that anonymous and/or public access to a Cloud KMS `cryptokey` is not allowed.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 1.9

**Evidence**

**From Google Cloud CLI**



1. List all Cloud KMS `Cryptokeys`.


```
gcloud kms keys list --keyring=[key_ring_name] --location=global --format=json | jq '.[].name'

```



2. Ensure the below command's output does not contain `allUsers` or `allAuthenticatedUsers`.


```
gcloud kms keys get-iam-policy [key_name] --keyring=[key_ring_name] --location=global --format=json | jq '.bindings[].members[]'
```


**Verification**

Evidence or test output indicates that cloud KML cryptokeys are not anonymously or publicly accessible.


---


## 2.8 Establish and Maintain a Secure Configuration Process
### **Description**

Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### **Rationale**

"""This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software."""


### **Audit**


---

### 2.8.1 Ensure Security Defaults is enabled on Azure Active Directory
**Platform:** Azure

**Rationale:** Security defaults provide secure default settings that we manage on behalf of organizations to keep customers safe until they are ready to manage their own identity security settings.

For example, doing the following:



* Requiring all users and admins to register for MFA.
* Challenging users with MFA - when necessary, based on factors such as location, device, role, and task.
* Disabling authentication from legacy authentication clients, which can’t do MFA.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.1.1

**Evidence**

**From Azure Portal**

To ensure security defaults is enabled in your directory:



1. From Azure Home select the Portal Menu.
2. Browse to `Azure Active Directory` > `Properties`.
3. Select `Manage security defaults`.
4. Verify the `Enable security defaults` toggle is `Yes`.

**Verification**

Evidence or test output indicates that security defaults is enabled on Azure Active Directory.


---
### 2.8.2 Ensure IAM password policy requires minimum length of 14 or greater
**Platform:** AWS

**Rationale:** Setting a password complexity policy increases account resiliency against brute force login attempts.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.8

**Evidence**

Perform the following to ensure the password policy is configured as prescribed:

**From Console:**



1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
2. Go to IAM Service on the AWS Console
3. Click on Account Settings on the Left Pane
4. Ensure "Minimum password length" is set to 14 or greater.

**From Command Line:**


```
aws iam get-account-password-policy
```


Ensure the output of the above command includes "MinimumPasswordLength": 14 (or higher)

**Verification**

Evidence or test output indicates that the IAM password policy requires a minimum length of 14 or greater.


---

### 2.8.3 Ensure there is only one active access key available for any single IAM user
**Platform:** AWS

**Rationale:** Access keys are long-term credentials for an IAM user or the AWS account 'root' user. You can use access keys to sign programmatic requests to the AWS CLI or AWS API. One of the best ways to protect your account is to not allow users to have multiple access keys.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.13

**Evidence**

**From Console:**


1. Sign in to the AWS Management Console and navigate to the IAM dashboard at `https://console.aws.amazon.com/iam/`.
2. In the left navigation panel, choose `Users`.
3. Click on the IAM user name that you want to examine.
4. On the IAM user configuration page, select `Security Credentials` tab.
5. Under the `Access Keys` section, in the Status column, check the current status for each access key associated with the IAM user. If the selected IAM user has more than one access key activated then the user's access configuration does not adhere to security best practices and the risk of accidental exposures increases.
* Repeat steps no. 3 – 5 for each IAM user in your AWS account.

**From Command Line:**

1. Run `list-users` command to list all IAM users within your account:


```
aws iam list-users --query "Users[*].UserName"
```


The command output should return an array that contains all your IAM user names.



2. Run `list-access-keys` command using the IAM user name list to return the current status of each access key associated with the selected IAM user:


```
aws iam list-access-keys --user-name <user-name>
```


The command output should expose the metadata `("Username", "AccessKeyId", "Status", "CreateDate")` for each access key on that user account.



3. Check the `Status` property value for each key returned to determine each key's current state. If the `Status` property value for more than one IAM access key is set to `Active`, the user access configuration does not adhere to this requirement, refer to the remediation in the CIS Benchmark.
* Repeat steps no. 2 and 3 for each IAM user in your AWS account.

**Verification**

Evidence or test output indicates that no user has more than one active access key.


---

### 2.8.4 Ensure access keys are rotated every 90 days or less
**Platform:** AWS

**Rationale:** Rotating access keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used.

Access keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.14

**Evidence**

Perform the following to determine if access keys are rotated as prescribed:

**From Console:**

1. Go to Management Console ([https://console.aws.amazon.com/iam](https://console.aws.amazon.com/iam))
2. Click on `Users`
3. Click `setting` icon
4. Select `Console last sign-in`
5. Click `Close`
6. Ensure that the `Access key age` is less than 90 days ago. note) `None` in the `Access key age` means the user has not used the access key.

**From Command Line:**


```
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d
```


The `access_key_1_last_rotated` and the `access_key_2_last_rotated` fields in this file note the date and time, in ISO 8601 date-time format, when the user's access key was created or last changed. If the user does not have an active access key, the value in this field is N/A (not applicable).

**Verification**

Evidence or test output indicates that no user has an active access key with the last rotated date greater than 90 days in the past.


---


## 2.9 Use Unique Passwords
### Description

Use unique passwords for all enterprise assets. Best practice implementation includes, at a minimum, an 8-character password for accounts using MFA and a 14-character password for accounts not using MFA.


### Rationale

Malicious users automate login attempts using username and password databases from breaches of other systems. Password policies can help to reduce the risk of a breached or otherwise insecure password being used.


### Audit


---

### 2.9.1 Ensure IAM password policy prevents password reuse
**Platform:** AWS

**Rationale:** Preventing password reuse increases account resiliency against brute force login attempts.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.9

**Evidence**

Perform the following to ensure the password policy is configured as prescribed:

**From Console:**

1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
2. Go to IAM Service on the AWS Console
3. Click on Account Settings on the Left Pane
4. Ensure "Prevent password reuse" is checked
5. Ensure "Number of passwords to remember" is set to 24

**From Command Line:**


```
aws iam get-account-password-policy
```


Ensure the output of the above command includes "PasswordReusePrevention": 24

**Verification**

Evidence or test output indicates that the IAM password policy prevents password reuse.


---

### 2.9.2 Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization
**Platform:** Azure

**Rationale:** Enabling this gives your organization further customization on what secure passwords are allowed. Setting a bad password list enables your organization to fine-tune its password policy further, depending on your needs. Removing easy-to-guess passwords increases the security of access to your Azure resources.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.7

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active directory`.
3. Select 'Security'.
4. Under `Manage`, select `Authentication Methods`.
5. Select `Password Protection`.
6. Ensure `Enforce custom list` is set to `Yes`.
7. Scroll through the list to view the enforced passwords.

**Verification**

Evidence or test output indicates that a custom bad password is set to `enforce`. Developer states that they have reviewed the list and it is suitable for their organization.


---


## 2.10 Disable Dormant Accounts
### Description

Delete or disable any dormant accounts after a period of 45 days of inactivity, where supported.


### Rationale

Ensuring that dormant accounts are disabled when they're no longer needed reduces the target area for malicious users.


### Audit


---

### 2.10.1 Ensure credentials unused for 45 days or greater are disabled
**Platform:** AWS

**Rationale:** Disabling or removing unnecessary credentials will reduce the window of opportunity for credentials associated with a compromised or abandoned account to be used.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.12

**Evidence**

Perform the following to determine if unused credentials exist:

**From Console:**


1. Login to the AWS Management Console
2. Click `Services`
3. Click `IAM`
4. Click on `Users`
5. Click the `Settings` (gear) icon.
6. Select `Console last sign-in`, `Access key last used`, and `Access Key Id`
7. Click on `Close`
8. Check and ensure that the `Console last sign-in` is less than 45 days ago.

**Note** - `Never` means the user has never logged in.



1. Check and ensure that `Access key age` is less than 45 days and that `Access key last used` does not say `None`

If the user hasn't signed into the Console in the last 45 days or Access keys are over 45 days old then refer to the remediation in the CIS Benchmark.

**From Command Line:**

**Download Credential Report:**



1. Run the following commands:


```
 aws iam generate-credential-report

 aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,4,5,6,9,10,11,14,15,16 | grep -v '^<root_account>'
```


**Ensure unused credentials do not exist:**



1. For each user having `password_enabled` set to `TRUE` , ensure `password_last_used_date` is less than `45` days ago.
* When `password_enabled` is set to `TRUE` and `password_last_used` is set to `No_Information` , ensure `password_last_changed` is less than 45 days ago.
1. For each user having an `access_key_1_active` or `access_key_2_active` to `TRUE` , ensure the corresponding `access_key_n_last_used_date` is less than `45` days ago.
* When a user having an `access_key_x_active` (where x is 1 or 2) to `TRUE` and corresponding access_key_x_last_used_date is set to `N/A', ensure `access_key_x_last_rotated` is less than 45 days ago.

**Verification**

Evidence or test output indicates that no dormant credentials exist as defined by login via password greater than 45 days in the past or last access key active date greater than 45 days in the past.


---
### 2.10.2 Ensure Guest Users Are Reviewed on a Regular Basis
**Platform:** Azure

**Rationale:** Guest users in the Azure AD are generally required for collaboration purposes in Office 365, and may also be required for Azure functions in enterprises with multiple Azure tenants. Guest users are typically added outside your employee on-boarding/off-boarding process and could potentially be overlooked indefinitely, leading to a potential vulnerability. To prevent this, guest users should be reviewed on a regular basis. During this audit, guest users should also be determined to not have administrative privileges.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.5

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Select `Users`
4. Click on `Add filter`
5. Select `User type`
6. Select `Guest` from the Value dropdown
7. Click `Apply`
8. Audit the listed guest users

**From Azure CLI**


```
az ad user list --query "[?userType=='Guest']"
```


Ensure all users listed are still required and not inactive.

**From Azure PowerShell**


```
Get-AzureADUser |Where-Object {$_.UserType -like "Guest"} |Select-Object DisplayName, UserPrincipalName, UserType -Unique
```


**Verification**

Evidence or test output indicates there are no active guest users that have been inactive for greater than 90 days.

Developer states that they have reviewed guest users and that all users are still required and not inactive.


---


## 2.11 Restrict Administrator Privileges to Dedicated Administrator Accounts
### Description

Restrict administrator privileges to dedicated administrator accounts on enterprise assets. Conduct general computing activities, such as internet browsing, email, and productivity suite use, from the user’s primary, non-privileged account.


### Rationale

As a matter of good practice, users who can take administrative actions should use regular permissions for routine actions that do not require administrative privileges. This reduces the damage that could occur if the user encounters a malicious exploit attempt.


### Audit


---

### 2.11.1 Eliminate use of the 'root' user for administrative and daily tasks
**Platform:** AWS

**Rationale:** The 'root user' has unrestricted access to and control over all account resources. Use of it is inconsistent with the principles of least privilege and separation of duties, and can lead to unnecessary harm due to error or account compromise.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.7

**Evidence**

**From Console:**



1. Login to the AWS Management Console at `https://console.aws.amazon.com/iam/`
2. In the left pane, click `Credential Report`
3. Click on `Download Report`
4. Open of Save the file locally
5. Locate the `<root account>` under the user column
6. Review `password_last_used, access_key_1_last_used_date, access_key_2_last_used_date` to determine when the 'root user' was last used.

**From Command Line:**

Run the following CLI commands to provide a credential report for determining the last time the 'root user' was used:


```
aws iam generate-credential-report

aws iam get-credential-report --query 'Content' --output text | base64 -d | cut -d, -f1,5,11,16 | grep -B1 '<root_account>'
```


Review `password_last_used`, `access_key_1_last_used_date`, `access_key_2_last_used_date` to determine when the _root user_ was last used.

**Note:** There are a few conditions under which the use of the 'root' user account is required. Please see the reference links for all of the tasks that require use of the 'root' user.

**Verification**

Evidence or test output indicates the root account is not being used for any purpose except when absolutely necessary.


---

### 2.11.2 Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes'
**Platform:** Azure

**Rationale:** Global Administrator accounts are sensitive. Any password reset activity notification, when sent to all Global Administrators, ensures that all Global administrators can passively confirm if such a reset is a common pattern within their group. For example, if all Global Administrators change their password every 30 days, any password reset activity before that may require administrator(s) to evaluate any unusual activity and confirm its origin.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.10

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Select `Users`
4. Select `Password reset`
5. Under Manage, select `Notifications`
6. Ensure that `notify all admins when other admins reset their password?` is set to `Yes`

**Verification**

Evidence or test output indicates that the `Notify all admins when other admins reset their password?` configuration is set to `yes`.


---

### 2.11.3 Ensure That 'Restrict access to Azure AD administration portal' is Set to 'Yes'
**Platform:** Azure

**Rationale:** The Azure AD administrative portal has sensitive data and permission settings. All non-administrators should be prohibited from accessing any Azure AD data in the administration portal to avoid exposure.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.17

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Then `Users`
4. Select `User settings`
5. Ensure that `Restrict access to Azure AD administration portal` is set to `Yes`

**Verification**

Evidence or test output indicates that `Restrict access to Azure AD administration portal` is set to `yes`.


---

### 2.11.4 Ensure That No Custom Subscription Administrator Roles Exist
**Platform:** Azure

**Rationale:** Classic subscription admin roles offer basic access management and include Account Administrator, Service Administrator, and Co-Administrators. It is recommended the least necessary permissions be given initially. Permissions can be added as needed by the account holder. This ensures the account holder cannot perform actions which were not intended.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.23

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu.
2. Select `Subscriptions`.
3. Select `Access control (IAM)`.
4. Select `Roles`.
5. Click `Type` and select `CustomRole` from the drop down menu.
6. Select `View` next to a role.
7. Select `JSON`.
8. Check for `assignableScopes` set to `/` or the subscription, and `actions` set to `*`.
9. Repeat steps 6-8 for each custom role.

**From Azure CLI**

List custom roles:


```
az role definition list --custom-role-only True
```


Check for entries with `assignableScope` of `/` or the `subscription`, and an action of `*`

**From PowerShell**


```
Connect-AzAccount
Get-AzRoleDefinition |Where-Object {($_.IsCustom -eq $true) -and ($_.Actions.contains('*'))}
```


Check the output for `AssignableScopes` value set to '/' or the subscription.

**Verification**

Evidence or test output indicates that no custom subscription administrator roles exist.


---

### 2.11.5 Ensure That Service Account Has No Admin Privileges
**Platform:** Google

**Rationale:** Service accounts represent service-level security of the Resources (application or a VM) which can be determined by the roles assigned to it. Enrolling ServiceAccount with Admin rights gives full access to an assigned application or a VM. A ServiceAccount Access holder can perform critical actions like delete, update change settings, etc. without user intervention. For this reason, it's recommended that service accounts not have Admin rights.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 1.5

**Evidence**

**From Google Cloud Console**



1. Go to `IAM & admin/IAM` using `https://console.cloud.google.com/iam-admin/iam`
2. Go to the `Members`
3. Ensure that there are no `User-Managed user created service account(s)` with roles containing `*Admin` or `*admin` or role matching `Editor` or role matching `Owner`

**From Google Cloud CLI**



1. Get the policy that you want to modify, and write it to a JSON file:


```
gcloud projects get-iam-policy PROJECT_ID --format json > iam.json

```



2. The contents of the JSON file will look similar to the following. Note that `role` of members group associated with each `serviceaccount` does not contain `*Admin` or `*admin` or does not match `roles/editor` or does not match `roles/owner`.

This requirement is only applicable to `User-Managed user-created` service accounts. These accounts have the nomenclature: `SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com`. Note that some Google-managed, Google-created service accounts have the same naming format, and should be excluded (e.g., `appsdev-apps-dev-script-auth@system.gserviceaccount.com` which needs the Owner role).

**Sample Json output:**

{ "bindings": [ { "members": [ "serviceAccount:our-project-123@appspot.gserviceaccount.com", ], "role": "roles/appengine.appAdmin" }, { "members": [ "user:email1@gmail.com" ], "role": "roles/owner" }, { "members": [ "serviceAccount:our-project-123@appspot.gserviceaccount.com", "serviceAccount:123456789012-compute@developer.gserviceaccount.com" ], "role": "roles/editor" } ], "etag": "BwUjMhCsNvY=", "version": 1 }

**Verification**

Evidence or test output indicates that the service account has no admin privileges.


---


## 2.12 Centralize Account Management

### Description

Centralize account management through a directory or identity service.


### Rationale

Centralizing makes administration simpler and therefore reduces risks related to unauthorized account creation or usage.


### Audit


---

### 2.12.1 Ensure that Corporate Login Credentials are Used
**Platform:** Google

**Rationale:** It is recommended fully-managed corporate Google accounts be used for increased visibility, auditing, and controlling access to Cloud Platform resources. Email accounts based outside of the user's organization, such as personal accounts, should not be used for business purposes.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 1.1

**Evidence**

For each Google Cloud Platform project, list the accounts that have been granted access to that project:

**From Google Cloud CLI**


```
gcloud projects get-iam-policy PROJECT_ID
```


Also list the accounts added on each folder:


```
gcloud resource-manager folders get-iam-policy FOLDER_ID
```


And list your organization's IAM policy:


```
gcloud organizations get-iam-policy ORGANIZATION_ID
```


No email accounts outside the organization domain should be granted permissions in the IAM policies. This excludes Google-owned service accounts.

**Verification**

Evidence or test output indicates that corporate login credentials are used and that no email accounts outside the organization have permissions in the IAM policies.


---


## 2.13 Establish an Access Revoking Process
### Description

Establish and follow a process, preferably automated, for revoking access to enterprise assets, through disabling accounts immediately upon termination, rights revocation, or role change of a user. Disabling accounts, instead of deleting accounts, may be necessary to preserve audit trails.


### Rationale

Ensuring that access grants are revoked when they're no longer needed reduces the target area for malicious users.


### Audit


---
### 2.13.1 Ensure that 'Number of days before users are asked to re-confirm their authentication information' is set to '90'
**Platform:** Azure

**Rationale:** This setting is necessary if you have set up 'Require users to register when signing in option'. If authentication re-confirmation is disabled, registered users will never be prompted to re-confirm their existing authentication information. If the authentication information for a user changes, such as a phone number or email, then the password reset information for that user reverts to the previously registered authentication information.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.8

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Then `Users`
4. Select `Password reset`
5. Then `Registration`
6. Ensure that `Number of days before users are asked to re-confirm their authentication information` is set to `90`

**Verification**

Evidence or test output indicates that `Number of days before users are asked to re-confirm their authentication information` is set to `90`.


---


## 2.14 Require MFA for Externally-Exposed Applications
### Description

Require all externally-exposed enterprise or third-party applications to enforce MFA, where supported. Enforcing MFA through a directory service or SSO provider is a satisfactory implementation of this Safeguard.


### Rationale

Requiring MFA makes it harder for malicious attackers to takeover accounts, e.g., by re-using username and password combinations that have become leaked from other systems


### Audit


---

### 2.14.1 Ensure That 'Number of methods required to reset' is set to '2'
**Platform:** Azure

**Rationale:** A Self-service Password Reset (SSPR) through Azure Multi-factor Authentication (MFA) ensures the user's identity is confirmed using two separate methods of identification. With multiple methods set, an attacker would have to compromise both methods before they could maliciously reset a user's password.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.6

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Then `Users`
4. Select `Password reset`
5. Then `Authentication methods`
6. Ensure that `Number of methods required to reset` is set to `2`

**Verification**

Evidence or test output indicates that the `Number of methods required to reset `is set to `2`.


---

### 2.14.2 Ensure that 'Require Multi-Factor Authentication to register or join devices with Azure AD' is set to 'Yes'
**Platform:** Azure

**Rationale:** Multi-factor authentication is recommended when adding devices to Azure AD. When set to `Yes`, users who are adding devices from the internet must first use the second method of authentication before their device is successfully added to the directory. This ensures that rogue devices are not added to the domain using a compromised user account. _Note:_ Some Microsoft documentation suggests using conditional access policies for joining a domain from certain whitelisted networks or devices. Even with these in place, using Multi-Factor Authentication is still recommended, as it creates a process for review before joining the domain.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.22

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Select `Devices`
4. Select `Device settings`
5. Ensure that `Require Multi-Factor Authentication to register or join devices with Azure AD` is set to `Yes`

**Verification**

Evidence or test output indicates that `Require MFA to register or join devices with Azure AD `is set to `Yes`.


---

### 2.14.3 Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users
**Platform:** Azure

**Rationale:** Multi-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.1.2

**Evidence**

**From Azure Portal**

1. From Azure Home select the Portal Menu
2. Select the `Azure Active Directory` blade
3. Select `Users`
4. Take note of all users with the role `Service Co-Administrators`, `Owners` or `Contributors`
5. Click on the `Per-User MFA` button in the top row menu
6. Ensure that `MULTI-FACTOR AUTH STATUS` is `Enabled` for all noted users

**From REST API**

For Every Subscription, For Every Tenant

**Step 1:** Identify Users with Administrative Access



1. List All Users Using Microsoft Graph API:


```
GET https://graph.microsoft.com/v1.0/users
```


Capture `id` and corresponding `userPrincipalName` ('$uid', '$userPrincipalName')



2. List all Role Definitions Using Azure management API:


```
https://management.azure.com/subscriptions/:subscriptionId/providers/Microsoft.Authorization/roleDefinitions?api-version=2017-05-01
```


Capture Role Definition IDs/Name ('$name') and role names ('$properties/roleName') where "properties/roleName" contains (`Owner` or `*contributor` or `admin` )



3. List All Role Assignments (Mappings `$A.uid` to `$B.name`) Using Azure Management API:


```
GET https://management.azure.com/subscriptions/:subscriptionId/providers/Microsoft.Authorization/roleassignments?api-version=2017-10-01-preview
```


Find all administrative roles (`$B.name`) in `"Properties/roleDefinitionId"` mapped with user ids (`$A.id`) in `"Properties/principalId"` where `"Properties/principalType" == "User"`



4. Now Match (`$CProperties/principalId`) with `$A.uid` and get `$A.userPrincipalName` save this as `D.userPrincipalName`

**Step 2:** Run MSOL PowerShell command:


```
Get-MsolUser -All | where {$_.StrongAuthenticationMethods.Count -eq 0} | Select-Object -Property UserPrincipalName
```


If the output contains any of the `$D.userPrincipalName`, then this requirement is non-compliant.

**Verification**

Evidence or test output indicates that `MFA Status is `Enabled` for all privileged users.


---

### 2.14.4 Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled
**Platform:** Azure

**Rationale:** Remembering Multi-Factor Authentication (MFA) for devices and browsers allows users to have the option to bypass MFA for a set number of days after performing a successful sign-in using MFA. This can enhance usability by minimizing the number of times a user may need to perform two-step verification on the same device. However, if an account or device is compromised, remembering MFA for trusted devices may affect security. Hence, it is recommended that users not be allowed to bypass MFA.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.1.4

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Select `Users`
4. Click the `Per-user MFA` button on the top bar
5. Click on `service settings`
6. Ensure that `Allow users to remember multi-factor authentication on devices they trust` is not enabled

**Verification**

Evidence or test output indicates that `Allow users to remember MFA on devices they trust` is disabled.


---

### 2.14.5 Ensure that A Multi-factor Authentication Policy Exists for All Users
**Platform:** Azure

**Rationale:** Enabling multi-factor authentication is a recommended setting to limit the potential of accounts being compromised and limiting access to authenticated personnel.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.2.4

**Evidence**

**From Azure Portal**



1. From Azure Home open the Portal Menu in the top left, and select `Azure Active Directory`.
2. Scroll down in the menu on the left, and select `Security`.
3. Select on the left side `Conditional Access`.
4. Select the policy you wish to audit.
5. View under `Users and Groups` the corresponding users and groups to whom the policy is applied.
6. View under `Exclude` to determine which users and groups to whom the policy is not applied.

**Verification**

Evidence or test output indicates that a MFA policy exists for all users.


---

### 2.14.6 Ensure Multi-factor Authentication is Required for Risky Sign-ins
**Platform:** Azure

**Rationale:** Enabling multi-factor authentication is a recommended setting to limit the potential of accounts being compromised and limiting access to authenticated personnel.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.2.5

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu and select `Security`.
2. Select on the left side `Conditional Access`.
3. Select the policy you wish to audit.
4. View under `Users and Groups` the corresponding users and groups to whom the policy is applied.
5. View under `Exclude` to determine which users and groups to whom the policy is not applied.

**Verification**

Evidence or test output indicates that MFA is required for risky sign ins.


---

### 2.14.7 Ensure that Multi-Factor Authentication is 'Enabled' for All Non-Service Accounts
**Platform:** Google

**Rationale:** Multi-factor authentication requires more than one mechanism to authenticate a user. This secures user logins from attackers exploiting stolen or weak credentials.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 1.2

**Evidence**

**From Google Cloud Console**

For each Google Cloud Platform project, folder, or organization:



1. Identify non-service accounts.
2. Manually verify that multi-factor authentication for each account is set.

**Verification**

Evidence or test output indicates that MFA is enabled for all non service accounts.


---

### 2.14.8 Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users
**Platform:** Azure

**Rationale:** Multi-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk.**

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.1.3

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select the `Azure Active Directory` blade
3. Then `Users`
4. Select `All Users`
5. Click on `Per-User MFA` button on the top bar
6. Ensure that for all users `MULTI-FACTOR AUTH STATUS` is `Enabled`

**From REST API**

For Every Subscription, For Every Tenant

Step 1: Identify Users with non-administrative Access



1. List All Users Using Microsoft Graph API:

Capture `id` and corresponding `userPrincipalName` (`$uid`, `$userPrincipalName`)



2. List all Role Definitions Using Azure management API:

Capture Role Definition IDs/Name (`$name`) and role names (`$properties/roleName`) where `"properties/roleName"` does NOT contain (`Owner` or `*contributor` or `admin` )



3. List All Role Assignments (Mappings `$A.uid` to `$B.name`) Using Azure Management API:

Find all non-administrative roles (`$B.name`) in `"Properties/roleDefinationId"` mapped with user ids (`$A.id`) in `"Properties/principalId"` where `"Properties/principalType" == "User"`

D> Now Match (`$CProperties/principalId`) with `$A.uid` and get `$A.userPrincipalName` save this as `D.userPrincipleName`

Step 2: Run MSOL PowerShell command:

If the output contains any of the `$D.userPrincipleName`, then this requirement is non-compliant.

**Verification**

Evidence or test output indicates that MFA is enabled for all non-privileged users.


---


## 2.15 Require MFA for Remote Network Access
### Description

Require MFA for remote network access.


### Rationale

Requiring MFA makes it harder for malicious attackers to takeover accounts, e.g., by re-using username and password combinations that have become leaked from other systems


### Audit


---

### 2.15.1 Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups
**Platform:** Azure

**Rationale:** Enabling multi-factor authentication is a recommended setting to limit the use of Administrative accounts to authenticated personnel.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.2.3

**Evidence**

**From Azure Portal**



1. From Azure Home open the Portal Menu in the top left, and select `Azure Active Directory`.
2. Select `Security`.
3. Select `Conditional Access`.
4. Select the policy you wish to audit.
5. View under `Users and Groups` the corresponding users and groups to whom the policy is applied. Be certain the emergency access account is not in the list.
6. View under `Exclude` to determine which Users and groups to whom the policy is not applied.

**Verification**

Evidence or test output indicates that a MFA policy exists for administrative groups.


---

### 2.15.2 Ensure Multi-factor Authentication is Required for Azure Management
**Platform:** Azure

**Rationale:** Enabling multi-factor authentication is a recommended setting to limit the use of Administrative actions and to prevent intruders from changing settings.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.2.6

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu and select `Azure Active Directory`.
2. Scroll down in the menu on the left, and select `Security`.
3. Select on the left side `Conditional Access`.
4. Select the policy you wish to audit.
5. View under `Users and Groups` the corresponding users and groups to whom the policy is applied.
6. View under `Exclude` to determine which Users and groups to whom the policy is not applied.

**Verification**

Evidence or test output indicates that MFA is required for azure management.


---


## 2.16 Require MFA for Administrative Access
### Description

Require MFA for all administrative access accounts, where supported, on all enterprise assets, whether managed on-site or through a third-party provider.


### Rationale

Requiring MFA makes it harder for malicious attackers to takeover accounts, e.g., by re-using username and password combinations that have become leaked from other systems


### Audit


---

### 2.16.1 Ensure MFA is enabled for the 'root' user account
**Platform:** AWS

**Rationale:** Enabling MFA provides increased security for console access as it requires the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.5

**Evidence**

Perform the following to determine if the 'root' user account has MFA setup:

**From Console:**



1. Login to the AWS Management Console
2. Click `Services`
3. Click `IAM`
4. Click on `Credential Report`
5. This will download a `.csv` file which contains credential usage for all IAM users within an AWS Account - open this file
6. For the `<root_account>` user, ensure the `mfa_active` field is set to `TRUE` .

**From Command Line:**



1. Run the following command:


```
 aws iam get-account-summary | grep "AccountMFAEnabled"

```



2. Ensure the AccountMFAEnabled property is set to 1

**Verification**

Evidence or test output indicates that MFA is enabled for root user access.


---


## 2.17 Centralize Access Control
### Description

Centralize access control for all enterprise assets through a directory service or SSO provider, where supported.


### Rationale

Centralizing makes administration simpler and therefore reduces risks related to unauthorized account creation or usage.


### Audit


---

### 2.17.1 Ensure that 'Notify users on password resets?' is set to 'Yes'
**Platform:** Azure

**Rationale:** User notification on password reset is a proactive way of confirming password reset activity. It helps the user to recognize unauthorized password reset activities.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 1.9

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Azure Active Directory`
3. Select `Users`
4. Go to `Password reset`
5. Under Manage, select `Notifications`
6. Ensure that `Notify users on password resets?` is set to `Yes`

**Verification**

Evidence or test output indicates that `Notify users on password resets` is set to `yes`.


---


## 2.18 Define and Maintain Role-Based Access Control
### Description

Define and maintain role-based access control, through determining and documenting the access rights necessary for each role within the enterprise to successfully carry out its assigned duties. Perform access control reviews of enterprise assets to validate that all privileges are authorized, on a recurring schedule at a minimum annually, or more frequently.


### Rationale

Standardizing the mechanism for granting cloud permissions reduces the risk of an unintentional or unnoticed privilege.


### Audit


---

### 2.18.1 Ensure IAM Users Receive Permissions Only Through Groups
**Platform:** AWS

**Rationale:** Assigning IAM policy only through groups unifies permissions management to a single, flexible layer consistent with organizational functional roles. By unifying permissions management, the likelihood of excessive permissions is reduced.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 1.15

**Evidence**

Perform the following to determine if an inline policy is set or a policy is directly attached to users:



1. Run the following to get a list of IAM users:


```
 aws iam list-users --query 'Users[*].UserName' --output text

```



2. For each user returned, run the following command to determine if any policies are attached to them:


```
 aws iam list-attached-user-policies --user-name <iam_user>
 aws iam list-user-policies --user-name <iam_user>

```



3. If any policies are returned, the user has an inline policy or direct policy attachment.

**Verification**

Evidence or test output indicates that IAM users receive permissions only through groups.


---


# 3 Logging and Monitoring
## 3.1 Establish and Maintain Detailed Enterprise Asset Inventory
### Description

Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process, where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise’s network infrastructure, even if they are not under control of the enterprise. Review and update the inventory of all enterprise assets bi-annually, or more frequently.


### Rationale

It is necessary to first identify the systems and devices that need to be secured before taking additional steps towards achieving a suitable security baseline.


### Audit


---

### 3.1.1 Ensure Cloud Asset Inventory Is Enabled
**Platform:** Google

**Rationale:** The GCP resources and IAM policies captured by GCP Cloud Asset Inventory enables security analysis, resource change tracking, and compliance auditing.

It is recommended that GCP Cloud Asset Inventory be enabled for all GCP projects.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 2.13

**Evidence**

**From Google Cloud Console**

Ensure that the Cloud Asset API is enabled:



1. Go to `API & Services/Library` by visiting [https://console.cloud.google.com/apis/library](https://console.cloud.google.com/apis/library)
2. Search for `Cloud Asset API` and select the result for _Cloud Asset API_
3. Ensure that `API Enabled` is displayed.

**From Google Cloud CLI**

Ensure that the Cloud Asset API is enabled:



1. Query enabled services:


```
gcloud services list --enabled --filter=name:cloudasset.googleapis.com
```


If the API is listed, then it is enabled. If the response is `Listed 0 items` the API is not enabled.

**Verification**

Evidence or test output indicates that GCP Cloud Asset Inventory is enabled.


---


## 3.2 Tune Security Event Alerting Thresholds
### Description

Tune security event alerting thresholds monthly, or more frequently.


### Rationale

Tools must be tuned to reduce the prevalence of both false negatives and false positives.


### Audit


---

### 3.2.1 Ensure That 'Notify about alerts with the following severity' is Set to 'High'
**Platform:** Azure

**Rationale:** Enabling security alert emails ensures that security alert emails are received from Microsoft. This ensures that the right people are aware of any potential security issues and are able to mitigate the risk.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 2.1.20

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Microsoft Defender for Cloud`
3. Click on `Environment Settings`
4. Click on the appropriate Management Group, Subscription, or Workspace
5. Click on `Email notifications`
6. Ensure that the `Notify about alerts with the following severity (or higher):` setting is checked and set to `High`

**From Azure CLI**

Ensure the output of below command is set to `true`, enter your Subscription ID at the $0 between /subscriptions/<$0>/providers.


```
az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview' | jq '.|.[] | select(.name=="default")'|jq '.properties.alertNotifications'
```


**Verification**

Evidence or test output indicates that email notifications for high-severity (or higher) events are enabled.


---


## 3.3 Establish and Maintain Contact Information for Reporting Security Incidents
### Description

Establish and maintain contact information for parties that need to be informed of security incidents. Contacts may include internal staff, third-party vendors, law enforcement, cyber insurance providers, relevant government agencies, Information Sharing and Analysis Center (ISAC) partners, or other stakeholders. Verify contacts annually to ensure that information is up-to-date.


### Rationale

As time goes by -- and processes and people change within an organization -- it's important to keep contact information up to date so that information about a security incident reaches the right individuals promptly.


### Audit


---

### 3.3.1 Ensure That 'All users with the following roles' is set to 'Owner'
**Platform:** Azure

**Rationale:** Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 2.1.18

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Microsoft Defender for Cloud`
3. Then `Environment Settings`
4. Click on the appropriate Management Group, Subscription, or Workspace
5. Click on `Email notifications`
6. Ensure that `All users with the following roles` is set to `Owner`

**From Azure CLI**

Ensure the output of below command is set to `true`.


```
az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview' | jq '.|.value[] | select(.name=="default")'|jq '.properties.notificationsByRole'
```


**Verification**

Evidence or test output indicates that people with the role "owner" are subscribed to security alert emails.


---

### 3.3.2 Ensure 'Additional email addresses' is Configured with a Security Contact Email
**Platform:** Azure

**Rationale:** Microsoft Defender for Cloud emails the Subscription Owner to notify them about security alerts. Adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 2.1.19

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu.
2. Select `Microsoft Defender for Cloud`
3. Click on `Environment Settings`
4. Click on the appropriate Management Group, Subscription, or Workspace
5. Click on `Email notifications`
6. Ensure that a valid security contact email address is listed in the `Additional email addresses` field

**From Azure CLI**

Ensure the output of the below command is not empty and is set with appropriate email ids.


```
az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/$0/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview' | jq '.|.[] | select(.name=="default")'|jq '.properties.emails'
```


**Verification**

Evidence or test output indicates that a security POC is subscribed to security alerts.


---


## 3.4 Log Sensitive Data Access


### Description

Log sensitive data access, including modification and disposal.


### Rationale

Organizations need reliable forensic information about access, modification, and deletion of sensitive data.


### Audit


---

### 3.4.1 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket
**Platform:** AWS

**Rationale:** By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within any target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 3.6

**Evidence**

Perform the following ensure the CloudTrail S3 bucket has access logging is enabled:

**From Console:**



1. Go to the Amazon CloudTrail console at [https://console.aws.amazon.com/cloudtrail/home](https://console.aws.amazon.com/cloudtrail/home)
2. In the navigation pane on the left, click Trails.
3. In the Trails pane, note the bucket names in the S3 bucket column.
4. Go to the Amazon S3 console at [https://console.aws.amazon.com/s3](https://console.aws.amazon.com/s3).
5. For each bucket noted in step 3, click on a target S3 Bucket.
6. Click on `Properties`
7. In the `Server access logging` section, verify that server access logging is `Enabled`

**From Command Line:**



1. Get the name of the S3 bucket that CloudTrail is logging to:


```
aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'

```



2. Ensure Bucket Logging is enabled:


```
aws s3api get-bucket-logging --bucket <s3_bucket_for_cloudtrail>
```


Ensure command does not return empty output.

Sample Output for a bucket with logging enabled:


```
{
 "LoggingEnabled": {
 "TargetPrefix": "<Prefix_Test>",
 "TargetBucket": "<Bucket_name_for_Storing_Logs>"
 }
}
```


**Verification**

Evidence or test output indicates that all S3 buckets containing sensitive data have access logging enabled with a CloudTrail destination.


---


## 3.5 Configure Data Access Control Lists
### Description

Configure data access control lists based on a user’s need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.


### Rationale

The principle of least privilege reduces the risk of unauthorized actions being taken in your systems.


### Audit


---

### 3.5.1 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible
**Platform:** AWS

**Rationale:** Allowing public access to CloudTrail log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 3.3

**Evidence**

Perform the following to determine if any public access is granted to an S3 bucket via an ACL or S3 bucket policy:

**From Console:**



1. Go to the Amazon CloudTrail console at [https://console.aws.amazon.com/cloudtrail/home](https://console.aws.amazon.com/cloudtrail/home).
2. In the navigation pane on the left, click `Trails`.
3. In the `Trails` pane, note the bucket names in the `S3 bucket` column
4. Go to Amazon S3 console at [https://console.aws.amazon.com/s3/home](https://console.aws.amazon.com/s3/home).
5. For each bucket noted in step 3, click on the bucket name.
6. Click on the `Permissions` tab.
7. In the `Bucket policy` section, ensure that there is no statement with the `Effect` of `Allow` with a `Principal` of either `"\*"` or `{"AWS": "\*"}` unless it also has a suitable condition in place to restrict access, such as `aws:PrincipalOrgID`.
8. In the `Access control list (ACL)` section, that no permissions for either `Objects` or `Bucket ACL` are granted to either `Everyone` or `Authenticated users group`.

**From Command Line:**



1. Get the name of the S3 bucket that CloudTrail is logging to:


```
 aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'

```



2. Ensure the `AllUsers` principal is not granted privileges to that `<bucket>` :


```
 aws s3api get-bucket-acl --bucket <s3_bucket_for_cloudtrail> --query 'Grants[?Grantee.URI== `https://acs.amazonaws.com/groups/global/AllUsers` ]'

```



3. Ensure the `AuthenticatedUsers` principal is not granted privileges to that `<bucket>`:


```
 aws s3api get-bucket-acl --bucket <s3_bucket_for_cloudtrail> --query 'Grants[?Grantee.URI== `https://acs.amazonaws.com/groups/global/Authenticated Users`]'

```



4. Get the S3 Bucket Policy


```
 aws s3api get-bucket-policy --bucket <s3_bucket_for_cloudtrail>

```



5. Ensure the policy does not contain a `Statement` having an `Effect` set to `Allow` and a `Principal` set to "*" or {"AWS": "*"}. Additionally, check to see whether a condition has been added to the bucket policy covering `aws:PrincipalOrgID`, as having this (in the StringEquals or StringEqualsIgnoreCase) would restrict access to only the named Org ID.

**Note:** Principal set to "*" or {"AWS": "*"}, without any conditions, allows anonymous access.

**Verification**

Evidence or test output indicates that the CloudTrail destination bucket(s) do not grant public access.


---

### 3.5.2 Ensure the Storage Container Storing the Activity Logs is not Publicly Accessible
**Platform:** Azure

**Rationale:** Allowing public access to activity log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.1.3

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Diagnostic Settings` in the left column.
3. In section `Storage Account`, note the name of the Storage account
4. Close `Diagnostic settings`. Close the `Monitor - Activity Log` blade.
5. In left menu, Click `Storage Accounts`
6. For each storage account, go to the `Configuration` setting
7. Check if Blob public access is `Disabled`.

**From Azure CLI**



1. Get storage account id configured with Diagnostic Settings:


```
az monitor diagnostic-settings subscription list --subscription $subscription.Id --query 'value[*].storageAccountId'

```



2. Ensure the container storing activity logs (insights-activity-logs) is not publicly accessible:


```
az storage container list --account-name <Storage Account Name> --query "[?name=='insights-activity-logs']"
```


If this command returns output and no errors, the storage account is publicly accessible.



3. Otherwise, list `Storage Account Keys` for the storage account.


```
az storage account keys list --resource-group <storage account resource group> --account-name <storage account name>

```



4. Use a key to determine if the `Container` is also publicly accessible (in the event the storage account is)


```
az storage container list --account-name <Storage Account Name> --query "[?name=='insights-activity-logs']" --sas-token "<base64 key value from step 3>"
```


Ensure `publicAccess` is set to `null` in the output of the command in step 4.

**From PowerShell**

Create a new storage account context with either a Storage-level SAS token with at least read/list permissions for Blob > Service, Container, Object.


```
$context = New-AzStorageContext -StorageAccountName <storage account name> -SasToken "<SAS token>"
```


Use the newly created storage account context to determine if the `insights-activity-logs` container is publicly accessible.


```
Get-AzStorageContainer -Context $context -name "insights-activity-logs"
```


Ensure `PublicAccess` is `empty` or set to `null`, `0`, or `off`.

**Verification**

Evidence or test output indicates that the Storage Container(s) containing activity logs does not grant public access.


---


## 3.6 Establish and Maintain a Secure Configuration Process
### Description

Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software.


### Audit


---

### 3.6.1 Ensure Any of the ASC Default Policy Settings are Not Set to 'Disabled'
**Platform:** Azure

**Rationale:** A security policy defines the desired configuration of your workloads and helps ensure compliance with company or regulatory security requirements. ASC Default policy is associated with every subscription by default. ASC default policy assignment is a set of security recommendations based on best practices. Enabling recommendations in ASC default policy ensures that Azure security center provides the ability to monitor all of the supported recommendations and optionally allow automated action for a few of the supported recommendations.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 2.1.14

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Microsoft Defender for Cloud`
3. Then `Environment Settings`
4. Select subscription
5. Then on `Security Policy` in the left column.
6. Click on `ASC Default` under `Default initiative`
7. Scroll down to `Policy Enforcement` and ensure it is set to `Enabled`
8. Click on the `Parameters` tab and uncheck `Only show parameters that need input or review`
9. Review the Parameters to ensure none of the items are set to Disabled.

The `View effective Policy` button can be used to see all effects of policies even if they have not been modified.

**From Azure CLI**

Ensure the `properties.enforcementMode` in the output of the below command is set to `Default`. If `properties.enforcementMode` is set to `DoNotEnforce`, the default policies are disabled and therefore out of compliance.


```
az account get-access-token --query "{<subscription:subscription>,<accessToken:accessToken>}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/<subscriptionID>/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn?api-version=2021-06-01'
```


**Note** policies that have not been modified will not be listed in this output

**From PowerShell**


```
Get-AzPolicyAssignment | Where-Object {$_.Name -eq 'SecurityCenterBuiltIn'} | Select-Object -ExpandProperty Properties
```


If the `EnforcementMode` value equals `Default` the ASC Default Policies are enabled. Because several of the policies are in the `Disabled` state by default, check to see if the `Parameters` attribute in the output of the above command contains policies with the value of `Disabled` or if it's empty altogether. If so, these settings are out of compliance. If none of the values in the `Parameters` attribute show `Disabled`, these settings are in compliance. If the `EnforcementMode` parameter equals `DoNotEnforce` the ASC Default Policies are all disabled and thus out of compliance.

**Verification**

Evidence or test output indicates that Azure Security Center Default Policy Settings are not disabled.


---


## 3.7 Perform Automated Operating System Patch Management


### Description

Perform operating system updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.


### Rationale

Patching remediates known vulnerabilities. Using automation makes this process routine and reduces the window of opportunity for attackers.


### Audit


---

### 3.7.1 Ensure that Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed'
**Platform:** Azure

**Rationale:** Windows and Linux virtual machines should be kept updated to:



* Address a specific bug or flaw
* Improve an OS or application’s general stability
* Fix a security vulnerability

The Azure Security Center retrieves a list of available security and critical updates from Windows Update or Windows Server Update Services (WSUS), depending on which service is configured on a Windows VM. The security center also checks for the latest updates in Linux systems. If a VM is missing a system update, the security center will recommend system updates be applied.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 2.1.13

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Microsoft Defender for Cloud`
3. Then the `Recommendations` blade
4. Ensure that there are no recommendations for `Apply system updates`

Alternatively, you can employ your own patch assessment and management tool to periodically assess, report and install the required security patches for your OS.

**Verification**

Evidence or test output indicates that there are no unpatched servers or virtual machines where patches for critical or high severity security vulnerabilities exist. An equivalent control may be used in environments where Microsoft Defender is not used.


---


## 3.8 Perform Automated Vulnerability Scans of Internal Enterprise Assets


### Description

Perform automated vulnerability scans of internal enterprise assets on a quarterly, or more frequent, basis. Conduct both authenticated and unauthenticated scans, using a SCAP-compliant vulnerability scanning tool.


### Rationale

Tools can help to identify vulnerabilities that require remediation.


### Audit


---

### 3.8.1 Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'
**Platform:** Azure

**Rationale:** When `Log Analytics agent for Azure VMs` is turned on, Microsoft Defender for Cloud provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created. The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 2.1.15

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Select `Microsoft Defender for Cloud`
3. Then `Environment Settings`
4. Select a subscription
5. Click on `Settings & Monitoring`
6. Ensure that `Log Analytics agent/Azure Monitor agent` is set to `On`

Repeat the above for any additional subscriptions.

**From Azure CLI**

Ensure the output of the below command is `On`


```
az account get-access-token --query "{subscription:subscription,accessToken:accessToken}" --out tsv | xargs -L1 bash -c 'curl -X GET -H "Authorization: Bearer $1" -H "Content-Type: application/json" https://management.azure.com/subscriptions/<subscriptionID>/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview' | jq '.|.value[] | select(.name=="default")'|jq '.properties.autoProvision'
```


**Using PowerShell**


```
Connect-AzAccount
Get-AzSecurityAutoProvisioningSetting
```


Ensure output for `Id Name AutoProvision` is `/subscriptions//providers/Microsoft.Security/autoProvisioningSettings/default default On`

**Verification**

Evidence or test output indicates that auto provisioning of the log analytics agent for Azure VMs is enabled.


---


## 3.9 Conduct Audit Log Reviews


### Description

Conduct reviews of audit logs to detect anomalies or abnormal events that could indicate a potential threat. Conduct reviews on a weekly, or more frequent, basis.


### Rationale

Logs may contain indications of compromise, so it's important to review logs regularly to detect and stop unauthorized or destructive actions from taking place in your systems.


### Audit


---

### 3.9.1 Ensure management console sign-in without MFA is monitored
**Platform:** AWS

**Rationale:** CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail Logs can also be sent to an external Security information and event management (SIEM) environment for monitoring and alerting.

Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA. These types of accounts are more susceptible to compromise and unauthorized access.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.2

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:



1. Identify the log group name configured for use with active multi-region CloudTrail:
   * List all `CloudTrails`:


   ```
   aws cloudtrail describe-trails

   ```



   * ` \
   `Identify Multi region Cloudtrails: `Trails with "IsMultiRegionTrail" set to true`
   * From value associated with CloudWatchLogsLogGroupArn note `<cloudtrail_log_group_name>`

   Example: for CloudWatchLogsLogGroupArn that looks like `arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*`, `<cloudtrail_log_group_name>` would be `NewGroup`



   * Ensure Identified Multi region `CloudTrail` is active


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   Ensure in the output that `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region 'Cloudtrail' captures all Management Events


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
   ```


   Ensure in the output there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`



2. Get a list of all associated metric filters for this `<cloudtrail_log_group_name>`:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the output from the above command contains the following:


   ```
   "filterPattern": "{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }"
   ```


   Or (To reduce false positives incase Single Sign-On (SSO) is used in organization):


   ```
   "filterPattern": "{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }"

   ```



4. ` \
`Note the `<no_mfa_console_signin_metric>` value associated with the `filterPattern` found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<no_mfa_console_signin_metric>` captured in step 4.


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<no_mfa_console_signin_metric>`]'

   ```



6. ` \
`Note the `AlarmActions` value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic


```
aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
```


at least one subscription should have "SubscriptionArn" with valid aws ARN.


```
Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to console sign in without MFA.


---

### 3.9.2 Ensure usage of 'root' account is monitored
**Platform:** AWS

**Rationale:** Monitoring for 'root' account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it.

Cloud Watch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail Logs can also be sent to an external Security information and event management (SIEM) environment for monitoring and alerting.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.3

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:



1. Identify the log group name configured for use with active multi-region CloudTrail:
   * List all CloudTrails:


   ```
   aws cloudtrail describe-trails

   ```



   * Identify Multi region Cloudtrails: `Trails with "IsMultiRegionTrail" set to true`
   * From value associated with CloudWatchLogsLogGroupArn note `<cloudtrail_log_group_name>`

   Example: for CloudWatchLogsLogGroupArn that looks like `arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*`, `<cloudtrail_log_group_name>` would be `NewGroup`



   * Ensure Identified Multi region CloudTrail is active


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   ensure `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region Cloudtrail captures all Management Events


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
   ```


   Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`



2. Get a list of all associated metric filters for this `<cloudtrail_log_group_name>`:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the output from the above command contains the following:


   ```
   "filterPattern": "{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }"

   ```



4. ` \
`Note the `<root_usage_metric>` value associated with the `filterPattern` found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<root_usage_metric>` captured in step 4.


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<root_usage_metric>`]'

   ```



6. ` \
`Note the `AlarmActions` value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic


   ```
   aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
   ```


   at least one subscription should have "SubscriptionArn" with valid aws ARN.


   ```
   Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
   ```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to use of the root account.


---

### 3.9.3 Ensure IAM policy changes are monitored
**Platform:** AWS

**Rationale:** CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail Logs can also be sent to an external Security information and event management (SIEM) environment for monitoring and alerting.

Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.4

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:



1. Identify the log group name configured for use with active multi-region CloudTrail:
   * List all CloudTrails:


   ```
   aws cloudtrail describe-trails

   ```



   * Identify Multi region Cloudtrails: `Trails with "IsMultiRegionTrail" set to true`
   * From value associated with CloudWatchLogsLogGroupArn note `<cloudtrail_log_group_name>`

   Example: for CloudWatchLogsLogGroupArn that looks like `arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*`, `<cloudtrail_log_group_name>` would be `NewGroup`



   * Ensure Identified Multi region CloudTrail is active


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   ensure `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region Cloudtrail captures all Management Events


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
   ```


   Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`



2. Get a list of all associated metric filters for this `<cloudtrail_log_group_name>`:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the output from the above command contains the following:


   ```
   "filterPattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"

   ```



4. ` \
`Note the `<iam_changes_metric>` value associated with the `filterPattern` found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<iam_changes_metric>` captured in step 4.


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<iam_changes_metric>`]'

   ```



6. ` \
`Note the `AlarmActions` value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic


   ```
   aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
   ```


   at least one subscription should have "SubscriptionArn" with valid aws ARN.


   ```
   Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
   ```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to IAM policy changes.


---

### 3.9.4 Ensure CloudTrail configuration changes are monitored
**Platform:** AWS

**Rationale:** Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.5

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured, or that the filters are configured in the appropriate SIEM alerts:



1. Identify the log group name configured for use with active multi-region CloudTrail:
   * List all CloudTrails: `aws cloudtrail describe-trails`
   * Identify Multi region Cloudtrails: `Trails with "IsMultiRegionTrail" set to true`
   * From value associated with CloudWatchLogsLogGroupArn note `<cloudtrail_log_group_name>`

   Example: for CloudWatchLogsLogGroupArn that looks like `arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*`, `<cloudtrail_log_group_name>` would be `NewGroup`



   * Ensure Identified Multi region CloudTrail is active


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   ensure `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region Cloudtrail captures all Management Events


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
   ```


   Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`



2. Get a list of all associated metric filters for this `<cloudtrail_log_group_name>`:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the filterPattern output from the above command contains the following:


   ```
   "filterPattern": "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"

   ```



4. ` \
`Note the `<cloudtrail_cfg_changes_metric>` value associated with the `filterPattern` found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<cloudtrail_cfg_changes_metric>` captured in step 4.


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<cloudtrail_cfg_changes_metric>`]'

   ```



6. ` \
`Note the `AlarmActions` value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic


   ```
   aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
   ```


   at least one subscription should have "SubscriptionArn" with valid aws ARN.


   ```
   Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
   ```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to CloudTrail configuration changes.


---

### 3.9.5 Ensure S3 bucket policy changes are monitored
**Platform:** AWS

**Rationale:** CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail Logs can also be sent to an external Security information and event management (SIEM) environment for monitoring and alerting.

Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.8

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:



1. Identify the log group name configured for use with active multi-region CloudTrail:
   * List all CloudTrails: `aws cloudtrail describe-trails`
   * Identify Multi region Cloudtrails: `Trails with "IsMultiRegionTrail" set to true`
   * From value associated with CloudWatchLogsLogGroupArn note `<cloudtrail_log_group_name>`

   Example: for CloudWatchLogsLogGroupArn that looks like `arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*`, `<cloudtrail_log_group_name>` would be `NewGroup`



   * Ensure Identified Multi region CloudTrail is active


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   ensure `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region Cloudtrail captures all Management Events


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
   ```


   Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`



2. Get a list of all associated metric filters for this `<cloudtrail_log_group_name>`:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the output from the above command contains the following:


   ```
   "filterPattern": "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"

   ```



4. ` \
`Note the `<s3_bucket_policy_changes_metric>` value associated with the `filterPattern` found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<s3_bucket_policy_changes_metric>` captured in step 4.


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<s3_bucket_policy_changes_metric>`]'

   ```



6. ` \
`Note the `AlarmActions` value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic


   ```
   aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
   ```


   at least one subscription should have "SubscriptionArn" with valid aws ARN.


   ```
   Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
   ```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to S3 bucket policy changes.


---

### 3.9.6 Ensure changes to network gateways are monitored
**Platform:** AWS

**Rationale:** CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail Logs can also be sent to an external Security information and event management (SIEM) environment for monitoring and alerting.

Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.12

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:



1. Identify the log group name configured for use with active multi-region CloudTrail:
   * List all CloudTrails: `aws cloudtrail describe-trails`
   * Identify Multi region Cloudtrails: `Trails with "IsMultiRegionTrail" set to true`
   * From value associated with CloudWatchLogsLogGroupArn note `<cloudtrail_log_group_name>`

   Example: for CloudWatchLogsLogGroupArn that looks like `arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*`, `<cloudtrail_log_group_name>` would be `NewGroup`



   * Ensure Identified Multi region CloudTrail is active


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   ensure `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region Cloudtrail captures all Management Events


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
   ```


   Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`



2. Get a list of all associated metric filters for this `<cloudtrail_log_group_name>`:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the output from the above command contains the following:


   ```
   "filterPattern": "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"

   ```



4. ` \
`Note the `<network_gw_changes_metric>` value associated with the `filterPattern` found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<network_gw_changes_metric>` captured in step 4.


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<network_gw_changes_metric>`]'

   ```



6. ` \
`Note the `AlarmActions` value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic


   ```
   aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
   ```


   at least one subscription should have "SubscriptionArn" with valid aws ARN.


   ```
   Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
   ```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to Network Gateway changes.


---

### 3.9.7 Ensure route table changes are monitored
**Platform:** AWS

**Rationale:** CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail Logs can also be sent to an external Security information and event management (SIEM) environment for monitoring and alerting.

Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path and prevent any accidental or intentional modifications that may lead to uncontrolled network traffic. An alarm should be triggered every time an AWS API call is performed to create, replace, delete, or disassociate a Route Table.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.13

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:



1. Identify the log group name configured for use with active multi-region CloudTrail:
   * List all CloudTrails: `aws cloudtrail describe-trails`
   * Identify Multi region Cloudtrails: `Trails with "IsMultiRegionTrail" set to true`
   * From value associated with CloudWatchLogsLogGroupArn note `<cloudtrail_log_group_name>`

   Example: for CloudWatchLogsLogGroupArn that looks like `arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*`, `<cloudtrail_log_group_name>` would be `NewGroup`



   * Ensure Identified Multi region CloudTrail is active


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   ensure `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region Cloudtrail captures all Management Events


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
   ```


   Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`



2. Get a list of all associated metric filters for this `<cloudtrail_log_group_name>`:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the output from the above command contains the following:


   ```
   "filterPattern": "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"

   ```



4. ` \
`Note the `<route_table_changes_metric>` value associated with the `filterPattern` found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<route_table_changes_metric>` captured in step 4.


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<route_table_changes_metric>`]'

   ```



6. ` \
`Note the `AlarmActions` value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic

   ```
   aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
   ```


   at least one subscription should have "SubscriptionArn" with valid aws ARN.


   ```
   Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
   ```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to route table changes.


---

### 3.9.8 Ensure VPC changes are monitored
**Platform:** AWS

**Rationale:** CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail Logs can also be sent to an external Security information and event management (SIEM) environment for monitoring and alerting.

VPCs in AWS are logically isolated virtual networks that can be used to launch AWS resources. Monitoring changes to VPC configuration will help ensure VPC traffic flow is not getting impacted. Changes to VPCs can impact network accessibility from the public internet and additionally impact VPC traffic flow to and from resources launched in the VPC.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.14

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following to ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:



1. Identify the log group name configured for use with active multi-region CloudTrail:
   * List all CloudTrails: `aws cloudtrail describe-trails`
   * Identify Multi region Cloudtrails: `Trails with "IsMultiRegionTrail" set to true`
   * From value associated with CloudWatchLogsLogGroupArn note `<cloudtrail_log_group_name>`

   Example: for CloudWatchLogsLogGroupArn that looks like `arn:aws:logs:<region>:<aws_account_number>:log-group:NewGroup:*`, `<cloudtrail_log_group_name>` would be `NewGroup`



   * Ensure Identified Multi region CloudTrail is active


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   ensure `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region Cloudtrail captures all Management Events


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
   ```


   Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`



2. Get a list of all associated metric filters for this `<cloudtrail_log_group_name>`:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the output from the above command contains the following:


   ```
   "filterPattern": "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"

   ```



4. ` \
`Note the `<vpc_changes_metric>` value associated with the `filterPattern` found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<vpc_changes_metric>` captured in step 4.


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<vpc_changes_metric>`]'

   ```



6. ` \
`Note the `AlarmActions` value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic


   ```
   aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
   ```


   at least one subscription should have "SubscriptionArn" with valid aws ARN.


   ```
   Example of valid "SubscriptionArn": "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
   ```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to vpc changes.


---

### 3.9.9 Ensure AWS Organizations changes are monitored
**Platform:** AWS

**Rationale:** CloudWatch is an AWS native service that allows you to observe and monitor resources and applications. CloudTrail Logs can also be sent to an external Security information and event management (SIEM) environment for monitoring and alerting.

Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches. This monitoring technique helps you to ensure that any unexpected changes performed within your AWS Organizations can be investigated and any unwanted changes can be rolled back.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 4.15

**Evidence**

If you are using CloudTrails and CloudWatch, perform the following:



1. Ensure that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured:
   * Identify the log group name configured for use with active multi-region CloudTrail:
   * List all CloudTrails:


   ```
   aws cloudtrail describe-trails

   ```



   * ` \
   `Identify Multi region Cloudtrails, Trails with `"IsMultiRegionTrail"` set to true
   * From value associated with CloudWatchLogsLogGroupArn note <cloudtrail_log_group_name> **Example:** for CloudWatchLogsLogGroupArn that looks like arn:aws:logs::<aws_account_number>:log-group:NewGroup:*, <cloudtrail_log_group_name> would be NewGroup
   * Ensure Identified Multi region CloudTrail is active:


   ```
   aws cloudtrail get-trail-status --name <Name of a Multi-region CloudTrail>
   ```


   Ensure `IsLogging` is set to `TRUE`



   * Ensure identified Multi-region Cloudtrail captures all Management Events:


   ```
   aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>

   ```



   * Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to true and `ReadWriteType` set to `All`.
2. Get a list of all associated metric filters for this <cloudtrail_log_group_name>:


   ```
   aws logs describe-metric-filters --log-group-name "<cloudtrail_log_group_name>"

   ```



3. Ensure the output from the above command contains the following:


   ```
   "filterPattern": "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }"

   ```



4. ` \
`Note the `<organizations_changes>` value associated with the filterPattern found in step 3.
5. Get a list of CloudWatch alarms and filter on the `<organizations_changes>` captured in step 4:


   ```
   aws cloudwatch describe-alarms --query 'MetricAlarms[?MetricName== `<organizations_changes>`]'

   ```



6. ` \
`Note the AlarmActions value - this will provide the SNS topic ARN value.
7. Ensure there is at least one active subscriber to the SNS topic:


   ```
   aws sns list-subscriptions-by-topic --topic-arn <sns_topic_arn>
   ```


   at least one subscription should have "SubscriptionArn" with valid aws ARN. Example of valid "SubscriptionArn":


   ```
   "arn:aws:sns:<region>:<aws_account_number>:<SnsTopicName>:<SubscriptionID>"
   ```


**Verification**

Evidence or test output indicates that there is at least one active multi-region CloudTrail with prescribed metric filters and alarms configured related to changes to AWS organizations.


---

### 3.9.10 Ensure That Cloud Audit Logging Is Configured Properly
**Platform:** Google

**Rationale:** Cloud Audit Logging maintains two audit logs for each project, folder, and organization: Admin Activity and Data Access.



1. Admin Activity logs contain log entries for API calls or other administrative actions that modify the configuration or metadata of resources. Admin Activity audit logs are enabled for all services and cannot be configured.
2. Data Access audit logs record API calls that create, modify, or read user-provided data. These are disabled by default and should be enabled.

There are three kinds of Data Access audit log information:



* Admin read: Records operations that read metadata or configuration information. Admin Activity audit logs record writes of metadata and configuration information that cannot be disabled.
* Data read: Records operations that read user-provided data.
* Data write: Records operations that write user-provided data.

It is recommended to have an effective default audit config configured in such a way that:



1. logtype is set to DATA_READ (to log user activity tracking) and DATA_WRITES (to log changes/tampering to user data).
2. audit config is enabled for all the services supported by the Data Access audit logs feature.
3. Logs should be captured for all users, i.e., there are no exempted users in any of the audit config sections. This will ensure overriding the audit config will not contradict the requirement.


**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 2.1

**Evidence**

**From Google Cloud Console**



1. Go to `Audit Logs` by visiting [https://console.cloud.google.com/iam-admin/audit](https://console.cloud.google.com/iam-admin/audit).
2. Ensure that Admin Read, Data Write, and Data Read are enabled for all Google Cloud services and that no exemptions are allowed.

**From Google Cloud CLI**



1. List the Identity and Access Management (IAM) policies for the project, folder, or organization:


```
gcloud organizations get-iam-policy ORGANIZATION_ID
gcloud resource-manager folders get-iam-policy FOLDER_ID
gcloud projects get-iam-policy PROJECT_ID

```



2. Policy should have a default auditConfigs section which has the logtype set to DATA_WRITES and DATA_READ for all services. Note that projects inherit settings from folders, which in turn inherit settings from the organization. When called, projects get-iam-policy, the result shows only the policies set in the project, not the policies inherited from the parent folder or organization. Nevertheless, if the parent folder has Cloud Audit Logging enabled, the project does as well.

Sample output for default audit configs may look like this:


```
 auditConfigs:
 - auditLogConfigs:
 - logType: ADMIN_READ
 - logType: DATA_WRITE
 - logType: DATA_READ
 service: allServices

```



3. Any of the auditConfigs sections should not have parameter "exemptedMembers:" set, which will ensure that Logging is enabled for all users and no user is exempted.

**Verification**

Evidence or test output indicates that cloud audit logging is enabled comprehensively.


---

### 3.9.11 Ensure That Cloud DNS Logging Is Enabled for All VPC Networks
**Platform:** Google

**Rationale:** Security monitoring and forensics cannot depend solely on IP addresses from VPC flow logs, especially when considering the dynamic IP usage of cloud resources, HTTP virtual host routing, and other technology that can obscure the DNS name used by a client from the IP address. Monitoring of Cloud DNS logs provides visibility to DNS names requested by the clients within the VPC. These logs can be monitored for anomalous domain names, evaluated against threat intelligence, and

Note: For full capture of DNS, firewall must block egress UDP/53 (DNS) and TCP/443 (DNS over HTTPS) to prevent client from using external DNS name server for resolution.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 2.12

**Evidence**

**From Google Cloud CLI**



1. List all VPCs networks in a project:


```
gcloud compute networks list --format="table[box,title='All VPC Networks'](name:label='VPC Network Name')"

```



2. List all DNS policies, logging enablement, and associated VPC networks:


```
gcloud dns policies list --flatten="networks[]" --format="table[box,title='All DNS Policies By VPC Network'](name:label='Policy Name',enableLogging:label='Logging Enabled':align=center,networks.networkUrl.basename():label='VPC Network Name')"
```


Each VPC Network should be associated with a DNS policy with logging enabled.

**Verification**
 Evidence or test output indicates that cloud DNS logging is enabled for all critical VPC networks, meaning any VPC network that is used to process confidential data.


---


## 3.10 Collect Audit Logs
### Description

Collect audit logs. Ensure that logging, per the enterprise’s audit log management process, has been enabled across enterprise assets.


### Rationale

Having log files of what actions have taken place by users and also system events is fundamental to being able to detect security events.


### Audit


---

### 3.10.1 Ensure That Sinks Are Configured for All Log Entries
**Platform:** Google

**Rationale:** Log entries are held in Cloud Logging. To aggregate logs, export them to a SIEM. To keep them longer, it is recommended to set up a log sink. Exporting involves writing a filter that selects the log entries to export, and choosing a destination in Cloud Storage, BigQuery, or Cloud Pub/Sub. The filter and destination are held in an object called a sink. To ensure all log entries are exported to sinks, ensure that there is no filter configured for a sink. Sinks can be created in projects, organizations, folders, and billing accounts.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 2.2

**Evidence**

**From Google Cloud Console**



1. Go to `Logs Router` by visiting [https://console.cloud.google.com/logs/router](https://console.cloud.google.com/logs/router).
2. For every sink, click the 3-dot button for Menu options and select `View sink details`.
3. Ensure there is at least one sink with an `empty` Inclusion filter.
4. Additionally, ensure that the resource configured as `Destination` exists.

**From Google Cloud CLI**



1. Ensure that a sink with an `empty filter` exists. List the sinks for the project, folder or organization. If sinks are configured at a folder or organization level, they do not need to be configured for each project:


```
gcloud logging sinks list --folder=FOLDER_ID | --organization=ORGANIZATION_ID | --project=PROJECT_ID
```


The output should list at least one sink with an `empty filter`.



2. Additionally, ensure that the resource configured as `Destination` exists.

See [https://cloud.google.com/sdk/gcloud/reference/beta/logging/sinks/list](https://cloud.google.com/sdk/gcloud/reference/beta/logging/sinks/list) for more information.

**Verification**

Evidence or test output indicates that log sinks are configured for all log entries where required to satisfy the organization's log retention period.


---

### 3.10.2 Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes
**Platform:** Google

**Rationale:** Project ownership has the highest level of privileges on a project. To avoid misuse of project resources, the project ownership assignment/change actions mentioned above should be monitored and alerted to concerned recipients.



* Sending project ownership invites
* Acceptance/Rejection of project ownership invite by user
* Adding `role\Owner` to a user/service-account
* Removing a user/Service account from `role\Owner`

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 2.4

**Evidence**

**From Google Cloud Console**

**Ensure that the prescribed log metric is present:**



1. Go to `Logging/Log-based Metrics` by visiting [https://console.cloud.google.com/logs/metrics](https://console.cloud.google.com/logs/metrics).
2. In the `User-defined Metrics` section, ensure that at least one metric `<Log_Metric_Name>` is present with filter text:


```
(protoPayload.serviceName="cloudresourcemanager.googleapis.com")
AND (ProjectOwnership OR projectOwnerInvitee)
OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE"
AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
```


**Ensure that the prescribed Alerting Policy is present:**



1. Go to `Alerting` by visiting [https://console.cloud.google.com/monitoring/alerting](https://console.cloud.google.com/monitoring/alerting).
2. Under the `Policies` section, ensure that at least one alert policy exists for the log metric above. Clicking on the policy should show that it is configured with a condition. For example, `Violates when: Any logging.googleapis.com/user/<Log Metric Name> stream` `is above a threshold of zero(0) for greater than zero(0) seconds` means that the alert will trigger for any new owner change. Verify that the chosen alerting thresholds make sense for your organization.
3. Ensure that the appropriate notifications channels have been set up.

**From Google Cloud CLI**

**Ensure that the prescribed log metric is present:**



1. List the log metrics:


```
gcloud logging metrics list --format json

```



2. Ensure that the output contains at least one metric with filter set to:


```
(protoPayload.serviceName="cloudresourcemanager.googleapis.com")
AND (ProjectOwnership OR projectOwnerInvitee)
OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE"
AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")

```



3. Note the value of the property `metricDescriptor.type` for the identified metric, in the format `logging.googleapis.com/user/<Log Metric Name>`.

**Ensure that the prescribed alerting policy is present:**



1. List the alerting policies:


```
gcloud alpha monitoring policies list --format json

```



2. Ensure that the output contains an least one alert policy where:
   * `conditions.conditionThreshold.filter` is set to `metric.type=\"logging.googleapis.com/user/<Log Metric Name>\"`
   * AND `enabled` is set to `true`

**Verification**

Evidence or test output indicates that log metric filter(s) and alert(s) exist for project ownership assignments and changes.


---

### 3.10.3 Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes
**Platform:** Google

**Rationale:** Admin activity and data access logs produced by cloud audit logging enable security analysis, resource change tracking, and compliance auditing.

Configuring the metric filter and alerts for audit configuration changes ensures the recommended state of audit configuration is maintained so that all activities in the project are audit-able at any point in time.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 2.5

**Evidence**

**From Google Cloud Console**

**Ensure the prescribed log metric is present:**



1. Go to `Logging/Logs-based Metrics` by visiting [https://console.cloud.google.com/logs/metrics](https://console.cloud.google.com/logs/metrics).
2. In the `User-defined Metrics` section, ensure that at least one metric `<Log_Metric_Name>` is present with the filter text:


```
protoPayload.methodName="SetIamPolicy" AND
protoPayload.serviceData.policyDelta.auditConfigDeltas:*
```


**Ensure that the prescribed alerting policy is present:**



1. Go to `Alerting` by visiting [https://console.cloud.google.com/monitoring/alerting](https://console.cloud.google.com/monitoring/alerting).
2. Under the `Policies` section, ensure that at least one alert policy exists for the log metric above. Clicking on the policy should show that it is configured with a condition. For example, `Violates when: Any logging.googleapis.com/user/<Log Metric Name> stream` `is above a threshold of 0 for greater than zero(0) seconds`, means that the alert will trigger for any new owner change. Verify that the chosen alerting thresholds make sense for the user's organization.
3. Ensure that appropriate notification channels have been set up.

**From Google Cloud CLI**

**Ensure that the prescribed log metric is present:**



1. List the log metrics:


```
gcloud beta logging metrics list --format json

```



2. Ensure that the output contains at least one metric with the filter set to:


```
protoPayload.methodName="SetIamPolicy" AND
protoPayload.serviceData.policyDelta.auditConfigDeltas:*

```



1. Note the value of the property `metricDescriptor.type` for the identified metric, in the format `logging.googleapis.com/user/<Log Metric Name>`.

**Ensure that the prescribed alerting policy is present:**



1. List the alerting policies:


```
gcloud alpha monitoring policies list --format json

```



2. Ensure that the output contains at least one alert policy where:
   * `conditions.conditionThreshold.filter` is set to `metric.type=\"logging.googleapis.com/user/<Log Metric Name>\"`
   * AND `enabled` is set to `true`

**Verification**

Evidence or test output indicates that log metric filter(s) and alert(s) exist for audit configuration changes.


---

### 3.10.4 Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes
**Platform:** Google

**Rationale:** Google Cloud IAM provides predefined roles that give granular access to specific Google Cloud Platform resources and prevent unwanted access to other resources. However, to cater to organization-specific needs, Cloud IAM also provides the ability to create custom roles. Project owners and administrators with the Organization Role Administrator role or the IAM Role Administrator role can create custom roles. Monitoring role creation, deletion and updating activities will help in identifying any over-privileged role at early stages.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 2.6

**Evidence**

**From Console:**

**Ensure that the prescribed log metric is present:**



1. Go to `Logging/Logs-based Metrics` by visiting [https://console.cloud.google.com/logs/metrics](https://console.cloud.google.com/logs/metrics).
2. In the `User-defined Metrics` section, ensure that at least one metric `<Log_Metric_Name>` is present with filter text:


```
resource.type="iam_role"
AND (protoPayload.methodName="google.iam.admin.v1.CreateRole"
OR protoPayload.methodName="google.iam.admin.v1.DeleteRole"
OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")
```


**Ensure that the prescribed alerting policy is present:**



1. Go to `Alerting` by visiting [https://console.cloud.google.com/monitoring/alerting](https://console.cloud.google.com/monitoring/alerting).
2. Under the `Policies` section, ensure that at least one alert policy exists for the log metric above. Clicking on the policy should show that it is configured with a condition. For example, `Violates when: Any logging.googleapis.com/user/<Log Metric Name> stream` `is above a threshold of zero(0) for greater than zero(0) seconds` means that the alert will trigger for any new owner change. Verify that the chosen alerting thresholds make sense for the user's organization.
3. Ensure that the appropriate notifications channels have been set up.

**From Google Cloud CLI**

Ensure that the prescribed log metric is present:



1. List the log metrics:


```
gcloud logging metrics list --format json

```



2. Ensure that the output contains at least one metric with the filter set to:


```
resource.type="iam_role"
AND (protoPayload.methodName = "google.iam.admin.v1.CreateRole" OR
protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR
protoPayload.methodName="google.iam.admin.v1.UpdateRole")

```



3. Note the value of the property `metricDescriptor.type` for the identified metric, in the format `logging.googleapis.com/user/<Log Metric Name>`.

**Ensure that the prescribed alerting policy is present:**



1. List the alerting policies:


```
gcloud alpha monitoring policies list --format json

```



2. Ensure that the output contains an least one alert policy where:
   * `conditions.conditionThreshold.filter` is set to `metric.type=\"logging.googleapis.com/user/<Log Metric Name>\"`
   * AND `enabled` is set to `true`.

**Verification**

Evidence or test output indicates that log metric filter(s) and alert(s) exist for custom role changes.


---


## 3.11 Collect Detailed Audit Logs
### Description

Configure detailed audit logging for enterprise assets containing sensitive data. Include event source, date, username, timestamp, source addresses, destination addresses, and other useful elements that could assist in a forensic investigation.


### Rationale

Detailed logs with timestamps provide a record of user activity, system events, and application actions. This allows administrators to identify suspicious activity, potential security breaches, and unauthorized access attempts.


### Audit


---

### 3.11.1 Ensure CloudTrail is enabled in all regions
**Platform:** AWS

**Rationale:** The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing. Additionally,



* ensuring that a multi-regions trail exists will ensure that unexpected activity occurring in otherwise unused regions is detected
* ensuring that a multi-regions trail exists will ensure that `Global Service Logging` is enabled for a trail by default to capture recording of events generated on AWS global services
* for a multi-regions trail, ensuring that management events configured for all types of Read/Writes ensures recording of management operations that are performed on all resources in an AWS account.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 3.1

**Evidence**

Perform the following to determine if CloudTrail is enabled for all regions:

**From Console:**



1. Sign in to the AWS Management Console and open the CloudTrail console at [https://console.aws.amazon.com/cloudtrail](https://console.aws.amazon.com/cloudtrail)
2. Click on `Trails` on the left navigation pane
* You will be presented with a list of trails across all regions
1. Ensure at least one Trail has `All` specified in the `Region` column
2. Click on a trail via the link in the _Name_ column
3. Ensure `Logging` is set to `ON`
4. Ensure `Apply trail to all regions` is set to `Yes`
5. In section `Management Events` ensure `Read/Write Events` set to `ALL`

**From Command Line:**


```
 aws cloudtrail describe-trails
```


Ensure `IsMultiRegionTrail` is set to `true`


```
aws cloudtrail get-trail-status --name <trailname shown in describe-trails>
```


Ensure `IsLogging` is set to `true`


```
aws cloudtrail get-event-selectors --trail-name <trailname shown in describe-trails>
```


Ensure there is at least one Event Selector for a Trail with `IncludeManagementEvents` set to `true` and `ReadWriteType` set to `All`

**Verification**

Evidence or test output indicates that CloudTrail is enabled in all regions.


---

### 3.11.2 Ensure CloudTrail trails are integrated with CloudWatch Logs
**Platform:** AWS

**Rationale:** Sending CloudTrail logs to CloudWatch Logs will facilitate real-time and historic activity logging based on user, API, resource, and IP address, and provides opportunity to establish alarms and notifications for anomalous or sensitive account activity.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 3.4

**Evidence**

Perform the following to ensure CloudTrail is configured as prescribed:

**From Console:**



1. Login to the CloudTrail console at `https://console.aws.amazon.com/cloudtrail/`
2. Under `Trails` , click on the CloudTrail you wish to evaluate
3. Under the `CloudWatch Logs` section.
4. Ensure a `CloudWatch Logs` log group is configured and listed.
5. Under `General details` confirm `Last log file delivered` has a recent (~one day old) timestamp.

**From Command Line:**



1. Run the following command to get a listing of existing trails:


```
 aws cloudtrail describe-trails

```



2. Ensure `CloudWatchLogsLogGroupArn` is not empty and note the value of the `Name` property.
3. Using the noted value of the `Name` property, run the following command:


```
 aws cloudtrail get-trail-status --name <trail_name>

```



4. Ensure the `LatestcloudwatchLogdDeliveryTime` property is set to a recent (~one day old) timestamp.

If the `CloudWatch Logs` log group is not set up and the delivery time is not recent refer to the remediation in the CIS Benchmark.

**Verification**

Evidence or test output indicates that CloudTrail trails are integrated with CloudWatch logs.


---

### 3.11.3 Ensure that Azure Monitor Resource Logging is Enabled for All Services that Manage, Store, or Secure Sensitive Data
**Platform:** Azure

**Rationale:** A lack of monitoring reduces the visibility into the data plane, and therefore an organization's ability to detect reconnaissance, authorization attempts or other malicious activity. Unlike Activity Logs, Resource Logs are not enabled by default. Specifically, without monitoring it would be impossible to tell which entities had accessed a data store that was breached. In addition, alerts for failed attempts to access APIs for Web Services or Databases are only possible when logging is enabled.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.4

**Evidence**

**From Azure Portal**

The specific steps for configuring resources within the Azure console vary depending on resource, but typically the steps are:



1. Go to the resource
2. Click on Diagnostic settings
3. In the blade that appears, click "Add diagnostic setting"
4. Configure the diagnostic settings
5. Click on Save

**From Azure CLI**

List all `resources` for a `subscription`


```
az resource list --subscription <subscription id>
```


For each `resource` run the following


```
az monitor diagnostic-settings list --resource <resource ID>
```


An empty result means that no `diagnostic settings` are configured for that resource. An error message means that the configured `diagnostic settings` are not supported for that resource.

**From PowerShell**

Get a list of `resources` in a `subscription` context and store in a variable


```
$resources = Get-AzResource
```


Loop through each `resource` to determine if a diagnostic setting is configured or not.


```
foreach ($resource in $resources) {$diagnosticSetting = Get-AzDiagnosticSetting -ResourceId $resource.id -ErrorAction "SilentlyContinue"; if ([string]::IsNullOrEmpty($diagnosticSetting)) {$message = "Diagnostic Settings not configured for resource: " + $resource.Name;Write-Output $message}else{$diagnosticSetting}}
```


A result of `Diagnostic Settings not configured for resource: <resource name>` means  that no `diagnostic settings` are configured for that resource. Otherwise, the output of the above command will show configured `Diagnostic Settings` for a resource.

**Verification**

Evidence or test output indicates that Azure Monitor Resource Logging is enabled for all services that support it.


---

### 3.11.4 Ensure that logging for Azure Key Vault is 'Enabled'
**Platform:** Azure

**Rationale:** Monitoring how and when key vaults are accessed, and by whom, enables an audit trail of interactions with confidential information, keys, and certificates managed by Azure Keyvault. Enabling logging for Key Vault saves information in an Azure storage account which the user provides. This creates a new container named insights-logs-auditevent automatically for the specified storage account. This same storage account can be used for collecting logs for multiple key vaults.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.1.5

**Evidence**

**From Azure Portal**



1. Go to `Key vaults`
2. For each Key vault
3. Go to `Diagnostic settings`
4. Click on `Edit Settings`
5. Ensure that `Archive to a storage account` is `Enabled`
6. Ensure that `AuditEvent` is checked, and the retention days is set to `180 days` or as appropriate

**From Azure CLI**

List all key vaults


```
az keyvault list
```


For each keyvault `id`


```
az monitor diagnostic-settings list --resource <id>
```


Ensure that `storageAccountId` is set as appropriate. Also, ensure that `category` and `days` are set. One of the sample outputs is as below.


```
"logs": [
 {
 "category": "AuditEvent",
 "enabled": true,
 "retentionPolicy": {
 "days": 180,
 "enabled": true
 }
 }
 ]
```


**From PowerShell**

List the key vault(s) in the subscription


```
Get-AzKeyVault
```


For each key vault, run the following:


```
Get-AzDiagnosticSetting -ResourceId <key vault resource ID>
```


Ensure that `StorageAccountId`, `ServiceBusRuleId`, `MarketplacePartnerId`, or `WorkspaceId` is set as appropriate. Also, ensure that `enabled` is set to `true`, and that `category` and `days` are set under the `Log` heading.

**Verification**

Evidence or test output indicates that logging for Azure Key Vault is enabled.


---

### 3.11.5 Ensure that Activity Log Alert exists for Create Policy Assignment
**Platform:** Azure

**Rationale:** Monitoring for create policy assignment events gives insight into changes done in "Azure policy - assignments" and can reduce the time it takes to detect unsolicited changes.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.1

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **<code>Operation name=Microsoft.Authorization/policyAssignments/write</code></strong>
5. Click on the Alert <code>Name</code> associated with the previous step
6. Click on the Condition name of <strong><code>Whenever the Activity Log has an event with Category='Administrative', Signal name='Create policy assignment (policyAssignments)</code></strong>
7. In the Configure signal logic window, ensure the following is configured:
* Event level: <code>All selected</code>
* Status: <code>All selected</code>
* Event initiated by: <code>* (All services and users)</code>
1. Click <code>Done</code>
2. Back in the < Alert Name > window, review <code>Actions</code> to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

<strong>From Azure CLI</strong>


```
az monitor activity-log alert list --subscription <subscription ID> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Authorization/policyAssignments/write` in the output. If it's missing, generate a finding.

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Authorization/policyAssignments/write"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


If the output is empty, an `alert rule` for `Create Policy Assignments` is not configured.

**Verification**

Evidence or test output indicates that an activity log alert exists for Create Policy Assignment.


---

### 3.11.6 Ensure that Activity Log Alert exists for Delete Policy Assignment
**Platform:** Azure

**Rationale:** Monitoring for delete policy assignment events gives insight into changes done in "azure policy - assignments" and can reduce the time it takes to detect unsolicited changes.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.2

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Authorization/policyAssignments/delete`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete policy assignment (policyAssignments)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review `Actions` to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription ID> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Authorization/policyAssignments/delete` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Authorization/policyAssignments/delete"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Delete Policy Assignment


---

### 3.11.7 Ensure that Activity Log Alert exists for Create or Update Network Security Group
**Platform:** Azure

**Rationale:** Monitoring for Create or Update Network Security Group events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.3

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Network/networkSecurityGroups/write`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Administrative', Signal name='Create or Update Network Security Group (networkSecurityGroups)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected<`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review `Actions` to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription ID> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Network/networkSecurityGroups/write` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Network/networkSecurityGroups/write"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Create or Update Network Security Group


---

### 3.11.8 Ensure that Activity Log Alert exists for Delete Network Security Group
**Platform:** Azure

**Rationale:** Monitoring for "Delete Network Security Group" events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.4

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Network/networkSecurityGroups/delete`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete Network Security Group (networkSecurityGroups)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review `Actions` to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription ID> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Network/networkSecurityGroups/delete` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Network/networkSecurityGroups/delete"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Delete Network Security Group


---

### 3.11.9 Ensure that Activity Log Alert exists for Create or Update Security Solution
**Platform:** Azure

**Rationale:** Monitoring for Create or Update Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.5

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Security/securitySolutions/write`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Security', Signal name='Create or Update Security Solutions (securitySolutions)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review `Actions` to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription Id> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Security/securitySolutions/write` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Security/securitySolutions/write"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Create or Update Security Solution


---

### 3.11.10 Ensure that Activity Log Alert exists for Delete Security Solution
**Platform:** Azure

**Rationale:** Monitoring for Delete Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.6

**Evidence**

**From Azure Console**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Security/securitySolutions/delete`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Security', Signal name='Delete Security Solutions (securitySolutions)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review `Actions` to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription Id> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Security/securitySolutions/delete` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Security/securitySolutions/delete"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Delete Security Solution


---

### 3.11.11 Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule
**Platform:** Azure

**Rationale:** Monitoring for Create or Update SQL Server Firewall Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.7

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Sql/servers/firewallRules/write`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Administrative', Signal name='Create/Update server firewall rule (servers/firewallRules)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review `Actions` to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription Id> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Sql/servers/firewallRules/write` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Sql/servers/firewallRules/write"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Create or Update SQL Server Firewall Rule


---

### 3.11.12 Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule
**Platform:** Azure

**Rationale:** Monitoring for Delete SQL Server Firewall Rule events gives insight into SQL network access changes and may reduce the time it takes to detect suspicious activity.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.8

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Sql/servers/firewallRules/delete`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete server firewall rule (servers/firewallRules)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review <code>Actions</code> to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription Id> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Sql/servers/firewallRules/delete` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Sql/servers/firewallRules/delete"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Delete SQL Server Firewall Rule


---

### 3.11.13 Ensure that Activity Log Alert exists for Create or Update Public IP Address rule
**Platform:** Azure

**Rationale:** Monitoring for Create or Update Public IP Address events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.9

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Network/publicIPAddresses/write`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Administrative', Signal name='Create or Update Public Ip Address (publicIPAddresses)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review `Actions` to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription Id> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Network/publicIPAddresses/write` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Network/publicIPAddresses/write"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Create or Update Public IP Address Rule


---

### 3.11.14 Ensure that Activity Log Alert exists for Delete Public IP Address rule
**Platform:** Azure

**Rationale:** Monitoring for Delete Public IP Address events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 5.2.10

**Evidence**

**From Azure Portal**



1. Navigate to the `Monitor` blade
2. Click on `Alerts`
3. In the Alerts window, click on `Alert rules`
4. Hover mouse over the values in the Condition column to find an alert where **`Operation name=Microsoft.Network/publicIPAddresses/delete`**
5. Click on the Alert `Name` associated with the previous step
6. Click on the Condition name of **`Whenever the Activity Log has an event with Category='Administrative', Signal name='Delete Public Ip Address (Microsoft.Network/publicIPAddresses)'`**
7. In the Configure signal logic window, ensure the following is configured:
   * Event level: `All selected`
   * Status: `All selected`
   * Event initiated by: `* (All services and users)`
8. Click `Done`
9. Back in the < Alert Name > window, review `Actions` to ensure that an Action group is assigned to notify the appropriate personnel in your organization.

**From Azure CLI**


```
az monitor activity-log alert list --subscription <subscription Id> --query "[].{Name:name,Enabled:enabled,Condition:condition.allOf,Actions:actions}"
```


Look for `Microsoft.Network/publicIPAddresses/delete` in the output

**From PowerShell**


```
Get-AzActivityLogAlert -SubscriptionId <subscription ID>|where-object {$_.ConditionAllOf.Equal -match "Microsoft.Network/publicIPAddresses/delete"}|select-object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
```


**Verification**

Evidence or test output indicates that an activity log alert exists for Delete Public IP Address Rule


---


# 4 Networking


## 4.1 Encrypt Sensitive Data in Transit


### Description

Encrypt sensitive data in transit. Example implementations can include: Transport Layer Security (TLS) and Open Secure Shell (OpenSSH).


### Rationale

Encryption protects sensitive data when transmitted over untrusted network connections.


### Audit


---

### 4.1.1 Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites
**Platform:** Google

**Rationale:** Load balancers are used to efficiently distribute traffic across multiple servers. Both SSL proxy and HTTPS load balancers are external load balancers, meaning they distribute traffic from the Internet to a GCP network. GCP customers can configure load balancer SSL policies with a minimum TLS version (1.0, 1.1, or 1.2) that clients can use to establish a connection, along with a profile (Compatible, Modern, Restricted, or Custom) that specifies permissible cipher suites. To comply with users using outdated protocols, GCP load balancers can be configured to permit insecure cipher suites. In fact, the GCP default SSL policy uses a minimum TLS version of 1.0 and a Compatible profile, which allows the widest range of insecure cipher suites. As a result, it is easy for customers to configure a load balancer without even knowing that they are permitting outdated cipher suites.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 3.9

**Evidence**

**From Google Cloud Console**



1. See all load balancers by visiting [https://console.cloud.google.com/net-services/loadbalancing/loadBalancers/list](https://console.cloud.google.com/net-services/loadbalancing/loadBalancers/list).
2. For each load balancer for `SSL (Proxy)` or `HTTPS`, click on its name to go to the `Load balancer details` page.
3. Ensure that each target proxy entry in the `Frontend` table has an `SSL Policy` configured.
4. Click on each SSL policy to go to its `SSL policy details` page.
5. Ensure that the SSL policy satisfies one of the following conditions:
   * has a `Min TLS` set to `TLS 1.2` and `Profile` set to `Modern` profile, or
   * has `Profile` set to `Restricted`. Note that a Restricted profile effectively requires clients to use TLS 1.2 regardless of the chosen minimum TLS version, or
   * has `Profile` set to `Custom` and the following features are all disabled:


```
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA
```


**From Google Cloud CLI**



1. List all TargetHttpsProxies and TargetSslProxies.


```
gcloud compute target-https-proxies list
gcloud compute target-ssl-proxies list

```



2. For each target proxy, list its properties:


```
gcloud compute target-https-proxies describe TARGET_HTTPS_PROXY_NAME
gcloud compute target-ssl-proxies describe TARGET_SSL_PROXY_NAME

```



3. Ensure that the `sslPolicy` field is present and identifies the name of the SSL policy:


```
sslPolicy: https://www.googleapis.com/compute/v1/projects/PROJECT_ID/global/sslPolicies/SSL_POLICY_NAME
```


If the `sslPolicy` field is missing from the configuration, it means that the GCP default policy is used, which is insecure.



4. Describe the SSL policy:


```
gcloud compute ssl-policies describe SSL_POLICY_NAME

```



5. Ensure that the policy satisfies one of the following conditions:
   * has `Profile` set to `Modern` and `minTlsVersion` set to `TLS_1_2`, or
   * has `Profile` set to `Restricted`, or
   * has `Profile` set to `Custom` and  `enabledFeatures` does not contain any of the following values:


```
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA
```


**Verification**

Evidence or test output indicates that no HTTPS or SSL Proxy load balancers permit any of the following weak cipher suites:


```
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA


---
```



## 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure
### Description

Establish and maintain a secure configuration process for network devices. Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software.


### Audit


---

### 4.2.1 Ensure Legacy Networks Do Not Exist for Older Projects
**Platform:** Google

**Rationale:** Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. The network is global in scope and spans all cloud regions. Subnetworks cannot be created in a legacy network and are unable to switch from legacy to auto or custom subnet networks. Legacy networks can have an impact for high network traffic projects and are subject to a single point of contention or failure.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 3.2

**Evidence**

**From Google Cloud CLI**

For each Google Cloud Platform project,



1. Set the project name in the Google Cloud Shell:


```
gcloud config set project <Project-ID>

```



2. List the networks configured in that project:


```
gcloud compute networks list
```


None of the listed networks should be in the `legacy` mode.

**Verification**

Evidence or test output indicates that no project contains a network having the legacy mode configuration.


---

### 4.2.2 Ensure That DNSSEC Is Enabled for Cloud DNS
**Platform:** Google
**Rationale:** Domain Name System Security Extensions (DNSSEC) adds security to the DNS protocol by enabling DNS responses to be validated. Having a trustworthy DNS that translates a domain name like www.example.com into its associated IP address is an increasingly important building block of today’s web-based applications. Attackers can hijack this process of domain/IP lookup and redirect users to a malicious site through DNS hijacking and man-in-the-middle attacks. DNSSEC helps mitigate the risk of such attacks by cryptographically signing DNS records. As a result, it prevents attackers from issuing fake DNS responses that may misdirect browsers to nefarious websites.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 3.3

**Evidence**

**From Google Cloud Console**



1. Go to `Cloud DNS` by visiting [https://console.cloud.google.com/net-services/dns/zones](https://console.cloud.google.com/net-services/dns/zones).
2. For each zone of `Type` `Public`, ensure that `DNSSEC` is set to `On`.

**From Google Cloud CLI**



1. List all the Managed Zones in a project:


```
gcloud dns managed-zones list

```



2. For each zone of `VISIBILITY` `public`, get its metadata:


```
gcloud dns managed-zones describe ZONE_NAME

```



3. Ensure that `dnssecConfig.state` property is `on`.

**Verification**

Evidence or test output indicates that DNSSEC is enabled for all managed zones having public visibility.


---

### 4.2.3 Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC
**Platform:** Google

**Rationale:** Domain Name System Security Extensions (DNSSEC) algorithm numbers in this registry may be used in CERT RRs. Zonesigning (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms.

The algorithm used for key signing should be a recommended one and it should be strong. When enabling DNSSEC for a managed zone, or creating a managed zone with DNSSEC, the user can select the DNSSEC signing algorithms and the denial-of-existence type. Changing the DNSSEC settings is only effective for a managed zone if DNSSEC is not already enabled. If there is a need to change the settings for a managed zone where it has been enabled, turn DNSSEC off and then re-enable it with different settings.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 3.4

**Evidence**

**From Google Cloud CLI**

Ensure the property algorithm for keyType keySigning is not using `RSASHA1`.

gcloud dns managed-zones describe ZONENAME --format="json(dnsName,dnssecConfig.state,dnssecConfig.defaultKeySpecs)"

**Verification**

Evidence or test output indicates that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC


---

### 4.2.4 Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC
**Platform:** Google

**Rationale:** DNSSEC algorithm numbers in this registry may be used in CERT RRs. Zone signing (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms.

The algorithm used for key signing should be a recommended one and it should be strong. When enabling DNSSEC for a managed zone, or creating a managed zone with DNSSEC, the DNSSEC signing algorithms and the denial-of-existence type can be selected. Changing the DNSSEC settings is only effective for a managed zone if DNSSEC is not already enabled. If the need exists to change the settings for a managed zone where it has been enabled, turn DNSSEC off and then re-enable it with different settings.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 3.5

**Evidence**

**From Google Cloud CLI**

Ensure the property algorithm for keyType zone signing is not using RSASHA1.


```
gcloud dns managed-zones describe --format="json(dnsName,dnssecConfig.state,dnssecConfig.defaultKeySpecs)"
```


**Verification**

Evidence or test output indicates that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC

---
### 4.2.5 Ensure that EC2 Metadata Service only allows IMDSv2
**Platform:** AWS

**Rationale:** Allowing Version 1 of the service may open EC2 instances to Server-Side Request Forgery (SSRF) attacks, so Amazon recommends utilizing Version 2 for better instance security.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 5.6

**Evidence**

From Console:



1. Login to AWS Management Console and open the Amazon EC2 console using [https://console.aws.amazon.com/ec2/](https://console.aws.amazon.com/ec2/)
2. Under the Instances menu, select Instances.
3. For each Instance, select the instance, then choose Actions > Modify instance metadata options.
4. If the Instance metadata service is enabled, verify whether IMDSv2 is set to required.

From Command Line:



1. Use the describe-instances CLI command
2. Ensure for all ec2 instances that the metadata-options.http-tokens setting is set to required.
3. Repeat for all active regions.


```
aws ec2 describe-instances --filters "Name=metadata-options.http-tokens","Values=optional" "Name=metadata-options.state","Values=applied" --query "Reservations[*].Instances[*]."
```


**Verification**

Evidence or test output indicates that EC2 Metadata Service only allows IMSDv2.


---


## 4.3 Implement and Manage a Firewall on Servers
### Description

Implement and manage a firewall on servers, where supported. Example implementations include a virtual firewall, operating system firewall, or a third-party firewall agent.


### Rationale

Firewalls help to prevent unauthorized users from accessing servers or sending malicious payloads to those servers.


### Audit


---

### 4.3.1 Ensure that RDP access from the Internet is evaluated and restricted
**Platform:** Azure

**Rationale:** The potential security problem with using RDP over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on an Azure Virtual Network or even attack networked devices outside of Azure.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 6.1

**Evidence**

**From Azure Portal**



1. For each VM, open the `Networking` blade
2. Verify that the `INBOUND PORT RULES` **does not** have a rule for RDP such as
   * port = `3389`,
   * protocol = `TCP`,
   * Source = `Any` OR `Internet`

**From Azure CLI**

List Network security groups with corresponding non-default Security rules:


```
az network nsg list --query [*].[name,securityRules]
```


Ensure that none of the NSGs have security rule as below


```
"access" : "Allow"
"destinationPortRange" : "3389" or "*" or "[port range containing 3389]"
"direction" : "Inbound"
"protocol" : "TCP"
"sourceAddressPrefix" : "*" or "0.0.0.0" or "<nw>/0" or "/0" or "internet" or "any"
```


**Verification**

Evidence or test output indicates that no network security group is configured to allow inbound connections to port 3389 from the unrestricted public internet.


---

### 4.3.2 Ensure that SSH access from the Internet is evaluated and restricted
**Platform:** Azure

**Rationale:** The potential security problem with using SSH over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on the Azure Virtual Network or even attack networked devices outside of Azure.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 6.2

**Evidence**

**From Azure Portal**



1. Open the `Networking` blade for the specific Virtual machine in Azure portal
2. Verify that the `INBOUND PORT RULES` **does not** have a rule for SSH such as
   * port = `22`,
   * protocol = `TCP`,
   * Source = `Any` OR `Internet`

**From Azure CLI**

List Network security groups with corresponding non-default Security rules:


```
az network nsg list --query [*].[name,securityRules]
```


Ensure that none of the NSGs have security rule as below


```
"access" : "Allow"
"destinationPortRange" : "22" or "*" or "[port range containing 22]"
"direction" : "Inbound"
"protocol" : "TCP"
"sourceAddressPrefix" : "*" or "0.0.0.0" or "<nw>/0" or "/0" or "internet" or "any"
```


**Verification**

Evidence or test output indicates that no network security group is configured to allow inbound connections to port 22 from the unrestricted public internet.


---

### 4.3.3 Ensure That SSH Access Is Restricted From the Internet
**Platform:** Google

**Rationale:** GCP `Firewall Rules` within a `VPC Network` apply to outgoing (egress) traffic from instances and incoming (ingress) traffic to instances in the network. Egress and ingress traffic flows are controlled even if the traffic stays within the network (for example, instance-to-instance communication). For an instance to have outgoing Internet access, the network must have a valid Internet gateway route or custom route whose destination IP is specified. This route simply defines the path to the Internet, to avoid the most general `(0.0.0.0/0)` destination `IP Range` specified from the Internet through `SSH` with the default `Port 22`. Generic access from the Internet to a specific IP Range needs to be restricted.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 3.6

**Evidence**

**From Google Cloud Console**



1. Go to `VPC network`.
2. Go to the `Firewall Rules`.
3. Ensure that `Port` is not equal to `22` and `Action` is not set to `Allow`.
4. Ensure `IP Ranges` is not equal to `0.0.0.0/0` under `Source filters`.

**From Google Cloud CLI**

gcloud compute firewall-rules list --format=table'(name,direction,sourceRanges,allowed)'

Ensure that there is no rule matching the below criteria:
   * `SOURCE_RANGES` is `0.0.0.0/0`
   * AND `DIRECTION` is `INGRESS`
   * AND IPProtocol is `tcp` or `ALL`
   * AND `PORTS` is set to `22` or `range containing 22` or `Null (not set)`

Note:



   * When ALL TCP ports are allowed in a rule, PORT does not have any value set (`NULL`)
   * When ALL Protocols are allowed in a rule, PORT does not have any value set (`NULL`)

**Verification**

Evidence or test output indicates that no firewall rule allows inbound connections to port 22 from the unrestricted public internet.


---

### 4.3.4 Ensure That RDP Access Is Restricted From the Internet
**Platform:** Google

**Rationale:** GCP `Firewall Rules` within a `VPC Network`. These rules apply to outgoing (egress) traffic from instances and incoming (ingress) traffic to instances in the network. Egress and ingress traffic flows are controlled even if the traffic stays within the network (for example, instance-to-instance communication). For an instance to have outgoing Internet access, the network must have a valid Internet gateway route or custom route whose destination IP is specified. This route simply defines the path to the Internet, to avoid the most general `(0.0.0.0/0)` destination `IP Range` specified from the Internet through `RDP` with the default `Port 3389`. Generic access from the Internet to a specific IP Range should be restricted.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 3.7

**Evidence**

**From Google Cloud Console**



1. Go to `VPC network`.
2. Go to the `Firewall Rules`.
3. Ensure `Port` is not equal to `3389` and `Action` is not `Allow`.
4. Ensure `IP Ranges` is not equal to `0.0.0.0/0` under `Source filters`.

**From Google Cloud CLI**

gcloud compute firewall-rules list --format=table'(name,direction,sourceRanges,allowed.ports)'

Ensure that there is no rule matching the below criteria:
   * `SOURCE_RANGES` is `0.0.0.0/0`
   * AND `DIRECTION` is `INGRESS`
   * AND IPProtocol is `TCP` or `ALL`
   * AND `PORTS` is set to `3389` or `range containing 3389` or `Null (not set)`

Note:



   * When ALL TCP ports are allowed in a rule, PORT does not have any value set (`NULL`)
   * When ALL Protocols are allowed in a rule, PORT does not have any value set (`NULL`)

**Verification**

Evidence or test output indicates that no firewall rule allows inbound connections to port 3389 from the unrestricted public internet.


---

### 4.3.5 Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports
**Platform:** AWS

**Rationale:** Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 5.1

**Evidence**

**From Console:**

Perform the following to determine if the account is configured as prescribed:



1. Login to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
2. In the left pane, click `Network ACLs`
3. For each network ACL, perform the following:
   * Select the network ACL
   * Click the `Inbound Rules` tab
   * Ensure no rule exists that has a port range that includes port `22`, `3389`, using the protocols TDP (6), UDP (17) or ALL (-1) or other remote server administration ports for your environment and has a `Source` of `0.0.0.0/0` and shows `ALLOW`

**Note:** A Port value of `ALL` or a port range such as `0-1024` are inclusive of port `22`, `3389`, and other remote server administration ports

**Verification**

Evidence or test output indicates that no Network ACL allows ingress to port 22 or port 3389 from the unrestricted public internet.


---

### 4.3.6 Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports
**Platform:** AWS

**Rationale:** Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 5.2

**Evidence**

Perform the following to determine if the account is configured as prescribed:



1. Login to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
2. In the left pane, click `Security Groups`
3. For each security group, perform the following:
4. Select the security group
5. Click the `Inbound Rules` tab
6. Ensure no rule exists that has a port range that includes port `22`, `3389`, using the protocols TDP (6), UDP (17) or ALL (-1) or other remote server administration ports for your environment and has a `Source` of `0.0.0.0/0`

**Note:** A Port value of `ALL` or a port range such as `0-1024` are inclusive of port `22`, `3389`, and other remote server administration ports.

**Verification**

Evidence or test output indicates that no security group allows ingress to port 22 or port 3389 from 0.0.0.0/0.


---

### 4.3.7 Ensure no security groups allow ingress from ::/0 to remote server administration ports
**Platform:** AWS

**Rationale:** Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 5.3

**Evidence**

Perform the following to determine if the account is configured as prescribed:



1. Login to the AWS Management Console at [https://console.aws.amazon.com/vpc/home](https://console.aws.amazon.com/vpc/home)
2. In the left pane, click `Security Groups`
3. For each security group, perform the following:
4. Select the security group
5. Click the `Inbound Rules` tab
6. Ensure no rule exists that has a port range that includes port `22`, `3389`, or other remote server administration ports for your environment and has a `Source` of `::/0`

**Note:** A Port value of `ALL` or a port range such as `0-1024` are inclusive of port `22`, `3389`, and other remote server administration ports.

**Verification**

Evidence or test output indicates that no security group allows ingress to port 22 or port 3389 from ::/0


---


# 5 Storage


## 5.1 Establish and Maintain a Data Recovery Process


### Description

Establish and maintain a data recovery process. In the process, address the scope of data recovery activities, recovery prioritization, and the security of backup data. Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

Organizations need to establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state.


### Audit


---

### 5.1.1 Ensure Soft Delete is Enabled for Azure Containers and Blob Storage
**Platform:** Azure

**Rationale:** Containers and Blob Storage data can be incorrectly deleted. An attacker/malicious user may do this deliberately in order to cause disruption. Deleting an Azure Storage blob causes immediate data loss. Enabling this configuration for Azure storage ensures that even if blobs/data were deleted from the storage account, Blobs/data objects are recoverable for a particular time which is set in the "Retention policies," ranging from 7 days to 365 days.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 3.11

**Evidence**

**From Azure Portal:**



1. From the Azure home page, open the hamburger menu in the top left or click on the arrow pointing right with 'More services' underneath.
2. Select Storage.
3. Select Storage Accounts.
4. For each Storage Account, navigate to Data protection in the left scroll column.
5. Ensure that soft delete is checked for both blobs and containers. Also check if the retention period is a sufficient length for your organization.

**From Azure CLI**

**Blob Storage** Ensure that the output of the below command contains enabled status as true and days is not empty or null


```
az storage blob service-properties delete-policy show --account-name <StorageAccountName> --account-key <accountkey>
```


**Azure Containers** Make certain that the --enable-container-delete-retention is 'true'.


```
az storage account blob-service-properties show
 --account-name <StorageAccountName>
 --account-key <accountkey>
 --resource-group <resource_group>
```


**Verification**

Evidence or test output indicates that soft delete is enabled for all Azure Containers and Blob Storage.


---


## 5.2 Establish and Maintain a Secure Network Architecture
### Description

Establish and maintain a secure network architecture. A secure network architecture must address segmentation, least privilege, and availability, at a minimum.


### Rationale

Malicious actors can exploit insecure services, poor firewall and network configurations, and default or legacy credentials.


### Audit


---

### 5.2.1 Ensure Default Network Access Rule for Storage Accounts is Set to Deny
**Platform:** Azure

**Rationale:** Storage accounts should be configured to deny access to traffic from all networks (including internet traffic). Access can be granted to traffic from specific Azure Virtual networks, allowing a secure network boundary for specific applications to be built. Access can also be granted to public internet IP address ranges to enable connections from specific internet or on-premises clients. When network rules are configured, only applications from allowed networks can access a storage account. When calling from an allowed network, applications continue to require proper authorization (a valid access key or SAS token) to access the storage account.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 3.8

**Evidence**

**From Azure Console**



1. Go to Storage Accounts
2. For each storage account, Click on the `Networking` blade.
3. Click the `Firewalls and virtual networks` heading.
4. Ensure that Allow access from `All networks` is not selected.

**From Azure CLI**

Ensure `defaultAction` is not set to `Allow`.


```
 az storage account list --query '[*].networkRuleSet'
```


**From PowerShell**


```
Connect-AzAccount
Set-AzContext -Subscription <subscription ID>
Get-AzStorageAccountNetworkRuleset -ResourceGroupName <resource group> -Name <storage account name> |Select-Object DefaultAction
```


**PowerShell Result - Non-Compliant**


```
DefaultAction : Allow
```


**PowerShell Result - Compliant**


```
DefaultAction : Deny
```


**Verification**

Evidence or test output indicates that all storage accounts are configured such that the default action is set to Deny.


---


## 5.3 Encrypt Sensitive Data in Transit
### Description

Encrypt sensitive data in transit. Example implementations can include: Transport Layer Security (TLS) and Open Secure Shell (OpenSSH).


### Rationale

Encryption protects sensitive data when transmitted over untrusted network connections.


### Audit


---

### 5.3.1 Ensure that 'Secure transfer required' is set to 'Enabled'
**Platform:** Azure

**Rationale:** The secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn’t support HTTPS for custom domain names, this option is not applied when using a custom domain name.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 3.1

**Evidence**

**From Azure Portal**



1. Go to `Storage Accounts`
2. For each storage account, go to `Configuration`
3. Ensure that `Secure transfer required` is set to `Enabled`

**From Azure CLI**

Use the below command to ensure the `Secure transfer required` is enabled for all the `Storage Accounts` by ensuring the output contains `true` for each of the `Storage Accounts`.


```
az storage account list --query "[*].[name,enableHttpsTrafficOnly]"
```


**Verification**

Evidence or test output indicates that all storage accounts are configured such that secure transfer required is set to enabled.


---

### 5.3.2 Ensure the "Minimum TLS version" for storage accounts is set to "Version 1.2"
**Platform:** Azure

**Rationale:** TLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS protocol. Continued use of this legacy protocol affects the security of data in transit.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 3.15

**Evidence**

**From Azure Console**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/)
2. Go to `Storage Accounts`
3. Click on each Storage Account
4. Under `Setting` section, Click on `Configuration`
5. Ensure that the `minimum TLS version` is set to be Version 1.2

**From Azure CLI**

Get a list of all storage accounts and their resource groups


```
az storage account list | jq '.[] | {name, resourceGroup}'
```


Then query the minimumTLSVersion field


```
az storage account show \
 --name <storage-account> \
 --resource-group <resource-group> \
 --query minimumTlsVersion \
 --output tsv
```


**From Azure PowerShell**

To get the minimum TLS version, run the following command:


```
(Get-AzStorageAccount -Name <STORAGEACCOUNTNAME> -ResourceGroupName <RESOURCEGROUPNAME>).MinimumTlsVersion
```


**Verification**

Evidence or test output indicates that all storage accounts are configured such that the minimum TLS version is set to Version 1.2


---


## 5.4 Encrypt Sensitive Data at Rest


### Description

Encrypt sensitive data at rest on servers, applications, and databases containing sensitive data. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard. Additional encryption methods may include application-layer encryption, also known as client-side encryption, where access to the data storage device(s) does not permit access to the plain-text data.


### Rationale

Encryption at rest protects against some risks of unauthorized access to data, for example insecure disposal and reuse of storage media.


### Audit


---

### 5.4.1 Ensure EBS Volume Encryption is Enabled in all Regions
**Platform:** AWS

**Rationale:** Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 2.2.1

**Evidence**

**From Console:**



1. Login to AWS Management Console and open the Amazon EC2 console using [https://console.aws.amazon.com/ec2/](https://console.aws.amazon.com/ec2/)
2. Under `Account attributes`, click `EBS encryption`.
3. Verify `Always encrypt new EBS volumes` displays `Enabled`.
4. Review every region in-use.

**Note:** EBS volume encryption is configured per region.

**From Command Line:**



1. Run


```
aws --region <region> ec2 get-ebs-encryption-by-default

```



2. Verify that `"EbsEncryptionByDefault": true` is displayed.
3. Review every region in-use.

**Note:** EBS volume encryption is configured per region.

**Verification**

Evidence or test output indicates that all regions are configured such that EBS volume encryption is enabled.


---

### 5.4.2 Ensure that encryption is enabled for EFS file systems
**Platform:** AWS

**Rationale:** Data should be encrypted at rest to reduce the risk of a data breach via direct access to the storage device.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 2.4.1

**Evidence**

**From Console:**



1. Login to the AWS Management Console and Navigate to `Elastic File System (EFS) dashboard.
2. Select `File Systems` from the left navigation panel.
3. Each item on the list has a visible Encrypted field that displays data at rest encryption status.
4. Validate that this field reads `Encrypted` for all EFS file systems in all AWS regions.

**From CLI:**



1. Run describe-file-systems command using custom query filters to list the identifiers of all AWS EFS file systems currently available within the selected region:


```
aws efs describe-file-systems --region <region> --output table --query 'FileSystems[*].FileSystemId'

```



2. The command output should return a table with the requested file system IDs.
3. Run describe-file-systems command using the ID of the file system that you want to examine as identifier and the necessary query filters:


```
aws efs describe-file-systems --region <region> --file-system-id <file-system-id from step 2 output> --query 'FileSystems[*].Encrypted'

```



4. The command output should return the file system encryption status true or false. If the returned value is `false`, the selected AWS EFS file system is not encrypted and if the returned value is `true`, the selected AWS EFS file system is encrypted.

**Verification**

Evidence or test output indicates that all regions are configured such that EFS file systems are configured with encryption enabled.


---


## 5.5 Configure Data Access Control Lists
### Description

Configure data access control lists based on a user’s need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.


### Rationale

The principle of least privilege reduces the risk of unauthorized actions being taken in your systems.


### Audit


---

### 5.5.1 Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'
**Platform:** AWS

**Rationale:** Amazon S3 `Block public access (bucket settings)` prevents the accidental or malicious public exposure of data contained within the respective bucket(s).

Amazon S3 `Block public access (account settings)` prevents the accidental or malicious public exposure of data contained within all buckets of the respective AWS account.

Whether blocking public access to all or some buckets is an organizational decision that should be based on data sensitivity, least privilege, and use case.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 2.1.4

**Evidence**

**If utilizing Block Public Access (bucket settings)**

**From Console:**



1. Login to AWS Management Console and open the Amazon S3 console using [https://console.aws.amazon.com/s3/](https://console.aws.amazon.com/s3/)
2. Select the Check box next to the Bucket.
3. Click on 'Edit public access settings'.
4. Ensure that block public access settings are set appropriately for this bucket
5. Repeat for all the buckets in your AWS account.

**From Command Line:**



1. List all of the S3 Buckets


```
aws s3 ls

```



2. Find the public access setting on that bucket


```
aws s3api get-public-access-block --bucket <name-of-the-bucket>
```


Output if Block Public access is enabled:


```
{
 "PublicAccessBlockConfiguration": {
 "BlockPublicAcls": true,
 "IgnorePublicAcls": true,
 "BlockPublicPolicy": true,
 "RestrictPublicBuckets": true
 }
}
```


If the output reads `false` for the separate configuration settings then refer to the remediation in the CIS Benchmark.

**If utilizing Block Public Access (account settings)**

**From Console:**



1. Login to AWS Management Console and open the Amazon S3 console using [https://console.aws.amazon.com/s3/](https://console.aws.amazon.com/s3/)
2. Choose `Block public access (account settings)`
3. Ensure that block public access settings are set appropriately for your AWS account.

**From Command Line:**

To check Public access settings for this account status, run the following command, `aws s3control get-public-access-block --account-id <ACCT_ID> --region <REGION_NAME>`

Output if Block Public access is enabled:


```
{
 "PublicAccessBlockConfiguration": {
 "IgnorePublicAcls": true,
 "BlockPublicPolicy": true,
 "BlockPublicAcls": true,
 "RestrictPublicBuckets": true
 }
}
```


If the output reads `false` for the separate configuration settings then refer to the remediation in the CIS Benchmark.

**Verification**

Evidence or test output indicates that all S3 buckets are configured such that the following configurations are set to true: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`.


---

### 5.5.2 Ensure that 'Public access level' is disabled for storage accounts with blob containers
**Platform:** Azure

**Rationale:** The default configuration for a storage account permits a user with appropriate permissions to configure public (anonymous) access to containers and blobs in a storage account. Keep in mind that public access to a container is always turned off by default and must be explicitly configured to permit anonymous requests. It grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. It is recommended not to provide anonymous access to blob containers until, and unless, it is strongly desired. A shared access signature token or Azure AD RBAC should be used for providing controlled and timed access to blob containers. If no anonymous access is needed on any container in the storage account, it’s recommended to set allowBlobPublicAccess false at the account level, which forbids any container to accept anonymous access in the future.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 3.7

**Evidence**

**From Azure Portal**



1. Go to `Storage Accounts`
2. For each storage account, go to the `Networking` setting under `Security + networking`
3. Ensure the `Public Network Access` setting is set to `Disabled`.

**From Azure CLI**

Ensure `publicNetworkAccess` is `Disabled`


```
az storage account show --name <storage-account> --resource-group <resource-group> --query "{publicNetworkAccess:publicNetworkAccess}"
```


**From PowerShell**

For each Storage Account, ensure `PublicNetworkAccess` is `Disabled`


```
Get-AzStorageAccount -Name <storage account name> -ResourceGroupName <resource group name> |select PublicNetworkAccess
```


**Verification**

Evidence or test output indicates that `Public access level` is disabled for storage accounts with blob containers.


---

### 5.5.3 Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible
**Platform:** Google

**Rationale:** Allowing anonymous or public access grants permissions to anyone to access bucket content. Such access might not be desired if you are storing any sensitive data. Hence, ensure that anonymous or public access to a bucket is not allowed.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 5.1

**Evidence**

**From Google Cloud Console**



1. Go to `Storage browser` by visiting [https://console.cloud.google.com/storage/browser](https://console.cloud.google.com/storage/browser).
2. Click on each bucket name to go to its `Bucket details` page.
3. Click on the `Permissions` tab.
4. Ensure that `allUsers` and `allAuthenticatedUsers` are not in the `Members` list.

**From Google Cloud CLI**



1. List all buckets in a project


```
gsutil ls

```



2. Check the IAM Policy for each bucket:


```
gsutil iam get gs://BUCKET_NAME
```


No role should contain `allUsers` and/or `allAuthenticatedUsers` as a member.

**Using Rest API**



3. List all buckets in a project


```
Get https://www.googleapis.com/storage/v1/b?project=<ProjectName>

```



4. Check the IAM Policy for each bucket


```
GET https://www.googleapis.com/storage/v1/b/<bucketName>/iam
```


No role should contain `allUsers` and/or `allAuthenticatedUsers` as a member.

**Verification**

Evidence or test output indicates that all cloud storage buckets are configured to block anonymous or public access.


---


## 5.6 Establish and Maintain a Secure Configuration Process

### Description

Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

"This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software."


### Audit


---

### 5.6.1 Ensure that 'Enable key rotation reminders' is enabled for each Storage Account
**Platform:** Azure

**Rationale:** Reminders such as those generated by this requirement will help maintain a regular and healthy cadence for activities which improve the overall efficacy of a security program.

Cryptographic key rotation periods will vary depending on your organization's security requirements and the type of data which is being stored in the Storage Account. For example, PCI DSS mandates that cryptographic keys be replaced or rotated 'regularly,' and advises that keys for static data stores be rotated every 'few months.'

For the purposes of this requirement, 90 days are prescribed as the reminder frequency. Review and adjustment of the 90 day period is recommended, and may even be necessary. Your organization's security requirements should dictate the appropriate setting.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 3.3

**Evidence**

**From Azure Portal**



1. Go to `Storage Accounts`
2. For each Storage Account, go to `Access keys`
3. Click `Set rotation reminder`

If the checkbox for `Enable key rotation reminders` is already checked, that Storage Account is compliant. Review the `Remind me every` field for a desirable periodic setting that fits your security program's needs.

**Verification**

Evidence or test output indicates that `Enable key rotation reminders` are enabled for each storage account.


---


## 5.7 Securely Manage Enterprise Assets and Software
### Description

Securely manage enterprise assets and software. Example implementations include managing configuration through version-controlled-infrastructure-as-code and accessing administrative interfaces over secure network protocols, such as Secure Shell (SSH) and Hypertext Transfer Protocol Secure (HTTPS). Do not use insecure management protocols, such as Telnet (Teletype Network) and HTTP, unless operationally essential.


### Rationale

Secure management of assets and software guards against malicious users from being able to observe administrative communications with remote servers, possibly leading to compromise of that server, or from making configuration changes to introduce a security vulnerability into the server.


### Audit


---

### 5.7.1 Ensure that Storage Account Access Keys are Periodically Regenerated
**Platform:** Azure

**Rationale:** When a storage account is created, Azure generates two 512-bit storage access keys which are used for authentication when the storage account is accessed. Rotating these keys periodically ensures that any inadvertent access or exposure does not result from the compromise of these keys.

Cryptographic key rotation periods will vary depending on your organization's security requirements and the type of data which is being stored in the Storage Account. For example, PCI DSS mandates that cryptographic keys be replaced or rotated 'regularly,' and advises that keys for static data stores be rotated every 'few months.'

For the purposes of this requirement, 90 days are prescribed as the reminder frequency. Review and adjustment of the 90 day period is recommended, and may even be necessary. Your organization's security requirements should dictate the appropriate setting.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 3.4

**Evidence**

**From Azure Portal**



1. Go to `Storage Accounts`
2. For each Storage Account, go to `Access keys`
3. Review the date in the `Last rotated` field for **each** key.

If the `Last rotated` field indicates value greater than 90 days [or greater than your organization's period of validity], the key should be rotated.

**From Azure CLI**



1. Get a list of storage accounts


```
az storage account list --subscription <subscription-id>
```


Make a note of `id`, `name` and `resourceGroup`.



2. For every storage account make sure that key is regenerated in the past 90 days.


```
az monitor activity-log list --namespace Microsoft.Storage --offset 90d --query "[?contains(authorization.action, 'regenerateKey')]" --resource-id <resource id>
```


The output should contain


```
"authorization"/"scope": <your_storage_account> AND "authorization"/"action": "Microsoft.Storage/storageAccounts/regeneratekey/action" AND "status"/"localizedValue": "Succeeded" "status"/"Value": "Succeeded"
```


**Verification**

Evidence or test output indicates that all storage account access keys have been generated within the past 90 days.


---


## 5.8 Establish an Access Revoking Process


### Description

Establish and follow a process, preferably automated, for revoking access to enterprise assets, through disabling accounts immediately upon termination, rights revocation, or role change of a user. Disabling accounts, instead of deleting accounts, may be necessary to preserve audit trails.


### Rationale

Ensuring that access grants are revoked when they're no longer needed reduces the target area for malicious users.


### Audit


---

### 5.8.1 Ensure that Shared Access Signature Tokens Expire Within an Hour
**Platform:** Azure

**Rationale:** A shared access signature (SAS) is a URI that grants restricted access rights to Azure Storage resources. A shared access signature can be provided to clients who should not be trusted with the storage account key but for whom it may be necessary to delegate access to certain storage account resources. Providing a shared access signature URI to these clients allows them access to a resource for a specified period of time. This time should be set as low as possible and preferably no longer than an hour.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 3.6

**Evidence**

Currently, SAS token expiration times cannot be audited. Until Microsoft makes token expiration time a setting rather than a token creation parameter, this requirement will rely on manual verification.

**Verification**

Developer provides evidence (a written statement or code samples) that indicates that the token creation parameter used limits access signature token validity to less than 60 minutes.


---


# 6 Database Services


## 6.1 Use Standard Hardening Configuration Templates for Application Infrastructure
### Description

Use standard, industry-recommended hardening configuration templates for application infrastructure components. This includes underlying servers, databases, and web servers, and applies to cloud containers, Platform as a Service (PaaS) components, and SaaS components. Do not allow in-house developed software to weaken configuration hardening.


### Rationale

Industry-recommended hardening configuration templates reduce the attack surface area of your system and reduce the risk of configuration errors that could lead to a security incident.


### Audit


---

### 6.1.1 Ensure That the ‘Local_infile’ Database Flag for a Cloud SQL MySQL Instance Is Set to ‘Off’
**Platform:** Google

**Rationale:** The `local_infile` flag controls the server-side LOCAL capability for LOAD DATA statements. Depending on the `local_infile` setting, the server refuses or permits local data loading by clients that have LOCAL enabled on the client side.

To explicitly cause the server to refuse LOAD DATA LOCAL statements (regardless of how client programs and libraries are configured at build time or runtime), start mysqld with local_infile disabled. local_infile can also be set at runtime.

Due to security issues associated with the `local_infile` flag, it is recommended to disable it. This requirement is applicable to MySQL database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.1.3

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Ensure the database flag `local_infile` that has been set is listed under the `Database flags` section.

**From Google Cloud CLI**



1. List all Cloud SQL database instances:


```
gcloud sql instances list

```



2. Ensure the below command returns `off` for every Cloud SQL MySQL database instance.


```
gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="local_infile")|.value'
```


**Verification**

Evidence or test output indicates that Cloud SQL MySQL instance(s) have the Local_infile database flag set to off.


---


## 6.2 Allowlist Authorized Scripts


### Description

Use technical controls, such as digital signatures and version control, to ensure that only authorized scripts, such as specific .ps1, .py, etc., files, are allowed to execute. Block unauthorized scripts from executing. Reassess bi-annually, or more frequently.


### Rationale

Unauthorized scripts can be used by malicious users to take over a system or take other destructive actions.


### Audit


---

### 6.2.1 Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'
**Platform:** Google

**Rationale:** `external scripts enabled` allows the execution of scripts with certain remote language extensions. This property is OFF by default. When Advanced Analytics Services is installed, setup can optionally set this property to true. As the External Scripts Enabled feature allows scripts external to SQL such as files located in an R library to be executed, which could adversely affect the security of the system, hence this should be disabled. This requirement is applicable to SQL Server database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.3.1

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Ensure the database flag `external scripts enabled` is disabled under the `Database flags` section.

**From Google Cloud CLI**



1. Ensure the below command returns `off` for every Cloud SQL SQL Server database instance


```
gcloud sql instances list --format=json | jq '.settings.databaseFlags[] | select(.name=="external scripts enabled")|.value'
```


**Verification**

Evidence or test output indicates that Cloud SQL MySQL instance(s) have the external scripts enabled database flag set to off.


---


## 6.3 Encrypt Sensitive Data in Transit


### Description

Encrypt sensitive data in transit. Example implementations can include: Transport Layer Security (TLS) and Open Secure Shell (OpenSSH).


### Rationale

Encryption protects sensitive data when transmitted over untrusted network connections.


### Audit


---

### 6.3.1 Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server
**Platform:** Azure

**Rationale:** `SSL connectivity` helps to provide a new layer of security by connecting database servers to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against "man in the middle" attacks by encrypting the data stream between the server and application.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.3.1

**Evidence**

**From Azure Portal**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/)
2. Go to `Azure Database for PostgreSQL server`
3. For each database, click on `Connection security`
4. In `SSL` settings, ensure `Enforce SSL connection` is set to `ENABLED`.

**From Azure CLI**

Ensure the output of the below command returns `Enabled`.


```
az postgres server show --resource-group myresourcegroup --name <resourceGroupName> --query sslEnforcement
```


**From PowerShell**

Ensure the output of the below command returns `Enabled`.


```
Get-AzPostgreSqlServer -ResourceGroupName <ResourceGroupName > -ServerName <ServerName> | Select-Object SslEnforcement
```


**Verification**

Evidence or test output indicates that all PostgreSQL database servers are configured to enforce SSL connections.


---

### 6.3.2 Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server
**Platform:** Azure

**Rationale:** SSL connectivity helps to provide a new layer of security by connecting database servers to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against "man in the middle" attacks by encrypting the data stream between the server and application.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.4.1

**Evidence**

**From Azure Portal**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/)
2. Go to `Azure Database for MySQL servers`
3. For each database, click on `Connection security`
4. In `SSL` settings, ensure `Enforce SSL connection` is set to `ENABLED`.

**From Azure CLI**

Ensure the output of the below command returns ENABLED.


```
az mysql server show --resource-group <resourceGroupName> --name <serverName> --query sslEnforcement
```


**Verification**

Evidence or test output indicates that all Standard MySQL database servers are configured to enforce SSL connections.


---

### 6.3.3 Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server
**Platform:** Azure

**Rationale:** TLS connectivity helps to provide a new layer of security by connecting database servers to client applications using Transport Layer Security (TLS). Enforcing TLS connections between database server and client applications helps protect against "man in the middle" attacks by encrypting the data stream between the server and application.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.4.2

**Evidence**

**From Azure Portal**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/)
2. Go to `Azure Database for MySQL flexible servers`
3. For each database, click on `Server parameters` under `Settings`
4. In the search box, type in `tls_version`
5. Ensure `tls_version` is set to `TLSV1.2`

**From Azure CLI**

Ensure the output of the below command contains the key value pair `"values": "TLSV1.2"`.


```
az mysql flexible-server parameter show --name tls_version --resource-group <resourceGroupName> --server-name <serverName>
```


Example output:


```
{
 "allowedValues": "TLSv1,TLSv1.1,TLSv1.2",
 "dataType": "Set",
 "defaultValue": "TLSv1.2",
 "description": "Which protocols the server permits for encrypted connections. By default, TLS 1.2 is enforced",
 "id": "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.DBforMySQL/flexibleServers/<serverName>/configurations/tls_version",
 "isConfigPendingRestart": "False",
 "isDynamicConfig": "False",
 "isReadOnly": "False",
 "name": "tls_version",
 "resourceGroup": "<resourceGroupName>",
 "source": "system-default",
 "systemData": null,
 "type": "Microsoft.DBforMySQL/flexibleServers/configurations",
 "value": "TLSv1.2"
}
```


**Verification**

Evidence or test output indicates that all MySQL flexible database servers are configured with TLS version TLSV1.2 or higher.


---

### 6.3.4 Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL
**Platform:** Google

**Rationale:** SQL database connections if successfully trapped (MITM); can reveal sensitive data like credentials, database queries, query outputs etc. For security, it is recommended to always use SSL encryption when connecting to your instance. This requirement is applicable for Postgresql, MySql generation 1, MySql generation 2 and SQL Server 2017 instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.4

**Evidence**

**From Google Cloud Console**



1. Go to [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Click on an instance name to see its configuration overview.
3. In the left-side panel, select `Connections`.
4. In the `SSL connections` section, ensure that `Only secured connections are allowed to connect to this instance.`.

**From Google Cloud CLI**



1. Get the detailed configuration for every SQL database instance using the following command:


```
gcloud sql instances list --format=json
```


Ensure that section `settings: ipConfiguration` has the parameter `requireSsl` set to `true`.

**Verification**

Evidence or test output indicates that Cloud SQL database instance(s) are configured to require all incoming connections to use SSL.


---


## 6.4 Encrypt Sensitive Data at Rest


### Description

Encrypt sensitive data at rest on servers, applications, and databases containing sensitive data. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard. Additional encryption methods may include application-layer encryption, also known as client-side encryption, where access to the data storage device(s) does not permit access to the plain-text data.


### Rationale

Encryption at rest protects against some risks of unauthorized access to data, for example insecure disposal and reuse of storage media.


### Audit


---

### 6.4.1 Ensure that encryption-at-rest is enabled for RDS Instances
**Platform:** AWS

**Rationale:** Databases are likely to hold sensitive and critical data, it is highly recommended to implement encryption in order to protect your data from unauthorized access or disclosure. With RDS encryption enabled, the data stored on the instance's underlying storage, the automated backups, read replicas, and snapshots, are all encrypted.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 2.3.1; [Amazon Relational Database Service controls - AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-3)

**Evidence**

**From Console:**



1. Login to the AWS Management Console and open the RDS dashboard at [https://console.aws.amazon.com/rds/](https://console.aws.amazon.com/rds/)
2. In the navigation pane, under the RDS dashboard, click `Databases`.
3. Select the RDS Instance that you want to examine
4. Click `Instance Name` to see details, then click on `Configuration` tab.
5. Under the Configuration Details section, In Storage pane search for the `Encryption Enabled` Status.
6. If the current status is set to `Disabled`, Encryption is not enabled for the selected RDS Instance database instance.
7. Repeat steps 3 to 7 to verify encryption status of other RDS Instances in the same region.
8. Change region from the top of the navigation bar and repeat audit for other regions.

**From Command Line:**



1. Run `describe-db-instances` command to list all RDS Instance database names, available in the selected AWS region, Output will return each Instance database identifier-name.


```
aws rds describe-db-instances --region <region-name> --query 'DBInstances[*].DBInstanceIdentifier'

```



2. Run again `describe-db-instances` command using the RDS Instance identifier returned earlier, to determine if the selected database instance is encrypted, The command output should return the encryption status `True` Or `False`.


```
aws rds describe-db-instances --region <region-name> --db-instance-identifier <DB-Name> --query 'DBInstances[*].StorageEncrypted'

```



3. If the StorageEncrypted parameter value is `False`, Encryption is not enabled for the selected RDS database instance.
4. Repeat steps 1 to 3 for auditing each RDS Instance and change Region to verify for other regions

**Verification**

Evidence or test output indicates that all RDS instances are configured with encryption at rest enabled.


---

### 6.4.2 Ensure that 'Data encryption' is set to 'On' on a SQL Database
**Platform:** Azure

**Rationale:** Azure SQL Database transparent data encryption helps protect against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.1.5

**Evidence**

**From Azure Portal**



1. Go to `SQL databases`
2. For each DB instance
3. Click on `Transparent data encryption`
4. Ensure that `Data encryption` is set to `On`

**From Azure CLI**

Ensure the output of the below command is `Enabled`


```
az sql db tde show --resource-group <resourceGroup> --server <dbServerName> --database <dbName> --query status
```


**From PowerShell**

Get a list of SQL Servers.


```
Get-AzSqlServer
```


For each server, list the databases.


```
Get-AzSqlDatabase -ServerName <SQL Server Name> -ResourceGroupName <Resource Group Name>
```


For each database not listed as a `Master` database, check for Transparent Data Encryption.


```
Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName <Resource Group Name> -ServerName <SQL Server Name> -DatabaseName <Database Name>
```


Make sure `DataEncryption` is `Enabled` for each database except the `Master` database.

**Verification**

Evidence or test output indicates that all Azure SQL Databases are configured with Data Encryption set to on.


---


## 6.5 Configure Data Access Control Lists


### Description

Configure data access control lists based on a user’s need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.


### Rationale

The principle of least privilege reduces the risk of unauthorized actions being taken in your systems.


### Audit


---

### 6.5.1 Ensure that public access is not given to RDS Instance
**Platform:** AWS

**Rationale:** Ensure that no public-facing RDS database instances are provisioned in your AWS account and restrict unauthorized access in order to minimize security risks. When the RDS instance allows unrestricted access (0.0.0.0/0), everyone and everything on the Internet can establish a connection to your database and this can increase the opportunity for malicious activities such as brute force attacks, PostgreSQL injections, or DoS/DDoS attacks.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 2.3.3

**Evidence**

**From Console:**



1. Log in to the AWS management console and navigate to the RDS dashboard at [https://console.aws.amazon.com/rds/](https://console.aws.amazon.com/rds/).
2. Under the navigation panel, On the RDS Dashboard, click `Databases`.
3. Select the RDS instance that you want to examine.
4. Click `Instance Name` from the dashboard, Under `Connectivity and Security.
5. On the `Security`, check if the Publicly Accessible flag status is set to `Yes`, follow the below-mentioned steps to check database subnet access.
   * In the `networking` section, click the subnet link available under `Subnets`
   * The link will redirect you to the VPC Subnets page.
   * Select the subnet listed on the page and click the `Route Table` tab from the dashboard bottom panel. If the route table contains any entries with the destination `CIDR block set to 0.0.0.0/0` and with an `Internet Gateway` attached.
   * The selected RDS database instance was provisioned inside a public subnet, therefore is not running within a logically isolated environment and can be accessible from the Internet.
6. Repeat steps no. 4 and 5 to determine the type (public or private) and subnet for other RDS database instances provisioned in the current region.
7. Change the AWS region from the navigation bar and repeat the audit process for other regions.

**From Command Line:**



1. Run `describe-db-instances` command to list all RDS database names, available in the selected AWS region:


```
aws rds describe-db-instances --region <region-name> --query 'DBInstances[*].DBInstanceIdentifier'

```



2. The command output should return each database instance `identifier`.
3. Run again `describe-db-instances` command using the `PubliclyAccessible` parameter as query filter to reveal the database instance Publicly Accessible flag status:


```
aws rds describe-db-instances --region <region-name> --db-instance-identifier <db-instance-name> --query 'DBInstances[*].PubliclyAccessible'

```



4. Check for the Publicly Accessible parameter status, If the Publicly Accessible flag is set to `Yes`. Then selected RDS database instance is publicly accessible and insecure, follow the below-mentioned steps to check database subnet access
5. Run again `describe-db-instances` command using the RDS database instance identifier that you want to check and appropriate filtering to describe the VPC subnet(s) associated with the selected instance:


```
aws rds describe-db-instances --region <region-name> --db-instance-identifier <db-name> --query 'DBInstances[*].DBSubnetGroup.Subnets[]'

```



   * The command output should list the subnets available in the selected database subnet group.
6. Run `describe-route-tables` command using the ID of the subnet returned at the previous step to describe the routes of the VPC route table associated with the selected subnet:


```
aws ec2 describe-route-tables --region <region-name> --filters "Name=association.subnet-id,Values=<SubnetID>" --query 'RouteTables[*].Routes[]'

```



   * If the command returns the route table associated with database instance subnet ID. Check the `GatewayId` and `DestinationCidrBlock` attributes values returned in the output. If the route table contains any entries with the `GatewayId` value set to `igw-xxxxxxxx` and the `DestinationCidrBlock` value set to `0.0.0.0/0`, the selected RDS database instance was provisioned inside a public subnet.
   * Or
   * If the command returns empty results, the route table is implicitly associated with subnet, therefore the audit process continues with the next step
7. Run again `describe-db-instances` command using the RDS database instance identifier that you want to check and appropriate filtering to describe the VPC ID associated with the selected instance:


```
aws rds describe-db-instances --region <region-name> --db-instance-identifier <db-name> --query 'DBInstances[*].DBSubnetGroup.VpcId'

```



   * The command output should show the VPC ID in the selected database subnet group
8. Now run `describe-route-tables` command using the ID of the VPC returned at the previous step to describe the routes of the VPC main route table implicitly associated with the selected subnet:


```
aws ec2 describe-route-tables --region <region-name> --filters "Name=vpc-id,Values=<VPC-ID>" "Name=association.main,Values=true" --query 'RouteTables[*].Routes[]'

```



   * The command output returns the VPC main route table implicitly associated with database instance subnet ID. Check the `GatewayId` and `DestinationCidrBlock` attributes values returned in the output. If the route table contains any entries with the `GatewayId` value set to `igw-xxxxxxxx` and the `DestinationCidrBlock` value set to `0.0.0.0/0`, the selected RDS database instance was provisioned inside a public subnet, therefore is not running within a logically isolated environment and does not adhere to AWS security best practices.

**Verification**

Evidence or test output indicates that no RDS instance allows Public Accessibility.


---

### 6.5.2 Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)
**Platform:** Azure

**Rationale:** Azure SQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific data centers.

By default, for a SQL server, a Firewall exists with StartIp of 0.0.0.0 and EndIP of 0.0.0.0 allowing access to all the Azure services.

Additionally, a custom rule can be set up with StartIp of 0.0.0.0 and EndIP of 255.255.255.255 allowing access from ANY IP over the Internet.

In order to reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific data centers.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.1.2

**Evidence**

**From Azure Portal**



1. Go to `SQL servers`
2. For each SQL server
3. Click on `Networking`
4. Ensure that `Allow Azure services and resources to access this server` is `Unchecked`
5. Ensure that no firewall rule exists with
   * Start IP of `0.0.0.0`
   * or other combinations which allows access to wider public IP ranges

**From Azure CLI**

List all SQL servers


```
az sql server list
```


For each SQL server run the following command


```
az sql server firewall-rule list --resource-group <resource group name> --server <sql server name>
```


Ensure the output does not contain any firewall `allow` rules with a source of `0.0.0.0`, or any rules named `AllowAllWindowsAzureIps`

**From PowerShell**

Get the list of all SQL Servers


```
Get-AzSqlServer
```


For each Server


```
Get-AzSqlServerFirewallRule -ResourceGroupName <resource group name> -ServerName <server name>
```


Ensure that `StartIpAddress` is not set to `0.0.0.0`, `/0` or other combinations which allows access to wider public IP ranges including Windows Azure IP ranges. Also ensure that `FirewallRuleName` doesn't contain `AllowAllWindowsAzureIps` which is the rule created when the `Allow Azure services and resources to access this server` setting is enabled for that SQL Server.

**Verification**

Evidence or test output indicates that no Azure SQL Database instance allows ingress from the unrestricted internet.


---

### 6.5.3 Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses
**Platform:** Google

**Rationale:** To minimize attack surface on a Database server instance, only trusted/known and required IP(s) should be white-listed to connect to it.

An authorized network should not have IPs/networks configured to `0.0.0.0/0` which will allow access to the instance from anywhere in the world. Note that authorized networks apply only to instances with public IPs.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.5

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Click the instance name to open its `Instance details` page.
3. Under the `Configuration` section click `Edit configurations`
4. Under `Configuration options` expand the `Connectivity` section.
5. Ensure that no authorized network is configured to allow `0.0.0.0/0`.

**From Google Cloud CLI**



1. Get detailed configuration for every Cloud SQL database instance.


```
gcloud sql instances list --format=json
```


Ensure that the section `settings: ipConfiguration : authorizedNetworks` does not have any parameter `value` containing `0.0.0.0/0`.

**Verification**

Evidence or test output indicates that no Cloud SQL Database instances allow ingress from the unrestricted internet.


---

### 6.5.4 Ensure ‘Skip_show_database’ Database Flag for Cloud SQL MySQL Instance Is Set to ‘On’
**Platform:** Google

**Rationale:** 'skip_show_database' database flag prevents people from using the SHOW DATABASES statement if they do not have the SHOW DATABASES privilege. This can improve security if you have concerns about users being able to see databases belonging to other users. Its effect depends on the SHOW DATABASES privilege: If the variable value is ON, the SHOW DATABASES statement is permitted only to users who have the SHOW DATABASES privilege, and the statement displays all database names. If the value is OFF, SHOW DATABASES is permitted to all users, but displays the names of only those databases for which the user has the SHOW DATABASES or other privilege. This requirement is applicable to Mysql database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.1.2

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Ensure the database flag `skip_show_database` that has been set is listed under the `Database flags` section.

**From Google Cloud CLI**



1. List all Cloud SQL database Instances


```
gcloud sql instances list

```



2. Ensure the below command returns `on` for every Cloud SQL Mysql database instance


```
gcloud sql instances describe INSTANCE_NAME --format=json | jq '.settings.databaseFlags[] | select(.name=="skip_show_database")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL MySQL instance(s) have the Skip_show_database database flag set to on.


---

### 6.5.5 Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'
**Platform:** Google

**Rationale:** Use the `cross db ownership` for chaining option to configure cross-database ownership chaining for an instance of Microsoft SQL Server. This server option allows you to control cross-database ownership chaining at the database level or to allow cross-database ownership chaining for all databases. Enabling `cross db ownership` is not recommended unless all of the databases hosted by the instance of SQL Server must participate in cross-database ownership chaining and you are aware of the security implications of this setting. This requirement is applicable to SQL Server database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.3.2

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console.
2. Select the instance to open its `Instance Overview` page
3. Ensure the database flag `cross db ownership chaining` that has been set is listed under the `Database flags` section.

**From Google Cloud CLI**



1. Ensure the below command returns `off` for every Cloud SQL SQL Server database instance:


```
gcloud sql instances list --format=json | jq '.settings.databaseFlags[] | select(.name=="cross db ownership chaining")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL SQL Server instance(s) have the cross db ownership chaining database flag set to off.


---

### 6.5.6 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'
**Platform:** Google

**Rationale:** A contained database includes all database settings and metadata required to define the database and has no configuration dependencies on the instance of the Database Engine where the database is installed. Users can connect to the database without authenticating a login at the Database Engine level. Isolating the database from the Database Engine makes it possible to easily move the database to another instance of SQL Server. Contained databases have some unique threats that should be understood and mitigated by SQL Server Database Engine administrators. Most of the threats are related to the USER WITH PASSWORD authentication process, which moves the authentication boundary from the Database Engine level to the database level, hence this is recommended to disable this flag. This requirement is applicable to SQL Server database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.3.7

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Under the `Database flags` section, if the database flag `contained database authentication` is present, then ensure that it is not set to `on`.

**From Google Cloud CLI**



1. Ensure the below command doesn't return `on` for any Cloud SQL SQL Server database instance.


```
gcloud sql instances list --format=json | jq '.settings.databaseFlags[] | select(.name=="contained database authentication")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL SQL Server instance(s) have the contained database authentication database flag set to off.


---


## 6.6 Establish and Maintain a Secure Configuration Process


### Description

Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software.


### Audit


---

### 6.6.1 Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured
**Platform:** Google

**Rationale:** The `user options` option specifies global defaults for all users. A list of default query processing options is established for the duration of a user's work session. The user options option allows you to change the default values of the SET options (if the server's default settings are not appropriate).

A user can override these defaults by using the SET statement. You can configure user options dynamically for new logins. After you change the setting of user options, new login sessions use the new setting; current login sessions are not affected. This requirement is applicable to SQL Server database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.3.4

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Ensure the database flag `user options` containing any configuration values is not listed under the `Database flags` section.

**From Google Cloud CLI**



1. Ensure the below command returns empty result for every Cloud SQL SQL Server database instance


```
gcloud sql instances list --format=json | jq '.settings.databaseFlags[] | select(.name=="user options")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL SQL Server instance(s) do not have the user options database flag configured.


---

### 6.6.2 Ensure '3625 (trace flag)' database flag for all Cloud SQL Server instances is set to 'on'
**Platform:** Google

**Rationale:** Microsoft SQL Trace Flags are frequently used to diagnose performance issues or to debug stored procedures or complex computer systems, but they may also be recommended by Microsoft Support to address behavior that is negatively impacting a specific workload. All documented trace flags and those recommended by Microsoft Support are fully supported in a production environment when used as directed. `3625(trace log)` Limits the amount of information returned to users who are not members of the sysadmin fixed server role, by masking the parameters of some error messages using '******'. Setting this in a Google Cloud flag for the instance allows for security through obscurity and prevents the disclosure of sensitive information, hence it is recommended to set this flag globally to on to prevent the flag having been left off, or changed by bad actors. This requirement is applicable to SQL Server database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.3.6

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Ensure the database flag `3625` that has been set is listed under the `Database flags` section.

**From Google Cloud CLI**



1. Ensure the below command returns `on` for every Cloud SQL SQL Server database instance


```
gcloud sql instances list --format=json | jq '.settings.databaseFlags[] | select(.name=="3625")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL SQL Server instance(s) have the 3625 (trace flag) database flag configured on.


---


## 6.7 Implement and Manage a Firewall on Servers


### Description

Implement and manage a firewall on servers, where supported. Example implementations include a virtual firewall, operating system firewall, or a third-party firewall agent.


### Rationale

Firewalls help to prevent unauthorized users from accessing servers or sending malicious payloads to those servers.


### Audit


---

### 6.7.1 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled
**Platform:** Azure

**Rationale:** If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, set up firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.3.7

**Evidence**

**From Azure Portal**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/).
2. Go to `Azure Database for PostgreSQL servers`.
3. For each database, click on `Connection security`.
4. Under `Firewall rules`, ensure `Allow access to Azure services` is set to `No`.

**From Azure CLI**

Ensure the output of the below command does not include a rule with the name AllowAllWindowsAzureIps or "startIpAddress": "0.0.0.0" & "endIpAddress": "0.0.0.0",


```
az postgres server firewall-rule list --resource-group <resourceGroupName> --server <serverName>
```


**Verification**

Evidence or test output indicates that all PostgreSQL database server instances are configured with Allow access to Azure services disabled.


---


## 6.8 Securely Manage Enterprise Assets and Software


### Description

Securely manage enterprise assets and software. Example implementations include managing configuration through version-controlled-infrastructure-as-code and accessing administrative interfaces over secure network protocols, such as Secure Shell (SSH) and Hypertext Transfer Protocol Secure (HTTPS). Do not use insecure management protocols, such as Telnet (Teletype Network) and HTTP, unless operationally essential.


### Rationale

Secure management of assets and software guards against malicious users from being able to observe administrative communications with remote servers, possibly leading to compromise of that server, or from making configuration changes to introduce a security vulnerability into the server.


### Audit


---

### 6.8.1 Ensure Instance IP assignment is set to private
**Platform:** Google

**Rationale:** Setting database access only to private will reduce attack surface.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.2.9

**Evidence**

**From Google Cloud Console**



1. In the Google Cloud console, go to the `Cloud SQL Instances` page.
2. Open the `Overview page` of an instance by clicking the instance name.
3. Look for a field labeled `Private IP address` This field will only show if the Private IP option is checked. The IP listed should be in the private IP space.

**From Google Cloud CLI**



1. List cloud SQL instances


```
gcloud sql instances list --format="json" | jq '.[] | .connectionName,.ipAddresses'
```


Each instance listed should have a `type` of `PRIVATE`.



2. If you want to view a specific instance, note the <INSTANCE_NAME>(s) listed and run the following.


```
gcloud sql instances describe <INSTANCE_NAME> --format="json" | jq '.ipAddresses'
Type should be "PRIVATE"
 {
 "ipAddress": "10.21.0.2",
 "type": "PRIVATE"
 }
```


**Verification**

Evidence or test output indicates that all Cloud SQL instances have an IP Address of private.


---


## 6.9 Manage Default Accounts on Enterprise Assets and Software
### Description

Manage default accounts on enterprise assets and software, such as root, administrator, and other pre-configured vendor accounts. Example implementations can include: disabling default accounts or making them unusable.


### Rationale

Products typically ship with insecure defaults that, if not configured securely, can be used by malicious users to take over a system.


### Audit


---

### 6.9.1 Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges
**Platform:** Google

**Rationale:** At the time of MySQL Instance creation, not providing an administrative password allows anyone to connect to the SQL database instance with administrative privileges. The root password should be set to ensure only authorized users have these privileges.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.1.1

**Evidence**

**From Google Cloud CLI**



1. List All SQL database instances of type MySQL:


```
gcloud sql instances list --filter='DATABASE_VERSION:MYSQL* --project <project_id> --format="(NAME,PRIMARY_ADDRESS)"'

```



2. For every MySQL instance try to connect using the `PRIMARY_ADDRESS`, if available:


```
mysql -u root -h <mysql_instance_ip_address>
```


The command should return either an error message or a password prompt.

Sample Error message:


```
ERROR 1045 (28000): Access denied for user 'root'@'<Instance_IP>' (using password: NO)
```


If a command produces the `mysql>` prompt, the MySQL instance allows anyone to connect with administrative privileges without needing a password.

**Note:** The `No Password` setting is exposed only at the time of MySQL instance creation. Once the instance is created, the Google Cloud Platform Console does not expose the set to confirm whether a password for an administrative user is set to a MySQL instance.

**Verification**

Evidence or test output indicates that all MySQL instances are configured to prevent anyone from connecting with administrative privileges without needing a password.


---


## 6.10 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software
### Description

Uninstall or disable unnecessary services on enterprise assets and software, such as an unused file sharing service, web application module, or service function.


### Rationale

Uninstalling and disabling unnecessary services reduces the target area of your systems.


### Audit


---

### 6.10.1 Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'
**Platform:** Google

**Rationale:** The `remote access` option controls the execution of stored procedures from local or remote servers on which instances of SQL Server are running. The default value for this option is 1. This grants permission to run local stored procedures from remote servers or remote stored procedures from the local server. To prevent local stored procedures from being run from a remote server or remote stored procedures from being run on the local server, this must be disabled. The Remote Access option controls the execution of local stored procedures on remote servers or remote stored procedures on local servers. 'Remote access' functionality can be abused to launch a Denial-of-Service (DoS) attack on remote servers by off-loading query processing to a target, hence this should be disabled. This requirement is applicable to SQL Server database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.3.5

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Ensure the database flag `remote access` that has been set is listed under the `Database flags` section.

**From Google Cloud CLI**



1. Ensure the below command returns `off` for every Cloud SQL SQL Server database instance


```
gcloud sql instances list --format=json | jq '.settings.databaseFlags[] | select(.name=="remote access")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL SQL Server instance(s) have the `remote access` database flag configured to off.


---


### 6.11 Centralize Account Management


### Description

Centralize account management through a directory or identity service.


### Rationale

Centralizing makes administration simpler and therefore reduces risks related to unauthorized account creation or usage.


### Audit


---

### 6.11.1 Ensure that Azure Active Directory Admin is Configured for SQL Servers
**Platform:** Azure

**Rationale:** Azure Active Directory authentication is a mechanism to connect to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, identities of database users and other Microsoft services can be managed in one central location. Central ID management provides a single place to manage database users and simplifies permission management.



* It provides an alternative to SQL Server authentication.
* Helps stop the proliferation of user identities across database servers.
* Allows password rotation in a single place.
* Customers can manage database permissions using external (AAD) groups.
* It can eliminate storing passwords by enabling integrated Windows authentication and other forms of authentication supported by Azure Active Directory.
* Azure AD authentication uses contained database users to authenticate identities at the database level.
* Azure AD supports token-based authentication for applications connecting to SQL Database.
* Azure AD authentication supports ADFS (domain federation) or native user/password authentication for a local Azure Active Directory without domain synchronization.
* Azure AD supports connections from SQL Server Management Studio that use Active Directory Universal Authentication, which includes Multi-Factor Authentication (MFA). MFA includes strong authentication with a range of easy verification options — phone call, text message, smart cards with pin, or mobile app notification.


**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.1.4

**Evidence**

**From Azure Portal**



1. Go to `SQL servers`
2. For each SQL server, click on `Active Directory admin` under the Settings section
3. Ensure that a value has been set for `Admin Name` under the `Azure Active Directory admin` section

**From Azure CLI**

To list SQL Server Admins on a specific server:


```
az sql server ad-admin list --resource-group <resource-group> --server <server>
```


**From PowerShell**

Print a list of all SQL Servers to find which one you want to audit


```
Get-AzSqlServer
```


Audit a list of Administrators on a Specific Server


```
Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName <resource group name> -ServerName <server name>
```


Ensure Output shows `DisplayName` set to `AD account`.

**Verification**

Evidence or test output indicates that all SQL Servers are configured with an Azure AD Admin.


---


## 6.12 Perform Automated Application Patch Management
### Description

Perform application updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.


### Rationale

Patching remediates known vulnerabilities. Using automation makes this process routine and reduces the window of opportunity for attackers.


### Audit


---

### 6.12.1 Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances
**Platform:** AWS

**Rationale:** AWS RDS will occasionally deprecate minor engine versions and provide new ones for an upgrade. When the last version number within the release is replaced, the version changed is considered minor. With Auto Minor Version Upgrade feature enabled, the version upgrades will occur automatically during the specified maintenance window so your RDS instances can get the new features, bug fixes, and security patches for their database engines.

**External Reference:** CIS Amazon Web Services Foundations Benchmark v2.0.0, Section 2.3.2

**Evidence**

**From Console:**



1. Log in to the AWS management console and navigate to the RDS dashboard at [https://console.aws.amazon.com/rds/](https://console.aws.amazon.com/rds/).
2. In the left navigation panel, click on `Databases`.
3. Select the RDS instance
4. Click on the `Maintenance and backups` panel.
5. Under the `Maintenance` section, search for the Auto Minor Version Upgrade status.
   * If the current status is set to `Disabled`, means the feature is not set and the minor engine upgrades released will not be applied to the selected RDS instance

**From Command Line:**



1. Run `describe-db-instances` command to list all RDS database names, available in the selected AWS region:


```
aws rds describe-db-instances --region <regionName> --query 'DBInstances[*].DBInstanceIdentifier'

```



2. The command output should return each database instance identifier.
3. Run again `describe-db-instances` command using the RDS instance identifier returned earlier to determine the Auto Minor Version Upgrade status for the selected instance:


```
aws rds describe-db-instances --region <regionName> --db-instance-identifier <dbInstanceIdentifier> --query 'DBInstances[*].AutoMinorVersionUpgrade'

```



4. The command output should return the feature current status. If the current status is set to `true`, the feature is enabled and the minor engine upgrades will be applied to the selected RDS instance.

**Verification**

Evidence or test output indicates that auto minor version update feature is enabled for all RDS instances.


---


## 6.13 Collect Audit Logs
### Description

Collect audit logs. Ensure that logging, per the enterprise’s audit log management process, has been enabled across enterprise assets.


### Rationale

Having log files of what actions have taken place by users and also system events is fundamental to being able to detect security events.


### Audit


---

### 6.13.1 Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server
**Platform:** Azure

**Rationale:** Enabling `log_checkpoints` helps the PostgreSQL Database to `Log each checkpoint` in turn generates query and error logs. However, access to transaction logs is not supported. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.3.2

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu.
2. Go to `Azure Database for PostgreSQL servers`.
3. For each database, click on `Server parameters`.
4. Search for `log_checkpoints`.
5. Ensure that value is set to `ON`.

**From Azure CLI**

Ensure value is set to `ON`


```
az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_checkpoints
```


**From PowerShell**

Ensure value is set to `ON`


```
Get-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_checkpoints
```


**Verification**

Evidence or test output indicates that all PostgreSQL instances are configured with the `log_checkpoints` setting `on`.


---

### 6.13.2 Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server
**Platform:** Azure

**Rationale:** Enabling `log_connections` helps PostgreSQL Database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.3.3

**Evidence**

**From Azure Portal**



1. Login to Azure Portal using [https://portal.azure.com](https://portal.azure.com/).
2. Go to `Azure Database for PostgreSQL servers`.
3. For each database, click on `Server parameters`.
4. Search for `log_connections`.
5. Ensure that value is set to `ON`.

**From Azure CLI**

Ensure `log_connections` value is set to `ON`


```
az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_connections
```


**From PowerShell**

Ensure `log_connections` value is set to `ON`


```
Get-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_connections
```


**Verification**

Evidence or test output indicates that all PostgreSQL instances are configured with the `log_connections` setting `on`.


---

### 6.13.3 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server
**Platform:** Azure

**Rationale:** Enabling `log_disconnections` helps PostgreSQL Database to `Logs end of a session`, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.3.4

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu
2. Go to `Azure Database` for `PostgreSQL servers`
3. For each database, click on `Server parameters`
4. Search for `log_disconnections`.
5. Ensure that value is set to `ON`.

**From Azure CLI**

Ensure `log_disconnections` value is set to `ON`


```
az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_disconnections
```


**From PowerShell**

Ensure `log_disconnections` value is set to `ON`


```
Get-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_disconnections
```


**Verification**

Evidence or test output indicates that all PostgreSQL instances are configured with the `log_disconnections` setting `on`.


---


## 6.14 Ensure Adequate Audit Log Storage
### Description

Ensure that logging destinations maintain adequate storage to comply with the enterprise’s audit log management process.


### Rationale

Once configured, logs may generate large volumes of data. Organizations must ensure that logs are preserved according to the organization's retention policy and that there is sufficient storage for this requirement.


### Audit


---

### 6.14.1 Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server
**Platform:** Azure

**Rationale:** Configuring `log_retention_days` determines the duration in days that `Azure Database for PostgreSQL` retains log files. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.3.6

**Evidence**

**From Azure Portal**



1. From Azure Home select the Portal Menu.
2. Go to `Azure Database for PostgreSQL servers`.
3. For each database, click on `Server parameters`.
4. Search for `log_retention_days`.
5. Ensure that the `value` is between 4 and 7 (inclusive).

**From Azure CLI**

Ensure `log_retention_days` value is greater than 3.


```
az postgres server configuration show --resource-group <resourceGroupName> --server-name <serverName> --name log_retention_days
```


**From Powershell**

Ensure `log_retention_days` value is greater than 3.


```
Get-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_retention_days
```


**Verification**

Evidence or test output indicates that all PostgreSQL instances are configured with the `log_retention_days` setting of 3 days or greater.


---


## 6.15 Collect Detailed Audit Logs


### Description

Configure detailed audit logging for enterprise assets containing sensitive data. Include event source, date, username, timestamp, source addresses, destination addresses, and other useful elements that could assist in a forensic investigation.


### Rationale

Detailed logs with timestamps provide a record of user activity, system events, and application actions. This allows administrators to identify suspicious activity, potential security breaches, and unauthorized access attempts.


### Audit


---

### 6.15.1 Ensure that 'Auditing' is set to 'On'
**Platform:** Azure

**Rationale:** The Azure platform allows a SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted.

Auditing tracks database events and writes them to an audit log in the Azure storage account. It also helps to maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.

**External Reference:** CIS Microsoft Azure Foundations Benchmark v2.0.0, Section 4.1.1

**Evidence**

**From Azure Portal**



1. Go to `SQL servers`
2. For each server instance
3. Click on `Auditing`
4. Ensure that `Enable Azure SQL Auditing` is set to `On`

**From PowerShell**

Get the list of all SQL Servers


```
Get-AzSqlServer
```


For each Server


```
Get-AzSqlServerAudit -ResourceGroupName <ResourceGroupName> -ServerName <SQLServerName>
```


Ensure that `BlobStorageTargetState`, `EventHubTargetState`, or `LogAnalyticsTargetState` is set to `Enabled`.

**Verification**

Evidence or test output indicates that all SQL Server instances are configured with auditing set to on.


---

### 6.15.2 Ensure That the ‘Log_connections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’
**Platform:** Google

**Rationale:** PostgreSQL does not log attempted connections by default. Enabling the `log_connections` setting will create log entries for each attempted connection as well as successful completion of client authentication which can be useful in troubleshooting issues and to determine any unusual connection attempts to the server. This requirement is applicable to PostgreSQL database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.2.2

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page.
3. Go to the `Configuration` card.
4. Under `Database flags`, check the value of `log_connections` flag to determine if it is configured as expected.

**From Google Cloud CLI**



1. Ensure the below command returns `on` for every Cloud SQL PostgreSQL database instance:


```
gcloud sql instances list --format=json | jq '.settings.databaseFlags[] | select(.name=="log_connections")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL PostgreSQL instance(s) have the `log_connections` database flag configured to on.


---

### 6.15.3 Ensure That the ‘Log_disconnections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’
**Platform:** Google

**Rationale:** PostgreSQL does not log session details such as duration and session end by default. Enabling the `log_disconnections` setting will create log entries at the end of each session which can be useful in troubleshooting issues and determine any unusual activity across a time period. The `log_disconnections` and `log_connections` work hand in hand and generally, the pair would be enabled/disabled together. This requirement is applicable to PostgreSQL database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.2.3

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Go to the `Configuration` card.
4. Under `Database flags`, check the value of `log_disconnections` flag is configured as expected.

**From Google Cloud CLI**



1. Ensure the below command returns `on` for every Cloud SQL PostgreSQL database instance:


```
gcloud sql instances list --format=json | jq '.[].settings.databaseFlags[] | select(.name=="log_disconnections")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL PostgreSQL instance(s) have the `log_disconnections` database flag configured to on.


---

### 6.15.4 Ensure that the ‘Log_min_messages’ Flag for a Cloud SQL PostgreSQL Instance is set at minimum to 'Warning'
**Platform:** Google

**Rationale:** Auditing helps in troubleshooting operational problems and also permits forensic analysis. If `log_min_messages` is not set to the correct value, messages may not be classified as error messages appropriately. An organization will need to decide their own threshold for logging `log_min_messages` flag.

This requirement is applicable to PostgreSQL database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.2.5

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page.
3. Go to the `Configuration` card.
4. Under `Database flags`, check the value of `log_min_messages` flag is in accordance with the organization's logging policy.

**From Google Cloud CLI**



1. Use the below command for every Cloud SQL PostgreSQL database instance to verify that the value of `log_min_messages` is in accordance with the organization's logging policy.


```
gcloud sql instances list --format=json | jq '.settings.databaseFlags[] | select(.name=="log_min_messages")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL PostgreSQL instance(s) have the `log_min_messages` database flag set at the level of Warning (or more verbose).

---

### 6.15.5 Ensure ‘Log_min_error_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘Error’ or Stricter
**Platform:** Google

**Rationale:** Auditing helps in troubleshooting operational problems and also permits forensic analysis. If `log_min_error_statement` is not set to the correct value, messages may not be classified as error messages appropriately. Considering general log messages as error messages would make it difficult to find actual errors and considering only stricter severity levels as error messages may skip actual errors to log their SQL statements. The `log_min_error_statement` flag should be set to `ERROR` or stricter. This requirement is applicable to PostgreSQL database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.2.6

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page
3. Go to `Configuration` card
4. Under `Database flags`, check the value of `log_min_error_statement` flag is configured as to `ERROR` or stricter.

**From Google Cloud CLI**



1. Use the below command for every Cloud SQL PostgreSQL database instance to verify the value of `log_min_error_statement` is set to `ERROR` or stricter.


```
gcloud sql instances list --format=json | jq '.[].settings.databaseFlags[] | select(.name=="log_min_error_statement")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL PostgreSQL instance(s) have the `log_min_error_statement` database flag set to Error or stricter.


---

### 6.15.6 Ensure That the ‘Log_min_duration_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘-1′ (Disabled)
**Platform:** Google

**Rationale:** Logging SQL statements may include sensitive information that should not be recorded in logs. This requirement is applicable to PostgreSQL database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.2.7

**Evidence**

**From Google Cloud Console**



1. Go to the Cloud SQL Instances page in the Google Cloud Console by visiting [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Instance Overview` page.
3. Go to the `Configuration` card.
4. Under `Database flags`, check that the value of `log_min_duration_statement` flag is set to `-1`.

**From Google Cloud CLI**



1. Use the below command for every Cloud SQL PostgreSQL database instance to verify the value of `log_min_duration_statement` is set to `-1`.


```
gcloud sql instances list --format=json| jq '.settings.databaseFlags[] | select(.name=="log_min_duration_statement")|.value'
```


**Verification**

Evidence or test output indicates that all Cloud SQL PostgreSQL instance(s) have the `log_min_duration_statement` database flag set to -1 (Disabled).


---

### 6.15.7 Ensure That 'cloudsql.enable_pgaudit' Database Flag for each Cloud Sql Postgresql Instance Is Set to 'on' For Centralized Logging
**Platform:** Google

**Rationale:** As numerous other requirements in this section consist of turning on flags for logging purposes, your organization will need a way to manage these logs. You may have a solution already in place. If you do not, consider installing and enabling the open source pgaudit extension within PostgreSQL and enabling its corresponding flag of `cloudsql.enable_pgaudit`. This flag and installing the extension enables database auditing in PostgreSQL through the open-source pgAudit extension. This extension provides detailed session and object logging to comply with government, financial, & ISO standards and provides auditing capabilities to mitigate threats by monitoring security events on the instance. Enabling the flag and settings later in this requirement will send these logs to Google Logs Explorer so that you can access them in a central location. This requirement is applicable only to PostgreSQL database instances.

**External Reference:** CIS Google Cloud Platform Foundation Benchmark v2.0.0, Section 6.2.8

**Evidence**

**Determining if the pgAudit Flag is set to 'on'**

**From Google Cloud Console**



1. Go to [https://console.cloud.google.com/sql/instances](https://console.cloud.google.com/sql/instances).
2. Select the instance to open its `Overview` page.
3. Click `Edit`.
4. Scroll down and expand `Flags`.
5. Ensure that `cloudsql.enable_pgaudit` flag is set to `on`.

**From Google Cloud CLI**

Run the command by providing `<INSTANCE_NAME>`. Ensure the value of the flag is `on`.


```
gcloud sql instances describe <INSTANCE_NAME> --format="json" | jq '.settings|.|.databaseFlags[]|select(.name=="cloudsql.enable_pgaudit")|.value'
```


**Determine if the pgAudit extension is installed**



1. Connect to the server running PostgreSQL or through a SQL client of your choice.
2. Via command line open the PostgreSQL shell by typing `psql`
3. Run the following command


```
SELECT *
FROM pg_extension;

```



1. If pgAudit is in this list. If so, it is installed.

**Determine if Data Access Audit logs are enabled for your project and have sufficient privileges**



1. From the homepage open the hamburger menu in the top left.
2. Scroll down to `IAM & Admin`and hover over it.
3. In the menu that opens up, select `Audit Logs`
4. In the middle of the page, in the search box next to `filter` search for `Cloud Composer API`
5. Select it, and ensure that both 'Admin Read' and 'Data Read' are checked.

**Determine if logs are being sent to Logs Explorer**



1. From the Google Console home page, open the hamburger menu in the top left.
2. In the menu that pops open, scroll down to Logs Explorer under Operations.
3. In the query box, paste the following and search


```
resource.type="cloudsql_database"
logName="projects/<your-project-name>/logs/cloudaudit.googleapis.com%2Fdata_access"
protoPayload.request.@type="type.googleapis.com/google.cloud.sql.audit.v1.PgAuditEntry"

```



4. If it returns any log sources, they are correctly set up.

**Verification**

Evidence or test output indicates that all Cloud SQL PostgreSQL instance(s) have the `cloudsql.enable_pgaudit` database flag set to `on` for centralized logging.


---

### 6.15.8 Database logging should be enabled
**Platform:** AWS

**Rationale:** RDS databases should have relevant logs enabled. Database logging provides detailed records of requests made to RDS. Database logs can assist with security and access audits and can help to diagnose availability issues.

**External Reference:** [AWS Security Hub - RDS.9](https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html#rds-9)

**Evidence**

Todo

**Verification**

Evidence or test output indicates that database logging is enabled for all database instances.


---
