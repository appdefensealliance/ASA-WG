# App Defense Alliance Cloud App and Config Audit Summary
## Audit Requirements Per Platform

Version 0.7 - June 10, 2024




# Table of Contents
[Overview](#overview)

[1 AWS](#aws)

[2 Azure](#azure)

[3 Google](#google)


# Overview
This document provides  summary of the audit requirements sorted by platforms and is meant to be used as a supliment to the Cloud App and Config Specification and Cloud App and Config Test Guide.


# 1 AWS
| Spec | Description |
|---|----------|
| 1.2.1 | Ensure that all AWS Lambda functions are configured to use a current (not deprecated) runtime | 1.2.2 | Azure | Ensure that all Azure Functions are configured to use a current (not deprecated) runtime |
| 2.2.1 | Ensure a support role has been created to manage incidents with AWS Support |
| 2.3.1 | Maintain current contact details |
| 2.3.2 | Ensure security contact information is registered |
| 2.7.1 | Ensure no 'root' user account access key exists |
| 2.7.2 | Do not setup access keys during initial user setup for all IAM users that have a console password |
| 2.7.3 | Ensure IAM policies that allow full "_:_" administrative privileges are not attached |
| 2.8.2 | Ensure IAM password policy requires minimum length of 14 or greater |
| 2.8.3 | Ensure there is only one active access key available for any single IAM user |
| 2.8.4 | Ensure access keys are rotated every 90 days or less |
| 2.9.1 | Ensure IAM password policy prevents password reuse |
| 2.10.1 | Ensure credentials unused for 45 days or greater are disabled |
| 2.11.1 | Eliminate use of the 'root' user for administrative and daily tasks |
| 2.16.1 | Ensure MFA is enabled for the 'root' user account |
| 2.18.1 | Ensure IAM Users Receive Permissions Only Through Groups |
| 3.4.1 | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket |
| 3.5.1 | Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible  |
| 3.9.1 | Ensure management console sign-in without MFA is monitored |
| 3.9.2 | Ensure usage of 'root' account is monitored |
| 3.9.3 | Ensure IAM policy changes are monitored |
| 3.9.4 | Ensure CloudTrail configuration changes are monitored |
| 3.9.5 | Ensure S3 bucket policy changes are monitored |
| 3.9.6 | Ensure changes to network gateways are monitored |
| 3.9.7 | Ensure route table changes are monitored |
| 3.9.8 | Ensure VPC changes are monitored |
| 3.9.9 | Ensure AWS Organizations changes are monitored |
| 3.11.1 | Ensure CloudTrail is enabled in all regions |
| 3.11.2 | Ensure CloudTrail trails are integrated with CloudWatch Logs |
| 4.2.5 | Ensure that EC2 Metadata Service only allows IMDSv2 |
| 4.3.5 | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports |
| 4.3.6 | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports |
| 4.3.7 | Ensure no security groups allow ingress from ::/0 to remote server administration ports |
| 5.4.1 | Ensure EBS Volume Encryption is Enabled in all Regions |
| 5.4.2 | Ensure that encryption is enabled for EFS file systems |
| 5.5.1 | Ensure that S3 Buckets are configured with 'Block public access (bucket settings)' |
| 6.4.1 | Ensure that encryption-at-rest is enabled for RDS Instances |
| 6.5.1 | Ensure that public access is not given to RDS Instance |
| 6.12.1 | Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances |
| 6.15.8 | Database logging should be enabled |







# 2 Azure
| Spec | Description |
|---|----------|
| 1.1.1 | Ensure that Only Approved Extensions Are Installed |
| 1.2.3 | Ensure That 'PHP version' is the Latest, If Used to Run the Web App |
| 1.2.4 | Ensure that 'Python version' is the Latest Stable Version, if Used to Run the Web App |
| 1.2.5 | Ensure that 'Java version' is the latest, if used to run the Web App |
| 1.2.6 | Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App |
| 1.3.1 | Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service |
| 1.3.2 | Ensure Web App is using the latest version of TLS encryption |
| 1.3.3 | Ensure FTP deployments are Disabled |
| 1.4.1 | Ensure Virtual Machines are utilizing Managed Disks |
| 1.8.1 | Ensure that Register with Azure Active Directory is enabled on App Service |
| 2.1.1 | Ensure the Key Vault is Recoverable |
| 2.4.1 | Ensure <code>User consent for applications</code> is set to <code>Do not allow user consent</code> |
| 2.4.2 | Ensure that 'Users can add gallery apps to My Apps' is set to 'No' |
| 2.4.3 | Ensure That ‘Users Can Register Applications’ Is Set to ‘No’ |
| 2.5.1 | Ensure that the Expiration Date that is no more than 90 days in the future is set for all Keys in RBAC Key Vaults |
| 2.5.2 | Ensure that the Expiration Date that is no more than 90 days in the future is set for all Keys in Non-RBAC Key Vaults. |
| 2.5.3 | Ensure that the Expiration Date that is no more than 90 days in the future is set for all Secrets in RBAC Key Vaults |
| 2.5.4 | Ensure that the Expiration Date that is no more than 90 days in the future is set for all Secrets in Non-RBAC Key Vaults |
| 2.7.4 | Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects' |
| 2.8.1 | Ensure Security Defaults is enabled on Azure Active Directory |
| 2.9.2 | Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization |
| 2.10.2 | Ensure Guest Users Are Reviewed on a Regular Basis |
| 2.11.2 | Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes' |
| 2.11.3 | Ensure That 'Restrict access to Azure AD administration portal' is Set to 'Yes' |
| 2.11.4 | Ensure That No Custom Subscription Administrator Roles Exist |
| 2.13.1 | Ensure that 'Number of days before users are asked to re-confirm their authentication information' is set to '90' |
| 2.14.1 | Ensure That 'Number of methods required to reset' is set to '2' |
| 2.14.2 | Ensure that 'Require Multi-Factor Authentication to register or join devices with Azure AD' is set to 'Yes' |
| 2.14.3 | Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users |
| 2.14.4 | Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled |
| 2.14.5 | Ensure that A Multi-factor Authentication Policy Exists for All Users |
| 2.14.6 | Ensure Multi-factor Authentication is Required for Risky Sign-ins |
| 2.14.8 | Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users |
| 2.15.1 | Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups |
| 2.15.2 | Ensure Multi-factor Authentication is Required for Azure Management |
| 2.17.1 | Ensure that 'Notify users on password resets?' is set to 'Yes' |
| 3.2.1 | Ensure That 'Notify about alerts with the following severity' is Set to 'High' |
| 3.3.1 | Ensure That 'All users with the following roles' is set to 'Owner' |
| 3.3.2 | Ensure 'Additional email addresses' is Configured with a Security Contact Email |
| 3.5.2 | Ensure the Storage Container Storing the Activity Logs is not Publicly Accessible |
| 3.6.1 | Ensure Any of the ASC Default Policy Settings are Not Set to 'Disabled' |
| 3.7.1 | Ensure that Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed' |
| 3.8.1 | Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On' |
| 3.11.3 | Ensure that Azure Monitor Resource Logging is Enabled for All Services that Manage, Store, or Secure Sensitive Data |
| 3.11.4 | Ensure that logging for Azure Key Vault is 'Enabled' |
| 3.11.5 | Ensure that Activity Log Alert exists for Create Policy Assignment |
| 3.11.6 | Ensure that Activity Log Alert exists for Delete Policy Assignment |
| 3.11.7 | Ensure that Activity Log Alert exists for Create or Update Network Security Group |
| 3.11.8 | Ensure that Activity Log Alert exists for Delete Network Security Group |
| 3.11.9 | Ensure that Activity Log Alert exists for Create or Update Security Solution |
| 3.11.10 | Ensure that Activity Log Alert exists for Delete Security Solution |
| 3.11.11 | Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule |
| 3.11.12 | Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule |
| 3.11.13 | Ensure that Activity Log Alert exists for Create or Update Public IP Address rule |
| 3.11.14 | Ensure that Activity Log Alert exists for Delete Public IP Address rule |
| 4.3.1 | Ensure that RDP access from the Internet is evaluated and restricted |
| 4.3.2 | Ensure that SSH access from the Internet is evaluated and restricted |
| 5.1.1 | Ensure Soft Delete is Enabled for Azure Containers and Blob Storage |
| 5.2.1 | Ensure Default Network Access Rule for Storage Accounts is Set to Deny |
| 5.3.1 | Ensure that 'Secure transfer required' is set to 'Enabled' |
| 5.3.2 | Ensure the "Minimum TLS version" for storage accounts is set to "Version 1.2" |
| 5.5.2 | Ensure that 'Public access level' is disabled for storage accounts with blob containers |
| 5.6.1 | Ensure that 'Enable key rotation reminders' is enabled for each Storage Account |
| 5.7.1 | Ensure that Storage Account Access Keys are Periodically Regenerated |
| 5.8.1 | Ensure that Shared Access Signature Tokens Expire Within an Hour |
| 6.3.1 | Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server |
| 6.3.2 | Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server |
| 6.3.3 | Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server |
| 6.4.2 | Ensure that 'Data encryption' is set to 'On' on a SQL Database |
| 6.5.2 | Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) |
| 6.7.1 | Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled |
| 6.11.1 | Ensure that Azure Active Directory Admin is Configured for SQL Servers |
| 6.13.1 | Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server |
| 6.13.2 | Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server |
| 6.13.3 | Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server |
| 6.14.1 | Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server |
| 6.15.1 | Ensure that 'Auditing' is set to 'On' |



# 3 Google
| Spec | Description |
|---|----------|
| 1.2.6 | Ensure that all GCP Cloud functions are configured to use a current (not deprecated) runtime |
| 1.3.4 | Ensure “Block Project-Wide SSH Keys” Is Enabled for VM Instances |
| 1.5.1 | Ensure That IP Forwarding Is Not Enabled on Instances |
| 1.6.1 | Ensure That Instances Are Not Configured To Use the Default Service Account |
| 1.6.2 | Ensure That Instances Are Not Configured To Use the Default Service Account With Full Access to All Cloud APIs |
| 1.7.1 | Ensure ‘Enable Connecting to Serial Ports’ Is Not Enabled for VM Instance |
| 1.8.2 | Ensure Oslogin Is Enabled for a Project |
| 2.3.5 | Ensure Essential Contacts is Configured for Organization |
| 2.6.1 | Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager |
| 2.7.5 | Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level |
| 2.7.6 | Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible |
| 2.11.5 | Ensure That Service Account Has No Admin Privileges |
| 2.12.1 | Ensure that Corporate Login Credentials are Used |
| 2.14.7 | Ensure that Multi-Factor Authentication is 'Enabled' for All Non-Service Accounts |
| 3.1.1 | Ensure Cloud Asset Inventory Is Enabled |
| 3.9.10 | Ensure That Cloud Audit Logging Is Configured Properly |
| 3.9.11 | Googel | Ensure That Cloud DNS Logging Is Enabled for All VPC Networks |
| 3.10.1 | Ensure That Sinks Are Configured for All Log Entries |
| 3.10.2 | Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes |
| 3.10.3 | Googel | Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes |
| 3.10.4 | Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes |
| 4.1.1 | Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites |
| 4.2.1 | Ensure Legacy Networks Do Not Exist for Older Projects |
| 4.2.2 | Ensure That DNSSEC Is Enabled for Cloud DNS |
| 4.2.3 | Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC |
| 4.2.4 | Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC |
| 4.3.3 | Ensure That SSH Access Is Restricted From the Internet |
| 4.3.4 | Ensure That RDP Access Is Restricted From the Internet |
| 5.5.3 | Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible |
| 6.1.1 | Ensure That the ‘Local_infile’ Database Flag for a Cloud SQL MySQL Instance Is Set to ‘Off’ |
| 6.2.1 | Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off' |
| 6.3.4 | Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL |
| 6.5.3 | Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses |
| 6.5.4 | Ensure ‘Skip_show_database’ Database Flag for Cloud SQL MySQL Instance Is Set to ‘On’ |
| 6.5.5 | Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off' |
| 6.5.6 | Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off' |
| 6.6.1 | Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured |
| 6.6.2 | Ensure '3625 (trace flag)' database flag for all Cloud SQL Server instances is set to 'on' |
| 6.8.1 | Ensure Instance IP assignment is set to private |
| 6.9.1 | Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges |
| 6.10.1 | Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off' |
| 6.15.2 | Ensure That the ‘Log_connections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’ |
| 6.15.3 | Ensure That the ‘Log_disconnections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’ |
| 6.15.4 | Ensure that the ‘Log_min_messages’ Flag for a Cloud SQL PostgreSQL Instance is set at minimum to 'Warning' |
| 6.15.5 | Ensure ‘Log_min_error_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘Error’ or Stricter |
| 6.15.6 | Ensure That the ‘Log_min_duration_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘-1′ (Disabled) |
| 6.15.7 | Ensure That 'cloudsql.enable_pgaudit' Database Flag for each Cloud Sql Postgresql Instance Is Set to 'on' For Centralized Logging |

