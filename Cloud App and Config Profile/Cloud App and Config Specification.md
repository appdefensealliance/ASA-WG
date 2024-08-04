# App Defense Alliance Cloud Profile
## Specification

Version 0.5 - April 8, 2024

# Contributors
The App Defense Alliance Application Security Assessment Working Group (ASA WG) would like to thank the following individuals for their contributions to this specification.

### Application Security Assessment Working Group Leads
* Alex Duff (Meta) - ASA WG Chair
* Brooke Davis (Google) - ASA WG Vice Chair

### Cloud Profile Leads
* Alex Duff (Meta)
* Brad Ree (Google)

### Contributors
* Cody Martin (Leviathan)
* Juan Manuel Martinez Hernandez (Dekra)
* Julia McLaughlin (Google)
* Justin Gerace (Meta)
* Rennie deGraaf (NCC Group)
* Rupesh Nair (Netsentries )
* Soledad Antelada Toledano (Google)
* Tony Balkan (Microsoft)
* Viktor Sytnik (Leviathan)

# Table of Contents


1 [Compute](#1-compute)

1.1 [Establish and Maintain a Software Inventory](#11-establish-and-maintain-a-software-inventory)

1.2 [Ensure Authorized Software is Currently Supported](#12-ensure-authorized-software-is-currently-supported)

1.3 [Encrypt Confidential Data in Transit](#13-encrypt-confidential-data-in-transit)

1.4 [Encrypt Confidential Data at Rest](#14-encrypt-confidential-data-at-rest)

1.5 [Implement and Manage a Firewall on Servers](#15-implement-and-manage-a-firewall-on-servers)

1.6 [Manage Default Accounts on Enterprise Assets and Software](#16-manage-default-accounts-on-enterprise-assets-and-software)

1.7 [Uninstall or Disable Unnecessary Services on Enterprise Assets and Software](#17-uninstall-or-disable-unnecessary-services-on-enterprise-assets-and-software)

1.8 [Centralize Account Management](#18-centralize-account-management)

2 [Identity and Access Management](#2-identity-and-access-management)

2.1 [Establish and Maintain a Data Recovery Process](#21-establish-and-maintain-a-data-recovery-process)

2.2 [Designate Personnel to Manage Incident Handling](#22-designate-personnel-to-manage-incident-handling)

2.3 [Establish and Maintain Contact Information for Reporting Security Incidents](#23-establish-and-maintain-contact-information-for-reporting-security-incidents)

2.4 [Address Unauthorized Software](#24-address-unauthorized-software)

2.5 [Establish and Maintain a Data Management Process](#25-establish-and-maintain-a-data-management-process)

2.6 [Encrypt Confidential Data at Rest](#26-encrypt-confidential-data-at-rest)

2.7 [Configure Data Access Control Lists](#27-configure-data-access-control-lists)

2.8 [Establish and Maintain a Secure Configuration Process](#28-establish-and-maintain-a-secure-configuration-process)

2.9 [Use Unique Passwords](#29-use-unique-passwords)

2.10 [Disable Dormant Accounts](#210-disable-dormant-accounts)

2.11 [Restrict Administrator Privileges to Dedicated Administrator Accounts](#211-restrict-administrator-privileges-to-dedicated-administrator-accounts)

2.12 [Centralize Account Management](#212-centralize-account-management)

2.13 [Establish an Access Revoking Process](#213-establish-an-access-revoking-process)

2.14 [Require MFA for Externally-Exposed Applications](#214-require-mfa-for-externally-exposed-applications)

2.15 [Require MFA for Remote Network Access](#215-require-mfa-for-remote-network-access)

2.16 [Require MFA for Administrative Access](#216-require-mfa-for-administrative-access)

2.17 [Centralize Access Control](#217-centralize-access-control)

2.18 [Define and Maintain Role-Based Access Control](#218-define-and-maintain-role-based-access-control)

3 [Logging and Monitoring](#3-logging-and-monitoring)

3.1 [Establish and Maintain Detailed Enterprise Asset Inventory](#31-establish-and-maintain-detailed-enterprise-asset-inventory)

3.2 [Tune Security Event Alerting Thresholds](#32-tune-security-event-alerting-thresholds)

3.3 [Establish and Maintain Contact Information for Reporting Security Incidents](#33-establish-and-maintain-contact-information-for-reporting-security-incidents)

3.4 [Log Confidential Data Access](#34-log-confidential-data-access)

3.5 [Configure Data Access Control Lists](#35-configure-data-access-control-lists)

3.6 [Establish and Maintain a Secure Configuration Process](#36-establish-and-maintain-a-secure-configuration-process)

3.7 [Perform Automated Operating System Patch Management](#37-perform-automated-operating-system-patch-management)

3.8 [Perform Automated Vulnerability Scans of Internal Enterprise Assets](#38-perform-automated-vulnerability-scans-of-internal-enterprise-assets)

3.9 [Conduct Audit Log Reviews](#39-conduct-audit-log-reviews)

3.10 [Collect Audit Logs](#310-collect-audit-logs)

3.11 [Collect Detailed Audit Logs](#311-collect-detailed-audit-logs)

4 [Networking](#4-networking)

4.1 [Encrypt Confidential Data in Transit](#41-encrypt-confidential-data-in-transit)

4.2 [Establish and Maintain a Secure Configuration Process for Network Infrastructure](#42-establish-and-maintain-a-secure-configuration-process-for-network-infrastructure)

4.3 [Implement and Manage a Firewall on Servers](#43-implement-and-manage-a-firewall-on-servers)

5 [Storage](#5-storage)

5.1 [Establish and Maintain a Data Recovery Process](#51-establish-and-maintain-a-data-recovery-process)

5.2 [Establish and Maintain a Secure Network Architecture](#52-establish-and-maintain-a-secure-network-architecture)

5.3 [Encrypt Confidential Data in Transit](#53-encrypt-confidential-data-in-transit)

5.4 [Encrypt Confidential Data at Rest](#54-encrypt-confidential-data-at-rest)

5.5 [Configure Data Access Control Lists](#55-configure-data-access-control-lists)

5.6 [Establish and Maintain a Secure Configuration Process](#56-establish-and-maintain-a-secure-configuration-process)

5.7 [Securely Manage Enterprise Assets and Software](#57-securely-manage-enterprise-assets-and-software)

5.8 [Establish an Access Revoking Process](#58-establish-an-access-revoking-process)

6 [Database Services](#6-database-services)

6.1 [Use Standard Hardening Configuration Templates for Application Infrastructure](#61-use-standard-hardening-configuration-templates-for-application-infrastructure)

6.2 [Allowlist Authorized Scripts](#62-allowlist-authorized-scripts)

6.3 [Encrypt Confidential Data in Transit](#63-encrypt-confidential-data-in-transit)

6.4 [Encrypt Confidential Data at Rest](#64-encrypt-confidential-data-at-rest)

6.5 [Configure Data Access Control Lists](#65-configure-data-access-control-lists)

6.6 [Establish and Maintain a Secure Configuration Process](#66-establish-and-maintain-a-secure-configuration-process)

6.7 [Implement and Manage a Firewall on Servers](#67-implement-and-manage-a-firewall-on-servers)

6.8 [Securely Manage Enterprise Assets and Software](#68-securely-manage-enterprise-assets-and-software)

6.9 [Manage Default Accounts on Enterprise Assets and Software](#69-manage-default-accounts-on-enterprise-assets-and-software)

6.10 [Uninstall or Disable Unnecessary Services on Enterprise Assets and Software](#610-uninstall-or-disable-unnecessary-services-on-enterprise-assets-and-software)

6.11 [Centralize Account Management](#611-centralize-account-management)

6.12 [Perform Automated Application Patch Management](#612-perform-automated-application-patch-management)

6.13 [Collect Audit Logs](#613-collect-audit-logs)

6.14 [Ensure Adequate Audit Log Storage](#614-ensure-adequate-audit-log-storage)

6.15 [Collect Detailed Audit Logs](#615-collect-detailed-audit-logs)




# Overview

This document provides prescriptive guidance for configuring security options for a subset of cloud services offered by Amazon Web Services, Google Cloud Platform, and Microsoft Azure. This profile emphasizes foundational, testable, and architecture agnostic settings that are suitable for applications that process non-pubilc data such as user data, user device data, company data, or other types of confidential information (excluding highly sensitive financial or medical PII).


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
| Spec | Platform | Description |
|---|-----|----------|
| 1.1.1 | Azure | Ensure that Only Approved Extensions Are Installed |

---
## 1.2 Ensure Authorized Software is Currently Supported


### Description

Ensure that only currently supported software is designated as authorized in the software inventory for enterprise assets. If software is unsupported, yet necessary for the fulfillment of the enterprise’s mission, document an exception detailing mitigating controls and residual risk acceptance. For any unsupported software without an exception documentation, designate as unauthorized. Review the software list to verify software support at least monthly, or more frequently.


### Rationale

When software ceases to be supported, the maintainer of that software will no longer issue patches to remediate security vulnerabilities that are discovered in it. This leaves any organization relying on that software at a high risk of a security incident.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 1.2.1 | AWS | Ensure that all AWS Lambda functions are configured to use a current (not deprecated) runtime | 1.2.2 | Azure | Ensure that all Azure Functions are configured to use a current (not deprecated) runtime |
| 1.2.3 | Azure | Ensure That 'PHP version' is the Latest, If Used to Run the Web App |
| 1.2.4 | Azure | Ensure that 'Python version' is the Latest Stable Version, if Used to Run the Web App |
| 1.2.5 | Azure | Ensure that 'Java version' is the latest, if used to run the Web App |
| 1.2.6 | Azure | Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App |
| 1.2.6 | Google | Ensure that all GCP Cloud functions are configured to use a current (not deprecated) runtime |
---
## 1.3 Encrypt Confidential Data in Transit
### Description
Encrypt confidential data in transit. Example implementations can include: Transport Layer Security (TLS) and Open Secure Shell (OpenSSH).


### Rationale
Encryption protects confidential data when transmitted over untrusted network connections.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 1.3.1 | Azure | Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service |
| 1.3.2 | Azure | Ensure Web App is using the latest version of TLS encryption |
| 1.3.3 | Azure | Ensure FTP deployments are Disabled |
| 1.3.4 | Google | Ensure “Block Project-Wide SSH Keys” Is Enabled for VM Instances |

---


## 1.4 Encrypt Confidential Data at Rest


### Description

Encrypt confidential data at rest on servers, applications, and databases. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard. Additional encryption methods may include application-layer encryption, also known as client-side encryption, where access to the data storage device(s) does not permit access to the plain-text data.


### Rationale

Encryption at rest protects against some risks of unauthorized access to data, for example insecure disposal and reuse of storage media.


### Audit

| Spec | Platform | Description |
|---|-----|----------|
| 1.4.1 | Azure | Ensure Virtual Machines are utilizing Managed Disks |

---


## 1.5 Implement and Manage a Firewall on Servers


### Description

Implement and manage a firewall on servers, where supported. Example implementations include a virtual firewall, operating system firewall, or a third-party firewall agent.


### Rationale

Firewalls help to prevent unauthorized users from accessing servers or sending malicious payloads to those servers.


### Audit

| Spec | Platform | Description |
|---|-----|----------|
| 1.5.1 | Google | Ensure That IP Forwarding Is Not Enabled on Instances |

---


## 1.6 Manage Default Accounts on Enterprise Assets and Software
### Description

Manage default accounts on enterprise assets and software, such as root, administrator, and other pre-configured vendor accounts. Example implementations can include: disabling default accounts or making them unusable.


### Rationale

Products typically ship with insecure defaults that, if not configured securely, can be used by malicious users to take over a system.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 1.6.1 | Google | Ensure That Instances Are Not Configured To Use the Default Service Account |
| 1.6.2 | Google | Ensure That Instances Are Not Configured To Use the Default Service Account With Full Access to All Cloud APIs |

---


## 1.7 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software

### Description

Uninstall or disable unnecessary services on enterprise assets and software, such as an unused file sharing service, web application module, or service function.


### Rationale

Uninstalling and disabling unnecessary services reduces the target area of your systems.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 1.7.1 | Google | Ensure ‘Enable Connecting to Serial Ports’ Is Not Enabled for VM Instance |

---


## 1.8 Centralize Account Management


### Description

Centralize account management through a directory or identity service.


### Rationale

Centralizing makes administration simpler and therefore reduces risks related to unauthorized account creation or usage.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 1.8.1 | Azure | Ensure that Register with Azure Active Directory is enabled on App Service |
| 1.8.2  | Google | Ensure Oslogin Is Enabled for a Project |


---


# 2 Identity and Access Management


## 2.1 Establish and Maintain a Data Recovery Process

### Description

Establish and maintain a data recovery process. In the process, address the scope of data recovery activities, recovery prioritization, and the security of backup data. Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

"Organizations need to establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state."


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.1.1 | Azure | Ensure the Key Vault is Recoverable |

---


## 2.2 Designate Personnel to Manage Incident Handling

### Description

Designate one key person, and at least one backup, who will manage the enterprise’s incident handling process. Management personnel are responsible for the coordination and documentation of incident response and recovery efforts and can consist of employees internal to the enterprise, third-party vendors, or a hybrid approach. If using a third-party vendor, designate at least one person internal to the enterprise to oversee any third-party work. Review annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

Without an incident response plan, an enterprise may not discover an attack in the first place, or, if the attack is detected, the enterprise may not follow good procedures to contain damage, eradicate the attacker’s presence, and recover in a secure fashion.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.2.1 | AWS | Ensure a support role has been created to manage incidents with AWS Support |


---


## 2.3 Establish and Maintain Contact Information for Reporting Security Incidents

### Description

Establish and maintain contact information for parties that need to be informed of security incidents. Contacts may include internal staff, third-party vendors, law enforcement, cyber insurance providers, relevant government agencies, Information Sharing and Analysis Center (ISAC) partners, or other stakeholders. Verify contacts annually to ensure that information is up-to-date.


### Rationale

As time goes by -- and processes and people change within an organization -- it's important to keep contact information up to date so that information about a security incident reaches the right individuals promptly.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.3.1 | AWS | Maintain current contact details |
| 2.3.2 | AWS | Ensure security contact information is registered |
| 2.3.5 | Google | Ensure Essential Contacts is Configured for Organization |

---


## 2.4 Address Unauthorized Software


### Description

Ensure that unauthorized software is either removed from use on enterprise assets or receives a documented exception. Review monthly, or more frequently.


### Rationale

Actively manage (inventory, track, and correct) all software (operating systems and applications) on the network so that only authorized software is installed and can execute, and that unauthorized and unmanaged software is found and prevented from installation or execution.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.4.1 | Azure | Ensure <code>User consent for applications</code> is set to <code>Do not allow user consent |
| 2.4.2 | Azure | Ensure that 'Users can add gallery apps to My Apps' is set to 'No' |
| 2.4.3 | Azure | Ensure That ‘Users Can Register Applications’ Is Set to ‘No’ |

---


## 2.5 Establish and Maintain a Data Management Process

### Description

Establish and maintain a data management process. In the process, address data sensitivity, data owner, handling of data, data retention limits, and disposal requirements, based on sensitivity and retention standards for the enterprise. Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.5.1 | Azure | Ensure that the Expiration Date that is no more than 90 days in the future is set for all Keys in RBAC Key Vaults |
| 2.5.2 | Azure | Ensure that the Expiration Date that is no more than 90 days in the future is set for all Keys in Non-RBAC Key Vaults. |
| 2.5.3 | Azure | Ensure that the Expiration Date that is no more than 90 days in the future is set for all Secrets in RBAC Key Vaults |
| 2.5.4 | Azure | Ensure that the Expiration Date that is no more than 90 days in the future is set for all Secrets in Non-RBAC Key Vaults |


---


## 2.6 Encrypt Confidential Data at Rest


### Description

Encrypt confidential data at rest on servers, applications, and databases. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard. Additional encryption methods may include application-layer encryption, also known as client-side encryption, where access to the data storage device(s) does not permit access to the plain-text data.


### Rationale

Encryption at rest protects against some risks of unauthorized access to data, for example insecure disposal and reuse of storage media.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.6.1 | Google | Ensure Secrets are Not Stored in Cloud Functions Environment Variables by Using Secret Manager |

---


## 2.7 Configure Data Access Control Lists


### Description

Configure data access control lists based on a user’s need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.


### Rationale

The principle of least privilege reduces the risk of unauthorized actions being taken in your systems.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.7.1 | AWS | Ensure no 'root' user account access key exists |
| 2.7.2 | Aws | Do not setup access keys during initial user setup for all IAM users that have a console password |
| 2.7.3 | AWS | Ensure IAM policies that allow full "_:_" administrative privileges are not attached |
| 2.7.4 | Azure | Ensure That 'Guest users access restrictions' is set to 'Guest user access is restricted to properties and memberships of their own directory objects' |
| 2.7.5 | Google | Ensure That IAM Users Are Not Assigned the Service Account User or Service Account Token Creator Roles at Project Level |
| 2.7.6 | Google | Ensure That Cloud KMS Cryptokeys Are Not Anonymously or Publicly Accessible |


---


## 2.8 Establish and Maintain a Secure Configuration Process
### **Description**

Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### **Rationale**

"""This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software."""


### **Audit**
| Spec | Platform | Description |
|---|-----|----------|
| 2.8.1 | Azure | Ensure Security Defaults is enabled on Azure Active Directory |
| 2.8.2 | AWS | Ensure IAM password policy requires minimum length of 14 or greater |
| 2.8.3 | AWS | Ensure there is only one active access key available for any single IAM user |
| 2.8.4 | AWS | Ensure access keys are rotated every 90 days or less |

---


## 2.9 Use Unique Passwords
### Description

Use unique passwords for all enterprise assets. Best practice implementation includes, at a minimum, an 8-character password for accounts using MFA and a 14-character password for accounts not using MFA.


### Rationale

Malicious users automate login attempts using username and password databases from breaches of other systems. Password policies can help to reduce the risk of a breached or otherwise insecure password being used.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.9.1 | AWS | Ensure IAM password policy prevents password reuse |
| 2.9.2 | Azure | Ensure that a Custom Bad Password List is set to 'Enforce' for your Organization |

---


## 2.10 Disable Dormant Accounts
### Description

Delete or disable any dormant accounts after a period of 45 days of inactivity, where supported.


### Rationale

Ensuring that dormant accounts are disabled when they're no longer needed reduces the target area for malicious users.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.10.1 | AWS | Ensure credentials unused for 45 days or greater are disabled |
| 2.10.2 | Azure | Ensure Guest Users Are Reviewed on a Regular Basis |

---


## 2.11 Restrict Administrator Privileges to Dedicated Administrator Accounts
### Description

Restrict administrator privileges to dedicated administrator accounts on enterprise assets. Conduct general computing activities, such as internet browsing, email, and productivity suite use, from the user’s primary, non-privileged account.


### Rationale

As a matter of good practice, users who can take administrative actions should use regular permissions for routine actions that do not require administrative privileges. This reduces the damage that could occur if the user encounters a malicious exploit attempt.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.11.1 | AWS | Eliminate use of the 'root' user for administrative and daily tasks |
| 2.11.2 | Azure | Ensure That 'Notify all admins when other admins reset their password?' is set to 'Yes' |
| 2.11.3 | Azure | Ensure That 'Restrict access to Azure AD administration portal' is Set to 'Yes' |
| 2.11.4 | Azure | Ensure That No Custom Subscription Administrator Roles Exist |
| 2.11.5 | Google | Ensure That Service Account Has No Admin Privileges |


---


## 2.12 Centralize Account Management

### Description

Centralize account management through a directory or identity service.


### Rationale

Centralizing makes administration simpler and therefore reduces risks related to unauthorized account creation or usage.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.12.1 | Google | Ensure that Corporate Login Credentials are Used |

---


## 2.13 Establish an Access Revoking Process
### Description

Establish and follow a process, preferably automated, for revoking access to enterprise assets, through disabling accounts immediately upon termination, rights revocation, or role change of a user. Disabling accounts, instead of deleting accounts, may be necessary to preserve audit trails.


### Rationale

Ensuring that access grants are revoked when they're no longer needed reduces the target area for malicious users.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.13.1 | Azure | Ensure that 'Number of days before users are asked to re-confirm their authentication information' is set to '90' |


---


## 2.14 Require MFA for Externally-Exposed Applications
### Description

Require all externally-exposed enterprise or third-party applications to enforce MFA, where supported. Enforcing MFA through a directory service or SSO provider is a satisfactory implementation of this Safeguard.


### Rationale

Requiring MFA makes it harder for malicious attackers to takeover accounts, e.g., by re-using username and password combinations that have become leaked from other systems


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.14.1 | Azure | Ensure That 'Number of methods required to reset' is set to '2' |
| 2.14.2 | Azure | Ensure that 'Require Multi-Factor Authentication to register or join devices with Azure AD' is set to 'Yes' |
| 2.14.3 | Azure | Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Privileged Users |
| 2.14.4 | Azure | Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled |
| 2.14.5 | Azure | Ensure that A Multi-factor Authentication Policy Exists for All Users |
| 2.14.6 | Azure | Ensure Multi-factor Authentication is Required for Risky Sign-ins |
| 2.14.7 | Google | Ensure that Multi-Factor Authentication is 'Enabled' for All Non-Service Accounts |
| 2.14.8 | Azure | Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users |

---


## 2.15 Require MFA for Remote Network Access
### Description

Require MFA for remote network access.


### Rationale

Requiring MFA makes it harder for malicious attackers to takeover accounts, e.g., by re-using username and password combinations that have become leaked from other systems


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.15.1 | Azure | Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups |
| 2.15.2 | Azure | Ensure Multi-factor Authentication is Required for Azure Management |


---


## 2.16 Require MFA for Administrative Access
### Description

Require MFA for all administrative access accounts, where supported, on all enterprise assets, whether managed on-site or through a third-party provider.


### Rationale

Requiring MFA makes it harder for malicious attackers to takeover accounts, e.g., by re-using username and password combinations that have become leaked from other systems


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.16.1 | AWS | Ensure MFA is enabled for the 'root' user account |

---


## 2.17 Centralize Access Control
### Description

Centralize access control for all enterprise assets through a directory service or SSO provider, where supported.


### Rationale

Centralizing makes administration simpler and therefore reduces risks related to unauthorized account creation or usage.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.17.1 | Azure | Ensure that 'Notify users on password resets?' is set to 'Yes' |


---


## 2.18 Define and Maintain Role-Based Access Control
### Description

Define and maintain role-based access control, through determining and documenting the access rights necessary for each role within the enterprise to successfully carry out its assigned duties. Perform access control reviews of enterprise assets to validate that all privileges are authorized, on a recurring schedule at a minimum annually, or more frequently.


### Rationale

Standardizing the mechanism for granting cloud permissions reduces the risk of an unintentional or unnoticed privilege.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 2.18.1 | AWS | Ensure IAM Users Receive Permissions Only Through Groups |

---


# 3 Logging and Monitoring
## 3.1 Establish and Maintain Detailed Enterprise Asset Inventory
### Description

Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data, to include: end-user devices (including portable and mobile), network devices, non-computing/IoT devices, and servers. Ensure the inventory records the network address (if static), hardware address, machine name, enterprise asset owner, department for each asset, and whether the asset has been approved to connect to the network. For mobile end-user devices, MDM type tools can support this process, where appropriate. This inventory includes assets connected to the infrastructure physically, virtually, remotely, and those within cloud environments. Additionally, it includes assets that are regularly connected to the enterprise’s network infrastructure, even if they are not under control of the enterprise. Review and update the inventory of all enterprise assets bi-annually, or more frequently.


### Rationale

It is necessary to first identify the systems and devices that need to be secured before taking additional steps towards achieving a suitable security baseline.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.1.1 | Google | Ensure Cloud Asset Inventory Is Enabled |

---


## 3.2 Tune Security Event Alerting Thresholds
### Description

Tune security event alerting thresholds monthly, or more frequently.


### Rationale

Tools must be tuned to reduce the prevalence of both false negatives and false positives.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.2.1 | Azure | Ensure That 'Notify about alerts with the following severity' is Set to 'High' |

---


## 3.3 Establish and Maintain Contact Information for Reporting Security Incidents
### Description

Establish and maintain contact information for parties that need to be informed of security incidents. Contacts may include internal staff, third-party vendors, law enforcement, cyber insurance providers, relevant government agencies, Information Sharing and Analysis Center (ISAC) partners, or other stakeholders. Verify contacts annually to ensure that information is up-to-date.


### Rationale

As time goes by -- and processes and people change within an organization -- it's important to keep contact information up to date so that information about a security incident reaches the right individuals promptly.


### Audit

| Spec | Platform | Description |
|---|-----|----------|
| 3.3.1 | Azure | Ensure That 'All users with the following roles' is set to 'Owner' |
| 3.3.2 | Azure | Ensure 'Additional email addresses' is Configured with a Security Contact Email |

---


## 3.4 Log Confidential Data Access


### Description

Log confidential data access, including modification and disposal.


### Rationale

Organizations need reliable forensic information about access, modification, and deletion of confidential data.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.4.1 | AWS | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket |

---


## 3.5 Configure Data Access Control Lists
### Description

Configure data access control lists based on a user’s need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.


### Rationale

The principle of least privilege reduces the risk of unauthorized actions being taken in your systems.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.5.1 | AWS | Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible  |
| 3.5.2 | Azure | Ensure the Storage Container Storing the Activity Logs is not Publicly Accessible |

---


## 3.6 Establish and Maintain a Secure Configuration Process
### Description

Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.6.1 | Azure | Ensure Any of the ASC Default Policy Settings are Not Set to 'Disabled' |


---


## 3.7 Perform Automated Operating System Patch Management


### Description

Perform operating system updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.


### Rationale

Patching remediates known vulnerabilities. Using automation makes this process routine and reduces the window of opportunity for attackers.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.7.1 | Azure | Ensure that Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed' |

---


## 3.8 Perform Automated Vulnerability Scans of Internal Enterprise Assets


### Description

Perform automated vulnerability scans of internal enterprise assets on a quarterly, or more frequent, basis. Conduct both authenticated and unauthenticated scans, using a SCAP-compliant vulnerability scanning tool.


### Rationale

Tools can help to identify vulnerabilities that require remediation.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.8.1 | Azure | Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On' |

---


## 3.9 Conduct Audit Log Reviews


### Description

Conduct reviews of audit logs to detect anomalies or abnormal events that could indicate a potential threat. Conduct reviews on a weekly, or more frequent, basis.


### Rationale

Logs may contain indications of compromise, so it's important to review logs regularly to detect and stop unauthorized or destructive actions from taking place in your systems.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.9.1 | AWS | Ensure management console sign-in without MFA is monitored |
| 3.9.2 | AWS | Ensure usage of 'root' account is monitored |
| 3.9.3 | AWS | Ensure IAM policy changes are monitored |
| 3.9.4 | AWS | Ensure CloudTrail configuration changes are monitored |
| 3.9.5 | AWS | Ensure S3 bucket policy changes are monitored |
| 3.9.6 | AWS | Ensure changes to network gateways are monitored |
| 3.9.7 | AWS | Ensure route table changes are monitored |
| 3.9.8 | AWS | Ensure VPC changes are monitored |
| 3.9.9 | AWS | Ensure AWS Organizations changes are monitored |
| 3.9.10 | Google | Ensure That Cloud Audit Logging Is Configured Properly |
| 3.9.11 | Google | Ensure That Cloud DNS Logging Is Enabled for All VPC Networks |


---


## 3.10 Collect Audit Logs
### Description

Collect audit logs. Ensure that logging, per the enterprise’s audit log management process, has been enabled across enterprise assets and that logs are retained for at least a minimum period of time.


### Rationale

Having log files of what actions have taken place by users and also system events is fundamental to being able to detect security events.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.10.1 | Google | Ensure That Sinks Are Configured for All Log Entries |
| 3.10.2 | Google | Ensure Log Metric Filter and Alerts Exist for Project Ownership Assignments/Changes |
| 3.10.3 | Google | Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes |
| 3.10.4 | Google | Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes |
| 3.10.5 | Google | Ensure That Audit Logs are retained for a Minimum of 90 Days |
| 3.10.6 | AWS | Ensure That Audit Logs are retained for a Minimum of 90 Days |
| 3.10.7 | Azure | Ensure That Audit Logs are retained for a Minimum of 90 Days |

---


## 3.11 Collect Detailed Audit Logs
### Description

Configure detailed audit logging for enterprise assets containing confidential data. Include event source, date, username, timestamp, source addresses, destination addresses, and other useful elements that could assist in a forensic investigation.


### Rationale

Detailed logs with timestamps provide a record of user activity, system events, and application actions. This allows administrators to identify suspicious activity, potential security breaches, and unauthorized access attempts.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 3.11.1 | AWS | Ensure CloudTrail is enabled in all regions |
| 3.11.2 | AWS | Ensure CloudTrail trails are integrated with CloudWatch Logs |
| 3.11.3 | Azure | Ensure that Azure Monitor Resource Logging is Enabled for All Services that Manage, Store, or Secure Confidential Data |
| 3.11.4 | Azure | Ensure that logging for Azure Key Vault is 'Enabled' |
| 3.11.5 | Azure | Ensure that Activity Log Alert exists for Create Policy Assignment |
| 3.11.6 | Azure | Ensure that Activity Log Alert exists for Delete Policy Assignment |
| 3.11.7 | Azure | Ensure that Activity Log Alert exists for Create or Update Network Security Group |
| 3.11.8 | Azure | Ensure that Activity Log Alert exists for Delete Network Security Group |
| 3.11.9 | Azure | Ensure that Activity Log Alert exists for Create or Update Security Solution |
| 3.11.10 | Azure | Ensure that Activity Log Alert exists for Delete Security Solution |
| 3.11.11 | Azure | Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule |
| 3.11.12 | Azure | Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule |
| 3.11.13 | Azure | Ensure that Activity Log Alert exists for Create or Update Public IP Address rule |
| 3.11.14 | Azure | Ensure that Activity Log Alert exists for Delete Public IP Address rule |


---


# 4 Networking


## 4.1 Encrypt Confidential Data in Transit


### Description

Encrypt confidential data in transit. Example implementations can include: Transport Layer Security (TLS) and Open Secure Shell (OpenSSH).


### Rationale

Encryption protects confidential data when transmitted over untrusted network connections.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 4.1.1 | Google | Ensure No HTTPS or SSL Proxy Load Balancers Permit SSL Policies With Weak Cipher Suites |

---


## 4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure
### Description

Establish and maintain a secure configuration process for network devices. Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 4.2.1 | Google | Ensure Legacy Networks Do Not Exist for Older Projects |
| 4.2.2 | Google | Ensure That DNSSEC Is Enabled for Cloud DNS |
| 4.2.3 | Google | Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC |
| 4.2.4 | Google | Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC |
| 4.2.5 | AWS | Ensure that EC2 Metadata Service only allows IMDSv2 |

---


## 4.3 Implement and Manage a Firewall on Servers
### Description

Implement and manage a firewall on servers, where supported. Example implementations include a virtual firewall, operating system firewall, or a third-party firewall agent.


### Rationale

Firewalls help to prevent unauthorized users from accessing servers or sending malicious payloads to those servers.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 4.3.1 | Azure | Ensure that RDP access from the Internet is evaluated and restricted |
| 4.3.2 | Azure | Ensure that SSH access from the Internet is evaluated and restricted |
| 4.3.3 | Google | Ensure That SSH Access Is Restricted From the Internet |
| 4.3.4 | Google | Ensure That RDP Access Is Restricted From the Internet |
| 4.3.5 | AWS | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports |
| 4.3.6 | AWS | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports |
| 4.3.7 | AWS | Ensure no security groups allow ingress from ::/0 to remote server administration ports |


---


# 5 Storage


## 5.1 Establish and Maintain a Data Recovery Process


### Description

Establish and maintain a data recovery process. In the process, address the scope of data recovery activities, recovery prioritization, and the security of backup data. Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

Organizations need to establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 5.1.1 | Azure | Ensure Soft Delete is Enabled for Azure Containers and Blob Storage |

---


## 5.2 Establish and Maintain a Secure Network Architecture
### Description

Establish and maintain a secure network architecture. A secure network architecture must address segmentation, least privilege, and availability, at a minimum.


### Rationale

Malicious actors can exploit insecure services, poor firewall and network configurations, and default or legacy credentials.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 5.2.1 | Azure | Ensure Default Network Access Rule for Storage Accounts is Set to Deny |

---


## 5.3 Encrypt Confidential Data in Transit
### Description

Encrypt confidential data in transit. Example implementations can include: Transport Layer Security (TLS) and Open Secure Shell (OpenSSH).


### Rationale

Encryption protects confidential data when transmitted over untrusted network connections.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 5.3.1 | Azure | Ensure that 'Secure transfer required' is set to 'Enabled' |
| 5.3.2  Azure | Ensure the "Minimum TLS version" for storage accounts is set to "Version 1.2" |

---


## 5.4 Encrypt Confidential Data at Rest


### Description

Encrypt confidential data at rest on servers, applications, and databases. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard. Additional encryption methods may include application-layer encryption, also known as client-side encryption, where access to the data storage device(s) does not permit access to the plain-text data.


### Rationale

Encryption at rest protects against some risks of unauthorized access to data, for example insecure disposal and reuse of storage media.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 5.4.1 | AWS | Ensure EBS Volume Encryption is Enabled in all Regions |
| 5.4.2 | AWS | Ensure that encryption is enabled for EFS file systems |

---


## 5.5 Configure Data Access Control Lists
### Description

Configure data access control lists based on a user’s need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.


### Rationale

The principle of least privilege reduces the risk of unauthorized actions being taken in your systems.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 5.5.1 | AWS | Ensure that S3 Buckets are configured with 'Block public access (bucket settings)' |
| 5.5.2 | Azure | Ensure that 'Public access level' is disabled for storage accounts with blob containers |
| 5.5.3 | Google | Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible |

---


## 5.6 Establish and Maintain a Secure Configuration Process

### Description

Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

"This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software."


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 5.6.1 | Azure | Ensure that 'Enable key rotation reminders' is enabled for each Storage Account |

---


## 5.7 Securely Manage Enterprise Assets and Software
### Description

Securely manage enterprise assets and software. Example implementations include managing configuration through version-controlled-infrastructure-as-code and accessing administrative interfaces over secure network protocols, such as Secure Shell (SSH) and Hypertext Transfer Protocol Secure (HTTPS). Do not use insecure management protocols, such as Telnet (Teletype Network) and HTTP, unless operationally essential.


### Rationale

Secure management of assets and software guards against malicious users from being able to observe administrative communications with remote servers, possibly leading to compromise of that server, or from making configuration changes to introduce a security vulnerability into the server.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 5.7.1 | Azure | Ensure that Storage Account Access Keys are Periodically Regenerated |

---


## 5.8 Establish an Access Revoking Process


### Description

Establish and follow a process, preferably automated, for revoking access to enterprise assets, through disabling accounts immediately upon termination, rights revocation, or role change of a user. Disabling accounts, instead of deleting accounts, may be necessary to preserve audit trails.


### Rationale

Ensuring that access grants are revoked when they're no longer needed reduces the target area for malicious users.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 5.8.1 | Azure | Ensure that Shared Access Signature Tokens Expire Within an Hour |


---


# 6 Database Services


## 6.1 Use Standard Hardening Configuration Templates for Application Infrastructure
### Description

Use standard, industry-recommended hardening configuration templates for application infrastructure components. This includes underlying servers, databases, and web servers, and applies to cloud containers, Platform as a Service (PaaS) components, and SaaS components. Do not allow in-house developed software to weaken configuration hardening.


### Rationale

Industry-recommended hardening configuration templates reduce the attack surface area of your system and reduce the risk of configuration errors that could lead to a security incident.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.1.1 | Google | Ensure That the ‘Local_infile’ Database Flag for a Cloud SQL MySQL Instance Is Set to ‘Off’ |

---


## 6.2 Allowlist Authorized Scripts


### Description

Use technical controls, such as digital signatures and version control, to ensure that only authorized scripts, such as specific .ps1, .py, etc., files, are allowed to execute. Block unauthorized scripts from executing. Reassess bi-annually, or more frequently.


### Rationale

Unauthorized scripts can be used by malicious users to take over a system or take other destructive actions.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.2.1 | Google | Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off' |

---


## 6.3 Encrypt Confidential Data in Transit


### Description

Encrypt confidential data in transit. Example implementations can include: Transport Layer Security (TLS) and Open Secure Shell (OpenSSH).


### Rationale

Encryption protects confidential data when transmitted over untrusted network connections.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.3.1 | Azure | Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server |
| 6.3.2 | Azure | Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server |
| 6.3.3 | Azure | Ensure 'TLS Version' is set to 'TLSV1.2' for MySQL flexible Database Server |
| 6.3.4 | Google | Ensure That the Cloud SQL Database Instance Requires All Incoming Connections To Use SSL |


---


## 6.4 Encrypt Confidential Data at Rest


### Description

Encrypt confidential data at rest on servers, applications, and databases. Storage-layer encryption, also known as server-side encryption, meets the minimum requirement of this Safeguard. Additional encryption methods may include application-layer encryption, also known as client-side encryption, where access to the data storage device(s) does not permit access to the plain-text data.


### Rationale

Encryption at rest protects against some risks of unauthorized access to data, for example insecure disposal and reuse of storage media.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.4.1 | AWS | Ensure that encryption-at-rest is enabled for RDS Instances |
| 6.4.2 | Azure | Ensure that 'Data encryption' is set to 'On' on a SQL Database |

---


## 6.5 Configure Data Access Control Lists


### Description

Configure data access control lists based on a user’s need to know. Apply data access control lists, also known as access permissions, to local and remote file systems, databases, and applications.


### Rationale

The principle of least privilege reduces the risk of unauthorized actions being taken in your systems.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.5.1 | AWS | Ensure that public access is not given to RDS Instance |
| 6.5.2 | Azure | Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) |
| 6.5.3 | Google | Ensure That Cloud SQL Database Instances Do Not Implicitly Whitelist All Public IP Addresses |
| 6.5.4 | Google | Ensure ‘Skip_show_database’ Database Flag for Cloud SQL MySQL Instance Is Set to ‘On’ |
| 6.5.5 | Google | Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off' |
| 6.5.6 | Google | Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off' |

---


## 6.6 Establish and Maintain a Secure Configuration Process


### Description

Establish and maintain a secure configuration process for enterprise assets (end-user devices, including portable and mobile, non-computing/IoT devices, and servers) and software (operating systems and applications). Review and update documentation annually, or when significant enterprise changes occur that could impact this Safeguard.


### Rationale

This CIS Control provides guidance for securing hardware and software. As delivered by the CSP, the default configurations for operating systems and applications are normally geared toward ease-of-deployment and ease-of-use -- not security. Basic controls, open services and ports, default accounts or passwords, older (vulnerable) protocols, pre-installation of unneeded software -- all can be exploitable in their default state. Even if a strong initial configuration is developed and deployed in the cloud, it must be continually managed to avoid configuration drift as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked” to allow the installation of new software or to support new operational requirements. If not, attackers will find opportunities to exploit both network- accessible services and client software.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.6.1 | Google | Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured |
| 6.6.2 | Google | Ensure '3625 (trace flag)' database flag for all Cloud SQL Server instances is set to 'on' |


---


## 6.7 Implement and Manage a Firewall on Servers


### Description

Implement and manage a firewall on servers, where supported. Example implementations include a virtual firewall, operating system firewall, or a third-party firewall agent.


### Rationale

Firewalls help to prevent unauthorized users from accessing servers or sending malicious payloads to those servers.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.7.1 | Azure | Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled |

---


## 6.8 Securely Manage Enterprise Assets and Software


### Description

Securely manage enterprise assets and software. Example implementations include managing configuration through version-controlled-infrastructure-as-code and accessing administrative interfaces over secure network protocols, such as Secure Shell (SSH) and Hypertext Transfer Protocol Secure (HTTPS). Do not use insecure management protocols, such as Telnet (Teletype Network) and HTTP, unless operationally essential.


### Rationale

Secure management of assets and software guards against malicious users from being able to observe administrative communications with remote servers, possibly leading to compromise of that server, or from making configuration changes to introduce a security vulnerability into the server.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.8.1 | Google | Ensure Instance IP assignment is set to private |

---


## 6.9 Manage Default Accounts on Enterprise Assets and Software
### Description

Manage default accounts on enterprise assets and software, such as root, administrator, and other pre-configured vendor accounts. Example implementations can include: disabling default accounts or making them unusable.


### Rationale

Products typically ship with insecure defaults that, if not configured securely, can be used by malicious users to take over a system.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.9.1 | Google | Ensure That a MySQL Database Instance Does Not Allow Anyone To Connect With Administrative Privileges |

---


## 6.10 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software
### Description

Uninstall or disable unnecessary services on enterprise assets and software, such as an unused file sharing service, web application module, or service function.


### Rationale

Uninstalling and disabling unnecessary services reduces the target area of your systems.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.10.1 | Google | Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off' |


---


### 6.11 Centralize Account Management


### Description

Centralize account management through a directory or identity service.


### Rationale

Centralizing makes administration simpler and therefore reduces risks related to unauthorized account creation or usage.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.11.1 | Azure | Ensure that Azure Active Directory Admin is Configured for SQL Servers |

---


## 6.12 Perform Automated Application Patch Management
### Description

Perform application updates on enterprise assets through automated patch management on a monthly, or more frequent, basis.


### Rationale

Patching remediates known vulnerabilities. Using automation makes this process routine and reduces the window of opportunity for attackers.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.12.1 | AWS | Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances |

---


## 6.13 Collect Audit Logs
### Description

Collect audit logs. Ensure that logging, per the enterprise’s audit log management process, has been enabled across enterprise assets and that logs are retained for at least a minimum period of time.


### Rationale

Having log files of what actions have taken place by users and also system events is fundamental to being able to detect security events.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.13.1 | Azure | Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server |
| 6.13.2 | Azure | Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server |
| 6.13.3 | Azure | Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server |


---


## 6.14 Ensure Adequate Audit Log Storage
### Description

Ensure that logging destinations maintain adequate storage to comply with the enterprise’s audit log management process.


### Rationale

Once configured, logs may generate large volumes of data. Organizations must ensure that logs are preserved according to the organization's retention policy and that there is sufficient storage for this requirement.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.14.1 | Azure | Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server |

---


## 6.15 Collect Detailed Audit Logs


### Description

Configure detailed audit logging for enterprise assets containing confidential data. Include event source, date, username, timestamp, source addresses, destination addresses, and other useful elements that could assist in a forensic investigation.


### Rationale

Detailed logs with timestamps provide a record of user activity, system events, and application actions. This allows administrators to identify suspicious activity, potential security breaches, and unauthorized access attempts.


### Audit
| Spec | Platform | Description |
|---|-----|----------|
| 6.15.1 | Azure | Ensure that 'Auditing' is set to 'On' |
| 6.15.2 | Google | Ensure That the ‘Log_connections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’ |
| 6.15.3 | Google | Ensure That the ‘Log_disconnections’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘On’ |
| 6.15.4 | Google | Ensure that the ‘Log_min_messages’ Flag for a Cloud SQL PostgreSQL Instance is set at minimum to 'Warning' |
| 6.15.5 | Google | Ensure ‘Log_min_error_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘Error’ or Stricter |
| 6.15.6 | Google | Ensure That the ‘Log_min_duration_statement’ Database Flag for Cloud SQL PostgreSQL Instance Is Set to ‘-1′ (Disabled) |
| 6.15.7 | Google | Ensure That 'cloudsql.enable_pgaudit' Database Flag for each Cloud Sql Postgresql Instance Is Set to 'on' For Centralized Logging |
| 6.15.8 | AWS | Database logging should be enabled |

---
