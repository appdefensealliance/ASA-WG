# ASA-WG

## Introduction

Strong application security is imperative in today's digital landscape as applications serve as the primary interface between organizations and their customers, employees, and partners. By prioritizing application security, organizations can safeguard sensitive data, protect against cyberattacks, maintain customer trust, and be better prepared to respond to regulations. Neglecting application security can lead to costly data breaches, reputational damage, and financial losses.

However, the absence of a standardized application security certification introduces significant costs and complexities for software developers. Without a common standard, companies must invest heavily in interpreting and adhering to a multitude of disparate regimes, often resulting in redundant efforts, increased operational costs, and potential inconsistencies in their efforts. This lack of uniformity also hinders efficient risk assessment, resource allocation, and the ability to demonstrate compliance to stakeholders, ultimately impacting business agility and competitiveness.

The App Defense Alliance was founded to protect users by preventing threats from reaching their devices and improving app quality across the ecosystem. The App Defense Alliance intends to protect users of mobile and web applications via security standards, validation guidance, and a certification scheme that scales with risk.

## Overview
### Scope

The App Defense Alliance's initial focus is on creating baseline security standards relevant to software developers that process confidential data, specifically in the areas of application security and secure cloud configuration:
* Application Security - A software developer's application security responsibilities center on building security into the application from inception.  This involves secure coding practices, understanding and mitigating vulnerabilities, and conducting security testing.
* Secure Cloud Configuration - Similarly, if the developer is running some or all of their system in a public cloud, it is essential to maintain a secure configuration of cloud assets since confidential information stored in the cloud is a prime target for cyberattacks. Secure configurations help protect data from unauthorized access, theft, and corruption.

The App Defense Alliance does not cover other requirements necessary for an organization to implement a comprehensive information security regime, such as establishing, implementing, maintaining, and continually improving their people, processes, and tools. Organizations are adivsed to consult other resouces such as the ISO 27001 standard.

### Profiles

The App Defense Alliance’s initial set of profiles are specific to the architecture or technology and are intended to be a baseline set of requirements relevant to apps that process confidential data. Note that apps in certain verticals such as healthcare or finance may have to meet higher security, privacy, and regulatory requirements.

* Mobile - application security requirements and associated test guide applicable to developers that build apps that run on Android, Meta Quest, or Apple iOS devices
* Web - application security requirements and associated test guide applicable to developers of web apps and web-accessible APIs
* Cloud - security configuration requirements relevant to the use of IaaS and PaaS services offered by Amazon Web Services (AWS), Google Cloud Platform (GCP), and Microsoft Azure

In the future, the App Defense Alliance may pursue pursue new profiles (e.g., for new software types) or profile extensions that are applicable to specific subclasses of applications (e.g., for VPN apps).

## Validation
### Approach

This App Defense Alliance's validation approach involves a collaborative effort between a standards setting organization (the alliance itself), software developers, and independent assessors.
1. The App Defense Alliance establishes the criteria for product evaluation.
2. Software developers use these standards to create software and secure cloud configurations that meet these requirements.
3. Independent assessors, acting as neutral evaluators, then assess a developer's product against the standards and are authorize to issue a certification document if so.

This process aims to ensure that developers have met the security requirements, providing confidence to stakeholders.
### Levels

The App Defense Alliance has adopted a tiered approach to certification that varies the depth and intensity of assessment according to risk level. Higher-risk products undergo more rigorous testing and evaluation compared to lower-risk products. This tiered structure ensures that resources are allocated efficiently while maintaining appropriate levels of scrutiny for products that require greater assurance. There are three Assurance Levels (ALs):

1. AL0 - Self Assessment: Low risk products can be self assessed by the developer
2. AL1 - Developer Tested, Lab Reviewed: Medium risk products can be tested such that the developer runs the test cases and submits evidence demonstrating their conformance with the requirements to an independent assessor, who is then responsible for confirming the completeness and suficiency of the evidence
3. AL2 - Lab Tested: High risk products can be tested directly by the independent asssessor, providing the highest level of assurance that a product has met the requirements

## Summary of Requirements
### Mobile

The mobile profile outlines a baseline set of security requirements for mobile applications such as Android, iOS, and Quest apps. It covers key areas like:
* Data Security: Proper handling, storage, and transmission of sensitive data.
* Authentication and Authorization: Secure user identification and access control.
* Network Communication: Protecting data during transmission.
* Platform Interaction: Secure interaction with the underlying mobile platform.
* Code Quality: Writing secure and resilient code.
* Security Testing: Thoroughly testing the application for vulnerabilities.
* Reverse Engineering Protection: Safeguarding the app from unauthorized analysis.

### Web

The web profile provides ab baseline set of requirements for securing web applications. It covers a broad spectrum of security controls, including:
* Input Validation and Output Encoding: Ensuring that user input is properly sanitized and output is properly encoded to prevent vulnerabilities like SQL * injection, cross-site scripting (XSS), and cross-site request forgery (CSRF).
* Authentication and Session Management: Implementing secure authentication mechanisms and managing user sessions effectively to protect against unauthorized * access.
* Cryptography: Using strong encryption algorithms and key management practices to protect sensitive data.
* Access Control: Implementing appropriate access controls to protect resources and data based on user roles and permissions.
* Error and Exception Handling: Handling errors and exceptions gracefully to prevent information leakage and potential attacks.
* Security Testing: Conducting thorough security testing throughout the development lifecycle to identify and address vulnerabilities.

### Cloud

The cloud profile outlines a baseline set of secure cloud configuration requirements relevant to the use of Amazon Web Services (AWS), Google Cloud PLatform (GCP), and Microsoft Azure. It covers a broad spectrum of configuration settings, providing detailed guidelines for implementation and assessment.
Key areas addressed by the benchmark include:
* Identity and Access Management (IAM): Ensuring proper user and resource permissions.
* Network Security: Protecting AWS resources from unauthorized access through secure network configurations.
* Data Protection: Safeguarding sensitive data with encryption, access controls, and data lifecycle management.
* Logging and Monitoring: Implementing robust logging and monitoring to detect threats and anomalies.
* Security Groups and Network Access Control Lists (NACLs): Configuring network security groups and NACLs to protect resources.
* Key Management Services (KMS): Using KMS to protect encryption keys and manage cryptographic operations.
* Infrastructure as Code (IaC): Promoting secure configuration management through IaC tools.
