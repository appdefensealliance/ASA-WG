# Evaluation Methodology



# Contents

* [Introduction](#introduction)
* [Document Scope](#document-scope)
* [Document Maintenance](#document-maintenance)
* [Abbreviations](#abbreviations)
* [Certification Artifacts](#certification-artifacts)
  * [Developer Onboarding Questionnaire](#developer-onboarding-questionnaire)
  * [Developer Test Report](#developer-test-report)
  * [Compliance Report](#compliance-report)
  * [Confidential Information Handling](#confidential-information-handling)
  * [Multiple Application Evaluations](#multiple-application-evaluations)
  * [Documentary Evidence Requirements](#documentary-evidence-requirements)
  * [Developer Responsibilities](#developer-responsibilities)
  * [Certification and Public Disclosure](#certification-and-public-disclosure)
* [Security Assurance Levels](#security-assurance-levels)
  * [Verified Self Assessment Testing and Verification](#verified-self-assessment-testing-and-verification)
  * [Applications for Evaluation](#applications-for-evaluation)
  * [Platforms for Evaluation](#platforms-for-evaluation)
* [Evaluation Methodology](#evaluation-methodology)
  * [ASTL AL0 Evaluation Process](#astl-al0-evaluation-process)
  * [ASTL AL1 / AL2 Evaluation Process](#astl-al1--al2-evaluation-process)
  * [CB AL0 Evaluation Process](#cb-al0-evaluation-process)
  * [CB AL1/AL2 Evaluation Process](#cb-al1al2-evaluation-process)
  * [Assessment Verdicts](#assessment-verdicts)
* [Security Testing](#security-testing)





# Introduction

This document forms part of the documentation for the App Defense Alliance Certification (ADA Certification) Scheme Methodology. 


# Document Scope

The evaluation methodology establishes how the product and evidence evaluation is done at the procedural and operational level.


# Document Maintenance

The ADA Certification Scheme documentation was created and developed by the App Defense Alliance (ADA) Steering Committee.  This group will maintain responsibility for ongoing maintenance and development of the ADA Certification Scheme documents and facilitate periodic reviews involving relevant stakeholders. 


# Abbreviations

App Defense Alliance (ADA)

App Defense Alliance Certification Scheme (ADA Certification) 

ADA Security Test Laboratories (ASTL)

Center for Internet Security (CIS)

Certification Body (CB) 

Open Worldwide Application Security Project (OWASP) 

Security Assurance Level 0: Self Attestation (AL0)

Security Assurance Level 1: Verified Self Assessment (AL1) 

Security Assurance Level 2: Lab Assessment (AL2)


# Certification Artifacts

There are three core artifacts required for all certifications. The contents of each artifact will be dependent on the profile. Furthermore, the author may also change based on the assurance level. However, the basic process is the developer initiates the process with a Developer Onboarding Questionnaire. A Developer Test Report is generated based on the Onboarding Questionnaire and completion of the application assessment. The Developer Test Report contains detailed testing information and findings, which shall be kept confidential between the developer, ASTL and CB. Upon successful completion of the assessment with no findings, a Compliance Report shall be generated. The Compliance Report contains the high-level summary of all tests which have been performed, and will be published on the ADA certified products web site.


## Developer Onboarding Questionnaire

The Developer Onboarding Questionnaire shall be completed by the developer, for all profiles and all assurance levels. However, the specific information is dependent on both the profile and assurance level. In general, the higher the assurance level, the less developer supplied information is required. The Developer Onboarding Questionnaire is confidential and will only be shared between the Developer, ASTL and CB. All questionnaires can be found at this [link](https://github.com/appdefensealliance/ASA-WG/tree/main/Submission%20Forms%20and%20Templates/Developer%20Questionnaires).


<table>
  <tr>
   <td style="background-color: #c9daf8"><strong>Profile</strong>
   </td>
   <td style="background-color: #c9daf8"><strong>Onboarding Questionnaire</strong>
   </td>
  </tr>
  <tr>
   <td>Mobile App
   </td>
   <td>Mobile App AL0/AL1 Android Onboarding Questionnaire
<p>
Mobile App AL0/AL1 iOS Onboarding Questionnaire
<p>
Mobile App AL2 Android Onboarding Questionnaire
<p>
Mobile App AL2 iOS Onboarding Questionnaire
   </td>
  </tr>
  <tr>
   <td>Web App
   </td>
   <td>Web App AL0/AL1 Onboarding Questionnaire
<p>
Web App AL2 Onboarding Questionnaire
   </td>
  </tr>
  <tr>
   <td>Cloud App and Config
   </td>
   <td>Cloud App AL0/AL1/AL2 AWS Onboarding questionnaire
<p>
Cloud App AL0/AL1/AL2 Azure Onboarding questionnaire
<p>
Cloud App AL0/AL1/AL2 GCP Onboarding questionnaire
   </td>
  </tr>
</table>



## Developer Test Report

The Developer Test Report is a profile specific test report, which documents which tests have been performed, the evidence collected during the test, any findings and a final pass/fail result. For AL1 and AL2, the report is generated by the ASTL and given to the developer to address any findings. If all test cases pass, then the ASTL will generate the Compliance Report. Both reports will then be sent to the developer and CB.

For AL0, the developer shall generate the Developer Test Report and keep the copy in their records as it may be required during an audit or other market surveillance activity.

All Test and Compliance Report templates can be found at this [link](https://github.com/appdefensealliance/ASA-WG/tree/main/Submission%20Forms%20and%20Templates/Lab%20Templates). 

<b>*** The CB shall only accept test reports which use these templates. ***</b>


<table>
  <tr>
   <td style="background-color: #c9daf8"><strong>Profile</strong>
   </td>
   <td style="background-color: #c9daf8"><strong>Onboarding Questionnaire</strong>
   </td>
  </tr>
  <tr>
   <td>Mobile App
   </td>
   <td>Mobile App Android Developer Test Report
<p>
Mobile App iOS Developer Test Report
   </td>
  </tr>
  <tr>
   <td>Web App
   </td>
   <td>Web App Developer Test Report
   </td>
  </tr>
  <tr>
   <td>Cloud App and Config
   </td>
   <td>Cloud App AWS Developer Test Report
<p>
Cloud App Azure Developer Test Report
<p>
Cloud App GCP Developer Test Report
   </td>
  </tr>
</table>



## Compliance Report

For AL1 and AL2 assessments, the ASTL shall generate the Compliance Report once the application has successfully passed all profile test cases. The report is a truncated version of the Developer Test Report, such that it provides high level summaries of the testing which was performed. Upon review by the CB, the Compliance Report shall be published on the ADA website.

For AL0, the developer shall generate the Compliance Report and then submit it to ADA to be published on the ADA website.

All Test and Compliance Report templates can be found at this [link](https://github.com/appdefensealliance/ASA-WG/tree/main/Submission%20Forms%20and%20Templates/Lab%20Templates). 

<b>*** The CB shall only accept test reports which use these templates. ***</b>


<table>
  <tr>
   <td style="background-color: #c9daf8"><strong>Profile</strong>
   </td>
   <td style="background-color: #c9daf8"><strong>Onboarding Questionnaire</strong>
   </td>
  </tr>
  <tr>
   <td>Mobile App
   </td>
   <td>Mobile App Compliance Report
   </td>
  </tr>
  <tr>
   <td>Web App
   </td>
   <td>Web App Compliance Report
   </td>
  </tr>
  <tr>
   <td>Cloud App and Config
   </td>
   <td>Cloud App Compliance Report
   </td>
  </tr>
</table>



## Confidential Information Handling

If the onboarding questionnaire includes confidential information, the confidential information may be provided in a separate document. However, the public compliance report will be published at the completion of the certification and thus should not contain any confidential information. The Certification Body (CB) reserves the right to determine if the information provided in the compliance report is sufficient.


## Multiple Application Evaluations

When multiple applications are evaluated together, the developer must provide justification for their similarities (e.g., common software components) in the questionnaire. This allows the ASTL to assess the applications and their similarities using these components.


## Documentary Evidence Requirements

All documentary evidence must be provided in English. Failure to provide complete information will result in an unsuccessful evaluation and certification outcome.


## Developer Responsibilities

Developers are responsible for providing transparent, comprehensive, and accurate information to the ASTL throughout the evaluation process.


## Certification and Public Disclosure

Upon successful completion of the certification process, the certificate will be made publicly available by the Scheme Owner, along with the completed questionnaire. 


# Security Assurance Levels

The following Security Assurance Levels require different levels of evaluation:



*   Security Assurance Level 0 (AL0): Self Attestation
    *   The developer gathers onboarding information.
    *   The developer performs the application assessment and generates the Developer Test Report.
    *   The developer generates the Compliance Report.
    *   The developer submits the Compliance Report to the CB.
    *   The CB reviews Compliance Report for completeness.
    *   ADA publishes the Compliance Report.
*   Security Assurance Level 1 (AL1): Verified Self Assessment
    *   The developer gathers onboarding information.
    *   The developer performs the automated scan or manual test steps. (Some platform providers may require the ASTL to perform the automated scan.)
    *   The ASTL performs the application assessment, reviews the automated scan and generates the Developer Test Report.
    *   The ASTL generates the Compliance Report.
    *   The ASTL submits the onboarding questionnaire, developer test report and compliance report to the CB.
    *   The CB reviews the submission for completeness, accuracy and compliance to the ADA specification.
    *   The CB certifies the Compliance Report.
    *   ADA publishes the Compliance Report.
*   Security Assurance Level 2 (AL2) Lab Assessment
    *   The developer gathers minimal onboarding information.
    *   The ASTL performs the full application assessment and generates the Developer Test Report.
    *   The ASTL generates the Compliance Report.
    *   The ASTL submits the onboarding questionnaire, developer test report and compliance report to the CB.
    *   The CB reviews the submission for completeness, accuracy and compliance to the ADA specification.
    *   The CB certifies the Compliance Report.
    *   ADA publishes the Compliance Report.


## Verified Self Assessment Testing and Verification

When performing testing, Developers must provide sufficient detail for the ASTL to verify that the tests accurately demonstrate compliance with ADA [specifications](https://github.com/appdefensealliance/ASA-WG). The ASTL reserves the right to reject test evidence if the ASTL determines the evidence cannot be used to confirm compliance with a specific [ADA specification](https://github.com/appdefensealliance/ASA-WG). Some platform providers may require all testing to be performed by the ASTL.


## Applications for Evaluation

The expectation is that the Developer provides a production version of their application and the application relies upon a trustworthy computing platform that runs a recent version of an operating system (i.e. N-3).  When access to the production version of the app is not feasible, an alternative version may be tested (i.e. testing a web application in a non-production environment, testing a non-production mobile application with certain security mechanisms disabled, etc.)

The ASTL is responsible for ensuring that the tested version or environment is identical to the one used in production. 


## Platforms for Evaluation

It is the responsibility of the ASTL to have the necessary tools available to perform evaluations.  The ADA will not be involved in the distribution of devices/hardware. Automated scanning shall be performed with ADA approved tools.


# Evaluation Methodology

The three security assurance levels of the ADA Certification Scheme generate different levels of output corresponding to the activities mandated at each level. The evaluation process and reports are described in more detail in the following sections.


## ASTL AL0 Evaluation Process

There are no ASTL activities needed for AL0 assessments.


## ASTL AL1 / AL2 Evaluation Process

After receiving the required evidence artifacts from the Developer, the ASTL follows these steps to evaluate the application:



1. Initial Review: The ASTL conducts an initial review of the submitted material to ensure it meets the requirements.
2. Request for Additional Information: If necessary, the ASTL requests missing or additional information from the Developer within an agreed-upon time limit.
3. ASTL Determines Evaluation Outcome: If the ASTL finds that the evaluation outcome is “Pass” then the ASTL proceeds to the next step.  If the evaluation outcome is "Fail", the ASTL informs the Developer, who then has two options:
    *   Withdraw from the evaluation process
    *   Provide mitigation(s) or resolution(s) to address the identified issues
4. Compilation and Submission of Reports: The ASTL compiles the Developer Test Report and the Compliance Report. The ASTL then submits them to the Certification Body (CB).


## CB AL0 Evaluation Process

The developer shall submit the onboarding questionnaire, developer test report and Compliance Report to the CB. At the current time AL0 assessments are not supported by the ADA.



*   Completeness: 
    *   Completeness will be verified by automated tooling. No CB review shall be performed.
*   Certification:
    *   The CB shall NOT certify the Compliance Report as only AL1 and AL2 assessments are certified by the CB. The CB will publish the Compliance Report to AL0 product list.


## CB AL1/AL2 Evaluation Process

The ASTL shall submit the onboarding questionnaire, developer test report and Compliance Report to the CB. The CB shall perform the following evaluation steps.



*   Completeness: 
    *   The CB shall check that all fields of the onboarding questionnaire have been completed.
    *   The CB shall check that the information uniquely identifying the applications for certification has been included. 
    *   The CB shall check that the Compliance Report is complete and all requirements are declared to pass.
*   Accuracy:
    *   The CB shall check that the Developer test report contains evidence for each test case and that all test cases are declared to pass.
    *   The CB shall check that the evidence provided in the Developer Test Report is supported by the Onboarding Questionnaire, and the conclusion is in alignment with the ADA specification and testing guide.
    *   The CB shall check that the descriptions faithfully describe what is implemented.
*   Consistency:
    *   The CB shall check that the information does not provide divergent or conflicting answers to separate security requirements.
*   Certification:
    *   The CB shall certify the Compliance Report as only AL1 and AL2 assessments are certified by the CB.


## Assessment Verdicts

The verdicts of the testing include: PASS/FAIL/INCONCLUSIVE


# Security Testing

Security testing is a process that verifies the features and functions of a product are working as intended and protecting against potential vulnerabilities or attacks. ASTLs must follow the ADA’s test guides and acceptance criteria to ensure the product meets the ADA’s security standards. 

In some cases, developers may use alternative approaches to meet individual requirements, and it is the responsibility of the ASTL to:



1. Determine if the developer’s approach provide equivalent or stronger protection than the default approach described in the ADA test guide, and
2. List and justify each use of an alternative implementation in the resulting evaluation report


