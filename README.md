
 <div id='top'></div>

# CyberOwl

 > Last Updated 05/03/2023 15:15:49 UTC
 
 A daily updated summary of the most frequent types of security incidents currently being reported from different sources.
 
 For more information, please check out the documentation [here](./docs/README.md).
 
 ---
 |CyberOwl Sources|Description|
 |---|---|
 |[US-CERT](#us-cert-arrow_heading_up)|United States Computer Emergency and Readiness Team.|
 |[MA-CERT](#ma-cert-arrow_heading_up)|Moroccan Computer Emergency Response Team.|
 |[CERT-FR](#cert-fr-arrow_heading_up)|The French national government Computer Security Incident Response Team.|
 |[IBM X-Force Exchange](#ibmcloud-arrow_heading_up)|A cloud-based threat intelligence platform that allows to consume, share and act on threat intelligence.|
 |[ZeroDayInitiative](#zerodayinitiative-arrow_heading_up)|An international software vulnerability initiative that was started in 2005 by TippingPoint.|
 |[OBS Vigilance](#obs-vigilance-arrow_heading_up)|Vigilance is an initiative created by OBS (Orange Business Services) since 1999 to watch public vulnerabilities and then offer security fixes, a database and tools to remediate them.|
 |[VulDB](#vuldb-arrow_heading_up)|Number one vulnerability database documenting and explaining security vulnerabilities, threats, and exploits since 1970.|
 |[HK-CERT](#hk-cert-arrow_heading_up)|Hong Kong Computer Emergency Response Team Coordination Centre.|
 |[CA-CCS](#ca-ccs-arrow_heading_up)|Canadian Centre for Cyber Security.|
 |[EU-CERT](#eu-cert-arrow_heading_up)|European Union Agency for Cybersecurity.|
 
 > Suggest a source by opening an [issue](https://github.com/karimhabush/cyberowl/issues)! :raised_hands:

# EU-CERT

 |Title|Description|Date|
 |---|---|---|
 |[2023-014: Critical Vulnerabilities in VMware Products](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-014.pdf)|On February 20, 2023, the MISP project team released advisories regarding 2 critical SQL injection vulnerabilities in MISP Threat Intelligence and Sharing Platform. The team decided to follow a silent fix procedure, releasing several updates in November and December 2022, giving enough time to users to update their instances to a safe version.|Tuesday, February 23, 2023 10:30:00 PM CET|
 |[2023-013: Critical SQL injection vulnerabilities in MISP](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-013.pdf)|On February 20, 2023, the MISP project team released advisories regarding 2 critical SQL injection vulnerabilities in MISP Threat Intelligence and Sharing Platform. The team decided to follow a silent fix procedure, releasing several updates in November and December 2022, giving enough time to users to update their instances to a safe version.|Tuesday, February 21, 2023 11:15:00 AM CET|
 |[2023-012: RCE vulnerabilities in Fortinet products](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-012.pdf)|On February 16, 2023, Fortinet released advisories regarding critical vulnerabilities in FortiNAC and FortiWeb products that may allow unauthenticated attackers to perform remote arbitrary code or command execution.|Monday, February 20, 2023 03:40:00 PM CET|
 |[2023-011: ClamAV critical vulnerability](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-011.pdf)|On February 15th, 2023, ClamAV informed about a critical vulnerability in the cross-platform antimalware toolkit. The vulnerability is identified as CVE-2023-20032 and could lead to remote code execution.|Monday, February 20, 2023 03:40:00 PM CET|
 |[2023-010: Severe Vulnerabilities in Citrix Workspace, Virtual Apps and Desktops](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-010.pdf)|On February 14, 2023, Citrix released Security Bulletins regarding severe vulnerabilities affecting its Citrix Workspace, Virtual Apps and Desktops. If exploited, these vulnerabilities could enable attackers to elevate their privileges and take control of the affected system, but they need local access to the target.|Thursday, February 16, 2023 11:00:00 AM CET|
 |[2023-009: Multiple Critical Vulnerabilities in Microsoft Products](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-009.pdf)|On February 14, Microsoft released its February 2023 Patch Tuesday advisory disclosing 79 vulnerabilities (with 9 critical ones), including 3 exploited zero-day vulnerabilities identified with "CVE-2023-21823", "CVE-2023-21715" and "CVE-2023-23376", which affect respectively Windows Graphics Component, Microsoft Publisher and Windows Common Log File System Driver.|Thursday, February 16, 2023 11:00:00 AM CET|
 |[2023-008: Vulnerability in OpenSSH](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-008.pdf)|The development team of the OpenSSH suite has released the version 9.2 to address several security vulnerabilities, including a memory safety bug in the OpenSSH server (|Wednesday, February 08, 2023 06:20:00 PM CET|
 |[2023-007: High Severity Vulnerability in OpenSSL](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-007.pdf)|On February 7, the OpenSSL project team has released a major security update to address 8 vulnerabilities. One vulnerability, tracked as CVE-2023-0286 and rated as High, may allow a remote attacker to read arbitrary memory contents or cause OpenSSL to crash, resulting in a denial of service.|Wednesday, February 08, 2023 06:20:00 PM CET|
 |[2023-006: Critical Security Flaw in Jira Service Management Server and Data Center](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-006.pdf)|A critical security flaw has been discovered in Jira Service Management Server and Data Center that can be exploited by an attacker to impersonate another user and gain unauthorized access to instances. The vulnerability is tracked as CVE-2023-22501 with a CVSS score of 9.4.|Friday, February 03, 2023 07:20:00 PM CET|
 |[2023-005: Critical Code Injection Vulnerability in QNAP Devices](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-005.pdf)|On January 30th, 2023, QNAP published an advisory related to a critical vulnerability, identified as CVE-2022-27596, allowing remote attackers to inject malicious code on QNAP NAS devices.|Tuesday, January 31, 2023 05:55:00 PM CET|
 |[2023-004: Critical Vulnerability in Several ManageEngine Products](https://cert.europa.eu/static/SecurityAdvisories/2023/CERT-EU-SA2023-004.pdf)|On January 18th, ManageEngine released updates to several ManageEngine OnPremise products. The potentially vulnerable products use outdated versions of the open-source library Apache Santuario (XML Security for Java). Products must have enabled Single-Sign-On (SSO) using the Security Assertion Markup Language (SAML) to be vulnerable. For some products, the SSO must be active, while for others, it is sufficient that SSO was active once. As a result, the vulnerability allows an unauthenticated adversary to execute arbitrary code. Additionally, a Proof-of-Concept exploit is available.|Monday, January 30, 2023 10:15:00 AM CET|
 