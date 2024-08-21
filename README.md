# Release Information 

- **Version**: 1.0.0 
- **Certified**: No 
- **Publisher**: Fortinet 
- **Compatible Version**: FortiSOAR 7.4.0 and later 

# Overview 

FortiGuard Labs continues to observe attack attempts targeting the recent Apache OFBiz vulnerabilities (CVE-2024-38856 and CVE-2024-36104) that can be exploited by threat actors through maliciously crafted unauthorized requests, leading to the remote code execution. 

 The **Outbreak Response - Apache OFBiz RCE Attack** solution pack works with the Threat Hunt rules in [Outbreak Response Framework](https://github.com/fortinet-fortisoar/solution-pack-outbreak-response-framework/blob/release/1.1.0/README.md#threat-hunt-rules) solution pack to conduct hunts that identify and help investigate potential Indicators of Compromise (IOCs) associated with this vulnerability within operational environments of *FortiSIEM*, *FortiAnalyzer*, *QRadar*, *Splunk*, and *Azure Log Analytics*.

 The [FortiGuard Outbreak Page](https://www.fortiguard.com/outbreak-alert/apache-ofbiz-rce) contains information about the outbreak alert **Outbreak Response - Apache OFBiz RCE Attack**. 

## Background: 

Apache OFBiz is an open-source enterprise resource planning (ERP) system that provides business solutions to various industries. It includes tools to manage business operations such as customer relationships, order processing, human resource functions, and more. According to open sources, there are hundreds of companies worldwide that use Apache OFBiz. 

CVE-2024-38856 is an Incorrect Authorization vulnerability, meaning that an unauthenticated user can access restricted functionalities. This flaw was identified while analyzing the patch for CVE-2024-36104, which was an incomplete fix.

CVE-2024-36104 is a Path Traversal vulnerability in Apache OFBiz that exposes endpoints to unauthenticated users, who could leverage it to achieve remote code execution via specially crafted requests. 

## Announced: 

FortiGuard Labs recommends users of the Apache OFBiz application to upgrade to version 18.12.15 or later to mitigate the security vulnerabilities (CVE-2024-38856 and CVE-2024-36104).   

## Latest Developments: 

August 5, 2024: Researchers at Sonicwal discovers Apache OFBiz Zero-Day Vulnerability (CVE-2024-38856).
https://blog.sonicwall.com/en-us/2024/08/sonicwall-discovers-second-critical-apache-ofbiz-zero-day-vulnerability/

June 3, 2024: CVE-2024-36104 was disclosed by OSS- Security. 
https://www.openwall.com/lists/oss-security/2024/06/03/1 

# Next Steps
 | [Installation](./docs/setup.md#installation) | [Configuration](./docs/setup.md#configuration) | [Usage](./docs/usage.md) | [Contents](./docs/contents.md) | 
 |--------------------------------------------|----------------------------------------------|------------------------|------------------------------|