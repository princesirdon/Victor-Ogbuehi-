# COMP5002 – Security Operations & Incident Management  
## Coursework 2 – BOTSv3 Incident Analysis and Presentation  
### Student: Victor  
### Module Leader: Dr Ji Jian Chin  
### Institution: University of Plymouth  
### Date: December 2025  


# BOTSv3 Incident Analysis – Frothly Brewery  
## Splunk Investigation Report  


This report has been prepared as part of the COMP5002 Security Operations & Incident Management module under the guidance of Module Leader Dr Ji Jian Chin. It documents my investigation of the Boss of the SOC v3 (BOTSv3) dataset using Splunk Enterprise, following industry-standard SOC workflows and incident handling methodologies.

The report includes:
- A structured analysis of the simulated Frothly Brewery cyber incident  
- Reflections on SOC roles, responsibilities, and incident response processes  
- Documentation of Splunk installation, dataset ingestion, and validation  
- Detailed answers to the BOTSv3 300‑level questions using SPL queries  
- Screenshots and evidence demonstrating investigative steps  
- A summary of key findings and lessons learned  

This work is supported by a public GitHub repository showing continuous improvement over four weeks, and a 10‑minute video presentation summarising the investigation and demonstrating Splunk queries.


---

# 1. Introduction
# BOTSv3 Incident Analysis – Frothly Brewery  
### COMP5002 – Security Operations & Incident Management  
### Coursework 2 – Splunk Investigation Report  
### Author: Victor  
### Date: December 2025 

---

# 1. Introduction  
This report documents my investigation of the BOTSv3 (Boss of the SOC v3) dataset using Splunk Enterprise.  
BOTSv3 is a realistic, pre-indexed security dataset simulating a multi‑stage cyber attack against a fictional company named **Frothly Brewery**. It contains logs from:

- Email systems  
- Endpoint monitoring  
- Cloud services (AWS, Azure)  
- Network traffic  
- Authentication events  
- Antivirus and EDR tools  

The purpose of this investigation is to:

- Analyse the attack following the cyber kill chain  
- Use Splunk SPL queries to uncover attacker behaviour  
- Answer the BOTSv3 300‑level questions  
- Reflect on SOC operations and incident handling  
- Present findings in a professional, industry‑aligned format  

**Scope:**  
This report focuses exclusively on the BOTSv3 dataset and the Splunk environment I deployed on Ubuntu.  
**Assumptions:**  
All logs are complete, time‑synchronised, and representative of real‑world SOC data.

---

# 2. SOC Roles & Incident Handling Reflection  
Security Operations Centres (SOCs) operate using a tiered structure:

### **Tier 1 – Alert Analysts**
- Monitor dashboards  
- Triage alerts  
- Identify false positives  
- Escalate suspicious activity  

### **Tier 2 – Incident Responders**
- Perform deeper investigation  
- Correlate logs across systems  
- Contain active threats  
- Recommend remediation  

### **Tier 3 – Threat Hunters / Specialists**
- Reverse engineer malware  
- Perform threat intelligence correlation  
- Identify long‑term attacker behaviour  
- Improve detection rules  

### **Relevance to BOTSv3**
During this exercise:

- Tier 1 would detect suspicious login attempts, malware alerts, or unusual network activity.  
- Tier 2 would correlate events across email, endpoint, and cloud logs to identify attacker movement.  
- Tier 3 would analyse payloads, persistence mechanisms, and attacker infrastructure.

### **Incident Handling Phases**
- **Preparation:** Splunk setup, dashboards, detection rules  
- **Detection:** Identifying malicious emails, suspicious processes, or abnormal authentication  
- **Containment:** Blocking accounts, isolating hosts  
- **Eradication:** Removing malware, disabling persistence  
- **Recovery:** Restoring systems, validating integrity  
- **Lessons Learned:** Updating detections, improving SOC processes  

This exercise mirrors real SOC workflows and reinforces the importance of structured incident response.

---

# 3. Installation & Data Preparation  
This section documents how I installed Splunk and ingested the BOTSv3 dataset.

## 3.1 Splunk Installation (Ubuntu)
Steps taken:

1. Installed Ubuntu VM  
2. Downloaded Splunk Enterprise `.deb` package  
3. Installed using `sudo dpkg -i splunk*.deb`  
4. Started Splunk with `sudo /opt/splunk/bin/splunk start`  
5. Accepted license and created admin credentials  

**Screenshot – Splunk running:**  
![Splunk Running](screenshots/splunk_running.png)

---

## 3.2 Dataset Ingestion  
Steps:

1. Cloned the BOTSv3 repository  
2. Located the pre-indexed data under `/datasets/botsv3/`  
3. Configured Splunk to monitor the dataset directory  
4. Verified source types such as:  
   - `stream:smtp`  
   - `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`  
   - `ms:o365:management`  
   - `osquery:results`  

**Screenshot – Data ingestion:**  
![Data Ingestion](screenshots/data_ingestion.png)

---

## 3.3 Validation  
I validated ingestion by running:
# Task 6: Pivoting Back to Endpoint Events — Methodology and Findings

This task involved investigating malicious activity across endpoints and cloud services using **Splunk**. Below is a complete summary and methodology for each question.

---

## **Quick Summary of Findings**

| Question | Answer |
|----------|--------|
| 6.1 User Agent String | **Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4** |
| 6.2 Macro-Enabled Attachment | **Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm** |
| 6.3 Executable Embedded | **HxTsr.exe** |
| 6.4 Password for Linux User | **ilovedavidverve** |
| 6.5 Name of Compromised User | **svcvnc** |
| 6.6 Groups Assigned | **administrators,user** |
| 6.7 Process ID on Leet Port | **14356** |
| 6.8 MD5 of Network Scan File | **586EF56F4D8963DD546163AC31C865D** |


index=botsv3 sourcetype=ms:o365:management Workload=OneDrive Operation=FileUploaded
| table _time UserAgent user src_ip Operation object
| sort by +_time

Macro-Enabled Attachment Name


index=botsv3 | stats count by sourcetype

## 5.1 Conclusion

This investigation of the BOTSv3 dataset provided a realistic, end‑to‑end simulation of Security Operations Centre (SOC) workflows. By analysing logs from email, endpoint, cloud, and network sources, it was possible to reconstruct the attacker’s actions across multiple stages of the cyber kill chain. The exercise demonstrated how a single malicious email can escalate into credential compromise, persistence, lateral movement, and data manipulation when detection and response controls are insufficient.

Key findings include:
- The attack relied heavily on social engineering, highlighting the importance of user awareness and strong email filtering.
- Cloud and endpoint logs were essential for identifying malicious file uploads, suspicious processes, and unauthorised user creation.
- Correlation across multiple log sources was critical for understanding attacker movement and intent.
- SPL queries enabled precise detection of malicious activity that would otherwise remain hidden in large datasets.

Overall, the exercise reinforced the importance of structured SOC processes, layered detection mechanisms, and continuous monitoring.

---

## 5.2 Key Lessons Learned

Several important lessons emerged from the BOTSv3 investigation:

- Visibility is essential: without diverse log sources, the attack would have been impossible to trace.
- SOC tiers must work together: Tier 1 triage, Tier 2 investigation, and Tier 3 threat hunting all play essential roles.
- Incident handling is iterative: new evidence often requires revisiting earlier assumptions.
- Documentation and reporting matter: clear notes, screenshots, and queries support escalation and knowledge transfer.
- Automation improves efficiency: many detection gaps could be reduced with automated correlation rules and alerting.

These lessons reflect real‑world SOC challenges and emphasise the need for continuous improvement.

---

## 5.3 SOC Strategy Implications

The BOTSv3 exercise highlights several strategic improvements that would strengthen SOC operations:

### Enhance Detection Capabilities
- Implement correlation rules for suspicious OneDrive uploads.
- Improve detection of abnormal process execution.
- Strengthen monitoring of new user creation and privilege escalation.
- Deploy behavioural analytics for unusual login patterns.

### Improve Response Processes
- Faster isolation of compromised endpoints.
- Automated disabling of suspicious accounts.
- Clearer escalation paths between SOC tiers.
- Regular tabletop exercises to improve readiness.

### Strengthen Preventive Controls
- Advanced phishing protection.
- Mandatory multi‑factor authentication.
- Endpoint hardening and application control.
- Regular security awareness training.

### Increase SOC Maturity
- Develop threat hunting playbooks.
- Integrate threat intelligence feeds.
- Expand log coverage across cloud and on‑prem systems.
- Conduct regular post‑incident reviews.

These improvements would significantly reduce the likelihood and impact of similar attacks in a real environment.
## 5.4 References

[1] Splunk, “Boss of the SOC v3 (BOTSv3) Dataset,” GitHub Repository, 2025.  

[2] Splunk, “Search Processing Language (SPL) Documentation,” Splunk Docs, 2025.  

[3] MITRE Corporation, “MITRE ATT&CK Framework: Enterprise Matrix,” MITRE, 2025.  

[4] NIST, “Computer Security Incident Handling Guide,” NIST Special Publication 800‑61 Revision 2, 2024.  

[5] NIST, “Guide to Intrusion Detection and Prevention Systems (IDPS),” NIST SP 800‑94, 2023.  

[6] UK National Cyber Security Centre (NCSC), “Security Operations Centre (SOC) Guidance,” NCSC, 2025.  

[7] Amazon Web Services, “AWS CloudTrail Logging and Monitoring,” AWS Documentation, 2025.  

[8] Microsoft, “Azure Active Directory Sign‑In Logs,” Microsoft Learn Documentation, 2025.  

[9] Sysinternals, “Sysmon System Monitoring Tool,” Microsoft Sysinternals Documentation, 2025.  

[10] Palo Alto Networks Unit 42, “Threat Intelligence Report: Malware Trends,” Unit 42, 2024.  
6.2 Macro-Enabled Attachment Name

Answer:
Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm

Method:

Queried stream:smtp sourcetype for email alerts flagged as malicious.

Ran query with keyword *alert*:

index=botsv3 sourcetype=stream:smtp *alert*


Retrieved subject and attach_content_decoded_md5_hash{} fields.

Decoded the attachment using CyberChef to reveal the macro-enabled file.

6.3 Executable Embedded in the Malware

Answer:
HxTsr.exe

Method:

Queried Windows Sysmon logs for evidence of .xlsm macro execution.

Splunk query:

index=botsv3 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational *xlsm* 
| sort by +_time


Found the embedded executable in the logs.

6.4 Password for the Created Linux User

Answer:
ilovedavidverve

Method:

Used osquery logs on Linux host hoth to monitor user creation commands.

Splunk query:

index=botsv3 host=hoth (adduser OR useradd)


Identified the password used for the new account.

6.5 Name of the Compromised User Account

Answer:
svcvnc

Method:

Queried Windows Security Event logs for new account creation (EventCode=4720).

Splunk query:

index=botsv3 source=wineventlog:security EventCode=4720


Extracted the new account username.

6.6 Groups Assigned to the New User

Answer:
administrators,user

Method:

Queried Windows Security logs for group membership (EventCode=4732) for svcvnc.

Splunk query:

index=botsv3 svcvnc EventCode=4732
| table Group_Name


Found groups Administrators and Users, listed alphabetically and comma-separated.

6.7 Process ID of the Process Listening on “leet” Port

Answer:
14356

Method:

Queried osquery logs for open ports on Linux host hoth.

Focused on port 1337 (leet).

Splunk query:

index=botsv3 sourcetype=osquery.results host=hoth 1337


Found the PID associated with that port.

6.8 MD5 Value of the File Used to Scan the Network

Answer:
586EF56F4D8963DD546163AC31C865D7

Method:

Queried Sysmon logs for executed processes and hashes.

Focused on hdoor.exe downloaded to FYODOR-L.

Splunk query:

index=botsv3 source=WinEventLog:Microsoft-Windows-Sysmon/Operational host=FYODOR-L Hashes=*  Image="C:\\Windows\\Temp\\hdoor.exe"


Retrieved the MD5 hash from the executed file’s log entry.
this is my video link
https://1drv.ms/v/c/1ba4b9a4ee714807/IQCkxcz_AR3JR7wOXzc1wXG_Aa367DOKUPwVbbX9wCJcpSQ?e=EuDvRA
