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

```spl
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
