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
