# SOC Fundamentals: Suspicious XLS File Analysis

**Platform:** LetsDefend.io  
**Case ID:** SOC138  
**Alert Type:** Detected Suspicious XLS File  

---

## 📝 Summary
This exercise involved investigating an alert for a suspicious `.xls` file. The workflow simulated real SOC triage and analysis steps, including endpoint review, log analysis, malware validation, and incident response actions.  

Key outcome: I confirmed the file was malicious, identified C2 communication attempts, and applied the playbook response of quarantining the device and documenting findings.  

---

## 🔎 Investigation Process

### Step 1: Alert Review
- Received alert for suspicious XLS file.  
- Opened case and reviewed alert details.  
- Investigated endpoint `172.16.17.56`.

### Step 2: Endpoint Analysis
- Observed suspicious process: `POwersheLL.exe`.  
- Terminal history showed directory commands followed by a PowerShell execution ~10 hours later.  
- Gathered **file hash** for deeper analysis.

### Step 3: Malware Verification
- Submitted file hash to **VirusTotal**.  
- Latest analysis (4 days ago) indicated the file contained a **malicious macro**.  
- Determined user likely opened or executed the file (though not fully confirmed).  

### Step 4: Log Analysis
- Queried endpoint logs in SIEM for host `172.16.17.56`.  
- Found 3 logs: 2 HTTPS and 1 HTTP request.  
- Port 80 traffic revealed destination IP `35.189.10.17`.  
- URL extracted and submitted to VirusTotal → flagged as **malicious**.

### Step 5: Response Actions
- Applied playbook:
  - Quarantined affected endpoint.  
  - Confirmed malicious macro via VirusTotal.  
  - Verified outbound C2 attempt but **no contact established**.  
- Created analyst notes and closed the alert.

---

## ✅ Key Findings
- Malicious XLS file containing a macro was downloaded after visiting a malicious site.  
- File execution triggered PowerShell activity on host.  
- Confirmed malicious domain communication attempt, blocked before successful C2 connection.  

---

## 💡 Takeaways
- Practiced end-to-end SOC triage workflow:
  - **Alert → Endpoint → Hash → Logs → Threat Intel → Playbook → Closure**.  
- Learned importance of validating both **file artifacts** and **network traffic** for full context.  
- Noted that training lacked steps for file removal and device unlock — important considerations for **real-world remediation**.  
- Reinforced skills in **VirusTotal, endpoint log analysis, and SIEM investigation**.  

---

## 🔗 Tools & Skills Used
- **VirusTotal** — Hash & URL reputation analysis  
- **Log Management / SIEM** — Endpoint & network log review  
- **Incident Response Playbook** — Quarantine, validation, reporting  
- **Windows Endpoint Analysis** — Process & command history inspection  

---
