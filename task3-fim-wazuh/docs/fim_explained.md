# Task 3: File Integrity Monitoring (FIM) — Full Explanation

## What is FIM?

File Integrity Monitoring (FIM) tracks changes to critical files and directories
on a monitored endpoint. Wazuh's built-in `syscheck` module provides FIM by:

- Computing cryptographic hashes (MD5, SHA-1, SHA-256) at baseline
- Continuously monitoring for changes in real time via OS kernel hooks
- Alerting when files are **created**, **modified**, or **deleted**

FIM is a core control in compliance frameworks including:

| Framework | Control |
|-----------|---------|
| PCI DSS | 11.5 |
| HIPAA | 164.312.c.1 / 164.312.c.2 |
| GDPR | Article 32 |
| NIST 800-53 | SI-7 |
| TSC | PI.4, PI.5, CC6.1, CC6.8, CC7.2, CC7.3 |

---

## Environment

| Component | OS | IP |
|-----------|-----|-----|
| Wazuh Manager | Ubuntu 22.04 | 10.33.3.4 |
| Agent 1 | Ubuntu 20.04 | 10.33.3.2 |
| Agent 2 | Windows 11 | 10.33.3.7 |

---

## How syscheck Works

```
  [Endpoint]                          [Wazuh Manager]
      │                                     │
      │  1. Agent starts → baseline scan    │
      │     Hash all monitored files ──────►│  Store baseline DB
      │                                     │
      │  2. inotify/kernel detects change   │
      │     File modified/created/deleted ─►│  Compare to baseline
      │                                     │  Rule 550/553/554 fires
      │                                     │  Alert → Elasticsearch
      │                                     │  Visible in Kibana ────►
```

---

## Wazuh FIM Rule IDs

| Rule ID | Event Type | Level | Description |
|---------|-----------|-------|-------------|
| 550 | Modified | 7 | Integrity checksum changed |
| 553 | Modified | 7 | File modified |
| 554 | Added | 5 | File added to the system |
| 555 | Deleted | 7 | File deleted |

### Rule 550 — Full Definition

```xml
<rule id="550" level="7">
  <category>ossec</category>
  <decoded_as>syscheck_integrity_changed</decoded_as>
  <description>Integrity checksum changed.</description>
  <group>syscheck,syscheck_entry_modified,sycheck_file,ossec</group>
  <compliance>
    <pci_dss>11.5</pci_dss>
    <gpg13>4.11</gpg13>
    <gdpr>II_5.1.f</gdpr>
    <hipaa>164.312.c.1,164.312.c.2</hipaa>
    <nist_800_53>SI.7</nist_800_53>
    <tsc>PI.4,PI.5,CC6.1,CC6.8,CC7.2,CC7.3</tsc>
  </compliance>
</rule>
```

### Rule 554 — File Added

```xml
<rule id="554" level="5">
  <category>ossec</category>
  <decoded_as>syscheck_new_entry</decoded_as>
  <description>File added to the system.</description>
  <group>syscheck,syscheck_entry_added,syscheck_file,ossec</group>
</rule>
```

---

## Ubuntu Agent — Configuration Summary

File: `/var/ossec/etc/ossec.conf`

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc</directories>
</syscheck>
```

After config change:
```bash
sudo systemctl restart wazuh-agent
```

---

## Windows Agent — Configuration Summary

File: `C:\Program Files (x86)\ossec-agent\ossec.conf`

```xml
<syscheck>
  <disabled>no</disabled>
  <directories check_all="yes" report_changes="yes" realtime="yes">
    C:\Users\student\Desktop
  </directories>
</syscheck>
```

After config change (PowerShell as Admin):
```powershell
Restart-Service -Name wazuh
```

---

## Testing FIM Alerts

### Ubuntu Test

```bash
# Create a file → triggers Rule 554 (added)
echo "test file" > /root/fim_test.txt

# Modify the file → triggers Rule 550 (checksum changed)
echo "modified content" >> /root/fim_test.txt

# Delete the file → triggers Rule 555 (deleted)
rm /root/fim_test.txt
```

### Windows Test

```powershell
# Create a file → triggers Rule 554
echo "test" > C:\Users\student\Desktop\fim_test.txt

# Modify the file → triggers Rule 550
Add-Content C:\Users\student\Desktop\fim_test.txt "modified"

# Delete the file → triggers Rule 555
Remove-Item C:\Users\student\Desktop\fim_test.txt
```

---

## Kibana Queries

### Ubuntu agent alerts:
```
rule.groups:syscheck AND agent.id:006 AND rule.id:(550 OR 554 OR 555)
```

### Windows agent alerts:
```
rule.groups:syscheck AND agent.id:007 AND rule.id:(550 OR 553 OR 554)
```

### All FIM alerts in last hour:
```
rule.groups:syscheck AND @timestamp:[now-1h TO now]
```

---

## Alert Fields in Kibana

When a FIM alert fires, these fields appear in the Wazuh alert document:

```json
{
  "rule.id": "550",
  "rule.description": "Integrity checksum changed.",
  "rule.level": 7,
  "syscheck.path": "/root/fim_test.txt",
  "syscheck.event": "modified",
  "syscheck.sha256_after": "e3b0c44298fc1c14...",
  "syscheck.sha256_before": "a87ff679a2f3e71d...",
  "syscheck.uname_after": "root",
  "syscheck.mtime_after": "2025-07-26T13:57:49Z",
  "agent.name": "Sayma_Ubuntu_VM",
  "agent.id": "006"
}
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|-----------|-----|-----------|
| Data Manipulation: Stored Data Manipulation | T1565.001 | FIM detects unauthorized file changes |
| Indicator Removal: File Deletion | T1070.004 | FIM detects file deletion by attackers |
| Masquerading | T1036 | FIM detects suspicious file drops |
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | FIM monitors Windows registry directories |

---

## Why FIM Matters for Defenders

- **Malware persistence** — attackers place executables in startup folders;
  FIM catches the file creation event immediately
- **Lateral movement** — credential files, SSH keys, and config files being
  altered signal an active intrusion
- **Compliance auditing** — proves to auditors that critical files were not
  tampered with between scan intervals
- **Insider threat** — detects unauthorized modification of sensitive files
  by privileged users
