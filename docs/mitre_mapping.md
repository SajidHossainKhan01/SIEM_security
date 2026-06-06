# MITRE ATT&CK Coverage

This document maps each lab task to the MITRE ATT&CK framework techniques observed
and detected during the exercises.

---

## Task 1 — DarkGate Malware (Suricata Detection)

| Tactic | Technique | ID | Detection Method |
|--------|-----------|-----|-----------------|
| Initial Access | Phishing: Spearphishing Attachment (Excel) | T1566.001 | Email gateway / AV |
| Execution | User Execution: Malicious File | T1204.002 | Endpoint EDR |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | **Suricata Rule SID 3001004** |
| Command & Control | Ingress Tool Transfer (AutoHotkey) | T1105 | **Suricata Rule SID 3001001** |

### Suricata Rule → MITRE Mapping

| SID | Rule | ATT&CK ID |
|-----|------|-----------|
| 3001001–3003 | DarkGate HTTP GET (adfhjadfbjadbfjkhad44jka.com) | T1071.001, T1105 |
| 3001004–3006 | DarkGate HTTP GET (nextroundst.com) | T1071.001, T1105 |
| 3001007–3009 | DarkGate HTTP GET (diveupdown.com) | T1071.001, T1105 |
| 3001010–3012 | DarkGate DNS queries to C2 domains | T1071.004 |

---

## Task 2 — Google Calendar Phishing Attack

| Phase | Tactic | Technique | ID | Wazuh Rule |
|-------|--------|-----------|-----|-----------|
| 1 | Initial Access | Phishing: Spearphishing via Service | T1566.003 | — |
| 2 | Execution | User Execution: Malicious File | T1204.002 | — |
| 3 | C2 | Application Layer Protocol | T1071.001 | — |
| 4 | Lateral Movement | Lateral Tool Transfer | T1570 | **92217** |
| 5 | Defense Evasion | Masquerading | T1036 | — |

### Wazuh Rule 92217 — Explained

```
Tactic:      Lateral Movement
Technique:   T1570 — Lateral Tool Transfer
Description: Executable dropped in folder commonly used by malware
             (C:\Users\<user>\AppData\Local\Temp or Windows root)
Trigger:     Sysmon Event ID 11 (FileCreate) for .exe in suspicious path
Level:       8 (high)
```

---

## Task 3 — File Integrity Monitoring

| Event | Tactic | Technique | ID | Wazuh Rule |
|-------|--------|-----------|-----|-----------|
| File created in monitored path | Persistence | Boot or Logon Autostart | T1547 | 554 |
| File content modified | Impact | Data Manipulation: Stored | T1565.001 | 550, 553 |
| File deleted | Defense Evasion | Indicator Removal: File Deletion | T1070.004 | 555 |

---

## Coverage Summary

```
Initial Access      ██████░░░░  Tasks 1, 2
Execution           ████████░░  Tasks 1, 2
Persistence         ████░░░░░░  Task 3
Privilege Escalation░░░░░░░░░░  Not covered
Defense Evasion     ██████░░░░  Tasks 2, 3
Credential Access   ░░░░░░░░░░  Not covered
Discovery           ░░░░░░░░░░  Not covered
Lateral Movement    ████░░░░░░  Task 2
Collection          ░░░░░░░░░░  Not covered
Command & Control   ██████████  Task 1
Exfiltration        ░░░░░░░░░░  Not covered
Impact              ████░░░░░░  Task 3
```

---

## References

- [MITRE ATT&CK v14](https://attack.mitre.org/)
- [DarkGate ATT&CK Navigator Layer](https://unit42.paloaltonetworks.com/darkgate-malware-uses-excel-files/)
- [Wazuh MITRE ATT&CK Integration](https://documentation.wazuh.com/current/user-manual/capabilities/mitre.html)
