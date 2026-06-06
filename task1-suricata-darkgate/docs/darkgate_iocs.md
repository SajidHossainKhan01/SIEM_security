# DarkGate IOCs & Rule Explanation

## Threat Intelligence Reference

**Source:** [Palo Alto Unit 42 — DarkGate Malware Uses Excel Files](https://unit42.paloaltonetworks.com/darkgate-malware-uses-excel-files/)  
**Malware Family:** DarkGate  
**Delivery Method:** Excel files → AutoHotkey package downloads via HTTP

---

## What is DarkGate?

DarkGate is a sophisticated malware-as-a-service (MaaS) loader active since 2018. It is
distributed through phishing emails containing malicious Excel files. When a victim opens
the file, a macro or OLE object initiates an HTTP GET request to attacker-controlled
servers to download AutoHotkey script packages — the actual payload stage.

---

## Indicators of Compromise (IOCs)

### March 12, 2024

| URL | SID |
|-----|-----|
| `hxxp://adfhjadfbjadbfjkhad44jka[.]com/aa` | 3001001 |
| `hxxp://adfhjadfbjadbfjkhad44jka[.]com/xxhhodrq` | 3001002 |
| `hxxp://adfhjadfbjadbfjkhad44jka[.]com/zanmjtvh` | 3001003 |

### March 13, 2024

| URL | SID |
|-----|-----|
| `hxxp://nextroundst[.]com/aa` | 3001004 |
| `hxxp://nextroundst[.]com/ffcxlohx` | 3001005 |
| `hxxp://nextroundst[.]com/nlcsphze` | 3001006 |

### March 15, 2024

| URL | SID |
|-----|-----|
| `hxxp://diveupdown[.]com/aa` | 3001007 |
| `hxxp://diveupdown[.]com/aaa` | 3001008 |
| `hxxp://diveupdown[.]com/hlsxaifp` | 3001009 |

> ⚠️ URLs are defanged (hxxp) for safety. Do not browse to these addresses.

---

## Suricata Rule Anatomy

Each HTTP detection rule follows this structure:

```
alert http any any -> any any (
    msg:"DARKGATE - GET to nextroundst.com /aa";   ← Human-readable description
    flow:established,to_server;                     ← Only outbound established TCP
    http.uri; content:"/aa";                        ← URI path match
    http.host; content:"nextroundst.com";           ← Host header match
    classtype:trojan-activity;                      ← Classification
    sid:3001004;                                    ← Unique rule ID (local range)
    rev:1;                                          ← Rule revision
)
```

### Why both HTTP and DNS rules?

- **HTTP rules** inspect the actual request URI and Host header — the most precise match.
- **DNS rules** fire even before the TCP connection is made, enabling earlier blocking if
  Suricata is deployed inline as an IPS.

---

## Kibana Alert Fields

When an alert fires, the following fields are populated in the Suricata EVE JSON log:

```json
{
  "event_type": "alert",
  "src_ip": "10.33.3.X",
  "dest_ip": "x.x.x.x",
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 3001004,
    "rev": 1,
    "signature": "DARKGATE - GET to nextroundst.com /aa",
    "category": "A Network Trojan was detected",
    "severity": 1
  },
  "http": {
    "hostname": "nextroundst.com",
    "url": "/aa",
    "http_method": "GET"
  }
}
```

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Technique | T1071.001 — Application Layer Protocol: Web Protocols |
| Tactic | Command and Control |
| Sub-technique | HTTP/HTTPS C2 traffic |

---

## Testing the Rule (Safe Simulation)

```bash
# Safely simulate a DNS lookup without actually connecting
# This will trigger the DNS-based Suricata rule (SID 3001011)
curl -v http://nextroundst.com/aa
# Expected: curl: (6) Could not resolve host: nextroundst.com
# But Suricata will still log the DNS query attempt

# View the alert immediately
sudo tail -f /var/log/suricata/fast.log | grep DARKGATE
```
