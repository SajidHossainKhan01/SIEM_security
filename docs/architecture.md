# Lab Architecture

## Network Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                    Virtual Lab Network (Bridged)                   │
│                     Subnet: 10.33.3.0/26                          │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                SOC Manager Node — Ubuntu 22.04              │  │
│  │                      IP: 10.33.3.4                          │  │
│  │                                                             │  │
│  │  ┌─────────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │  │
│  │  │Wazuh Manager│  │  Elastic │  │  Kibana  │  │Filebeat│  │  │
│  │  │   :1514/UDP │  │  :9200   │  │  :5601   │  │        │  │  │
│  │  └─────────────┘  └──────────┘  └──────────┘  └────────┘  │  │
│  │                                                             │  │
│  │  ┌──────────────────────────────┐                          │  │
│  │  │         Suricata IDS         │                          │  │
│  │  │  Rules: darkgate.rules       │                          │  │
│  │  │  Interface: eth0 (promiscuous│                          │  │
│  │  └──────────────────────────────┘                          │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              ▲  ▲  ▲                              │
│                  Wazuh Agent │  │  │ Wazuh Agent                  │
│                              │  │  │                              │
│  ┌──────────────────┐        │  │  │        ┌──────────────────┐  │
│  │  Ubuntu 20.04    │────────┘  │  └────────│  Windows 11      │  │
│  │  IP: 10.33.3.2   │          │            │  IP: 10.33.3.7   │  │
│  │  Agent (FIM)     │          │            │  Agent (FIM+Sysmon│  │
│  └──────────────────┘          │            └──────────────────┘  │
│                                │                                  │
│              Task 2 Attack Simulation                             │
│  ┌──────────────────┐          │            ┌──────────────────┐  │
│  │  Kali Linux VM   │──────────┘            │  Windows 10 VM   │  │
│  │  IP: 10.33.3.49  │ Phishing email ──────►│  IP: 10.33.3.50  │  │
│  │  (Attacker)      │◄── Reverse shell ─────│  (Victim)        │  │
│  └──────────────────┘                       └──────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

---

## Component Roles

### Wazuh Manager (10.33.3.4)
- Central log aggregation and analysis engine
- Receives logs from all Wazuh agents
- Applies detection rules and generates alerts
- Feeds alerts to Elasticsearch for indexing

### Elasticsearch (10.33.3.4:9200)
- Time-series document store for all security events
- Indexed by Filebeat and Wazuh

### Kibana (10.33.3.4:5601)
- Web UI for searching, filtering, and visualising alerts
- Suricata alerts via the Filebeat Suricata module dashboard
- Wazuh alerts via the Wazuh Elastic plugin

### Filebeat (10.33.3.4)
- Ships Suricata EVE JSON logs to Elasticsearch
- Enables the Suricata alert dashboard in Kibana

### Suricata IDS (10.33.3.4)
- Network Intrusion Detection System (NIDS)
- Monitors all inbound/outbound network traffic
- Custom rules in `darkgate.rules` detect DarkGate C2 traffic
- Writes alerts to `/var/log/suricata/fast.log` and `eve.json`

### Wazuh Agents
| Agent | Host | Purpose |
|-------|------|---------|
| Ubuntu 20.04 | 10.33.3.2 | FIM on `/root`, `/etc` |
| Windows 11 | 10.33.3.7 | FIM on Desktop, Sysmon events |
| Windows 10 Victim | 10.33.3.50 | Attack target in Task 2 |

---

## Data Flow

```
[Endpoint Event]
       │
       ▼
[Wazuh Agent]  ──────────────────────────────►  [Wazuh Manager]
   ossec.conf                                    /var/ossec/logs/alerts/
   syscheck FIM                                         │
   localfile (Sysmon)                                   │
                                                        ▼
[Network Traffic]                               [Elasticsearch]
       │                                         Index: wazuh-alerts-*
       ▼                                                │
[Suricata IDS]  ─── EVE JSON ──►  [Filebeat]           │
   darkgate.rules                  filebeat.yml         │
   fast.log                        Index: filebeat-*    │
                                                        │
                                                        ▼
                                               [Kibana Dashboard]
                                                https://10.33.3.4:5601
```

---

## Port Reference

| Service | Port | Protocol |
|---------|------|---------|
| Kibana | 5601 | TCP/HTTPS |
| Elasticsearch | 9200 | TCP/HTTP |
| Wazuh Agent | 1514 | UDP |
| Wazuh API | 55000 | TCP/HTTPS |
| Apache (payload host) | 80 | TCP/HTTP |
| Meterpreter listener | 4444 | TCP |
