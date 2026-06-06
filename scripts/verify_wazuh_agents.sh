#!/usr/bin/env bash
# =============================================================================
# verify_wazuh_agents.sh — Check all Wazuh agent connectivity
# CSE804: Network and Internet Security — University of Dhaka
#
# Run on the Wazuh Manager host.
# Usage: sudo bash scripts/verify_wazuh_agents.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
section() { echo -e "\n${CYAN}━━━ $* ━━━${NC}\n"; }

echo ""
echo "============================================================"
echo "  CSE804 — Wazuh Agent Connectivity Check"
echo "============================================================"
echo ""

[[ "$EUID" -eq 0 ]] || { warn "Run as root for full agent status output"; }

# ── Wazuh Manager status ──────────────────────────────────────────────────────
section "Wazuh Manager"
if systemctl is-active --quiet wazuh-manager; then
    echo -e "  ${GREEN}✔${NC}  wazuh-manager is running"
else
    echo -e "  ${RED}✘${NC}  wazuh-manager is NOT running"
    echo "  Run: sudo systemctl start wazuh-manager"
fi

# ── Agent list ────────────────────────────────────────────────────────────────
section "Registered Agents"
if command -v /var/ossec/bin/agent_control >/dev/null 2>&1; then
    /var/ossec/bin/agent_control -l 2>/dev/null | grep -E "ID|Name|IP|Status" || true
elif command -v /var/ossec/bin/manage_agents >/dev/null 2>&1; then
    /var/ossec/bin/manage_agents -l 2>/dev/null || true
else
    warn "/var/ossec/bin/agent_control not found. Check Wazuh installation."
fi

# ── Active agents ─────────────────────────────────────────────────────────────
section "Active Agent Count"
AGENT_COUNT=$(find /var/ossec/queue/agent-info/ -type f 2>/dev/null | wc -l || echo "0")
info "Active agents detected: $AGENT_COUNT"

# ── Network reachability ──────────────────────────────────────────────────────
section "Network Reachability"

declare -A HOSTS=(
    ["Ubuntu Agent (10.33.3.2)"]="10.33.3.2"
    ["Windows Agent (10.33.3.7)"]="10.33.3.7"
    ["Kibana (10.33.3.4:5601)"]="10.33.3.4"
)

for name in "${!HOSTS[@]}"; do
    ip="${HOSTS[$name]}"
    if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✔${NC}  $name — reachable"
    else
        echo -e "  ${RED}✘${NC}  $name — unreachable"
    fi
done

# ── Suricata status ───────────────────────────────────────────────────────────
section "Suricata IDS"
if systemctl is-active --quiet suricata; then
    echo -e "  ${GREEN}✔${NC}  Suricata is running"
    info "Log: /var/log/suricata/fast.log"
    info "Last 3 alerts:"
    tail -3 /var/log/suricata/fast.log 2>/dev/null | sed 's/^/    /' || warn "No alerts yet."
else
    echo -e "  ${RED}✘${NC}  Suricata is NOT running"
fi

# ── Elasticsearch / Kibana ────────────────────────────────────────────────────
section "Elasticsearch & Kibana"
for svc in elasticsearch kibana filebeat; do
    if systemctl is-active --quiet "$svc"; then
        echo -e "  ${GREEN}✔${NC}  $svc"
    else
        echo -e "  ${YELLOW}○${NC}  $svc  (not active)"
    fi
done

echo ""
info "Agent verification complete."
echo "  Kibana dashboard: https://10.33.3.4:5601"
echo ""
