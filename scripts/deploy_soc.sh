#!/usr/bin/env bash
# =============================================================================
# deploy_soc.sh — SOC Stack Bootstrap
# CSE804: Network and Internet Security — University of Dhaka
#
# Clones the soc_setup project and launches Elasticsearch, Kibana,
# Filebeat, Suricata, and Wazuh Manager on an Ubuntu 22.04 host.
#
# Usage: sudo bash scripts/deploy_soc.sh
#
# Tested on: Ubuntu 22.04 LTS (x86_64)
# Requirements: 8 GB RAM, 4 vCPUs, 40 GB disk, internet access
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
error()   { echo -e "${RED}[ERROR]${NC}   $*" >&2; exit 1; }
section() { echo -e "\n${CYAN}━━━ $* ━━━${NC}\n"; }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
section "Pre-flight checks"

[[ "$EUID" -eq 0 ]] || error "Run this script as root: sudo bash deploy_soc.sh"

command -v git  >/dev/null 2>&1 || { info "Installing git..."; apt-get install -y git; }
command -v curl >/dev/null 2>&1 || { info "Installing curl..."; apt-get install -y curl; }

info "System checks passed."

# ── Update system ─────────────────────────────────────────────────────────────
section "System update"
apt-get update -qq && apt-get upgrade -y -qq
info "System updated."

# ── Clone SOC setup ───────────────────────────────────────────────────────────
section "Cloning SOC setup"

SOC_DIR="/opt/soc_setup"
if [[ -d "$SOC_DIR" ]]; then
    warn "SOC setup directory already exists: $SOC_DIR"
    warn "Pulling latest changes..."
    git -C "$SOC_DIR" pull
else
    info "Cloning samiul008ghub/soc_setup ..."
    git clone https://github.com/samiul008ghub/soc_setup "$SOC_DIR"
fi

# ── Run SOC setup ─────────────────────────────────────────────────────────────
section "Running SOC setup"

if [[ -f "$SOC_DIR/setup.sh" ]]; then
    info "Executing setup.sh ..."
    cd "$SOC_DIR"
    bash setup.sh
else
    error "setup.sh not found in $SOC_DIR. Check the repo structure."
fi

# ── Deploy custom Suricata rules ──────────────────────────────────────────────
section "Deploying custom Suricata rules"

RULES_SRC="$(dirname "$0")/../task1-suricata-darkgate/rules/darkgate.rules"
RULES_DEST="/var/lib/suricata/rules/darkgate.rules"

if [[ -f "$RULES_SRC" ]]; then
    info "Copying darkgate.rules to Suricata rules directory ..."
    cp "$RULES_SRC" "$RULES_DEST"
    chmod 644 "$RULES_DEST"
    info "Rules deployed: $RULES_DEST"

    # Add to suricata.yaml if not already present
    YAML="/etc/suricata/suricata.yaml"
    if [[ -f "$YAML" ]]; then
        if ! grep -q "darkgate.rules" "$YAML"; then
            info "Adding darkgate.rules to suricata.yaml ..."
            sed -i '/rule-files:/a\  - darkgate.rules' "$YAML"
        else
            warn "darkgate.rules already registered in suricata.yaml"
        fi

        # Validate config
        info "Validating Suricata configuration ..."
        if suricata -T -c "$YAML" -v 2>&1 | grep -q "successfully loaded"; then
            info "Suricata configuration: OK"
        else
            warn "Suricata configuration test failed. Check $YAML manually."
        fi

        info "Restarting Suricata ..."
        systemctl restart suricata
        systemctl is-active suricata && info "Suricata is running." || warn "Suricata failed to start."
    fi
else
    warn "darkgate.rules source not found at $RULES_SRC — skipping Suricata rule deployment."
fi

# ── Service status summary ────────────────────────────────────────────────────
section "Service Status Summary"

SERVICES=(elasticsearch kibana filebeat suricata wazuh-manager)
for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc"; then
        echo -e "  ${GREEN}✔${NC}  $svc"
    else
        echo -e "  ${RED}✘${NC}  $svc  (not running)"
    fi
done

echo ""
info "SOC stack deployment complete."
echo ""
echo "  Kibana: https://$(hostname -I | awk '{print $1}'):5601"
echo "  Wazuh:  https://$(hostname -I | awk '{print $1}'):443"
echo ""
