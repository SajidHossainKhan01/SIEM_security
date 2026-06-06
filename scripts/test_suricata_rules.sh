#!/usr/bin/env bash
# =============================================================================
# test_suricata_rules.sh — Validate custom Suricata rule syntax
# CSE804: Network and Internet Security — University of Dhaka
#
# Usage: bash scripts/test_suricata_rules.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

RULES_FILE="task1-suricata-darkgate/rules/darkgate.rules"
SURICATA_YAML="/etc/suricata/suricata.yaml"
TEMP_YAML="/tmp/suricata_test.yaml"
PASS_COUNT=0
FAIL_COUNT=0

echo ""
echo "============================================================"
echo "  CSE804 — Suricata Rule Validation"
echo "============================================================"
echo ""

# ── Check dependencies ────────────────────────────────────────────────────────
command -v suricata >/dev/null 2>&1 || { error "suricata not installed."; exit 1; }
[[ -f "$RULES_FILE" ]] || { error "Rule file not found: $RULES_FILE"; exit 1; }

# ── Count rules ───────────────────────────────────────────────────────────────
TOTAL_RULES=$(grep -c "^alert" "$RULES_FILE" || true)
info "Rule file: $RULES_FILE"
info "Total rules: $TOTAL_RULES"
echo ""

# ── Check rule syntax basics ──────────────────────────────────────────────────
info "Checking rule syntax ..."

while IFS= read -r line; do
    # Skip comments and blank lines
    [[ "$line" =~ ^# ]] && continue
    [[ -z "$line" ]] && continue

    # Check for required fields
    if [[ "$line" =~ ^alert ]]; then
        SID=$(echo "$line" | grep -oP 'sid:\K[0-9]+' || echo "MISSING")
        MSG=$(echo "$line" | grep -oP 'msg:"\K[^"]+' || echo "MISSING")

        if [[ "$SID" == "MISSING" ]]; then
            fail "Rule missing sid: $line"
            ((FAIL_COUNT++))
        elif [[ "$MSG" == "MISSING" ]]; then
            fail "Rule missing msg: (sid:$SID)"
            ((FAIL_COUNT++))
        else
            pass "Rule sid:$SID — \"$MSG\""
            ((PASS_COUNT++))
        fi
    fi
done < "$RULES_FILE"

echo ""

# ── Test with suricata -T ─────────────────────────────────────────────────────
if [[ -f "$SURICATA_YAML" ]]; then
    info "Running suricata -T (config test) ..."

    # Temporarily add our rules to the yaml for testing
    cp "$SURICATA_YAML" "$TEMP_YAML"

    # Copy rules to expected location
    cp "$RULES_FILE" /tmp/darkgate_test.rules

    if SURICATA_OUTPUT=$(suricata -T -c "$SURICATA_YAML" -l /tmp 2>&1); then
        if echo "$SURICATA_OUTPUT" | grep -q "successfully loaded"; then
            pass "suricata -T: Configuration valid"
            ((PASS_COUNT++))
        else
            warn "suricata -T returned unexpected output"
        fi
    else
        fail "suricata -T failed"
        echo "$SURICATA_OUTPUT" | tail -5
        ((FAIL_COUNT++))
    fi

    rm -f "$TEMP_YAML" /tmp/darkgate_test.rules
else
    warn "Suricata YAML not found at $SURICATA_YAML — skipping config test."
    warn "Run this script on the Wazuh/Suricata host for full validation."
fi

# ── Check for duplicate SIDs ─────────────────────────────────────────────────
echo ""
info "Checking for duplicate SIDs ..."
SIDS=$(grep -oP 'sid:\K[0-9]+' "$RULES_FILE" | sort)
UNIQUE_SIDS=$(echo "$SIDS" | sort -u)
if [[ "$(echo "$SIDS" | wc -l)" -eq "$(echo "$UNIQUE_SIDS" | wc -l)" ]]; then
    pass "No duplicate SIDs found"
    ((PASS_COUNT++))
else
    fail "Duplicate SIDs detected:"
    echo "$SIDS" | sort | uniq -d
    ((FAIL_COUNT++))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
echo "============================================================"
echo ""

[[ "$FAIL_COUNT" -eq 0 ]] && exit 0 || exit 1
