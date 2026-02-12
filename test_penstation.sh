#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  PENSTATION — Functional Test Script
#  Run on Raspberry Pi: sudo bash test_penstation.sh
# ═══════════════════════════════════════════════════════════
set -o pipefail

API="http://localhost:8080"
PASS=0
FAIL=0
WARN=0
ERRORS=""

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1 — $2"; ((FAIL++)); ERRORS+="\n  - $1: $2"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }

# Helper: call API and check response
api_test() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local body="$4"
    local check_field="$5"

    if [ "$method" = "GET" ]; then
        RESP=$(curl -s -w "\n%{http_code}" "$API$endpoint" 2>&1)
    else
        RESP=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "$body" "$API$endpoint" 2>&1)
    fi

    HTTP_CODE=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | sed '$d')

    if [ "$HTTP_CODE" = "200" ]; then
        if [ -n "$check_field" ]; then
            if echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d)" &>/dev/null; then
                VAL=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$check_field','__MISSING__'))" 2>/dev/null)
                if [ "$VAL" = "__MISSING__" ]; then
                    fail "$name" "Missing field '$check_field' in response"
                    return 1
                else
                    ok "$name ($check_field=$VAL)"
                    return 0
                fi
            else
                fail "$name" "Invalid JSON response"
                return 1
            fi
        else
            ok "$name"
            return 0
        fi
    elif [ "$HTTP_CODE" = "000" ]; then
        fail "$name" "Connection refused (service not running?)"
        return 1
    else
        fail "$name" "HTTP $HTTP_CODE"
        return 1
    fi
}

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  PENSTATION — Functional Test${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ── 1. System checks ────────────────────────────────────
echo -e "${CYAN}[1/7] System Tools${NC}"

for tool in iw iwlist nmcli airmon-ng airodump-ng aireplay-ng aircrack-ng reaver bully nmap nuclei hydra; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool found ($(which $tool))"
    else
        fail "$tool" "not installed"
    fi
done

# Check wordlist
if [ -f /usr/share/wordlists/rockyou.txt ]; then
    ok "rockyou.txt found"
elif [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    warn "rockyou.txt.gz exists but not extracted (run: sudo gunzip /usr/share/wordlists/rockyou.txt.gz)"
else
    warn "rockyou.txt not found"
fi

# ── 2. Service status ───────────────────────────────────
echo ""
echo -e "${CYAN}[2/7] PENSTATION Service${NC}"

if systemctl is-active --quiet penstation; then
    ok "penstation service is running"
else
    fail "penstation service" "not running"
    info "Try: sudo systemctl start penstation"
    info "Logs: journalctl -u penstation -n 20 --no-pager"
fi

# Check if API is responding
if curl -s "$API/api/stats" &>/dev/null; then
    ok "API responding at $API"
else
    fail "API" "not responding at $API"
    echo -e "\n${RED}  Cannot continue without API. Exiting.${NC}\n"
    exit 1
fi

# ── 3. WiFi interfaces ──────────────────────────────────
echo ""
echo -e "${CYAN}[3/7] WiFi Interfaces${NC}"

IFACES=$(iw dev 2>/dev/null | grep Interface | awk '{print $2}')
if [ -z "$IFACES" ]; then
    fail "WiFi interfaces" "none found"
else
    for iface in $IFACES; do
        DRIVER=$(readlink -f "/sys/class/net/$iface/device/driver/module" 2>/dev/null | xargs basename 2>/dev/null || echo "unknown")
        ok "Interface: $iface (driver: $DRIVER)"
    done
fi

# ── 4. Core API endpoints ───────────────────────────────
echo ""
echo -e "${CYAN}[4/7] Core API Endpoints${NC}"

api_test "GET /api/stats" GET "/api/stats" "" "hosts_total"
api_test "GET /api/hosts" GET "/api/hosts"
api_test "GET /api/scans" GET "/api/scans"
api_test "GET /api/vulns" GET "/api/vulns"
api_test "GET /api/alerts" GET "/api/alerts"
api_test "GET /api/heatmap" GET "/api/heatmap"
api_test "GET /api/network/map" GET "/api/network/map"

# ── 5. WiFi API endpoints ───────────────────────────────
echo ""
echo -e "${CYAN}[5/7] WiFi API Endpoints${NC}"

api_test "GET /api/wifi/status" GET "/api/wifi/status"
api_test "GET /api/wifi/scan" GET "/api/wifi/scan" "" "networks"

# Check scan actually found networks
NETS=$(curl -s "$API/api/wifi/scan" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('networks',[])))" 2>/dev/null || echo "0")
if [ "$NETS" -gt 0 ]; then
    ok "WiFi scan found $NETS networks"
else
    fail "WiFi scan" "0 networks found"
fi

api_test "GET /api/wifi/saved" GET "/api/wifi/saved"
api_test "GET /api/wifi/adapters" GET "/api/wifi/adapters"
api_test "GET /api/wifi/adapters/roles" GET "/api/wifi/adapters/roles"

# Check adapter roles
ROLES=$(curl -s "$API/api/wifi/adapters/roles")
PRIMARY=$(echo "$ROLES" | python3 -c "import sys,json; print(json.load(sys.stdin).get('primary','none'))" 2>/dev/null)
ATTACK=$(echo "$ROLES" | python3 -c "import sys,json; print(json.load(sys.stdin).get('attack','none'))" 2>/dev/null)
info "Adapter roles: primary=$PRIMARY, attack=$ATTACK"
if [ "$ATTACK" = "None" ] || [ "$ATTACK" = "none" ]; then
    warn "No attack adapter assigned (wlan1 should be attack)"
fi

# Check injection support
ADAPTERS_JSON=$(curl -s "$API/api/wifi/adapters")
echo "$ADAPTERS_JSON" | python3 -c "
import sys, json
adapters = json.load(sys.stdin)
for a in adapters:
    inj = 'YES' if a.get('supports_injection') else 'NO'
    mon = 'YES' if a.get('supports_monitor') else 'NO'
    print(f\"  [{a.get('role','?').upper():7s}] {a['interface']:8s} driver={a.get('driver','?'):12s} monitor={mon} injection={inj}\")
" 2>/dev/null

# ── 6. WiFi Pentesting endpoints ────────────────────────
echo ""
echo -e "${CYAN}[6/7] WiFi Pentesting API${NC}"

api_test "GET /api/wifi/attacks" GET "/api/wifi/attacks" "" "attacks"
api_test "GET /api/wifi/captures" GET "/api/wifi/captures"

# Test monitor mode start (on attack adapter)
ATTACK_IF="${ATTACK:-wlan1}"
if [ "$ATTACK_IF" != "None" ] && [ "$ATTACK_IF" != "none" ]; then
    info "Testing monitor mode on $ATTACK_IF..."
    MON_RESP=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"interface\":\"$ATTACK_IF\",\"enable\":true}" \
        "$API/api/wifi/monitor/start")
    MON_OK=$(echo "$MON_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success',False))" 2>/dev/null)
    MON_IF=$(echo "$MON_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('monitor_interface',''))" 2>/dev/null)

    if [ "$MON_OK" = "True" ]; then
        ok "Monitor mode started: $MON_IF"

        # Quick airodump test (5 seconds)
        info "Running quick airodump test (5s)..."
        AIRO_RESP=$(curl -s --max-time 30 -X POST -H "Content-Type: application/json" \
            -d "{\"interface\":\"$MON_IF\",\"duration\":5,\"channel\":0}" \
            "$API/api/wifi/airodump")
        AIRO_NETS=$(echo "$AIRO_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('networks',[])))" 2>/dev/null || echo "0")
        AIRO_CLI=$(echo "$AIRO_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('clients',[])))" 2>/dev/null || echo "0")

        if [ "$AIRO_NETS" -gt 0 ]; then
            ok "Airodump scan found $AIRO_NETS APs, $AIRO_CLI clients"
        else
            warn "Airodump scan returned 0 results (may need longer duration)"
        fi

        # Stop monitor mode
        info "Stopping monitor mode..."
        curl -s -X POST -H "Content-Type: application/json" \
            -d "{\"interface\":\"$MON_IF\",\"enable\":false}" \
            "$API/api/wifi/monitor/stop" >/dev/null
        sleep 2

        # Check if interface is back
        if iw dev | grep -q "$ATTACK_IF"; then
            ok "Monitor mode stopped, $ATTACK_IF restored"
        else
            warn "$ATTACK_IF not found after stopping monitor mode"
        fi
    else
        fail "Monitor mode" "failed to start on $ATTACK_IF"
        info "Response: $MON_RESP"
    fi
else
    warn "Skipping monitor mode test (no attack adapter)"
fi

# ── 7. Captures directory ───────────────────────────────
echo ""
echo -e "${CYAN}[7/7] Files & Directories${NC}"

if [ -d /home/kali/penstation ]; then
    ok "Install directory exists"
else
    fail "Install directory" "/home/kali/penstation not found"
fi

if [ -d /home/kali/penstation/captures ]; then
    CAPS=$(ls /home/kali/penstation/captures/*.cap 2>/dev/null | wc -l)
    ok "Captures directory exists ($CAPS .cap files)"
else
    warn "Captures directory missing (will be created on first capture)"
fi

DB_FILE=$(find /home/kali/penstation -name "penstation.db" 2>/dev/null | head -1)
if [ -n "$DB_FILE" ]; then
    DB_SIZE=$(du -h "$DB_FILE" | cut -f1)
    ok "Database exists: $DB_FILE ($DB_SIZE)"
else
    warn "penstation.db not found (may be in data/ subdirectory or created on first scan)"
fi

if [ -f /home/kali/penstation/.env ]; then
    ok ".env config exists"
else
    warn ".env config missing"
fi

# ── Summary ──────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}WARN: $WARN${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

if [ $FAIL -gt 0 ]; then
    echo -e "\n${RED}  Failed tests:${ERRORS}${NC}\n"
fi

if [ $FAIL -eq 0 ]; then
    echo -e "\n  ${GREEN}All tests passed! PENSTATION is fully operational.${NC}\n"
elif [ $FAIL -le 3 ]; then
    echo -e "\n  ${YELLOW}Minor issues found. Core functionality works.${NC}\n"
else
    echo -e "\n  ${RED}Multiple failures. Check errors above.${NC}\n"
fi

exit $FAIL
