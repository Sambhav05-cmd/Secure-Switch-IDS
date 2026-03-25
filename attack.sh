#!/bin/bash
# attack_and_detect.sh
# Run attacks from the attacker container using scanner.py,
# then verify host Snort detected them.
#
# Usage: ./attack_and_detect.sh [TARGET_IP]
#   Default target: 10.0.0.1 (node1)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()     { echo -e "\n${CYAN}${BOLD}[*] $1${NC}"; }
ok()      { echo -e "${GREEN}[✔] $1${NC}"; }
warn()    { echo -e "${YELLOW}[!] $1${NC}"; }
die()     { echo -e "${RED}[✘] $1${NC}"; exit 1; }
section() { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${BOLD}    $1${NC}"
            echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

TARGET="${1:-10.0.0.1}"
SNORT_LOG="/var/log/snort/alert"
ALERT_WAIT=5

# ─────────────────────────────────────────────────────────────
# PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────
section "Pre-flight Checks"

log "Checking containers are running..."
for container in attacker node1 ovs-switch os-ken-ctrl; do
    STATUS=$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null)
    if [ "$STATUS" = "running" ]; then
        ok "$container is running"
    else
        die "$container is not running (status: ${STATUS:-not found}). Run ./run.sh first."
    fi
done

log "Checking host Snort is running..."
if pgrep -f "snort -i snort0" > /dev/null; then
    ok "Snort is running on host (PID: $(pgrep -f 'snort -i snort0'))"
else
    die "Snort is NOT running on host. Run ./run.sh first (it starts Snort automatically)."
fi

log "Checking snort0 interface is up on host..."
if ip link show snort0 > /dev/null 2>&1; then
    ok "snort0 is present on host"
else
    die "snort0 not found on host. run.sh mirror setup may have failed."
fi

log "Checking Snort alert log exists..."
if sudo test -f "$SNORT_LOG"; then
    ok "Alert log found: $SNORT_LOG"
else
    warn "Alert log not found yet at $SNORT_LOG — it will be created on first alert"
fi

log "Checking attacker has SDN interface (veth4 / 10.0.0.4)..."
ATTACKER_IP=$(docker exec attacker ip addr show veth4 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
if [ -n "$ATTACKER_IP" ]; then
    ok "Attacker IP: $ATTACKER_IP"
else
    die "Attacker has no IP on veth4. run.sh attacker wiring may have failed."
fi

log "Checking attacker → target reachability..."
if docker exec attacker ping -c 2 -W 2 "$TARGET" > /dev/null 2>&1; then
    ok "Attacker can reach $TARGET"
else
    warn "Attacker cannot ping $TARGET — TCP scans may still work and trigger Snort"
fi

log "Checking scanner.py is in attacker container..."
if docker exec attacker test -f /app/scanner.py; then
    ok "scanner.py found"
else
    die "scanner.py not found at /app/scanner.py in attacker container"
fi

# Clear old alerts for a clean baseline
log "Clearing Snort alert log for clean run..."
sudo truncate -s 0 "$SNORT_LOG" 2>/dev/null || sudo bash -c "> $SNORT_LOG" 2>/dev/null || true
ok "Alert log cleared"

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
check_for_rule() {
    local rule_msg="$1"
    local label="$2"
    COUNT=$(sudo grep -c "$rule_msg" "$SNORT_LOG" 2>/dev/null || echo "0")
    if [ "$COUNT" -gt 0 ]; then
        ok "DETECTED [$label]: $COUNT alert(s) matching \"$rule_msg\""
    else
        warn "NOT DETECTED [$label]: No alerts matching \"$rule_msg\""
    fi
}

# ─────────────────────────────────────────────────────────────
# ATTACK 1: ICMP Flood  →  sid:1000001
# ─────────────────────────────────────────────────────────────
section "Attack 1: ICMP Flood"
log "Sending 50 concurrent pings to $TARGET..."

docker exec attacker bash -c "
    for i in \$(seq 1 50); do
        ping -c 1 -W 1 $TARGET > /dev/null 2>&1 &
    done
    wait
"
ok "ICMP flood sent (50 concurrent pings)"
sleep "$ALERT_WAIT"
check_for_rule "ICMP Flood Detected" "ICMP Flood"

# ─────────────────────────────────────────────────────────────
# ATTACK 2: TCP Port Scan (common)  →  sid:1000002
# ─────────────────────────────────────────────────────────────
section "Attack 2: TCP Port Scan (common mode)"
log "Running scanner.py --mode common against $TARGET (~1000 ports)..."

docker exec attacker python3 /app/scanner.py "$TARGET" \
    --mode common \
    --threads 200 \
    --timeout 1.0

ok "Port scan complete"
sleep "$ALERT_WAIT"
check_for_rule "Port Scan Detected" "Port Scan"

# ─────────────────────────────────────────────────────────────
# ATTACK 3: SYN Stealth Scan  →  sid:1000002
# ─────────────────────────────────────────────────────────────
section "Attack 3: SYN Stealth Scan"
log "Running scanner.py --mode stealth against $TARGET (ports 1-1024)..."

docker exec attacker python3 /app/scanner.py "$TARGET" \
    --mode stealth \
    --ports 1-1024 \
    --threads 150 \
    --timeout 1.0

ok "Stealth scan complete"
sleep "$ALERT_WAIT"
check_for_rule "Port Scan Detected" "Stealth Scan"

# ─────────────────────────────────────────────────────────────
# ATTACK 4: SSH Brute Force  →  sid:1000003
# ─────────────────────────────────────────────────────────────
section "Attack 4: SSH Brute Force Simulation"
log "Hammering $TARGET:22 with rapid connections..."

docker exec attacker python3 /app/scanner.py "$TARGET" \
    --mode banner \
    --ports 22 \
    --threads 10 \
    --timeout 2.0

if docker exec attacker which hping3 > /dev/null 2>&1; then
    log "Using hping3 for guaranteed SYN flood on port 22..."
    docker exec attacker hping3 -S -p 22 --faster -c 20 "$TARGET" > /dev/null 2>&1 || true
    ok "hping3 SYN flood sent"
else
    warn "hping3 not available, relying on scanner.py only"
fi

sleep "$ALERT_WAIT"
check_for_rule "SSH Brute Force" "SSH Brute Force"

# ─────────────────────────────────────────────────────────────
# ATTACK 5: Full Scan
# ─────────────────────────────────────────────────────────────
section "Attack 5: Full Scan (OS + Banner + Common)"
log "Running scanner.py --mode full against $TARGET..."

docker exec attacker python3 /app/scanner.py "$TARGET" \
    --mode full \
    --threads 200 \
    --timeout 1.0 \
    --output /tmp/scan_report.txt

docker cp attacker:/tmp/scan_report.txt ./scan_report.txt 2>/dev/null && \
    ok "Scan report saved: ./scan_report.txt" || \
    warn "Could not copy scan report"

sleep "$ALERT_WAIT"

# ─────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────
section "Final Snort Alert Summary"

ALL_ALERTS=$(sudo cat "$SNORT_LOG" 2>/dev/null)

if [ -z "$ALL_ALERTS" ]; then
    warn "No alerts were generated at all."
    echo ""
    echo "  Troubleshooting:"
    echo "    1. Check OVS mirror is set:  docker exec ovs-switch ovs-vsctl list mirror"
    echo "    2. Check snort0 gets traffic: sudo tcpdump -i snort0 -c 10"
    echo "    3. Check Snort is running:   pgrep -a snort"
    echo "    4. Check HOME_NET in snort/snort.conf matches target ($TARGET)"
    echo "    5. Check Snort startup log:  cat /tmp/snort_startup.log"
else
    echo -e "${GREEN}${BOLD}All alerts this session:${NC}\n"
    echo "$ALL_ALERTS"
    echo ""

    ICMP_COUNT=$(sudo grep -c "ICMP Flood"  "$SNORT_LOG" 2>/dev/null || echo 0)
    SCAN_COUNT=$(sudo grep -c "Port Scan"   "$SNORT_LOG" 2>/dev/null || echo 0)
    SSH_COUNT=$(sudo grep -c  "SSH Brute"   "$SNORT_LOG" 2>/dev/null || echo 0)
    TOTAL=$(echo "$ALL_ALERTS" | grep -c '\[' 2>/dev/null || echo 0)

    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  %-32s %s\n" "ICMP Flood alerts:"      "$ICMP_COUNT"
    printf "  %-32s %s\n" "Port Scan alerts:"       "$SCAN_COUNT"
    printf "  %-32s %s\n" "SSH Brute Force alerts:" "$SSH_COUNT"
    printf "  %-32s %s\n" "Total alert lines:"      "$TOTAL"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    ok "Attack + detection cycle complete."
fi

echo ""
echo -e "${CYAN}Useful commands:${NC}"
echo "  sudo tail -f /var/log/snort/alert                               # live alerts"
echo "  sudo tcpdump -i snort0 -c 20                                    # verify mirror traffic"
echo "  docker exec ovs-switch ovs-vsctl list mirror                    # check OVS mirror"
echo "  docker logs -f os-ken-ctrl                                       # controller"
echo "  docker exec ovs-switch ovs-ofctl -O OpenFlow13 dump-flows br0  # flow table"