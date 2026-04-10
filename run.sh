#!/bin/bash
# run.sh — SDN lab setup
#
# ARCHITECTURE:
#   controller  → os-ken container (OpenFlow 1.3)
#   ovs-switch  → OVS container (br0 bridge)
#   node1/2/3   → plain Ubuntu containers, wired via veth pairs into OVS
#   attacker    → Ubuntu container with hping3 + scanner.py, wired via veth4
#   snort       → runs DIRECTLY on the HOST (root namespace), NOT a container
#                 Snort listens on snort0, which is the host end of a veth pair
#                 whose other end (snort-br) sits in OVS and receives mirrored traffic
#
# No snort container needed — just install snort on the host once:
#   sudo apt-get install -y snort iproute2

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[*] $1${NC}"; }
ok()   { echo -e "${GREEN}[✔] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }
die()  { echo -e "${RED}[✘] $1${NC}"; exit 1; }

# ─────────────────────────────────────────────
# PRE-FLIGHT: check snort is installed on host
# ─────────────────────────────────────────────
if ! command -v snort > /dev/null 2>&1; then
    die "Snort is not installed on the host. Run: sudo apt-get install -y snort"
fi
ok "Snort found on host: $(snort --version 2>&1 | head -1)"

# ─────────────────────────────────────────────
# STEP 1: Kill any host snort already running
# ─────────────────────────────────────────────
log "Stopping any existing host Snort process..."
sudo pkill -f "snort -i snort0" 2>/dev/null || true
sleep 1

# ─────────────────────────────────────────────
# STEP 2: Bring down old containers
# ─────────────────────────────────────────────
log "Bringing down existing containers..."
docker compose down 2>/dev/null || true
# Remove any leftover named containers that conflict
for name in attacker os-ken-ctrl ovs-switch block-agent node1 node2 node3; do
    docker rm -f "$name" 2>/dev/null || true
done

# ─────────────────────────────────────────────
# STEP 3: Clean up leftover veth interfaces
# We do this BEFORE compose up so OVS_PID is
# stale — clean only host-side and by name.
# ─────────────────────────────────────────────
log "Cleaning up leftover veth interfaces..."
for iface in snort0 snort-br veth1 veth2 veth3 veth1-br veth2-br veth3-br veth4 veth4-br; do
    sudo ip link del "$iface" 2>/dev/null || true
done
ok "Leftover interfaces cleared"

# ─────────────────────────────────────────────
# STEP 4: Build controller and start containers
# (No snort container anymore — removed from compose)
# ─────────────────────────────────────────────
log "Building controller (no cache)..."
docker compose build --no-cache controller || die "Controller build failed"

log "Starting containers..."
docker compose up -d || die "docker compose up failed"

log "Waiting for containers to stabilize..."
sleep 5

# ─────────────────────────────────────────────
# STEP 5: Wait for OVS daemons
# ─────────────────────────────────────────────
log "Waiting for OVS daemons to be ready..."
for i in $(seq 1 20); do
    if docker exec ovs-switch ovs-vsctl show > /dev/null 2>&1; then
        ok "OVS ready (attempt $i)"
        break
    fi
    [ "$i" -eq 20 ] && die "OVS daemons never became ready after 20s"
    sleep 1
done

# ─────────────────────────────────────────────
# STEP 6: Get container PIDs
# ─────────────────────────────────────────────
log "Getting container PIDs..."

NODE1_PID=$(docker inspect -f '{{.State.Pid}}' node1)
NODE2_PID=$(docker inspect -f '{{.State.Pid}}' node2)
NODE3_PID=$(docker inspect -f '{{.State.Pid}}' node3)
OVS_PID=$(docker inspect -f '{{.State.Pid}}' ovs-switch)
ATTACKER_PID=$(docker inspect -f '{{.State.Pid}}' attacker)

ok "node1 PID:      $NODE1_PID"
ok "node2 PID:      $NODE2_PID"
ok "node3 PID:      $NODE3_PID"
ok "ovs-switch PID: $OVS_PID"
ok "attacker PID:   $ATTACKER_PID"

[ -z "$NODE1_PID"    ] && die "node1 not running"
[ -z "$NODE2_PID"    ] && die "node2 not running"
[ -z "$NODE3_PID"    ] && die "node3 not running"
[ -z "$OVS_PID"      ] && die "ovs-switch not running"
[ -z "$ATTACKER_PID" ] && die "attacker not running"

# ─────────────────────────────────────────────
# STEP 7: Create node veth pairs
# ─────────────────────────────────────────────
log "Creating node veth pairs..."
sudo ip link add veth1 type veth peer name veth1-br || die "veth1 failed"
sudo ip link add veth2 type veth peer name veth2-br || die "veth2 failed"
sudo ip link add veth3 type veth peer name veth3-br || die "veth3 failed"
ok "Node veth pairs created"

# ─────────────────────────────────────────────
# STEP 8: Move node veths into namespaces
# ─────────────────────────────────────────────
log "Moving node veths into namespaces..."
sudo ip link set veth1    netns $NODE1_PID || die "veth1 -> node1 failed"
sudo ip link set veth2    netns $NODE2_PID || die "veth2 -> node2 failed"
sudo ip link set veth3    netns $NODE3_PID || die "veth3 -> node3 failed"
sudo ip link set veth1-br netns $OVS_PID  || die "veth1-br -> ovs failed"
sudo ip link set veth2-br netns $OVS_PID  || die "veth2-br -> ovs failed"
sudo ip link set veth3-br netns $OVS_PID  || die "veth3-br -> ovs failed"
ok "Node veths moved"

# ─────────────────────────────────────────────
# STEP 9: Configure node IPs
# ─────────────────────────────────────────────
log "Configuring node interfaces..."
docker exec node1 ip link set veth1 up
docker exec node2 ip link set veth2 up
docker exec node3 ip link set veth3 up
docker exec node1 ip addr add 10.0.0.1/24 dev veth1 || die "node1 IP failed"
docker exec node2 ip addr add 10.0.0.2/24 dev veth2 || die "node2 IP failed"
docker exec node3 ip addr add 10.0.0.3/24 dev veth3 || die "node3 IP failed"
ok "Node IPs: 10.0.0.1 / 10.0.0.2 / 10.0.0.3"

# ─────────────────────────────────────────────
# STEP 10: Bring up OVS-side node veths
# ─────────────────────────────────────────────
log "Bringing up OVS-side node veth interfaces..."
sudo nsenter -t $OVS_PID -n ip link set veth1-br up || die "veth1-br up failed"
sudo nsenter -t $OVS_PID -n ip link set veth2-br up || die "veth2-br up failed"
sudo nsenter -t $OVS_PID -n ip link set veth3-br up || die "veth3-br up failed"
ok "OVS-side node veths up"

# ─────────────────────────────────────────────
# STEP 11: Configure OVS bridge
# ─────────────────────────────────────────────
log "Configuring OVS bridge..."
docker exec ovs-switch ovs-vsctl del-br br0 2>/dev/null || true
docker exec ovs-switch ovs-vsctl add-br br0               || die "add-br failed"
docker exec ovs-switch ovs-vsctl set bridge br0 protocols=OpenFlow13
docker exec ovs-switch ovs-vsctl set-fail-mode br0 secure
docker exec ovs-switch ovs-vsctl set-controller br0 tcp:controller:6633
docker exec ovs-switch ovs-vsctl add-port br0 veth1-br    || die "add veth1-br failed"
docker exec ovs-switch ovs-vsctl add-port br0 veth2-br    || die "add veth2-br failed"
docker exec ovs-switch ovs-vsctl add-port br0 veth3-br    || die "add veth3-br failed"
ok "Bridge br0 ready with OpenFlow13 + secure mode"

# ─────────────────────────────────────────────
# STEP 12: Wire attacker container
# ─────────────────────────────────────────────
log "Wiring attacker container..."
sudo ip link add veth4 type veth peer name veth4-br || die "veth4 creation failed"
sudo ip link set veth4    netns $ATTACKER_PID || die "veth4 -> attacker failed"
sudo ip link set veth4-br netns $OVS_PID      || die "veth4-br -> OVS failed"
docker exec attacker ip link set veth4 up
docker exec attacker ip addr add 10.0.0.4/24 dev veth4
sudo nsenter -t $OVS_PID -n ip link set veth4-br up
docker exec ovs-switch ovs-vsctl add-port br0 veth4-br || die "add veth4-br failed"
ok "Attacker wired: 10.0.0.4 on veth4"

# ─────────────────────────────────────────────
# STEP 13: Set up Snort mirror on HOST
#
# snort0    → stays on HOST (root namespace), Snort listens here
# snort-br  → moved into OVS namespace, added to br0 as mirror output
#
# No container involved. No namespace migration of the listening end.
# ─────────────────────────────────────────────
log "Setting up Snort mirror interface on host..."

# Create veth pair — both ends start on host
sudo ip link add snort0 type veth peer name snort-br || die "snort veth creation failed"

# Move ONLY snort-br into OVS namespace
sudo ip link set snort-br netns $OVS_PID || die "snort-br -> OVS failed"

# Bring up snort0 on host
sudo ip link set snort0 up || die "snort0 bring-up failed"

# Bring up snort-br inside OVS namespace and add to bridge
sudo nsenter -t $OVS_PID -n ip link set snort-br up
docker exec ovs-switch ovs-vsctl add-port br0 snort-br || die "add snort-br to br0 failed"

# Create OVS mirror: copy all br0 traffic → snort-br
SNORT_BR_UUID=$(docker exec ovs-switch ovs-vsctl get port snort-br _uuid)
docker exec ovs-switch ovs-vsctl \
    -- --id=@m create mirror name=snort-mirror \
       select-all=true \
       output-port="$SNORT_BR_UUID" \
    -- set bridge br0 mirrors=@m \
|| die "OVS mirror creation failed"

ok "OVS mirror created: all traffic mirrored to snort0 on host"

# ─────────────────────────────────────────────
# STEP 14: Start Snort on host in background
# ─────────────────────────────────────────────
log "Starting Snort on host (listening on snort0)..."

SNORT_CONF="$(pwd)/snort/snort.conf"
SNORT_RULES_SRC="$(pwd)/snort/local.rules"
SNORT_LOG="/var/log/snort"

sudo mkdir -p "$SNORT_LOG"
sudo mkdir -p /etc/snort/rules

if [ ! -f "$SNORT_CONF" ]; then
    die "snort.conf not found at $SNORT_CONF — check your project structure"
fi

# Copy local rules to where snort.conf expects them
sudo cp "$SNORT_RULES_SRC" /etc/snort/rules/local.rules

# Launch Snort in background, log to /var/log/snort/alert
sudo snort -i snort0 -c "$SNORT_CONF" -A fast -l "$SNORT_LOG" -D 2>/dev/null

sleep 2

if pgrep -f "snort -i snort0" > /dev/null; then
    ok "Snort is running on host (PID: $(pgrep -f 'snort -i snort0'))"
    ok "Alert log: $SNORT_LOG/alert"
else
    warn "Snort failed to start — check /tmp/snort_startup.log"
    cat /tmp/snort_startup.log
fi

# ─────────────────────────────────────────────
# STEP 15: Verify everything
# ─────────────────────────────────────────────
log "Verifying OVS state..."
echo ""
docker exec ovs-switch ovs-vsctl show
echo ""

log "Checking controller logs..."
docker logs os-ken-ctrl 2>&1 | tail -20
echo ""

log "Waiting 10s for controller to connect to OVS..."
sleep 10

log "Checking OpenFlow connection..."
docker exec ovs-switch ovs-ofctl -O OpenFlow13 show br0 2>&1 | head -20
echo ""

log "Checking flow table..."
docker exec ovs-switch ovs-ofctl -O OpenFlow13 dump-flows br0
echo ""

# ─────────────────────────────────────────────
# STEP 16: Test ping
# ─────────────────────────────────────────────
log "Testing ping node1 → node2..."
if docker exec node1 ping -c 4 10.0.0.2; then
    ok "Ping successful! SDN dataplane is working."
else
    warn "Ping failed — check controller: docker logs -f os-ken-ctrl"
fi

echo ""
ok "Setup complete."
echo -e "${CYAN}Useful commands:${NC}"
echo "  docker logs -f os-ken-ctrl                                      # watch controller"
echo "  docker exec ovs-switch ovs-ofctl -O OpenFlow13 dump-flows br0  # watch flows"
echo "  docker exec node1 ping 10.0.0.2                                 # test connectivity"
echo "  sudo tail -f /var/log/snort/alert                               # live Snort alerts"
echo "  sudo pkill -f 'snort -i snort0'                                 # stop Snort"