#!/usr/bin/env bash
# Gatecrash setup — run once as root to install and configure everything.
set -euo pipefail

INSTALL_DIR="/opt/gatecrash"
WG_CONF="/etc/wireguard/wg0.conf"
SYSCTL_CONF="/etc/sysctl.d/99-gatecrash.conf"
RT_TABLES="/etc/iproute2/rt_tables"

# Trap unexpected errors with a line number hint
trap 'echo ""; echo "ERROR: setup failed at line $LINENO. See output above." >&2' ERR

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()    { echo "  $*"; }
success() { echo "  [OK] $*"; }
warn()    { echo "  [WARN] $*"; }
prompt()  { read -rp "  > $1: " "$2"; }
confirm() {
    local ans
    read -rp "  > $1 [${2:-Y/n}]: " ans
    ans="${ans:-${3:-y}}"
    [[ "$ans" =~ ^[Yy] ]]
}

validate_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -ra parts <<< "$ip"
    for part in "${parts[@]}"; do
        (( part >= 0 && part <= 255 )) || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo bash setup.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              Gatecrash Setup                         ║"
echo "║  Routes specific LAN devices through a VPN tunnel   ║"
echo "║  without touching the devices or your router.       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "This script will:"
echo "  1. Install dependencies (wireguard, dsniff, iptables, iproute2)"
echo "  2. Configure WireGuard"
echo "  3. Configure target devices and network settings"
echo "  4. Enable IP forwarding and set up policy routing"
echo "  5. Install the gatecrash service"
echo ""
confirm "Continue?" "Y/n" "y" || { echo "Aborted."; exit 0; }
echo ""

# ---------------------------------------------------------------------------
# 1. Install dependencies
# ---------------------------------------------------------------------------

echo "=== Installing dependencies ==="
apt-get update -q
apt-get install -y wireguard dsniff iptables iproute2

for bin in wg-quick arpspoof iptables ip; do
    command -v "$bin" &>/dev/null || { echo "ERROR: $bin not found after install."; exit 1; }
done
success "All dependencies installed."
echo ""

# ---------------------------------------------------------------------------
# 2. WireGuard configuration
# ---------------------------------------------------------------------------

echo "=== WireGuard configuration ==="
echo ""

if confirm "Do you have a WireGuard .conf file from your VPN provider?" "y/N" "n"; then
    echo ""
    while true; do
        prompt "Path to your .conf file" SRC_CONF
        [[ -f "$SRC_CONF" && -r "$SRC_CONF" ]] && break
        warn "File not found or not readable: $SRC_CONF"
    done

    # Parse the source conf
    PRIV_KEY=$(awk '/^\[Interface\]/,/^\[Peer\]/' "$SRC_CONF" | grep -i "^PrivateKey" | awk -F'=' '{print $2}' | tr -d ' ')
    WG_ADDR=$(awk '/^\[Interface\]/,/^\[Peer\]/' "$SRC_CONF" | grep -i "^Address" | awk -F'=' '{print $2}' | tr -d ' ')
    PUB_KEY=$(awk '/^\[Peer\]/,0' "$SRC_CONF" | grep -i "^PublicKey" | awk -F'=' '{print $2}' | tr -d ' ')
    ENDPOINT=$(awk '/^\[Peer\]/,0' "$SRC_CONF" | grep -i "^Endpoint" | awk -F'= *' '{print $2}' | tr -d ' ')
    ALLOWED=$(awk '/^\[Peer\]/,0' "$SRC_CONF" | grep -i "^AllowedIPs" | awk -F'= *' '{print $2}' | tr -d ' ')
    KEEPALIVE=$(awk '/^\[Peer\]/,0' "$SRC_CONF" | grep -i "^PersistentKeepalive" | awk -F'=' '{print $2}' | tr -d ' ')
    KEEPALIVE="${KEEPALIVE:-25}"

    # Warn about stripped fields
    if grep -qi "^DNS\s*=" "$SRC_CONF"; then
        warn "DNS line found in source config — stripped. DNS is handled locally by systemd-resolved."
    fi
    if grep -qi "^Table\s*=" "$SRC_CONF"; then
        warn "Table line found in source config — replaced with 'Table = off'. This is required for Gatecrash's policy routing."
    fi
    if grep -qi "^MTU\s*=" "$SRC_CONF"; then
        warn "MTU line found in source config — replaced with 'MTU = 1280' (conservative value to prevent TCP hangs)."
    fi

    echo ""
    info "Parsed from source config:"
    info "  Address:   $WG_ADDR"
    info "  Endpoint:  $ENDPOINT"
    info "  AllowedIPs: $ALLOWED"
    echo ""
    confirm "Does this look correct?" "Y/n" "y" || {
        echo "Please edit your .conf file and re-run setup."
        exit 1
    }
else
    echo ""
    echo "  Enter your WireGuard credentials manually."
    echo "  You can find these in your VPN provider's dashboard."
    echo ""
    prompt "PrivateKey (from your WireGuard keypair)" PRIV_KEY
    prompt "Address (e.g. 10.14.0.2/32)" WG_ADDR
    prompt "Server PublicKey" PUB_KEY
    prompt "Server Endpoint (host:port, e.g. 185.234.218.1:51820)" ENDPOINT

    read -rp "  > AllowedIPs [0.0.0.0/0]: " ALLOWED
    ALLOWED="${ALLOWED:-0.0.0.0/0}"

    read -rp "  > PersistentKeepalive [25]: " KEEPALIVE
    KEEPALIVE="${KEEPALIVE:-25}"
fi

echo ""
echo "  Writing /etc/wireguard/wg0.conf..."

cat > "$WG_CONF" <<EOF
[Interface]
PrivateKey = ${PRIV_KEY}
Address = ${WG_ADDR}
Table = off
MTU = 1280

[Peer]
PublicKey = ${PUB_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED}
PersistentKeepalive = ${KEEPALIVE}
EOF

chmod 600 "$WG_CONF"
success "WireGuard config written."
echo ""

echo "  Bringing up WireGuard tunnel..."
wg-quick up wg0

echo ""
echo "  Testing tunnel — this will return your VPN provider's IP..."
VPN_IP=$(curl --interface wg0 -m 15 -s http://ifconfig.me 2>/dev/null || true)
if [[ -n "$VPN_IP" ]]; then
    success "Tunnel is working. VPN exit IP: $VPN_IP"
else
    warn "Could not reach ifconfig.me through the tunnel."
    warn "The tunnel may still work — some providers block this endpoint."
    confirm "Continue anyway?" "y/N" "n" || {
        echo "Fix the WireGuard tunnel and re-run setup."
        exit 1
    }
fi
echo ""

# ---------------------------------------------------------------------------
# 3. Network configuration
# ---------------------------------------------------------------------------

echo "=== Network configuration ==="
echo ""

# Detect interfaces
echo "  Available network interfaces:"
ip -o link show | awk -F': ' '{print $2}' | grep -v "^lo$\|^wg" | while read -r iface; do
    ip4=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet )[^/]+' || true)
    printf "    %-12s %s\n" "$iface" "${ip4:-no IP}"
done
echo ""

while true; do
    prompt "LAN interface (bridged adapter, e.g. eth0)" LAN_IF
    ip link show "$LAN_IF" &>/dev/null && break
    warn "Interface '$LAN_IF' not found. Try again."
done

echo ""
while true; do
    prompt "Gateway IP (your router, e.g. 192.168.1.1)" GATEWAY_IP
    validate_ip "$GATEWAY_IP" && break
    warn "Invalid IP address. Try again."
done

ping -c1 -W2 "$GATEWAY_IP" &>/dev/null \
    && success "Gateway $GATEWAY_IP is reachable." \
    || warn "Cannot ping gateway $GATEWAY_IP — make sure the VM is on the correct LAN interface."

echo ""
echo "  Enter the IP address(es) of the device(s) you want to route through VPN."
echo "  Separate multiple IPs with spaces. Example: 192.168.1.90 192.168.1.183"
echo ""
while true; do
    prompt "Target IP(s)" TARGET_IPS_RAW
    valid=true
    for ip in $TARGET_IPS_RAW; do
        validate_ip "$ip" || { warn "Invalid IP: $ip"; valid=false; break; }
    done
    $valid && break
done

echo ""
for ip in $TARGET_IPS_RAW; do
    ping -c1 -W2 "$ip" &>/dev/null \
        && success "Target $ip is reachable." \
        || warn "Cannot ping target $ip — it may be offline or blocking ICMP. Continuing anyway."
done
echo ""

# ---------------------------------------------------------------------------
# 4. IP forwarding
# ---------------------------------------------------------------------------

echo "=== Enabling IP forwarding ==="
sysctl -w net.ipv4.ip_forward=1 > /dev/null
cat > "$SYSCTL_CONF" <<EOF
net.ipv4.ip_forward = 1
EOF
success "IP forwarding enabled permanently."
echo ""

# ---------------------------------------------------------------------------
# 5. Policy routing table
# ---------------------------------------------------------------------------

echo "=== Policy routing ==="
if grep -q "vpntarget" "$RT_TABLES"; then
    info "vpntarget routing table already present."
else
    echo "100 vpntarget" >> "$RT_TABLES"
    success "Added vpntarget to $RT_TABLES."
fi

# Add the ip rule (idempotent)
if ! ip rule show | grep -q "fwmark 0x1 lookup vpntarget"; then
    ip rule add fwmark 0x1 table vpntarget
    success "Added fwmark rule: 0x1 → vpntarget."
else
    info "fwmark rule already present."
fi
echo ""

# ---------------------------------------------------------------------------
# 6. Install scripts and service
# ---------------------------------------------------------------------------

echo "=== Installing Gatecrash ==="
mkdir -p "$INSTALL_DIR"

# Write config
cat > "$INSTALL_DIR/gatecrash.conf" <<EOF
LAN_IF="${LAN_IF}"
VPN_IF="wg0"
GATEWAY_IP="${GATEWAY_IP}"
TARGET_IPS="${TARGET_IPS_RAW}"
ROUTE_TABLE="vpntarget"
FWMARK="0x1"
EOF
chmod 640 "$INSTALL_DIR/gatecrash.conf"
success "Config written to $INSTALL_DIR/gatecrash.conf"

# Install scripts from the repo directory (same dir as setup.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for script in start.sh stop.sh; do
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        cp "$SCRIPT_DIR/$script" "$INSTALL_DIR/$script"
        chmod 750 "$INSTALL_DIR/$script"
        success "Installed $script"
    else
        warn "$script not found in $SCRIPT_DIR — skipping. You can install it manually later."
    fi
done

# Install systemd service
if [[ -f "$SCRIPT_DIR/gatecrash.service" ]]; then
    cp "$SCRIPT_DIR/gatecrash.service" /etc/systemd/system/gatecrash.service
    systemctl daemon-reload
    systemctl enable gatecrash
    success "gatecrash.service installed and enabled."
else
    warn "gatecrash.service not found — systemd service not installed."
fi
echo ""

# ---------------------------------------------------------------------------
# 7. Optional immediate start
# ---------------------------------------------------------------------------

if confirm "Start Gatecrash now?" "Y/n" "y"; then
    echo ""
    "$INSTALL_DIR/start.sh"
else
    echo ""
    info "To start manually: sudo /opt/gatecrash/start.sh"
    info "Or via systemd:    sudo systemctl start gatecrash"
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Setup complete!                             ║"
echo "║                                              ║"
echo "║  Commands:                                   ║"
echo "║    sudo /opt/gatecrash/start.sh              ║"
echo "║    sudo /opt/gatecrash/stop.sh               ║"
echo "║    sudo systemctl status gatecrash           ║"
echo "║                                              ║"
echo "║  Config: /opt/gatecrash/gatecrash.conf       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
