#!/usr/bin/env bash
# Gatecrash setup — installs dependencies and scaffolding.
# Does not start or enable any services. Configure first, then start manually.
set -euo pipefail

INSTALL_DIR="/opt/gatecrash"
RT_TABLES="/etc/iproute2/rt_tables"
SYSCTL_CONF="/etc/sysctl.d/99-gatecrash.conf"

trap 'echo ""; echo "ERROR: setup failed at line $LINENO." >&2' ERR

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo bash setup.sh"
    exit 1
fi

echo ""
echo "=== Gatecrash Setup ==="
echo ""

# ---------------------------------------------------------------------------
# 1. Install dependencies
# ---------------------------------------------------------------------------

echo "Installing dependencies..."
apt-get update -q
apt-get install -y wireguard dsniff iptables iproute2 curl

for bin in wg-quick arpspoof iptables ip curl; do
    command -v "$bin" &>/dev/null || { echo "ERROR: $bin not found after install."; exit 1; }
done
echo "  [OK] Dependencies installed."

# ---------------------------------------------------------------------------
# 2. Enable IP forwarding
# ---------------------------------------------------------------------------

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
cat > "$SYSCTL_CONF" <<EOF
net.ipv4.ip_forward = 1
EOF
echo "  [OK] IP forwarding enabled."

# ---------------------------------------------------------------------------
# 3. Policy routing table
# ---------------------------------------------------------------------------

echo "Configuring policy routing..."
if [[ ! -f "$RT_TABLES" ]]; then
    mkdir -p /etc/iproute2
    cat > "$RT_TABLES" <<EOF
255     local
254     main
253     default
0       unspec
EOF
    echo "  [OK] Created $RT_TABLES."
fi
if grep -q "vpntarget" "$RT_TABLES"; then
    echo "  [OK] vpntarget routing table already present."
else
    echo "100 vpntarget" >> "$RT_TABLES"
    echo "  [OK] Added vpntarget to $RT_TABLES."
fi

if ! ip rule show | grep -q "fwmark 0x1 lookup vpntarget"; then
    ip rule add fwmark 0x1 table vpntarget
    echo "  [OK] Added fwmark rule: 0x1 → vpntarget."
else
    echo "  [OK] fwmark rule already present."
fi

# ---------------------------------------------------------------------------
# 4. Install scripts and config
# ---------------------------------------------------------------------------

echo "Installing scripts to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for script in start.sh stop.sh; do
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        cp "$SCRIPT_DIR/$script" "$INSTALL_DIR/$script"
        chmod 750 "$INSTALL_DIR/$script"
        echo "  [OK] Installed $script"
    else
        echo "  [WARN] $script not found in $SCRIPT_DIR — skipping."
    fi
done

if [[ ! -f "$INSTALL_DIR/gatecrash.conf" ]]; then
    cp "$SCRIPT_DIR/gatecrash.conf.example" "$INSTALL_DIR/gatecrash.conf"
    chmod 640 "$INSTALL_DIR/gatecrash.conf"
    echo "  [OK] Created $INSTALL_DIR/gatecrash.conf from example."
else
    echo "  [OK] $INSTALL_DIR/gatecrash.conf already exists — not overwritten."
fi

# ---------------------------------------------------------------------------
# 5. Install systemd service (not enabled, not started)
# ---------------------------------------------------------------------------

echo "Installing systemd service..."
if [[ -f "$SCRIPT_DIR/gatecrash.service" ]]; then
    cp "$SCRIPT_DIR/gatecrash.service" /etc/systemd/system/gatecrash.service
    systemctl daemon-reload
    echo "  [OK] gatecrash.service installed (not enabled)."
else
    echo "  [WARN] gatecrash.service not found — skipping."
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo ""
echo "  1. Create your WireGuard config:"
echo "       sudo nano /etc/wireguard/wg0.conf"
echo "       (see readme for required format — Table=off and MTU=1280 are critical)"
echo ""
echo "  2. Edit the Gatecrash config:"
echo "       sudo nano $INSTALL_DIR/gatecrash.conf"
echo "       (set LAN_IF, GATEWAY_IP, TARGET_IPS)"
echo ""
echo "  3. Test WireGuard before starting Gatecrash:"
echo "       sudo wg-quick up wg0"
echo "       curl --interface wg0 -m 10 http://ifconfig.me"
echo "       (should return your VPN provider's IP)"
echo ""
echo "  4. Start Gatecrash:"
echo "       sudo /opt/gatecrash/start.sh"
echo ""
echo "  5. To start on boot once you're happy it works:"
echo "       sudo systemctl enable gatecrash"
echo ""
