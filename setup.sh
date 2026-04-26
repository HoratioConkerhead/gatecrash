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
# 1. Remove conflicting packages (apache2 binds port 80, blocks web UI)
# ---------------------------------------------------------------------------

if dpkg -l apache2 2>/dev/null | grep -q '^ii'; then
    echo "Removing apache2 (conflicts with web UI on port 80)..."
    systemctl stop apache2 2>/dev/null || true
    systemctl disable apache2 2>/dev/null || true
    apt-get --purge remove -y apache2 apache2-utils apache2-bin apache2-data || true
    apt-get autoremove --purge -y
    echo "  [OK] apache2 removed."
fi

# ---------------------------------------------------------------------------
# 2. Install dependencies
# ---------------------------------------------------------------------------

echo "Installing dependencies..."
apt-get update -q
apt-get install -y wireguard dsniff iptables iproute2 curl python3 python3-venv tcpdump avahi-daemon nmap conntrack

for bin in wg-quick arpspoof iptables ip curl python3 tcpdump; do
    command -v "$bin" &>/dev/null || { echo "ERROR: $bin not found after install."; exit 1; }
done
echo "  [OK] Dependencies installed."

# ---------------------------------------------------------------------------
# Hostname
# ---------------------------------------------------------------------------

echo "Setting hostname to 'gatecrash'..."
hostnamectl set-hostname gatecrash
systemctl enable avahi-daemon
systemctl start avahi-daemon
echo "  [OK] Hostname set. Device accessible at https://gatecrash.local"

# ---------------------------------------------------------------------------
# 3. Enable IP forwarding
# ---------------------------------------------------------------------------

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
cat > "$SYSCTL_CONF" <<EOF
net.ipv4.ip_forward = 1
EOF
echo "  [OK] IP forwarding enabled."

# ---------------------------------------------------------------------------
# 4. Policy routing table
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
# 5. Install scripts and config
# ---------------------------------------------------------------------------

echo "Installing scripts to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for script in start.sh stop.sh log.sh; do
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

    # Auto-detect LAN interface from default route (gateway is detected on
    # every boot by start.sh, so we leave GATEWAY_IP blank intentionally).
    DETECTED_IF=$(ip route show default | awk '/default/ {print $5; exit}')
    if [[ -n "$DETECTED_IF" ]]; then
        sed -i "s/^LAN_IF=.*/LAN_IF=\"$DETECTED_IF\"/" "$INSTALL_DIR/gatecrash.conf"
        echo "  [OK] Auto-detected LAN_IF=$DETECTED_IF"
    fi
    echo "  [OK] Created $INSTALL_DIR/gatecrash.conf from example."
else
    echo "  [OK] $INSTALL_DIR/gatecrash.conf already exists — not overwritten."
fi

# ---------------------------------------------------------------------------
# 6. Install systemd service (not enabled, not started)
# ---------------------------------------------------------------------------

echo "Installing systemd services..."
if [[ -f "$SCRIPT_DIR/gatecrash.service" ]]; then
    cp "$SCRIPT_DIR/gatecrash.service" /etc/systemd/system/gatecrash.service
    echo "  [OK] gatecrash.service installed (not enabled)."
else
    echo "  [WARN] gatecrash.service not found — skipping."
fi
if [[ -f "$SCRIPT_DIR/gatecrash-resume.service" ]]; then
    cp "$SCRIPT_DIR/gatecrash-resume.service" /etc/systemd/system/gatecrash-resume.service
    cp "$SCRIPT_DIR/resume-state.sh" /opt/gatecrash/resume-state.sh
    chmod +x /opt/gatecrash/resume-state.sh
    systemctl enable gatecrash-resume
    echo "  [OK] gatecrash-resume.service installed and enabled."
fi
systemctl daemon-reload

# ---------------------------------------------------------------------------
# 7. Generate self-signed TLS certificate (if not already present)
# ---------------------------------------------------------------------------

CERT_DIR="$INSTALL_DIR/certs"
CERT_FILE="$CERT_DIR/gatecrash.crt"
KEY_FILE="$CERT_DIR/gatecrash.key"

mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
    echo "Generating self-signed TLS certificate..."
    # 825 days is the maximum self-signed validity Apple platforms (iOS/macOS
    # Safari) will accept — anything longer fails with "cert validity too long".
    # The web UI will auto-renew when it gets close to expiry.
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -days 825 -subj "/CN=gatecrash" \
        -addext "subjectAltName=DNS:gatecrash,DNS:gatecrash.local,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
    echo "  [OK] TLS certificate generated (valid 825 days)."
else
    echo "  [OK] TLS certificate already exists — not overwritten."
fi

# ---------------------------------------------------------------------------
# 8. Install web UI
# ---------------------------------------------------------------------------

echo "Installing web UI..."
WEBUI_DIR="$INSTALL_DIR/webui"
mkdir -p "$WEBUI_DIR/templates" "$WEBUI_DIR/static"

cp "$SCRIPT_DIR/webui/app.py" "$WEBUI_DIR/app.py"
cp "$SCRIPT_DIR/webui/templates/index.html" "$WEBUI_DIR/templates/index.html"
cp -r "$SCRIPT_DIR/webui/static/." "$WEBUI_DIR/static/"

if [[ ! -d "$WEBUI_DIR/venv" ]]; then
    echo "  Creating Python virtual environment..."
    python3 -m venv "$WEBUI_DIR/venv"
fi
echo "  Installing Python dependencies..."
"$WEBUI_DIR/venv/bin/pip" install --quiet flask bcrypt flask-limiter
echo "  [OK] Python environment ready."

cp "$SCRIPT_DIR/webui/gatecrash-webui.service" /etc/systemd/system/gatecrash-webui.service
systemctl daemon-reload
systemctl enable gatecrash-webui
echo "  Restarting web UI service (connection will drop briefly)..."
systemctl restart gatecrash-webui
echo "  [OK] Web UI installed and restarted."

# Note: gatecrash itself is NOT enabled here. The web UI enables it
# automatically the first time the user saves a WireGuard config, so a fresh
# install doesn't have a `failed` service unit sitting in systemctl status.

# Save repo path so the web UI can run upgrades
echo "$SCRIPT_DIR" > "$INSTALL_DIR/repo_path"
echo "  [OK] Repo path saved."

# Allow root to run git in this repo (owned by a different user)
git config --global --add safe.directory "$SCRIPT_DIR"
echo "  [OK] Git safe.directory configured."

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
echo "  4. Start Gatecrash from the web UI (the big power button at the bottom)."
echo "     Once you've uploaded a VPN config the web UI enables Gatecrash on boot"
echo "     automatically, so it'll come back up after every reboot."
echo ""
echo "  Web UI is running at:"
WEBUI_IP=$(ip -4 addr show | grep -oP '(?<=inet )[\d.]+' | grep -v 127 | head -1)
echo "       https://${WEBUI_IP:-<VM-IP>}"
echo ""
