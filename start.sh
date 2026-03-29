#!/usr/bin/env bash
# Gatecrash start — bring up the full stack.
# Idempotent: safe to run when already running.
set -euo pipefail

CONF="/opt/gatecrash/gatecrash.conf"

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: $CONF not found. Run setup.sh first."
    exit 1
fi
# shellcheck source=/dev/null
source "$CONF"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

rule_exists() { iptables -C "$@" 2>/dev/null; }

# ---------------------------------------------------------------------------
# 1. WireGuard
# ---------------------------------------------------------------------------

if ! ip link show "$VPN_IF" &>/dev/null; then
    echo "Bringing up WireGuard ($VPN_IF)..."
    wg-quick up "$VPN_IF"
else
    echo "WireGuard ($VPN_IF) already up."
fi

# ---------------------------------------------------------------------------
# 2. Policy routing (wg-quick wipes the vpntarget route on every restart)
# ---------------------------------------------------------------------------

if ! ip route show table "$ROUTE_TABLE" 2>/dev/null | grep -q "^default"; then
    echo "Restoring vpntarget default route..."
    ip route add default dev "$VPN_IF" table "$ROUTE_TABLE"
fi

if ! ip rule show | grep -q "fwmark $FWMARK lookup $ROUTE_TABLE"; then
    echo "Restoring fwmark rule..."
    ip rule add fwmark "$FWMARK" table "$ROUTE_TABLE"
fi

# ---------------------------------------------------------------------------
# 3. Global iptables rules
# ---------------------------------------------------------------------------

rule_exists -t mangle FORWARD -o "$VPN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu \
    || iptables -t mangle -A FORWARD -o "$VPN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

rule_exists -t nat POSTROUTING -o "$VPN_IF" -j MASQUERADE \
    || iptables -t nat -A POSTROUTING -o "$VPN_IF" -j MASQUERADE

# ---------------------------------------------------------------------------
# 4. Per-target rules and ARP spoofing
# ---------------------------------------------------------------------------

for ip in $TARGET_IPS; do
    echo "Activating target: $ip"

    rule_exists -t mangle PREROUTING -s "$ip" -i "$LAN_IF" -j MARK --set-mark "$FWMARK" \
        || iptables -t mangle -A PREROUTING -s "$ip" -i "$LAN_IF" -j MARK --set-mark "$FWMARK"

    rule_exists FORWARD -i "$LAN_IF" -o "$VPN_IF" -s "$ip" -j ACCEPT \
        || iptables -A FORWARD -i "$LAN_IF" -o "$VPN_IF" -s "$ip" -j ACCEPT

    rule_exists FORWARD -i "$VPN_IF" -o "$LAN_IF" -d "$ip" -m state --state RELATED,ESTABLISHED -j ACCEPT \
        || iptables -A FORWARD -i "$VPN_IF" -o "$LAN_IF" -d "$ip" -m state --state RELATED,ESTABLISHED -j ACCEPT

    # DNAT DNS to Cloudflare via the VPN tunnel (prevents DNS leaks and avoids
    # needing a local DNS server — REDIRECT to local :53 broke devices that
    # use plain DNS because nothing was listening).
    rule_exists -t nat PREROUTING -s "$ip" -p udp --dport 53 -j DNAT --to-destination 1.1.1.1:53 \
        || iptables -t nat -A PREROUTING -s "$ip" -p udp --dport 53 -j DNAT --to-destination 1.1.1.1:53

    rule_exists -t nat PREROUTING -s "$ip" -p tcp --dport 53 -j DNAT --to-destination 1.1.1.1:53 \
        || iptables -t nat -A PREROUTING -s "$ip" -p tcp --dport 53 -j DNAT --to-destination 1.1.1.1:53

    # Kill any stale arpspoof for this target before (re)starting
    pkill -f "arpspoof -i $LAN_IF -t $ip $GATEWAY_IP" 2>/dev/null || true
    pkill -f "arpspoof -i $LAN_IF -t $GATEWAY_IP $ip" 2>/dev/null || true

    arpspoof -i "$LAN_IF" -t "$ip" "$GATEWAY_IP" > /dev/null 2>&1 &
    arpspoof -i "$LAN_IF" -t "$GATEWAY_IP" "$ip" > /dev/null 2>&1 &
done

# ---------------------------------------------------------------------------
# 5. Status summary
# ---------------------------------------------------------------------------

echo ""
echo "=== Gatecrash running ==="
echo "Targets:       $TARGET_IPS"
HANDSHAKE=$(wg show "$VPN_IF" 2>/dev/null | grep 'latest handshake' | head -1 || true)
echo "WireGuard:     ${HANDSHAKE:-no handshake yet — traffic will trigger one}"
ROUTE=$(ip route show table "$ROUTE_TABLE" 2>/dev/null | grep "^default" || true)
echo "vpntarget:     ${ROUTE:-MISSING — check wg-quick status}"
ARPS=$(pgrep -c arpspoof 2>/dev/null || echo 0)
echo "arpspoof pids: $ARPS running"
echo "========================="
echo ""

# Keep the process alive so systemd (Type=simple) tracks it.
# SIGTERM from systemd will kill this and all child arpspoof processes
# because the service uses KillMode=control-group.
wait
