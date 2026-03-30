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
# 1. WireGuard
# ---------------------------------------------------------------------------

if ! ip link show "$VPN_IF" &>/dev/null; then
    echo "Bringing up WireGuard ($VPN_IF)..."
    wg-quick up "$VPN_IF"
else
    echo "WireGuard ($VPN_IF) already up."
fi

# ---------------------------------------------------------------------------
# 2. Policy routing
# ---------------------------------------------------------------------------
# Two routes in the vpntarget table with different metrics:
#   metric 100 = VPN tunnel (preferred when wg0 is up)
#   metric 200 = real gateway (fallback — keeps devices online when VPN is down)
# When wg0 goes down, Linux removes its route automatically → traffic falls
# back to the real gateway. When wg0 comes back, it wins again.

if ip link show "$VPN_IF" &>/dev/null; then
    ip route replace default dev "$VPN_IF" table "$ROUTE_TABLE" metric 100
    echo "  vpntarget: VPN route via $VPN_IF (metric 100)"
else
    echo "  vpntarget: $VPN_IF not up — VPN route skipped"
fi

ip route replace default via "$GATEWAY_IP" dev "$LAN_IF" table "$ROUTE_TABLE" metric 200
echo "  vpntarget: fallback route via $GATEWAY_IP (metric 200)"

if ! ip rule show | grep -q "fwmark $FWMARK lookup $ROUTE_TABLE"; then
    ip rule add fwmark "$FWMARK" table "$ROUTE_TABLE"
    echo "  fwmark rule added: $FWMARK → $ROUTE_TABLE"
else
    echo "  fwmark rule already present."
fi

# ---------------------------------------------------------------------------
# 3. Clean slate — flush all Gatecrash iptables rules before re-adding
# ---------------------------------------------------------------------------
# Previous versions used rule_exists checks to be idempotent, but this led to
# stale rules accumulating (e.g. old REDIRECT rules blocking new DNAT rules).
# Flushing is safe because Gatecrash owns these chains — no other service uses
# mangle PREROUTING/FORWARD or nat PREROUTING/POSTROUTING on this box.

echo "Flushing iptables rules and connection tracking..."
iptables -t mangle -F PREROUTING
iptables -t mangle -F FORWARD
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
iptables -F FORWARD
conntrack -F 2>/dev/null || true
echo "  [OK] iptables and conntrack flushed."

# ---------------------------------------------------------------------------
# 4. Global iptables rules
# ---------------------------------------------------------------------------

iptables -t mangle -A FORWARD -o "$VPN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t nat -A POSTROUTING -o "$VPN_IF" -j MASQUERADE

# ---------------------------------------------------------------------------
# 5. Per-target rules and ARP spoofing
# ---------------------------------------------------------------------------

for ip in $TARGET_IPS; do
    echo "Activating target: $ip"

    # Mark traffic from this device for policy routing
    iptables -t mangle -A PREROUTING -s "$ip" -i "$LAN_IF" -j MARK --set-mark "$FWMARK"

    # Forward target traffic (to VPN or to real gateway — no output interface
    # restriction so the fallback route works when VPN is down)
    iptables -A FORWARD -i "$LAN_IF" -s "$ip" -j ACCEPT
    iptables -A FORWARD -d "$ip" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$VPN_IF" -o "$LAN_IF" -d "$ip" -m state --state RELATED,ESTABLISHED -j ACCEPT

    # DNAT DNS to Cloudflare via the VPN tunnel (prevents DNS leaks and avoids
    # needing a local DNS server — REDIRECT to local :53 broke devices that
    # use plain DNS because nothing was listening).
    iptables -t nat -A PREROUTING -s "$ip" -p udp --dport 53 -j DNAT --to-destination 1.1.1.1:53
    iptables -t nat -A PREROUTING -s "$ip" -p tcp --dport 53 -j DNAT --to-destination 1.1.1.1:53

    # Kill any stale arpspoof for this target before (re)starting
    pkill -f "arpspoof -i $LAN_IF -t $ip $GATEWAY_IP" 2>/dev/null || true
    pkill -f "arpspoof -i $LAN_IF -t $GATEWAY_IP $ip" 2>/dev/null || true

    arpspoof -i "$LAN_IF" -t "$ip" "$GATEWAY_IP" > /dev/null 2>&1 &
    arpspoof -i "$LAN_IF" -t "$GATEWAY_IP" "$ip" > /dev/null 2>&1 &
done

# ---------------------------------------------------------------------------
# 6. Status summary
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

# Keep the process alive and watch for arpspoof processes that have exited
# (e.g. target device was offline at start or rebooted). Restart them as needed.
# SIGTERM from systemd kills this loop and all children via KillMode=control-group.
while true; do
    sleep 30
    for ip in $TARGET_IPS; do
        fwd=$(pgrep -cf "arpspoof -i $LAN_IF -t $ip $GATEWAY_IP" 2>/dev/null || true)
        rev=$(pgrep -cf "arpspoof -i $LAN_IF -t $GATEWAY_IP $ip" 2>/dev/null || true)
        if [[ "${fwd:-0}" -eq 0 ]] || [[ "${rev:-0}" -eq 0 ]]; then
            echo "arpspoof for $ip exited — restarting"
            pkill -f "arpspoof -i $LAN_IF -t $ip $GATEWAY_IP" 2>/dev/null || true
            pkill -f "arpspoof -i $LAN_IF -t $GATEWAY_IP $ip" 2>/dev/null || true
            arpspoof -i "$LAN_IF" -t "$ip" "$GATEWAY_IP" > /dev/null 2>&1 &
            arpspoof -i "$LAN_IF" -t "$GATEWAY_IP" "$ip" > /dev/null 2>&1 &
        fi
    done
done
