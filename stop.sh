#!/usr/bin/env bash
# Gatecrash stop — clean teardown, restores normal routing.
# Safe to run even if Gatecrash was only partially started.
set -euo pipefail

CONF="/opt/gatecrash/gatecrash.conf"

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: $CONF not found."
    exit 1
fi
# shellcheck source=/dev/null
source "$CONF"

echo "Stopping Gatecrash..."

# ---------------------------------------------------------------------------
# 1. Stop ARP spoofing
# ---------------------------------------------------------------------------

if pkill -f arpspoof 2>/dev/null; then
    echo "  arpspoof stopped."
else
    echo "  arpspoof was not running."
fi

# ---------------------------------------------------------------------------
# 2. Flush all iptables rules
# ---------------------------------------------------------------------------

echo "  Flushing iptables rules and connection tracking..."
iptables -t mangle -F PREROUTING
iptables -t mangle -F FORWARD
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
iptables -F FORWARD
conntrack -F 2>/dev/null || true
echo "  [OK] iptables and conntrack flushed."

# ---------------------------------------------------------------------------
# 3. vpntarget routes
# ---------------------------------------------------------------------------

ip route del default dev "$VPN_IF" table "$ROUTE_TABLE" metric 100 2>/dev/null && echo "  vpntarget VPN route removed." || true
ip route del default via "$GATEWAY_IP" dev "$LAN_IF" table "$ROUTE_TABLE" metric 200 2>/dev/null && echo "  vpntarget fallback route removed." || true
# Clean up old non-metric routes from previous versions
ip route del default dev "$VPN_IF" table "$ROUTE_TABLE" 2>/dev/null || true
ip route del default via "$GATEWAY_IP" dev "$LAN_IF" table "$ROUTE_TABLE" 2>/dev/null || true

# ip rule and rt_tables entry are left intact — they are harmless
# and will be needed again on next start.

# ---------------------------------------------------------------------------
# 4. WireGuard
# ---------------------------------------------------------------------------

if ip link show "$VPN_IF" &>/dev/null; then
    wg-quick down "$VPN_IF" && echo "  WireGuard ($VPN_IF) down." \
        || echo "  wg-quick down failed — check manually."
else
    echo "  WireGuard ($VPN_IF) was not up."
fi

echo ""
echo "Gatecrash stopped."
echo "Target devices will resume normal routing within ~2 minutes as ARP caches expire."
