#!/usr/bin/env bash
# Gatecrash stop — clean teardown, restores normal routing.
# Safe to run even if Gatecrash was only partially started.
set -euo pipefail

CONF="/opt/gatecrash/gatecrash.conf"

# shellcheck source=log.sh
source "$(dirname "$0")/log.sh"

log INFO "SERVICE  stop.sh invoked (PID $$, PPID $PPID)"

if [[ ! -f "$CONF" ]]; then
    log ERROR "SERVICE  $CONF not found — aborting"
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

# SECURITY: default-deny FORWARD on teardown.  ip_forward stays 1 (sysctl),
# so without this DROP policy the box becomes an open router after stop —
# silently forwarding traffic in the clear.  Do NOT remove.  (MED-10)
iptables -P FORWARD DROP

# SECURITY: flush only target devices' conntrack — never the whole table.
# `conntrack -F` would kill SSH, the web UI, and anything else talking to the
# box.  Per-target `-D` is the safe alternative.  (MED-13)
for ip in ${TARGET_IPS:-}; do
    conntrack -D -s "$ip" 2>/dev/null || true
    conntrack -D -d "$ip" 2>/dev/null || true
done
echo "  [OK] iptables flushed, target conntrack entries cleared."

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
# 4. WireGuard — leave alone
# ---------------------------------------------------------------------------
# WireGuard is managed independently. Stopping Gatecrash should not kill
# the VPN tunnel — the user may want it up for other reasons, or may
# restart Gatecrash without a WireGuard interruption.

if ip link show "$VPN_IF" &>/dev/null; then
    echo "  WireGuard ($VPN_IF) is still up (managed separately)."
else
    echo "  WireGuard ($VPN_IF) was not up."
fi

log INFO "SERVICE  Gatecrash stopped"
echo ""
echo "Gatecrash stopped."
echo "Target devices will resume normal routing within ~2 minutes as ARP caches expire."
