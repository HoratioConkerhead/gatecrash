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
# 2. Per-target iptables rules
# ---------------------------------------------------------------------------

rule_delete() {
    iptables -C "$@" 2>/dev/null && iptables -D "$@" 2>/dev/null || true
}

for ip in $TARGET_IPS; do
    echo "  Removing rules for target: $ip"

    rule_delete -t mangle PREROUTING -s "$ip" -i "$LAN_IF" -j MARK --set-mark "$FWMARK"
    rule_delete FORWARD -i "$LAN_IF" -o "$VPN_IF" -s "$ip" -j ACCEPT
    rule_delete FORWARD -i "$VPN_IF" -o "$LAN_IF" -d "$ip" -m state --state RELATED,ESTABLISHED -j ACCEPT
    rule_delete -t nat PREROUTING -s "$ip" -p udp --dport 53 -j REDIRECT --to-port 53
    rule_delete -t nat PREROUTING -s "$ip" -p tcp --dport 53 -j REDIRECT --to-port 53
done

# ---------------------------------------------------------------------------
# 3. Global iptables rules
# ---------------------------------------------------------------------------

echo "  Removing global iptables rules..."
rule_delete -t mangle FORWARD -o "$VPN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
rule_delete -t nat POSTROUTING -o "$VPN_IF" -j MASQUERADE

# ---------------------------------------------------------------------------
# 4. vpntarget route
# ---------------------------------------------------------------------------

if ip route del default dev "$VPN_IF" table "$ROUTE_TABLE" 2>/dev/null; then
    echo "  vpntarget route removed."
else
    echo "  vpntarget route was not present."
fi

# ip rule and rt_tables entry are left intact — they are harmless
# and will be needed again on next start.

# ---------------------------------------------------------------------------
# 5. WireGuard
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
