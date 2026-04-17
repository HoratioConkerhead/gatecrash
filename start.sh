#!/usr/bin/env bash
# Gatecrash start — bring up the full stack.
# Idempotent: safe to run when already running.
set -euo pipefail

CONF="/opt/gatecrash/gatecrash.conf"

# shellcheck source=log.sh
source "$(dirname "$0")/log.sh"

log INFO "SERVICE  start.sh invoked (PID $$, PPID $PPID)"

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------

if [[ ! -f "$CONF" ]]; then
    log ERROR "SERVICE  $CONF not found — aborting"
    echo "ERROR: $CONF not found. Run setup.sh first."
    exit 1
fi
# shellcheck source=/dev/null
source "$CONF"

# ---------------------------------------------------------------------------
# 1. WireGuard — check only, do NOT bring up
# ---------------------------------------------------------------------------
# WireGuard is managed independently (web UI / wg-quick@wg0 service).
# Gatecrash works with or without it: when wg0 is up the VPN route wins
# (metric 100); when it's down, traffic falls back to the real gateway
# (metric 200). This avoids start.sh undoing a deliberate WireGuard stop.

if ip link show "$VPN_IF" &>/dev/null; then
    echo "WireGuard ($VPN_IF) is up — VPN routing will be active."
    log INFO "SERVICE  WireGuard ($VPN_IF) is up"
else
    echo "WireGuard ($VPN_IF) is NOT up — targets will use direct connection."
    echo "  Start WireGuard separately if VPN routing is needed."
    log INFO "SERVICE  WireGuard ($VPN_IF) is not up — proceeding without VPN"
fi

# ---------------------------------------------------------------------------
# 2. Policy routing
# ---------------------------------------------------------------------------
# Two routes in the vpntarget table with different metrics:
#   metric 100 = VPN tunnel (preferred when wg0 is up)
#   metric 200 = real gateway (fallback — keeps devices online when VPN is down)
# When wg0 goes down, Linux removes its route automatically → traffic falls
# back to the real gateway. When wg0 comes back, it wins again.

# Auto-detect gateway if not set in config
if [[ -z "${GATEWAY_IP:-}" ]]; then
    GATEWAY_IP=$(ip route show default | awk '/default/ {print $3}' | head -1)
    log INFO "SERVICE  GATEWAY_IP was empty — detected $GATEWAY_IP"
fi

log INFO "SERVICE  Policy routing setup (GW=$GATEWAY_IP LAN=$LAN_IF RT=$ROUTE_TABLE VPN=$VPN_IF)"
if ip link show "$VPN_IF" &>/dev/null; then
    ip route replace default dev "$VPN_IF" table "$ROUTE_TABLE" metric 100
    echo "  vpntarget: VPN route via $VPN_IF (metric 100)"
else
    echo "  vpntarget: $VPN_IF not up — VPN route skipped"
fi

log INFO "SERVICE  Adding fallback route"
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

log INFO "SERVICE  Flushing iptables rules"
echo "Flushing iptables rules and connection tracking..."
iptables -t mangle -F PREROUTING
iptables -t mangle -F FORWARD
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
iptables -F FORWARD

# SECURITY: default-deny FORWARD.  ip_forward=1 is required for ARP spoofing
# to work, but without this DROP policy the box would silently forward ANY
# traffic between interfaces — turning it into an open router.  Only the
# per-target ACCEPT rules below re-open specific devices.  (MED-10)
iptables -P FORWARD DROP

# SECURITY: only flush conntrack for target devices — NOT the whole table.
# `conntrack -F` would tear down SSH, the web UI, and every other connection
# to the box, including the session running this script.  An attacker could
# exploit a full flush to cause a denial-of-service.  (MED-13)
for ip in $TARGET_IPS; do
    conntrack -D -s "$ip" 2>/dev/null || true
    conntrack -D -d "$ip" 2>/dev/null || true
done
echo "  [OK] iptables flushed, target conntrack entries cleared."

# ---------------------------------------------------------------------------
# 4. Global iptables rules
# ---------------------------------------------------------------------------

log INFO "SERVICE  Adding global iptables rules"
iptables -t mangle -A FORWARD -o "$VPN_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t nat -A POSTROUTING -o "$VPN_IF" -j MASQUERADE

# ---------------------------------------------------------------------------
# 5. Per-target rules and ARP spoofing
# ---------------------------------------------------------------------------

log INFO "SERVICE  Activating per-target rules for: ${TARGET_IPS:-(none)}"
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
log INFO "SERVICE  Gatecrash running — targets: $TARGET_IPS"
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
