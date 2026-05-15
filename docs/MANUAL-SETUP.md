# Manual Setup

> The `setup.sh` script handles all of the steps below automatically.
> This document is a reference for understanding what `setup.sh` does, or for
> setting things up by hand on a system where the script doesn't fit.

## 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y wireguard dsniff iptables iproute2 curl python3 python3-venv \
    tcpdump avahi-daemon nmap conntrack unattended-upgrades
```

`dsniff` provides `arpspoof`. `nmap` powers the web UI's network scan,
`conntrack` is used to flush per-target connection state on start/stop, and
`unattended-upgrades` backs the optional OS auto-update feature.

## 2. Configure WireGuard

Get a WireGuard config from your VPN provider. For Surfshark: log in at
https://my.surfshark.com → VPN → Manual setup → Desktop or mobile →
WireGuard → generate a key pair → choose a location → download the .conf.

Create `/etc/wireguard/wg0.conf` using the values from the downloaded config,
but with two critical changes:

```ini
[Interface]
PrivateKey = <your-private-key>
Address = <address-from-config>
Table = off
MTU = 1280

[Peer]
PublicKey = <server-public-key>
Endpoint = <server-endpoint>
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**`Table = off`** — Prevents WireGuard from installing a default route. Without
this, the box's own traffic (and everything else on the network) tries to go
through the tunnel. We handle routing ourselves with policy routing so only
marked target traffic uses the tunnel.

**`MTU = 1280`** — WireGuard's default MTU of 1420 causes silent packet drops
with many ISPs and devices, especially smart TVs. TCP handshakes work (small
packets) but actual data transfer hangs. 1280 is conservative but reliable.
You can try increasing it later once everything is working.

**No DNS line** — DNS is handled separately (see below).

```bash
sudo wg-quick up wg0
sudo wg show    # Verify tunnel is up — look for a recent handshake
```

## 3. Verify the Tunnel

Before setting up any routing, confirm the tunnel itself works:

```bash
curl --interface wg0 -m 10 http://ifconfig.me
```

This should return your VPN provider's IP (not your ISP's). If this doesn't
work, nothing else will — fix the tunnel first.

Note: `curl http://ifconfig.me` (without `--interface wg0`) will correctly
return your ISP's IP. The box's own traffic deliberately bypasses the tunnel.

## 4. Enable IP Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-gatecrash.conf
```

## 5. Policy Routing

Create a separate routing table that only marked packets will use:

```bash
# Add the routing table (only needed once)
grep -q "vpntarget" /etc/iproute2/rt_tables || \
    echo "100 vpntarget" >> /etc/iproute2/rt_tables

# Add two default routes to that table, at different metrics:
#   metric 100 — through WireGuard (preferred when the tunnel is up)
#   metric 200 — via the real gateway (fallback when WireGuard is down)
sudo ip route add default dev wg0 table vpntarget metric 100
sudo ip route add default via 192.168.1.254 dev eth0 table vpntarget metric 200

# Packets with fwmark 0x1 use the vpntarget table
sudo ip rule add fwmark 0x1 table vpntarget
```

The lower-metric WireGuard route wins whenever the tunnel is up; if it drops,
the metric-200 route keeps the target online via the normal gateway (a
deliberate fail-open — there is no kill-switch).

**Important:** `wg-quick down/up` wipes the vpntarget routing table. You must
re-add the `metric 100` WireGuard route after any WireGuard restart.
`start.sh` handles this automatically.

## 6. iptables Rules

```bash
TARGET_IP="192.168.1.90"
LAN_IF="eth0"
VPN_IF="wg0"

# Mark traffic from the target
sudo iptables -t mangle -A PREROUTING -s $TARGET_IP -i $LAN_IF -j MARK --set-mark 0x1

# MSS clamping — critical for preventing TCP hangs
sudo iptables -t mangle -A FORWARD -o $VPN_IF -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# NAT out through WireGuard
sudo iptables -t nat -A POSTROUTING -o $VPN_IF -j MASQUERADE

# Default-deny forwarding, then allow only the target both directions.
# ip_forward stays on, so without the default DROP the box is an open router.
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -i $LAN_IF -o $VPN_IF -s $TARGET_IP -j ACCEPT
sudo iptables -A FORWARD -i $VPN_IF -o $LAN_IF -d $TARGET_IP -m state --state RELATED,ESTABLISHED -j ACCEPT

# DNS — DNAT the target's DNS queries to a public resolver (see DNS section below)
sudo iptables -t nat -A PREROUTING -s $TARGET_IP -p udp --dport 53 -j DNAT --to-destination 1.1.1.1:53
sudo iptables -t nat -A PREROUTING -s $TARGET_IP -p tcp --dport 53 -j DNAT --to-destination 1.1.1.1:53
```

## 7. DNS

DNS queries from the target device are **DNAT'd to a public resolver**
(`1.1.1.1:53`) rather than sent to the box itself.

**Why not REDIRECT DNS to a local resolver?**

`REDIRECT` sends the queries to port 53 *on the box*. That only works if
something is actually listening there — and on a minimal appliance nothing
reliably is, so target devices that use plain DNS simply lose name resolution.
DNAT to `1.1.1.1` always points at a working resolver. DNS doesn't reveal the
target's apparent location anyway — the actual traffic still exits through the
VPN.

**Do not install dnsmasq** — it conflicts with `systemd-resolved` on port 53.

## 8. ARP Spoofing

```bash
TARGET_IP="192.168.1.90"
GATEWAY_IP="192.168.1.254"
LAN_IF="eth0"

# Tell the target "I am the gateway"
sudo arpspoof -i $LAN_IF -t $TARGET_IP $GATEWAY_IP > /dev/null 2>&1 &

# Tell the gateway "I am the target"
sudo arpspoof -i $LAN_IF -t $GATEWAY_IP $TARGET_IP > /dev/null 2>&1 &
```

Both directions are required. `arpspoof` sends periodic gratuitous ARP replies
to keep the spoofed entries fresh in both ARP caches.

## 9. Verify

```bash
# Check WireGuard is passing traffic
sudo wg show
# Look for "latest handshake" and increasing transfer bytes

# Watch target traffic flowing through the tunnel
sudo tcpdump -i wg0 -n host 192.168.1.90

# Check iptables counters
sudo iptables -t mangle -L PREROUTING -v -n
```

On the target device, visit https://whatismyip.com — it should show the VPN
exit IP, not your ISP's IP.
