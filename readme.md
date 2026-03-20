# Gatecrash

Force specific devices on your LAN through a VPN tunnel — without touching
the devices or your router. Uses ARP spoofing to transparently redirect
traffic from target devices through a WireGuard VPN.

## Quickstart

See [Preparing the VM](#preparing-the-vm) first if you haven't set up your
Linux VM yet.

**1. Clone and run setup** (installs dependencies and scripts, starts nothing):

```bash
git clone https://github.com/HoratioConkerhead/gatecrash
cd gatecrash
sudo bash setup.sh
```

**2. Create your WireGuard config** (see [Configure WireGuard](#2-configure-wireguard) for the required format):

```bash
sudo nano /etc/wireguard/wg0.conf
```

**3. Edit the Gatecrash config:**

```bash
sudo nano /opt/gatecrash/gatecrash.conf
```

Set `LAN_IF` (your bridged network interface), `GATEWAY_IP` (your router),
and `TARGET_IPS` (the device(s) to route through VPN).

**4. Test WireGuard before starting:**

```bash
sudo wg-quick up wg0
curl --interface wg0 -m 10 http://ifconfig.me   # should return VPN IP, not your ISP's
```

**5. Start Gatecrash:**

```bash
sudo /opt/gatecrash/start.sh
```

On the target device, visit https://whatismyip.com — it should show the VPN
exit IP, not your ISP's IP.

**6. Enable on boot once you're happy it works:**

```bash
sudo systemctl enable gatecrash
```

**Other commands:**

```bash
sudo /opt/gatecrash/stop.sh          # stop and restore normal routing
sudo systemctl status gatecrash      # check service status
```

---

## Preparing the VM

These steps get the VM ready before you run `setup.sh`. The instructions
cover Hyper-V specifically but the concepts apply to any hypervisor.

### 1. Reserve a static IP for the VM on your router

Gatecrash needs a stable IP on your LAN. The cleanest way is a DHCP
reservation on your router — the VM keeps DHCP (simpler to manage) but
always gets the same IP.

Find the VM's MAC address first. In Hyper-V Manager, before the VM is
created or after creation:

- **Settings → Network Adapter → Advanced Features**
- The MAC address is listed here (you can also let Hyper-V assign one
  dynamically — just start the VM once and read it with `ip link show`)

Then on your router, add a DHCP reservation:
- Most routers: **DHCP → Address Reservation** or **Static Leases**
- Bind the VM's MAC address to a chosen IP (e.g. `192.168.1.100`)
- The exact steps vary by router — consult your router's manual

### 2. Create an External Virtual Switch (Hyper-V)

The VM needs to appear directly on your physical LAN, not on an isolated
virtual network.

1. Open **Hyper-V Manager**
2. **Action → Virtual Switch Manager**
3. Select **External** → **Create Virtual Switch**
4. Name it (e.g. `LAN Bridge`)
5. Under **Connection type**, select **External network** and choose your
   physical NIC from the dropdown
6. Leave **Allow management OS to share this network adapter** checked
   (this keeps your Windows host connected to the LAN through the same NIC)
7. Click **OK**

### 3. Create the VM

- **New → Virtual Machine**
- Generation 2 (UEFI), 1–2 vCPUs, 512 MB RAM (1 GB to be comfortable)
- Attach the **External Virtual Switch** you created above as the network adapter
- Install **Debian 12 (Bookworm)** — use the netinstall ISO for a minimal install

During Debian installation, when you reach **Software selection**, uncheck
everything except:
- **SSH server**
- **Standard system utilities**

No desktop, no print server. This keeps the VM footprint small.

### 4. Enable MAC Address Spoofing (Hyper-V)

This is required. Without it, ARP spoof packets are silently dropped by
the Hyper-V virtual switch and nothing will work.

**Shut the VM down first**, then:

1. **Hyper-V Manager → VM Settings → Network Adapter → Advanced Features**
2. Check **Enable MAC address spoofing**
3. Click **OK**

If you want a fixed MAC address (useful for the DHCP reservation above):

1. In the same **Advanced Features** panel, switch MAC address from
   **Dynamic** to **Static**
2. Enter a MAC address in the format `xx-xx-xx-xx-xx-xx`
   (e.g. `52-54-00-AB-CD-EF` — the `52-54-00` prefix is conventionally
   used for virtual machines)
3. Use this MAC address for your DHCP reservation on the router

### 5. First boot — confirm networking

Start the VM and log in. Verify it got the expected IP:

```bash
ip addr show
```

Confirm internet access works:

```bash
curl -s http://ifconfig.me
```

This should return your ISP's IP. If networking isn't working, check the
virtual switch assignment and that the DHCP reservation is active on your
router.

### 6. Install git and clone the repo

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/HoratioConkerhead/gatecrash
cd gatecrash
sudo bash setup.sh
```

---

## How It Works

```
Target Device (e.g. 192.168.1.90)
    │
    │  ARP spoofed — thinks the VM is the default gateway
    │
    ▼
Gatecrash VM (e.g. 192.168.1.100)
    │
    ├── Marks target traffic with fwmark → policy routes into WireGuard
    │
    ├── wg0 ──► VPN Provider ──► Internet (target's traffic exits here)
    │
    └── eth0 ──► Real Gateway ──► Internet (VM's own traffic, unaffected)
```

The target device needs zero configuration changes. It doesn't know anything
has changed. If Gatecrash stops, the device's ARP cache self-corrects within
a couple of minutes and traffic flows normally again.

## Manual Setup

> The `setup.sh` script handles all of the steps below automatically.
> This section is a reference for understanding what it does, or for
> setting things up by hand.

### 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y wireguard dsniff iptables iproute2
```

`dsniff` provides `arpspoof`.

### 2. Configure WireGuard

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
this, the VM's own traffic (and everything else on the network) tries to go
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

### 3. Verify the Tunnel

Before setting up any routing, confirm the tunnel itself works:

```bash
curl --interface wg0 -m 10 http://ifconfig.me
```

This should return your VPN provider's IP (not your ISP's). If this doesn't
work, nothing else will — fix the tunnel first.

Note: `curl http://ifconfig.me` (without `--interface wg0`) will correctly
return your ISP's IP. The VM's own traffic deliberately bypasses the tunnel.

### 4. Enable IP Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-gatecrash.conf
```

### 5. Policy Routing

Create a separate routing table that only marked packets will use:

```bash
# Add the routing table (only needed once)
grep -q "vpntarget" /etc/iproute2/rt_tables || \
    echo "100 vpntarget" >> /etc/iproute2/rt_tables

# Add default route via WireGuard in that table
sudo ip route add default dev wg0 table vpntarget

# Packets with fwmark 0x1 use the vpntarget table
sudo ip rule add fwmark 0x1 table vpntarget
```

**Important:** `wg-quick down/up` wipes the vpntarget routing table. You must
re-run `ip route add default dev wg0 table vpntarget` after any WireGuard
restart.

### 6. iptables Rules

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

# Allow forwarding both directions
sudo iptables -A FORWARD -i $LAN_IF -o $VPN_IF -s $TARGET_IP -j ACCEPT
sudo iptables -A FORWARD -i $VPN_IF -o $LAN_IF -d $TARGET_IP -m state --state RELATED,ESTABLISHED -j ACCEPT

# DNS — redirect to local resolver (see DNS section below)
sudo iptables -t nat -A PREROUTING -s $TARGET_IP -p udp --dport 53 -j REDIRECT --to-port 53
sudo iptables -t nat -A PREROUTING -s $TARGET_IP -p tcp --dport 53 -j REDIRECT --to-port 53
```

### 7. DNS

DNS queries from the target device are redirected to the VM's local resolver
using REDIRECT rules (see above). Debian runs `systemd-resolved` by default,
which handles this automatically.

**Why not route DNS through the tunnel?**

During testing, we found that UDP traffic through the WireGuard tunnel can be
unreliable (DNS queries sent but no responses received), while TCP works fine.
Since DNS is just name resolution and doesn't reveal the target device's
apparent location (the actual traffic still exits through the VPN), resolving
DNS locally is simpler and more reliable.

**Do not install dnsmasq** — it conflicts with `systemd-resolved` on port 53.
The default `systemd-resolved` setup works out of the box.

### 8. ARP Spoofing

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

### 9. Verify

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

## Switching Target Devices

```bash
OLD_IP="192.168.1.183"
NEW_IP="192.168.1.90"
GATEWAY_IP="192.168.1.254"
LAN_IF="eth0"

# Stop arpspoof for old target
sudo pkill arpspoof

# Remove old iptables rules
sudo iptables -t mangle -D PREROUTING -s $OLD_IP -i $LAN_IF -j MARK --set-mark 0x1
sudo iptables -D FORWARD -i $LAN_IF -o wg0 -s $OLD_IP -j ACCEPT
sudo iptables -D FORWARD -i wg0 -o $LAN_IF -d $OLD_IP -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -D PREROUTING -s $OLD_IP -p udp --dport 53 -j REDIRECT --to-port 53
sudo iptables -t nat -D PREROUTING -s $OLD_IP -p tcp --dport 53 -j REDIRECT --to-port 53

# Add new target rules
sudo iptables -t mangle -A PREROUTING -s $NEW_IP -i $LAN_IF -j MARK --set-mark 0x1
sudo iptables -A FORWARD -i $LAN_IF -o wg0 -s $NEW_IP -j ACCEPT
sudo iptables -A FORWARD -i wg0 -o $LAN_IF -d $NEW_IP -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -A PREROUTING -s $NEW_IP -p udp --dport 53 -j REDIRECT --to-port 53
sudo iptables -t nat -A PREROUTING -s $NEW_IP -p tcp --dport 53 -j REDIRECT --to-port 53

# Start arpspoof for new target
sudo arpspoof -i $LAN_IF -t $NEW_IP $GATEWAY_IP > /dev/null 2>&1 &
sudo arpspoof -i $LAN_IF -t $GATEWAY_IP $NEW_IP > /dev/null 2>&1 &
```

## Multiple Devices

Add iptables and arpspoof rules per IP, all using the same fwmark:

```bash
for ip in 192.168.1.90 192.168.1.183 192.168.1.50; do
    iptables -t mangle -A PREROUTING -s $ip -i eth0 -j MARK --set-mark 0x1
    iptables -A FORWARD -i eth0 -o wg0 -s $ip -j ACCEPT
    iptables -A FORWARD -i wg0 -o eth0 -d $ip -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A PREROUTING -s $ip -p udp --dport 53 -j REDIRECT --to-port 53
    iptables -t nat -A PREROUTING -s $ip -p tcp --dport 53 -j REDIRECT --to-port 53
    arpspoof -i eth0 -t $ip 192.168.1.254 > /dev/null 2>&1 &
    arpspoof -i eth0 -t 192.168.1.254 $ip > /dev/null 2>&1 &
done
```

## Auto-Start on Boot

`setup.sh` installs and enables the systemd service automatically. The
service file is `gatecrash.service` in this repo.

To install manually:

```bash
sudo cp gatecrash.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable gatecrash
sudo systemctl start gatecrash
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Target loses internet completely | IP forwarding not enabled | `sysctl net.ipv4.ip_forward` should return 1 |
| Target has internet but not via VPN | vpntarget routing table empty | `ip route show table vpntarget` — re-add route if missing |
| vpntarget route disappears | WireGuard was restarted | Run `ip route add default dev wg0 table vpntarget` after every `wg-quick` restart |
| ARP spoof silently fails (Hyper-V) | MAC spoofing disabled | VM Settings → Network → Advanced → Enable MAC Address Spoofing |
| TCP connections hang | MTU too high | Set `MTU = 1280` in wg0.conf, add MSS clamp iptables rule |
| DNS not resolving | DNS routed through tunnel (UDP unreliable) | Use REDIRECT to local systemd-resolved instead of DNAT to remote DNS |
| dnsmasq won't start | Port 53 conflict with systemd-resolved | Don't install dnsmasq — systemd-resolved handles port 53 |
| `tcpdump -i wg0` says "No such device" | WireGuard tunnel is down | `sudo wg-quick up wg0` then re-add vpntarget route |
| VM's own internet breaks | `Table = off` missing in wg0.conf | WireGuard is hijacking the default route |
| Works initially then stops | arpspoof process died | `pgrep arpspoof` — restart if missing |
| Slow speeds | MTU too low or ISP throttling | Try increasing MTU in increments of 20 from 1280 |

## How It Fails Safely

- If the VM goes down, target devices lose internet briefly until their ARP
  cache expires (typically 1–2 minutes), then traffic routes normally via the
  real gateway
- If WireGuard goes down, marked packets have no route and are dropped — the
  target loses internet but no traffic leaks outside the tunnel
- If arpspoof stops, ARP caches self-correct and traffic bypasses the VM

## Tested With

- Debian 12 (Bookworm) on Hyper-V (Dell Precision 7920)
- Surfshark WireGuard (Albania endpoint)
- LG smart TV and Windows laptop as target devices

## Future Ideas

- Config file driven target management
- CLI wrapper (`gatecrash add/remove/status/list`)
- Automatic vpntarget route restoration after WireGuard restart
- Web UI for managing targets
- Per-device VPN exit selection (different countries for different devices)

## License

MIT