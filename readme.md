# Gatecrash

**Route specific devices on your network through a VPN — without installing
anything on them, without replacing your router, and without any inline
hardware.**

Gatecrash is a small Linux appliance that sits alongside your existing router
and uses ARP spoofing to selectively intercept traffic from chosen devices,
routing it through a WireGuard VPN tunnel. Target devices don't know anything
has changed — no apps to install, no settings to configure, no profiles to
accept. Your smart TV, games console, or streaming box just quietly gets a
different exit IP.

### What makes this different?

- **VPN routers** (GL.iNet, Vilfo, pfSense) can route per-device — but they
  replace your router. Gatecrash works alongside it.
- **Device VPN apps** (NordVPN, Surfshark) require software on each device.
  Smart TVs and IoT devices often can't run them at all.
- **Inline devices** (Hak5 Packet Squirrel) sit physically between a device
  and the network. Gatecrash works from anywhere on the LAN.
- **Pi-hole** has a similar "plug in a box" philosophy — but it blocks ads
  via DNS, not route traffic through a VPN.

Gatecrash needs nothing from the target device and nothing from the router.
Plug it in, point it at the devices you want, and their traffic exits from
a different country. Everything else on your network is unaffected. If the
VPN drops, target devices fall back to the normal gateway automatically.

## Quickstart

See [Preparing the VM](#preparing-the-vm) first if you haven't set up your
Linux VM yet.

**1. Clone and run setup:**

```bash
sudo apt install -y git
git clone https://github.com/HoratioConkerhead/gatecrash
cd gatecrash
sudo bash setup.sh
```

This installs dependencies, sets the hostname to `gatecrash`, and starts
the web UI. It does not start Gatecrash itself.

**2. Open the web UI:**

```
http://gatecrash.local
```

Use the web UI to paste in your WireGuard config and set your target
device IPs, gateway, and LAN interface.

**3. Test WireGuard first** using the **Start WireGuard** and **Check VPN IP**
buttons in the web UI before starting Gatecrash.

**4. Start Gatecrash** using the **Start Gatecrash** button in the web UI.

**5. Enable Gatecrash on boot** once you're happy it works:

```bash
sudo systemctl enable gatecrash
```

**CLI commands (if preferred):**

```bash
sudo /opt/gatecrash/start.sh           # start Gatecrash
sudo /opt/gatecrash/stop.sh            # stop and restore normal routing
sudo systemctl status gatecrash        # Gatecrash service status
sudo systemctl status gatecrash-webui  # web UI status
```

---

## Preparing the VM

These steps get the VM ready before you run `setup.sh`. The instructions
cover Hyper-V on Windows specifically.

> **Note:** This process is more involved than it needs to be. Streamlining
> it (ideally into a flashable image) is on the roadmap.

### Hyper-V VM Setup (Detailed)

#### 1. Create the VM in Hyper-V Manager

- **New → Virtual Machine**
- Memory: 2 GB
- Network: select your **External** virtual switch
- Disk: 8 GB, stored wherever you keep your VMs
- ISO: **Debian 13 netinstall** — use the small installation image from [debian.org](https://www.debian.org/distrib/)

Then before starting, go into **Settings**:
- **Security** → disable Secure Boot
- **Network Adapter → Advanced Features** → enable MAC address spoofing

Start the VM and connect to it. Once Debian is installed, go back into
Settings and:
- **Network Adapter → Advanced Features** → switch MAC address from Dynamic
  to **Static** and note the value (e.g. `00:15:5d:01:51:1e`)

Then on your router, create a **DHCP reservation** binding that MAC address
to a fixed IP (e.g. `192.168.1.9`).

#### 2. Install Debian

Choose **graphical install** or plain **install** — either works.

- Language: English, location: UK, locale: British English
- Hostname: `gatecrash`, domain: leave blank
- Set a root password (keep a note of it)
- Create a user account with a username and password of your choice
- Disk: **Guided — use entire disk**, partitioning scheme: **all files in one partition**
- Extra media: No
- Mirror: pick any

**Software selection** — uncheck everything except:
- **SSH server**
- **Standard system utilities**

No desktop environment.

#### 3. Post-install: enable sudo

Log in as your user. You'll need to use `su` to run root commands until
`sudo` is set up:

```bash
su -
/usr/sbin/usermod -aG sudo yourusername
exit
```

Log out and back in, then verify:

```bash
sudo apt update
```

#### 4. Enable SSH password authentication

```bash
sudo nano /etc/ssh/sshd_config
```

Make sure these lines are set to `yes`:

```
PasswordAuthentication yes
KbdInteractiveAuthentication yes
```

Then:

```bash
sudo systemctl restart ssh
```

You can now SSH in from Windows: `ssh yourusername@192.168.1.x`

#### 5. Create a GitHub token

You need a read-only token to clone the (private) repo:

1. GitHub → profile picture → **Settings → Developer settings**
2. **Fine-grained tokens → Generate new token**
3. Repository access: **Only select repositories** → pick `gatecrash`
4. Permissions → **Contents: Read-only**
5. Expiry: your preference (No expiry is fine for a dedicated device)
6. Copy the token — you won't see it again

#### 6. Clone and run setup

```bash
sudo apt install -y git
git clone https://YOUR_TOKEN@github.com/HoratioConkerhead/gatecrash
cd gatecrash
sudo bash setup.sh
```

Replace `YOUR_TOKEN` with the token you just created.

---

### 1. Reserve a static IP for the VM on your router

Gatecrash needs a stable IP on your LAN. The cleanest way is a DHCP
reservation on your router — the VM keeps DHCP (simpler to manage) but
always gets the same IP.

Find the VM's MAC address first. In Hyper-V Manager:

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
- Generation 2 (UEFI), 1–2 vCPUs, 1 GB RAM minimum
- Attach the **External Virtual Switch** you created above as the network adapter
- Install **Debian 12 (Bookworm)** — use the netinstall ISO for a minimal install

During Debian installation, when you reach **Software selection**, uncheck
everything except:
- **SSH server**
- **Standard system utilities**

No desktop. This keeps the VM footprint small.

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

### 6. SSH in and clone the repo

From your Windows machine you can now SSH in:

```bash
ssh username@192.168.x.x
```

Then install git and clone:

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
Gatecrash VM (gatecrash.local)
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

## Web UI

After setup, the web UI is available at **http://gatecrash.local**. It provides:

- **Status** — live indicators for Gatecrash and WireGuard
- **Controls** — start/stop Gatecrash and WireGuard independently
- **VPN Test** — checks your VPN exit IP through the tunnel
- **Config editor** — set target IPs, gateway, and LAN interface
- **WireGuard config editor** — paste your VPN provider's config
- **WireGuard stats** — endpoint, last handshake, bytes transferred
- **DNS query log** — live view of DNS requests from target devices
- **Updates** — check for and apply updates from GitHub in one click

## Manual Setup

> The `setup.sh` script handles all of the steps below automatically.
> This section is a reference for understanding what it does, or for
> setting things up by hand.

### 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y wireguard dsniff iptables iproute2 curl python3 python3-venv tcpdump avahi-daemon
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
restart. `start.sh` handles this automatically.

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

## Auto-Start on Boot

`setup.sh` installs and enables the systemd service automatically. The
web UI (`gatecrash-webui`) starts on boot automatically. Gatecrash itself
must be manually enabled once you're satisfied it works:

```bash
sudo systemctl enable gatecrash
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `http://gatecrash.local` not reachable | avahi-daemon not running | `sudo systemctl status avahi-daemon` |
| Target loses internet completely | IP forwarding not enabled | `sysctl net.ipv4.ip_forward` should return 1 |
| Target has internet but not via VPN | vpntarget routing table empty | `ip route show table vpntarget` — re-add route if missing |
| vpntarget route disappears | WireGuard was restarted | `start.sh` restores it automatically on next start |
| ARP spoof silently fails (Hyper-V) | MAC spoofing disabled | VM Settings → Network → Advanced → Enable MAC Address Spoofing |
| TCP connections hang | MTU too high | Set `MTU = 1280` in wg0.conf, add MSS clamp iptables rule |
| DNS not resolving | DNS routed through tunnel (UDP unreliable) | Use REDIRECT to local systemd-resolved instead of DNAT to remote DNS |
| dnsmasq won't start | Port 53 conflict with systemd-resolved | Don't install dnsmasq — systemd-resolved handles port 53 |
| `tcpdump -i wg0` says "No such device" | WireGuard tunnel is down | Use Start WireGuard button in web UI, or `sudo wg-quick up wg0` |
| VM's own internet breaks | `Table = off` missing in wg0.conf | WireGuard is hijacking the default route |
| Works initially then stops | arpspoof process died | Restart Gatecrash via web UI or `sudo systemctl restart gatecrash` |
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

## Known Issues

- **IPv6 bypass risk** — ARP spoofing only intercepts IPv4. If a target device prefers IPv6 (most modern devices do when available), its traffic goes directly to the router via NDP, completely bypassing Gatecrash. Investigate: warn in the UI if IPv6 is active on the LAN, consider NDP spoofing, or strip AAAA records from DNS responses to force IPv4


## Fixes

- **Scan network needs tidying**
  - ignore the ones already added
  - tv's at the top?
  - remove existing results when scanning again

- **diagnostics**
  - remove dns for the gatecrash device, as it's just cluttering it up

- **Device management improvements:**
  - **Search/filter** the device list when adding devices
  - **Device list from ARP table and DHCP leases** — richer source of truth than nmap-only
  - **no refresh on remove** - if a device that's not selected is removed from favourites, no need to stop/start Gatecrash

- **Update refresh screen**
  - Doesn't refresh screen on upgrade.  Need to refresh webpage, but 'app' needs quiting and reloading.
  

## Future Ideas

### Web App Improvements

- **Config backup** - export/import configuration to the cloud or as a downloadable file
- **PWA Info** - popup showing how to add as an app



### Discovery and Access

- **Authentication** — single shared password set during first-time setup, stored as bcrypt hash, cookie-based session
- **mDNS** already implemented (`gatecrash.local`); ensure it works on all client platforms

### First-Time Setup Wizard

- On first boot with no config, serve a setup wizard at `gatecrash.local`
- User enters VPN credentials or uploads a `.conf` file, sets admin password
- No WiFi hotspot needed — device gets a DHCP address via Ethernet and is immediately reachable via mDNS

### Set and Forget

- **MAC-based device tracking** — store devices by MAC address rather than IP (needs testing); poll ARP table periodically — if a saved MAC appears at a new IP, automatically update iptables rules and arpspoof targets. Handles DHCP renewals without needing static reservations. iPhones and Android use per-network randomised MACs which stay consistent on the same network, so this works reliably
- **Automatic vpntarget route restoration** after WireGuard restart

### Auto Mode (v2)

Gatecrash has two modes of operation:

- **Normal mode** — user manually turns on spoof + VPN routing for selected devices whenever they want. Simple, no extra setup.
- **Auto mode** — Gatecrash watches DNS traffic and automatically activates spoof + VPN routing per device when it sees queries for configured domains (e.g. `youtube.com`, `googlevideo.com`), then drops them after a configurable idle timeout.

**Auto mode requires Gatecrash to act as the DNS server for the LAN.** The recommended setup is:

- Run `dnsmasq` on Gatecrash in forwarding mode — receives all DNS queries, logs them with source IP, forwards to upstream (e.g. 1.1.1.1)
- Configure the router's DHCP to advertise **Gatecrash as primary DNS, the router itself as secondary** — this way if Gatecrash is down, clients fall back to the router and still have DNS (avoids breaking the network if Gatecrash is off)
- The Gatecrash daemon watches the dnsmasq query log; when a trigger domain is queried by a device in auto mode, it activates ARP spoof + VPN routing for that device only — no need to spoof all devices just to observe DNS
- After a configurable idle period with no matching queries (default 1 minute), deactivate spoof + VPN routing for that device automatically

**Per-device mode selection:** always-on / auto / off — keeps non-targeted traffic (iPlayer, general browsing) on the direct connection

**Note:** This is an advanced configuration. Normal mode requires no router changes and no DNS server. Auto mode requires one router setting change (primary DNS) and is only needed if the user wants hands-free activation.

### Robustness

- **Bulletproof cleanup on shutdown** — restore real gateway ARP entries with proper gratuitous ARPs before stopping; works even if the main process was killed ungracefully
- **Rate-limit arpspoof** — send every 2 seconds rather than as fast as possible, to reduce router stress
- **Per-app VPN** — route only traffic to specific destinations, e.g. all YouTube traffic
- **Auto-configure VPN** — accept the `.conf` file the VPN provider supplies, or auto-fetch config by logging in for known providers
- **Appliance image** — a flashable SD card image (Pi-hole style) so setup is: flash → plug in → open browser. No Linux knowledge required

### Hardware Appliance

- **Target platform: NanoPi Zero2 (2GB)** — 45×45mm, native Gigabit Ethernet, ~$28 with case, runs Ubuntu/Debian natively
- **BOM** — NanoPi Zero2 2GB, microSD card, USB-C power supply, Ethernet cable — under £35 total
- **Single RGB LED** for status: green (running), blue (VPN active), red (error), pulsing white (booting)
- **Optional OLED display** for detailed status — future upgrade
- **3D printed case** — custom design with Ethernet/USB-C cutouts, LED window, ventilation, logo, optional wall-mount clip; include OLED cutout even if not fitted initially; translucent filament option for LED glow-through
- **Publish STL files and BOM** alongside the code in the repo

## License

MIT
