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

Gatecrash has been tested on a Hyper-V VM and a Raspberry Pi 4B.

## Quickstart — Installing on a Raspberry Pi

A Raspberry Pi running Pi OS Lite is the simplest way to get Gatecrash running.

> You don't need a monitor, keyboard, or mouse — the Raspberry Pi Imager sets up
> all the remote access. You may want to plug into a monitor if there are issues.

We use **Raspberry Pi OS Lite**, the command-line-only version. This should work
on a 4 GB card, but hasn't been tested at that size.

**1. Prepare the SD card**

On a computer, use Raspberry Pi Imager from https://www.raspberrypi.com/software/ to install and configure the OS:

1. Pick OS → Raspberry Pi OS (other) → Raspberry Pi OS Lite (64-bit)
2. Set hostname to `gatecrash`
3. Create a username and password
4. Enable SSH (password or public key — password is easiest)
5. Optionally enable Raspberry Pi Connect (not required)

**2. Boot and log on**

1. Insert the SD card into the Pi
2. Plug into ethernet
3. Turn on — first boot takes a few minutes to set up
4. SSH in remotely from another computer (e.g. on Windows):
   1. Open a terminal (or `cmd.exe`)
   2. Run `ssh gatecrash -l <user_you_specified>`
   3. Accept the fingerprint
   4. Enter the password

**3. Install Git**

```bash
sudo apt -y install git-all
```

**4. Get a GitHub token (only if the repo is still private)**

If Gatecrash is still in a private repo, you'll need a personal access token to
clone it. **The token must be provided by the repo owner** (you can't create
one yourself unless you're a collaborator on the repo).

If you are the repo owner setting this up for someone else, generate a token
on GitHub → **Settings → Developer settings → Fine-grained tokens → Generate
new token**, scoped to just this repo with:

- Contents: **Read-only**
- No expiry (fine for a dedicated device)

The token looks like `github_pat_<long string of random letters and numbers>`.
Copy it once — GitHub won't show it again.

**5. Install Gatecrash**

This installs dependencies, clones the repo, and runs the setup script.
It starts the web UI but does not start Gatecrash itself.

```bash
sudo apt install -y git
git clone https://[the_long_key_from_above]@github.com/HoratioConkerhead/gatecrash
cd gatecrash
sudo bash setup.sh
```

**6. Open the web UI**

On a computer or mobile device:

```
http://gatecrash.local
```

Now follow the prompts to configure your WireGuard (VPN) config and target devices.

**7. Test WireGuard first**

Using the **Start WireGuard** and **Check VPN IP**
buttons in the web UI before starting Gatecrash.

**8. Start Gatecrash** using the **Start Gatecrash** button in the web UI.

---

### CLI commands (if preferred): ###

```bash
sudo /opt/gatecrash/start.sh           # start Gatecrash
sudo /opt/gatecrash/stop.sh            # stop and restore normal routing
sudo systemctl status gatecrash        # Gatecrash service status
sudo systemctl status gatecrash-webui  # web UI status
```

---

## Other platforms

Not running a Raspberry Pi? Gatecrash will also run on:

- A **Hyper-V VM** on Windows (Debian guest)
- **Bare-metal Debian** on any small machine
- **DietPi** (untested but expected to work)

See [docs/INSTALL-OTHER.md](docs/INSTALL-OTHER.md) for instructions.

---

## How It Works

Gatecrash spoofs ARP **in both directions** so it sits invisibly between the
target device and the real gateway. Neither end realises:

```
   ┌──────────────┐         ┌──────────────────┐         ┌──────────────┐
   │   Target     │ ◄─ARP─► │    Gatecrash     │ ◄─ARP─► │ Real Gateway │
   │ 192.168.1.90 │  spoof  │ (gatecrash.local)│  spoof  │ 192.168.1.1  │
   └──────────────┘         └────────┬─────────┘         └──────┬───────┘
                                     │                          │
                                wg0  │                          │  eth0
                                     ▼                          ▼
                              VPN Provider                  Internet
                                     │                 (Gatecrash's own
                                     ▼                  traffic, unaffected)
                                 Internet
                            (target's exit IP)
```

- **Forward spoof** (target → Gatecrash): the target sees Gatecrash's MAC
  when it ARPs for the gateway, so all its outbound traffic comes to Gatecrash.
- **Reverse spoof** (gateway → Gatecrash): the real gateway sees Gatecrash's
  MAC when it ARPs for the target, so any return traffic destined for the
  target also flows through Gatecrash. (Most return traffic for VPN-routed
  flows comes back via WireGuard, but the reverse spoof keeps the
  man-in-the-middle complete for any LAN-side packets the gateway might send
  to the target — DHCP renewals, ICMP, etc.)

The target device needs zero configuration changes. It doesn't know anything
has changed. If Gatecrash stops, both ARP caches self-correct within a couple
of minutes and traffic flows normally again.

### Device tracking

Gatecrash tracks target devices by **MAC address**, not IP address. You do not
need static DHCP reservations for your target devices — if a device gets a new
IP from DHCP, Gatecrash detects the change via the ARP table within 60 seconds
and updates its routing rules automatically.

iPhones and Android devices use **per-network randomised MACs** (the same
random MAC is reused consistently on the same network), so they are tracked
reliably without any extra configuration.

## Web UI

After setup, the web UI is available at **http://gatecrash.local**. It provides:

- **Status** — live indicators for Gatecrash and WireGuard
- **Controls** — start/stop Gatecrash and WireGuard independently
- **Device management** — scan the LAN, save devices by MAC, enable/disable per-device
- **Auto-stop** — automatically disable idle devices after configurable timeout (e.g. user stopped streaming and went to bed)
- **VPN Test** — checks your VPN exit IP through the tunnel
- **Config editor** — set target IPs, gateway, and LAN interface
- **WireGuard config** — upload/paste your VPN provider's config
- **WireGuard stats** — endpoint, last handshake, bytes transferred
- **DNS query log** — live view of DNS requests from target devices
- **Audit log** — persistent log of all service actions, auth events, config changes (Diagnostics tab)
- **Updates** — check for and apply updates from GitHub in one click
- **PWA** — install as an app on iPhone, Android, or desktop

## Auto-Stop (Idle Device Timeout)

Gatecrash can automatically disable devices that have gone idle — useful for
devices left on overnight after streaming.

Enable it in **Config → Auto-Stop** in the web UI. Settings:

| Setting | Default | Description |
|---------|---------|-------------|
| Traffic threshold | 50 KB/min | Below this = "idle" (streaming is typically 5,000+ KB/min) |
| Idle timeout | 30 min | How long below threshold before disabling |
| Minimum active time | 5 min | Don't auto-stop recently enabled devices |

Individual devices can be exempted from auto-stop via the device info popup
(tap the **i** button on any saved device).

Auto-stopped devices appear as disabled in the device list. Re-enable them
to start routing again. Events are logged to the audit log.

## Auto-Start on Boot

The web UI (`gatecrash-webui`) is always enabled on boot. Gatecrash and
WireGuard themselves are state-resumed via `gatecrash-resume.service`:
whatever was running at the time of the last shutdown comes back up, so
the two services stay in sync (no "gatecrash up but WG down" surprises).

If you'd rather have it always-on regardless of last state:

```bash
sudo systemctl enable gatecrash
sudo systemctl enable wg-quick@wg0
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

## Known Issues

- **IPv6 bypass risk** — ARP spoofing only intercepts IPv4. If a target device prefers IPv6 (most modern devices do when available), its traffic goes directly to the router via NDP, completely bypassing Gatecrash. Investigate: warn in the UI if IPv6 is active on the LAN, consider NDP spoofing, or strip AAAA records from DNS responses to force IPv4

## Documentation

| Doc | Audience |
|-----|----------|
| [docs/INSTALL-OTHER.md](docs/INSTALL-OTHER.md) | Installing on Hyper-V, bare-metal Debian, or DietPi |
| [docs/MANUAL-SETUP.md](docs/MANUAL-SETUP.md) | What `setup.sh` does under the hood — for setting up by hand |
| [docs/SUPPORT.md](docs/SUPPORT.md) | Diagnosing, maintaining, and resetting an installed appliance |
| [docs/WORKFLOW.md](docs/WORKFLOW.md) | Branching and release workflow (developer docs) |
| [docs/vulnerabilities.md](docs/vulnerabilities.md) | Security audit (round 1, March 2026) |
| [docs/vulnerabilities_2.md](docs/vulnerabilities_2.md) | Security audit (round 2, April 2026) |
| [docs/vulnerabilities_3.md](docs/vulnerabilities_3.md) | Security audit (round 3, April 2026) |
| [docs/vulnerabilities_progress.md](docs/vulnerabilities_progress.md) | Progress tracker — every audit finding, what's fixed and what's deferred |

## License

MIT — see [LICENSE](LICENSE).
