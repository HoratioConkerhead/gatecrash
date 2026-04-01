# Gatecrash — Support Reference

This document is a quick reference for diagnosing, maintaining, and resetting a Gatecrash appliance.
For initial setup and a full explanation of how it works, see [readme.md](readme.md).

---

## Services

Two systemd services run on the device:

| Service | Purpose | Auto-start |
|---------|---------|------------|
| `gatecrash-webui` | Flask web UI on port 80 | Yes (on boot) |
| `gatecrash` | ARP spoofing + routing daemon | Optional (enable once tested) |

```bash
sudo systemctl status gatecrash-webui
sudo systemctl status gatecrash
sudo systemctl restart gatecrash-webui   # restart UI after config change
sudo systemctl restart gatecrash         # restart routing after target change
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/opt/gatecrash/gatecrash.conf` | Main config: LAN/VPN interface names, gateway IP, target IPs, route table, fwmark |
| `/etc/wireguard/wg0.conf` | WireGuard VPN config (private key, peer, endpoint) |
| `/opt/gatecrash/devices.json` | Saved devices (MAC → nickname/IP mapping) |
| `/opt/gatecrash/webui_token` | Web UI login password (plaintext, `chmod 600`) |
| `/opt/gatecrash/webui_secret` | Flask session signing key (binary, auto-generated) |
| `/opt/gatecrash/update_settings.json` | Auto-update preferences |
| `/opt/gatecrash/repo_path` | Path to the cloned git repo (used by the updater) |

All user data lives under `/opt/gatecrash/` except the WireGuard config in `/etc/wireguard/`.

### Key values in `gatecrash.conf`

| Key | Example | What it is |
|-----|---------|------------|
| `LAN_IF` | `eth0` | Network interface connected to the LAN |
| `VPN_IF` | `wg0` | WireGuard interface name |
| `GATEWAY_IP` | `192.168.1.254` | Your router's IP (auto-detected) |
| `TARGET_IPS` | `192.168.1.90 192.168.1.105` | IPs currently being routed through the VPN |
| `ROUTE_TABLE` | `vpntarget` | Name of the policy routing table |
| `FWMARK` | `0x1` | Packet mark used to identify target traffic |

---

## Web UI

**URL:** `http://gatecrash.local` (or the device's IP directly)

**Authentication:** password set on first run, stored in `/opt/gatecrash/webui_token`.
Change or reset via **Config → Security** in the UI.

| Tab | What it does |
|-----|-------------|
| Status | Live service state, WireGuard stats, DNS query log |
| Devices | Scan network, save devices, enable/disable VPN routing per device |
| Config | VPN config upload, update settings, appearance, change password, factory reset |
| Diagnostics | Interface info, iptables rules, routing tables, arpspoof processes |
| Updates | Check for and apply updates from GitHub |

---

## Logs

```bash
# Web UI logs
sudo journalctl -u gatecrash-webui -n 50 --no-pager

# Gatecrash daemon logs
sudo journalctl -u gatecrash -n 50 --no-pager

# Upgrade log (after applying an update)
cat /var/log/gatecrash-upgrade.log

# Live DNS queries from target devices (via web UI DNS log tab, or directly)
sudo journalctl -u gatecrash-webui -f
```

---

## Common Tasks

**Check what's running:**
```bash
systemctl is-active gatecrash gatecrash-webui
wg show          # WireGuard tunnel status
ip rule show     # Policy routing rules
ip route show table vpntarget   # VPN routing table
```

**Verify traffic is reaching the VPN:**
```bash
sudo iptables -t mangle -L PREROUTING -v -n
# Look for packet/byte counters on target IP rules
```

**Check which devices are being intercepted:**
```bash
ps -eo pid,args | grep arpspoof | grep -v grep
```

**Confirm VPN exit IP:**
```bash
curl --interface wg0 -m 10 -s http://ifconfig.me
```

**Reset web UI password (via SSH, if locked out):**
```bash
echo "yournewpassword" | sudo tee /opt/gatecrash/webui_token
sudo chmod 600 /opt/gatecrash/webui_token
sudo systemctl restart gatecrash-webui
```

---

## Factory Reset

The web UI has a factory reset option under **Config → Danger Zone**. It requires your
current password and wipes:

- All network configuration
- Saved devices
- WireGuard VPN config
- Login password
- Session keys and update preferences

It does **not** remove the Gatecrash software or the git repository.
After a reset, the device returns to its first-run state and will prompt for a new password on next visit.

**If the device needs to be wiped via SSH** (e.g. locked out of the UI):
```bash
sudo systemctl stop gatecrash gatecrash-webui
sudo wg-quick down wg0 2>/dev/null || true
sudo rm -f /opt/gatecrash/gatecrash.conf \
           /opt/gatecrash/devices.json \
           /opt/gatecrash/webui_token \
           /opt/gatecrash/webui_secret \
           /opt/gatecrash/update_settings.json \
           /etc/wireguard/wg0.conf
sudo systemctl start gatecrash-webui
```

---

## Architecture Summary

```
Target device (e.g. smart TV)
    │  ARP spoofed — believes the Gatecrash VM is the gateway
    ▼
Gatecrash VM
    ├── arpspoof     — keeps ARP cache poisoned on both target and router
    ├── iptables     — marks target packets with fwmark 0x1
    ├── ip rule      — fwmark 0x1 → vpntarget routing table
    ├── wg0          — WireGuard tunnel to VPN provider
    └── gatecrash-webui — Flask app managing everything above
```

Devices are tracked by **MAC address**. If a target gets a new IP via DHCP, Gatecrash
detects the change via the ARP table within ~60 seconds and updates routing automatically.

If Gatecrash stops, the target's ARP cache self-corrects within 1–2 minutes and
traffic routes normally. No configuration changes are needed on the target device.
