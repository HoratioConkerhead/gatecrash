#!/usr/bin/env python3
"""Saved-device persistence and MAC-based IP resolution.

Devices are tracked by MAC (DHCP changes IPs); load/save persist the list as
JSON. _neigh_map resolves MAC->IP from the kernel neighbour table (freshest
entry per MAC); sync_targets_from_devices turns the enabled devices into the
TARGET_IPS line in gatecrash.conf. No audit_log / boot-state coupling — the
firewall-plumbing (_hot_reload_targets) stays in app.py for now.
"""

import ipaddress
import json
import re

from netutils import run_argv
from parsing import parse_neigh
from config import read_conf, write_conf

DEVICES_FILE = "/opt/gatecrash/devices.json"


def _neigh_map():
    """Return {mac: ip} from the kernel neighbour table.

    Picks the freshest entry per MAC (by NUD state) and skips FAILED, so a MAC
    with both a stale old-IP entry and a fresh new-IP entry resolves to the new
    one. Used by the "sync now" / device paths as a cheap passive resolver; the
    IP-change watchdog no longer relies on it — it validates via active ARP
    probes (see _arp_probe / _discover_arp) so a lingering STALE lease can't
    move a target.
    """
    arp_out, _ = run_argv(["ip", "neigh", "show"])
    rank = {"REACHABLE": 4, "PERMANENT": 4, "DELAY": 3, "PROBE": 3, "STALE": 2}
    best = {}  # mac -> (ip, rank)
    for e in parse_neigh(arp_out):
        if e["state"] == "FAILED":
            continue
        r = rank.get(e["state"], 1)
        mac = e["mac"]
        if mac not in best or r > best[mac][1]:
            best[mac] = (e["ip"], r)
    return {mac: ip for mac, (ip, _r) in best.items()}


def load_devices():
    """Load saved devices from JSON file. Returns list of device dicts."""
    try:
        with open(DEVICES_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_devices(devices):
    """Write device list to JSON file."""
    with open(DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=2)


def resolve_mac(ip):
    """Look up MAC address for an IP from the ARP table."""
    try:
        ipaddress.ip_address(ip)  # reject anything that isn't a valid IP
    except ValueError:
        return ""
    out, _ = run_argv(["ip", "neigh", "show", ip])
    m = re.search(r"lladdr\s+([0-9a-f:]+)", out)
    return m.group(1).lower() if m else ""


def sync_targets_from_devices(neigh=None):
    """Update TARGET_IPS in gatecrash.conf from enabled saved devices.

    Uses ARP table to resolve current IPs from saved MAC addresses.
    Returns the list of active IPs written to config.

    Pass `neigh` (a {mac: ip} map, e.g. one already augmented with an active
    nmap scan) to avoid a second passive lookup that could resolve a roamed
    device back to its stale IP; when omitted, resolves from the live table.
    """
    devices = load_devices()
    active_ips = []
    updated = False

    # Resolve current IPs from the neighbour table once for all devices.
    # _neigh_map() picks the freshest entry per MAC (skips FAILED / stale
    # duplicates) so a roamed device resolves to its new IP, not the old one.
    if neigh is None:
        neigh = _neigh_map()

    for dev in devices:
        if not dev.get("enabled", False):
            continue
        mac = dev.get("mac", "").lower()
        if not mac:
            continue
        ip = neigh.get(mac)
        if ip:
            active_ips.append(ip)
            if dev.get("ip") != ip:
                dev["ip"] = ip
                updated = True
        elif dev.get("ip"):
            # MAC not in neighbour table — use last-known IP if available.
            active_ips.append(dev["ip"])

    if updated:
        save_devices(devices)

    # Write to gatecrash.conf
    conf = read_conf()
    conf["TARGET_IPS"] = " ".join(active_ips)
    write_conf(conf)
    return active_ips
