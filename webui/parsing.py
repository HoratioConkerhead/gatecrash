#!/usr/bin/env python3
"""Pure text parsers for external-tool output (nmap, ip neigh, iptables).

No I/O, no subprocess — each function takes the already-captured stdout string
and returns structured data, so they can be unit-tested with pasted real output
(see tests/test_parsing.py). The thin "run the command" wrappers stay in app.py
and hand their output to these functions.

Extracted from app.py. Consolidating the ip-neigh parsing here (it used to be
copy-pasted in three places with slightly different regexes) is review item M4.
"""

import re

# Neighbour-table line: "<ip> dev <if> lladdr <mac> [flags...] <STATE>".
# The NUD state is always the LAST token; optional flags (router, proxy,
# extern_learn) can sit between the MAC and the state, so we capture everything
# after the MAC and take the final word. The older scan-stream copy used
# `(\w+)` (the FIRST word after the MAC), which mis-read the state whenever a
# flag was present — fixed by routing every caller through here.
_NEIGH_RE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})\s+(.+)$"
)


def parse_neigh(output):
    """Parse `ip neigh show` output into a list of {ip, mac, state} dicts.

    mac is lower-cased, state upper-cased. Entries without an lladdr (e.g. bare
    INCOMPLETE/FAILED lines) are skipped. Callers decide whether to drop FAILED.
    """
    entries = []
    for line in output.splitlines():
        m = _NEIGH_RE.match(line)
        if not m:
            continue
        entries.append({
            "ip":    m.group(1),
            "mac":   m.group(2).lower(),
            "state": m.group(3).split()[-1].upper(),
        })
    return entries


def parse_nmap_devices(output):
    """Parse `nmap -sn` output into a list of device dicts, sorted by IP.

    Each dict has ip, hostname, mac (lower-cased, "" if none) and, when nmap
    reported one, vendor.
    """
    devices = []
    current = {}
    for line in output.splitlines():
        m = re.match(r"Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)", line)
        if m:
            if current:
                devices.append(current)
            current = {"hostname": m.group(1), "ip": m.group(2), "mac": ""}
            continue
        m = re.match(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            if current:
                devices.append(current)
            current = {"hostname": "", "ip": m.group(1), "mac": ""}
            continue
        m = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})(?: \((.+)\))?", line)
        if m and current:
            current["mac"] = m.group(1).lower()
            current["vendor"] = m.group(2) or ""
    if current:
        devices.append(current)
    devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])
    return devices


def parse_mangle_counters(output):
    """Parse per-device byte counters from `iptables -L FORWARD -n -v -x`.

    Returns {ip: total_bytes} summed across the per-device upload (src=<ip>,
    dst=0.0.0.0/0) and download (src=0.0.0.0/0, dst=<ip>) ACCEPT rules.
    """
    result = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 9 or parts[2] != "ACCEPT":
            continue
        try:
            bytes_val = int(parts[1])
        except ValueError:
            continue  # header/summary line — not a counter row
        src, dst = parts[7], parts[8]
        # Upload rule: src=<device> dst=0.0.0.0/0
        if src != "0.0.0.0/0" and dst == "0.0.0.0/0":
            result[src] = result.get(src, 0) + bytes_val
        # Download rule: src=0.0.0.0/0 dst=<device>
        elif src == "0.0.0.0/0" and dst != "0.0.0.0/0":
            result[dst] = result.get(dst, 0) + bytes_val
    return result
