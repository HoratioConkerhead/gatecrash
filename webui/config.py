#!/usr/bin/env python3
"""gatecrash.conf I/O and WireGuard status.

read_conf/write_conf load and (validated) save the bash-sourced config file;
wg_stats parses `wg show`. write_conf goes through the same allowlist +
per-field validators as the request path — this file is sourced as bash by
start.sh/stop.sh, so an unvalidated value is a root-level RCE risk. (CRIT-4)
"""

import re

from netutils import run_argv, _default_route
from validators import _CONF_ALLOWED_KEYS, _CONF_VALIDATORS

CONF_PATH = "/opt/gatecrash/gatecrash.conf"


def read_conf():
    conf = {"LAN_IF": "", "VPN_IF": "wg0", "GATEWAY_IP": "", "TARGET_IPS": "", "ROUTE_TABLE": "vpntarget", "FWMARK": "0x1", "DNS_SERVER": ""}
    try:
        with open(CONF_PATH) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    conf[k.strip()] = v.strip().strip('"')
    except FileNotFoundError:
        pass
    # Auto-detect LAN interface from the default route if not set.
    # Was: run("ip route show default | awk '{print $5}' | head -1") — replaced
    # by _default_route() to keep this file shell=False. (HIGH-14)
    if not conf["LAN_IF"]:
        dev = _default_route().get("dev", "")
        if dev:
            conf["LAN_IF"] = dev
    return conf


def write_conf(data):
    # Defense-in-depth: reject unknown keys and validate all values before
    # writing to disk.  This file is sourced as bash by start.sh / stop.sh,
    # so any unvalidated value is a root-level code-execution risk.
    unknown = set(data.keys()) - _CONF_ALLOWED_KEYS
    if unknown:
        raise ValueError(f"Unknown config keys: {', '.join(sorted(unknown))}")
    # GATEWAY_IP is intentionally allowed to be blank — start.sh auto-detects
    # from the default route on every boot, so the appliance works when moved
    # between networks. A non-blank value is a manual override.
    for key, value in data.items():
        if key in _CONF_VALIDATORS:
            _CONF_VALIDATORS[key](value)
    lines = [f'{k}="{v}"' for k, v in data.items()]
    with open(CONF_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")


def wg_stats():
    out, rc = run_argv(["wg", "show", "wg0"])
    if rc != 0 or not out:
        return None
    result = {}
    m = re.search(r"latest handshake: (.+)", out)
    result["handshake"] = m.group(1).strip() if m else "none"
    m = re.search(r"transfer: (.+)", out)
    result["transfer"] = m.group(1).strip() if m else "unknown"
    m = re.search(r"endpoint: (.+)", out)
    result["endpoint"] = m.group(1).strip() if m else "unknown"
    return result
