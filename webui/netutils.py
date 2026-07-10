#!/usr/bin/env python3
"""Shell-free subprocess boundary + `ip -j` JSON parsers.

Every subprocess in the web UI goes through run_argv() (argv list, shell=False)
— one choke point, no shell parsing. The _default_route/_iface_addr helpers
parse `ip -j` JSON so no caller reaches for an `awk | head` pipeline. These
depend only on subprocess/json (no Flask, no app globals), so they live here as
the base module the rest of the package builds on. (HIGH-14)
"""

import json
import subprocess


def run_argv(args, timeout=15, merge_stderr=False):
    # Shell-free subprocess helper — args is a list, no shell parsing.
    # merge_stderr=True merges stderr into stdout (replaces shell `2>&1`);
    # default drops stderr (replaces `2>/dev/null`).
    # The old shell=True `run()` helper was retired in v0.73.12-dev (HIGH-14).
    try:
        r = subprocess.run(
            args, shell=False, text=True, timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
        )
        return (r.stdout or "").strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "timed out", 1
    except Exception as e:
        return str(e), 1


def _default_route():
    """Return the first default route as {gateway, dev}, or {} on failure.

    SECURITY: replaces the shell pipeline
        run("ip route show default | awk '/default/ {print $3}' | head -1")
    and the parallel `awk '{print $5}'` form for the dev. Both were `shell=True`
    sites that we kept only because awk-extracting a field is verbose in Python.
    Once HIGH-14 forced shell=False, parsing `ip -j` JSON became the cleanest
    option. DO NOT regress to a shell pipeline for "simplicity" — the helper
    exists to keep the rest of the file shell-free. (HIGH-14)
    """
    out, rc = run_argv(["ip", "-j", "route", "show", "default"])
    if rc != 0 or not out:
        return {}
    try:
        routes = json.loads(out)
        if routes and isinstance(routes, list):
            r = routes[0]
            return {"gateway": r.get("gateway", ""), "dev": r.get("dev", "")}
    except (json.JSONDecodeError, AttributeError, IndexError, KeyError):
        pass
    return {}


def _iface_addr(lan_if):
    """Return {ip, cidr} for the first IPv4 address on lan_if, or {} on failure.

    SECURITY: replaces three shell pipelines that all extracted fields from
    `ip -o -f inet addr show ...` via `awk '{print $4}' [| cut -d/ -f1] | head -1`.
    Same rationale as _default_route — JSON parse beats awk-pipe under shell=False.
    DO NOT regress to a shell pipeline. (HIGH-14)
    """
    out, rc = run_argv(["ip", "-j", "-4", "addr", "show", lan_if])
    if rc != 0 or not out:
        return {}
    try:
        data = json.loads(out)
        if data and isinstance(data, list):
            for a in data[0].get("addr_info", []):
                if a.get("family") == "inet":
                    local = a.get("local", "")
                    prefix = a.get("prefixlen", 0)
                    return {"ip": local, "cidr": f"{local}/{prefix}" if local else ""}
    except (json.JSONDecodeError, AttributeError, IndexError, KeyError):
        pass
    return {}


def _iface_addr6(lan_if):
    """Return the box's IPv6 address on lan_if, or "" if none.

    Prefers a global address; falls back to the link-local (fe80::*) one with
    a `%<iface>` zone suffix appended (e.g. fe80::1%eth0) so the value is
    pingable as-shown from another LAN host. Many home setups have no IPv6
    from the ISP, so link-local is what you actually have.

    Same JSON-parse pattern as _iface_addr; same shell=False rationale. (HIGH-14)
    """
    out, rc = run_argv(["ip", "-j", "-6", "addr", "show", lan_if])
    if rc != 0 or not out:
        return ""
    try:
        data = json.loads(out)
        if data and isinstance(data, list):
            addrs = data[0].get("addr_info", [])
            # Prefer global
            for a in addrs:
                if a.get("family") == "inet6" and a.get("scope") == "global":
                    return a.get("local", "")
            # Fall back to link-local with zone suffix
            for a in addrs:
                if a.get("family") == "inet6" and a.get("scope") == "link":
                    local = a.get("local", "")
                    return f"{local}%{lan_if}" if local else ""
    except (json.JSONDecodeError, AttributeError, IndexError, KeyError):
        pass
    return ""


def _detect_gateway():
    """Return the default gateway IP from the routing table, or empty string."""
    return _default_route().get("gateway", "")
