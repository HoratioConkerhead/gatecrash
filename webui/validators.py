#!/usr/bin/env python3
"""Input validators for Gatecrash config values.

Pure functions — no I/O, no subprocess, no Flask. Extracted from app.py so they
can be unit-tested in isolation (see tests/test_validators.py) without importing
the whole web app and its import-time side effects (logger, cert check, secret
key, background threads).

SECURITY: these allowlists/validators stand between a config write and
root-level code execution — gatecrash.conf is `source`d as bash by
start.sh/stop.sh, and wg0.conf is consumed by wg-quick. Keep them strict.
"""

import re


# ---------------------------------------------------------------------------
# Input validators — guard against injection via config values in shell strings
# ---------------------------------------------------------------------------

# Linux IFNAMSIZ-1 = 15 chars; allow alphanumeric plus _ @ . -
_IF_RE    = re.compile(r'^[a-zA-Z0-9_@.-]{1,15}\Z')
# Route table names: alphanumeric, _ or -
_TABLE_RE = re.compile(r'^[a-zA-Z0-9_-]{1,31}\Z')
# IPv4 address: dotted quad
_IPV4_RE  = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\Z')
# Hex fwmark: 0x followed by 1-8 hex digits
_FWMARK_RE = re.compile(r'^0x[0-9a-fA-F]{1,8}\Z')
# Repo path: block newlines and common shell metacharacters
_REPO_SAFE_RE = re.compile(r'^[^\n\r;&|`$<>\\!]{1,512}\Z')
# MAC address: lowercase hex pairs separated by colons
_MAC_RE   = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}\Z')
_NICK_MAX = 64

# SECURITY: gatecrash.conf is `source`d as bash by start.sh/stop.sh, so any
# key or value written here executes as root.  The allowlist + per-field
# validators below are the only thing preventing config-write → RCE.  (CRIT-4)
_CONF_ALLOWED_KEYS = {"LAN_IF", "VPN_IF", "GATEWAY_IP", "TARGET_IPS", "ROUTE_TABLE", "FWMARK", "DNS_SERVER"}

# SECURITY: WireGuard config validation. Both the upload endpoint and the
# in-browser editor go through _normalize_wg_config() below, which parses the
# user's input, extracts only whitelisted keys per section, validates each
# value, and re-emits a canonical config from scratch. This is stricter than
# line-stripping and gives the same guarantees on both write paths:
#   - PostUp/PostDown/PreUp/PreDown can never reach disk (HIGH-6) because
#     they are not on the whitelist and so are dropped during the rebuild.
#   - Table = off and MTU = 1280 are forced regardless of input (CLAUDE.md
#     invariants — wg-quick would otherwise install a default route or use
#     1420 MTU that silently drops packets on many ISPs).
#   - DNS lines are dropped — Gatecrash handles DNS routing via DNAT, so
#     wg-quick must not fight us by setting /etc/resolv.conf.
#   - Endpoint, AllowedIPs, and keys are format-validated, so an attacker
#     with a session can't pivot the tunnel to a hostile WG endpoint with
#     a malformed Endpoint that confuses parsers downstream. (vulnerabilities_3.md)

_WG_KEY_RE  = re.compile(r'^[A-Za-z0-9+/]{43}=\Z')
_WG_PORT_RE = re.compile(r'^\d{1,5}\Z')
# Endpoint host: hostname (RFC 1123-ish, dots and hyphens) or IPv4. IPv6 is
# handled separately via the [v6]:port bracketed form.
_WG_HOST_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?\Z')
_WG_CIDR4_RE = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/(?:3[0-2]|[12]?\d))?\Z')
_WG_CIDR6_RE = re.compile(r'^[0-9a-fA-F:]{2,39}(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?\Z')
_WG_ENDPOINT_V6_RE = re.compile(r'^\[([0-9a-fA-F:]+)\]:(\d{1,5})\Z')


def _valid_wg_key(s):
    if not _WG_KEY_RE.match(s):
        raise ValueError("expected 44-char base64 ending with '='")
    return s


def _valid_wg_int_in_range(s, lo, hi):
    if not _WG_PORT_RE.match(s):
        raise ValueError(f"expected an integer, got {s!r}")
    n = int(s)
    if not (lo <= n <= hi):
        raise ValueError(f"out of range {lo}-{hi}")
    return str(n)


def _valid_wg_endpoint(s):
    s = s.strip()
    if s.startswith("["):
        m = _WG_ENDPOINT_V6_RE.match(s)
        if not m:
            raise ValueError("malformed IPv6 endpoint, expected [addr]:port")
        _valid_wg_int_in_range(m.group(2), 1, 65535)
        return s
    if ":" not in s:
        raise ValueError("missing :port")
    host, port = s.rsplit(":", 1)
    if not _WG_HOST_RE.match(host):
        raise ValueError(f"invalid host {host!r}")
    _valid_wg_int_in_range(port, 1, 65535)
    return s


def _valid_wg_cidr_list(s):
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        raise ValueError("empty list")
    for p in parts:
        if not (_WG_CIDR4_RE.match(p) or _WG_CIDR6_RE.match(p)):
            raise ValueError(f"invalid CIDR {p!r}")
    return ", ".join(parts)


def _valid_wg_fwmark(s):
    if not _FWMARK_RE.match(s):
        raise ValueError(f"invalid FwMark {s!r}")
    return s


# Per-section whitelists. Keys NOT in the whitelist are dropped during
# rebuild — that's how PostUp/PostDown/DNS/etc. get removed.
_WG_INTERFACE_KEYS = {
    "PrivateKey": _valid_wg_key,
    "Address":    _valid_wg_cidr_list,
    "ListenPort": lambda s: _valid_wg_int_in_range(s, 1, 65535),
    "FwMark":     _valid_wg_fwmark,
}
_WG_PEER_KEYS = {
    "PublicKey":           _valid_wg_key,
    "PresharedKey":        _valid_wg_key,
    "Endpoint":            _valid_wg_endpoint,
    "AllowedIPs":          _valid_wg_cidr_list,
    "PersistentKeepalive": lambda s: _valid_wg_int_in_range(s, 0, 65535),
}


def _normalize_wg_config(content):
    """Parse a WireGuard config, extract whitelisted fields, force Gatecrash
    invariants, and emit a canonical config from scratch.

    Returns (canonical_content, fixes_list).
    Raises ValueError with a user-friendly message on unrecoverable problems.
    """
    sections = []  # list of (section_name, [(key, value), ...])
    current = None
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = (line[1:-1].strip(), [])
            sections.append(current)
            continue
        if "=" not in line or current is None:
            continue
        k, v = line.split("=", 1)
        current[1].append((k.strip(), v.strip()))

    if not any(name == "Interface" for name, _ in sections):
        raise ValueError("Missing [Interface] section")
    if not any(name == "Peer" for name, _ in sections):
        raise ValueError("Missing [Peer] section")

    fixes = []
    out = []
    for name, pairs in sections:
        if name == "Interface":
            keep = {}
            for k, v in pairs:
                canon = next((wk for wk in _WG_INTERFACE_KEYS if wk.lower() == k.lower()), None)
                if canon is None:
                    if k.lower() in {"table", "mtu"}:
                        # Replaced below with forced values; skip silently.
                        continue
                    fixes.append(f"removed [Interface] {k}")
                    continue
                try:
                    keep[canon] = _WG_INTERFACE_KEYS[canon](v)
                except ValueError as e:
                    raise ValueError(f"[Interface] {canon}: {e}")
            if "PrivateKey" not in keep:
                raise ValueError("Missing PrivateKey in [Interface]")
            if "Address" not in keep:
                raise ValueError("Missing Address in [Interface]")
            out.append("[Interface]")
            for k in ("PrivateKey", "Address", "ListenPort", "FwMark"):
                if k in keep:
                    out.append(f"{k} = {keep[k]}")
            out.append("Table = off")
            out.append("MTU = 1280")
            out.append("")
        elif name == "Peer":
            keep = {}
            for k, v in pairs:
                canon = next((wk for wk in _WG_PEER_KEYS if wk.lower() == k.lower()), None)
                if canon is None:
                    fixes.append(f"removed [Peer] {k}")
                    continue
                try:
                    keep[canon] = _WG_PEER_KEYS[canon](v)
                except ValueError as e:
                    raise ValueError(f"[Peer] {canon}: {e}")
            if "PublicKey" not in keep:
                raise ValueError("Missing PublicKey in [Peer]")
            if "AllowedIPs" not in keep:
                raise ValueError("Missing AllowedIPs in [Peer]")
            out.append("[Peer]")
            for k in ("PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"):
                if k in keep:
                    out.append(f"{k} = {keep[k]}")
            out.append("")
        else:
            fixes.append(f"removed unknown section [{name}]")

    return "\n".join(out).rstrip() + "\n", fixes


def _valid_if(name):
    """Return name if it is a safe Linux interface name, else raise ValueError."""
    if not _IF_RE.match(name or ""):
        raise ValueError(f"Invalid interface name: {name!r}")
    return name


def _valid_table(name):
    """Return name if it is a safe route-table identifier, else raise ValueError."""
    if not _TABLE_RE.match(name or ""):
        raise ValueError(f"Invalid route table name: {name!r}")
    return name


def _valid_ip(addr):
    """Return addr if it is a valid IPv4 address, else raise ValueError."""
    if not _IPV4_RE.match(addr or ""):
        raise ValueError(f"Invalid IP address: {addr!r}")
    return addr


def _valid_ip_or_empty(addr):
    """Like _valid_ip but allows empty string (used for optional override fields)."""
    if not addr:
        return ""
    return _valid_ip(addr)


def _valid_fwmark(mark):
    """Return mark if it is a valid hex fwmark (e.g. 0x1), else raise ValueError."""
    if not _FWMARK_RE.match(mark or ""):
        raise ValueError(f"Invalid fwmark: {mark!r}")
    return mark


def _valid_target_ips(value):
    """Return value if it is empty or space-separated IPv4 addresses, else raise ValueError."""
    if not value or not value.strip():
        return ""
    for part in value.split():
        if not _IPV4_RE.match(part):
            raise ValueError(f"Invalid IP in TARGET_IPS: {part!r}")
    return value


def _valid_repo(path):
    """Return path if it contains no shell metacharacters, else raise ValueError."""
    if not _REPO_SAFE_RE.match(path or ""):
        raise ValueError("Repo path contains unsafe characters")
    return path


# Git ref names: alphanumerics plus a small set of safe punctuation.
# Deliberately excludes shell metacharacters and git's own special chars (~ ^ : ?).
_BRANCH_RE = re.compile(r'^[A-Za-z0-9._/-]{1,128}\Z')


def _valid_branch(name):
    """Return name if it's a safe git branch name, else raise ValueError."""
    if not _BRANCH_RE.match(name or ""):
        raise ValueError("Invalid branch name")
    if name.startswith("-") or ".." in name or name.endswith(".lock"):
        raise ValueError("Invalid branch name")
    return name


# Per-field validators for gatecrash.conf. Used by both write_conf() (the write
# path) and api_config() (the request path) — defense in depth, but one source.
_CONF_VALIDATORS = {
    "LAN_IF":      _valid_if,
    "VPN_IF":      _valid_if,
    "ROUTE_TABLE": _valid_table,
    "GATEWAY_IP":  _valid_ip_or_empty,
    "FWMARK":      _valid_fwmark,
    "TARGET_IPS":  _valid_target_ips,
    "DNS_SERVER":  _valid_ip_or_empty,
}
