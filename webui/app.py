#!/usr/bin/env python3
"""Gatecrash web UI — serves HTTPS on port 443, must run as root."""

import bcrypt
import ipaddress
import logging
import logging.handlers
import os
import re
import json
import secrets
import tempfile
import threading
import subprocess
from collections import deque
from datetime import timedelta
from flask import Flask, render_template, jsonify, request, Response, stream_with_context, session, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Rate limiting — protect against brute-force and abuse
# ---------------------------------------------------------------------------

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],          # no global limit — only on decorated routes
    storage_uri="memory://",
)

# ---------------------------------------------------------------------------
# Audit log — persistent file log for service actions, auth events, etc.
# ---------------------------------------------------------------------------

LOG_PATH = "/var/log/gatecrash.log"

audit_log = logging.getLogger("gatecrash.audit")
audit_log.setLevel(logging.INFO)
_log_handler = logging.handlers.RotatingFileHandler(
    LOG_PATH, maxBytes=2 * 1024 * 1024, backupCount=3,  # 2 MB, keep 3 old files
)
_log_handler.setFormatter(logging.Formatter(
    "%(asctime)s  %(levelname)-5s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
))
audit_log.addHandler(_log_handler)
audit_log.info("――――――――――――――――――――――――――――――――――――――――――――――――――――――――――")
audit_log.info("Web UI started (PID %d)", os.getpid())

# ---------------------------------------------------------------------------
# Authentication — session-based login with password stored on disk
# ---------------------------------------------------------------------------

WEBUI_TOKEN_PATH  = "/opt/gatecrash/webui_token"
SECRET_KEY_PATH   = "/opt/gatecrash/webui_secret"

# Endpoints always accessible without a session
_PUBLIC_PATHS = {"/", "/api/login", "/api/setup-auth"}


def _get_stored_token():
    """Return the stored password hash (bytes), or None if no token file exists."""
    try:
        with open(WEBUI_TOKEN_PATH, "rb") as f:
            data = f.read().strip()
            return data or None
    except FileNotFoundError:
        return None


def _hash_password(password):
    """Hash a plaintext password with bcrypt and return the hash bytes."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _check_password(password, stored):
    """Check a plaintext password against a stored hash or legacy plaintext.

    Returns (matched: bool, needs_rehash: bool).
    If stored is legacy plaintext, comparison uses hmac.compare_digest
    and signals that rehashing is needed.
    """
    import hmac
    if stored.startswith(b"$2b$") or stored.startswith(b"$2a$"):
        # bcrypt hash
        return bcrypt.checkpw(password.encode("utf-8"), stored), False
    # Legacy plaintext — constant-time comparison, flag for migration
    matched = hmac.compare_digest(password.encode("utf-8"), stored)
    return matched, True


def _store_password(password):
    """Hash and write a password to the token file."""
    hashed = _hash_password(password)
    with open(WEBUI_TOKEN_PATH, "wb") as f:
        f.write(hashed)
    os.chmod(WEBUI_TOKEN_PATH, 0o600)


def _get_or_create_secret():
    """Load or generate the Flask session signing key."""
    try:
        with open(SECRET_KEY_PATH, "rb") as f:
            key = f.read()
            if len(key) >= 32:
                return key
    except FileNotFoundError:
        pass
    key = secrets.token_bytes(32)
    with open(SECRET_KEY_PATH, "wb") as f:
        f.write(key)
    os.chmod(SECRET_KEY_PATH, 0o600)
    return key


app.secret_key = _get_or_create_secret()
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.path.isfile("/opt/gatecrash/certs/gatecrash.crt")


@app.errorhandler(429)
def rate_limit_exceeded(_e):
    return jsonify({"ok": False, "error": "Too many requests — please wait and try again"}), 429


@app.after_request
def set_security_headers(response):
    """Add security headers and prevent stale API caching."""
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';"
    # Hide server identity
    response.headers["Server"] = "Gatecrash"
    return response


@app.before_request
def require_auth():
    # Static assets are always public
    if request.path.startswith("/static/"):
        return
    stored = _get_stored_token()
    if stored is None:
        # Setup mode — only allow the setup endpoint and the page itself
        if request.path in ("/", "/api/setup-auth"):
            return
        if request.path.startswith("/api/"):
            return Response(
                json.dumps({"ok": False, "error": "Setup not complete"}),
                403,
                {"Content-Type": "application/json"},
            )
        return redirect("/")
    # Normal mode — public paths don't need a session
    if request.path in _PUBLIC_PATHS:
        return
    if session.get("authenticated"):
        return
    # Unauthenticated: API calls get JSON 401, everything else redirects to /
    if request.path.startswith("/api/"):
        return Response(
            json.dumps({"ok": False, "error": "Not authenticated"}),
            401,
            {"Content-Type": "application/json"},
        )
    return redirect("/")


# ---------------------------------------------------------------------------
# CSRF protection — double-submit token validated on state-changing requests
# ---------------------------------------------------------------------------

# Paths exempt from CSRF (login/setup need to work before a token exists)
_CSRF_EXEMPT = {"/api/login", "/api/setup-auth"}


def _ensure_csrf_token():
    """Create a CSRF token in the session if one doesn't exist."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.before_request
def csrf_protect():
    """Validate CSRF token on all state-changing requests."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.path.startswith("/static/") or request.path in _CSRF_EXEMPT:
        return
    # Only enforce for authenticated sessions (setup-mode is locked down by require_auth)
    if not session.get("authenticated"):
        return
    token = request.headers.get("X-CSRF-Token", "")
    if not token or token != session.get("csrf_token"):
        return Response(
            json.dumps({"ok": False, "error": "CSRF token missing or invalid"}),
            403,
            {"Content-Type": "application/json"},
        )


CONF_PATH      = "/opt/gatecrash/gatecrash.conf"
WG_CONF_PATH   = "/etc/wireguard/wg0.conf"
REPO_PATH_FILE = "/opt/gatecrash/repo_path"


def get_version():
    repo = get_repo_path()
    if repo:
        try:
            with open(os.path.join(repo, "VERSION")) as f:
                return f.read().strip()
        except FileNotFoundError:
            pass
    return "unknown"


def get_repo_path():
    try:
        with open(REPO_PATH_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

# Rolling DNS log — last 100 queries
dns_log = deque(maxlen=100)
dns_thread_started = False
_state_lock = threading.Lock()  # guards dns_log snapshot, *_thread_started, update_check_state

DEVICES_FILE = "/opt/gatecrash/devices.json"
BOOT_STATE_FILE = "/opt/gatecrash/boot_state.json"


def _read_boot_state():
    """Read the boot-mode config: mode ('resume'|'manual') and last-known running state."""
    default = {"mode": "resume", "wg_running": False, "gc_running": False}
    try:
        with open(BOOT_STATE_FILE) as f:
            data = json.load(f)
        for k in default:
            if k not in data:
                data[k] = default[k]
        return data
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write_boot_state(data):
    with open(BOOT_STATE_FILE, "w") as f:
        json.dump(data, f)


def _record_service_state(service, running):
    """Record that a service was started or stopped (for resume-on-boot)."""
    state = _read_boot_state()
    key = "wg_running" if service == "wg" else "gc_running"
    state[key] = running
    _write_boot_state(state)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "timed out", 1
    except Exception as e:
        return str(e), 1


def _detect_gateway():
    """Return the default gateway IP from the routing table, or empty string."""
    gw, _ = run("ip route show default | awk '/default/ {print $3}' | head -1")
    return gw.strip()


# ---------------------------------------------------------------------------
# Input validators — guard against injection via config values in shell strings
# ---------------------------------------------------------------------------

# Linux IFNAMSIZ-1 = 15 chars; allow alphanumeric plus _ @ . -
_IF_RE    = re.compile(r'^[a-zA-Z0-9_@.-]{1,15}$')
# Route table names: alphanumeric, _ or -
_TABLE_RE = re.compile(r'^[a-zA-Z0-9_-]{1,31}$')
# IPv4 address: dotted quad
_IPV4_RE  = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$')
# Hex fwmark: 0x followed by 1-8 hex digits
_FWMARK_RE = re.compile(r'^0x[0-9a-fA-F]{1,8}$')
# Repo path: block newlines and common shell metacharacters
_REPO_SAFE_RE = re.compile(r'^[^\n\r;&|`$<>\\!]{1,512}$')
# MAC address: lowercase hex pairs separated by colons
_MAC_RE   = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
_NICK_MAX = 64

# Only these keys are permitted in gatecrash.conf
_CONF_ALLOWED_KEYS = {"LAN_IF", "VPN_IF", "GATEWAY_IP", "TARGET_IPS", "ROUTE_TABLE", "FWMARK"}

# WireGuard hook lines that allow arbitrary code execution via wg-quick
_WG_HOOK_RE = re.compile(
    r'^\s*(PostUp|PostDown|PreUp|PreDown)\s*=',
    re.IGNORECASE,
)


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


def _strip_wg_hooks(content):
    """Remove PostUp/PostDown/PreUp/PreDown lines from a WireGuard config string."""
    return "".join(
        line for line in content.splitlines(keepends=True)
        if not _WG_HOOK_RE.match(line)
    )


def read_conf():
    conf = {"LAN_IF": "", "VPN_IF": "wg0", "GATEWAY_IP": "", "TARGET_IPS": "", "ROUTE_TABLE": "vpntarget", "FWMARK": "0x1"}
    try:
        with open(CONF_PATH) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    conf[k.strip()] = v.strip().strip('"')
    except FileNotFoundError:
        pass
    # Auto-detect LAN interface from the default route if not set
    if not conf["LAN_IF"]:
        detected, rc = run("ip route show default | awk '{print $5}' | head -1")
        if rc == 0 and detected.strip():
            conf["LAN_IF"] = detected.strip()
    return conf


def write_conf(data):
    # Defense-in-depth: reject unknown keys and validate all values before
    # writing to disk.  This file is sourced as bash by start.sh / stop.sh,
    # so any unvalidated value is a root-level code-execution risk.
    unknown = set(data.keys()) - _CONF_ALLOWED_KEYS
    if unknown:
        raise ValueError(f"Unknown config keys: {', '.join(sorted(unknown))}")
    validators = {
        "LAN_IF": _valid_if,
        "VPN_IF": _valid_if,
        "ROUTE_TABLE": _valid_table,
        "GATEWAY_IP": _valid_ip,
        "FWMARK": _valid_fwmark,
        "TARGET_IPS": _valid_target_ips,
    }
    # Ensure GATEWAY_IP is never written empty
    if not data.get("GATEWAY_IP"):
        gw = _detect_gateway()
        if gw:
            data["GATEWAY_IP"] = gw
    for key, value in data.items():
        if key in validators:
            validators[key](value)
    lines = [f'{k}="{v}"' for k, v in data.items()]
    with open(CONF_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")


def wg_stats():
    out, rc = run("wg show wg0 2>/dev/null")
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


# ---------------------------------------------------------------------------
# DNS capture (background thread)
# ---------------------------------------------------------------------------

def capture_dns():
    global dns_thread_started
    conf = read_conf()
    try:
        lan_if = _valid_if(conf.get("LAN_IF", "eth0"))
    except ValueError:
        return  # unsafe interface name — exit thread safely
    # Get our own LAN IP so we can exclude Gatecrash's own DNS queries
    own_ip_out, _ = run(f"ip -o -f inet addr show {lan_if} | awk '{{print $4}}' | cut -d/ -f1 | head -1")
    own_ip = own_ip_out.strip()
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", lan_if, "-n", "-l", "udp dst port 53"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # IMPORTANT: use readline() instead of iterating proc.stdout directly.
        # Python's for-loop over stdout uses an internal read-ahead buffer (~8KB)
        # which delays output. readline() returns each line immediately.
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            # Modern tcpdump (no -q) outputs:
            # "HH:MM:SS.us IP src.port > dst.53: id+ TYPE? domain. (len)"
            m = re.search(
                r"(\d+:\d+:\d+)\.\d+\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.\d+\s+>.*?\s+[A-Za-z]+\?\s+(\S+?)\.?\s+\(",
                line,
            )
            if m and m.group(2) != own_ip:
                dns_log.appendleft({
                    "time":  m.group(1),
                    "src":   m.group(2),
                    "query": m.group(3).strip(),
                })
    except Exception:
        pass
    finally:
        # Allow thread to be restarted if it dies
        with _state_lock:
            dns_thread_started = False


def ensure_dns_thread():
    global dns_thread_started
    with _state_lock:
        if dns_thread_started:
            return
        dns_thread_started = True
    t = threading.Thread(target=capture_dns, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# IP re-resolution watchdog (background thread)
# ---------------------------------------------------------------------------
# Runs every 60 s. Checks the ARP table against saved devices. If any
# enabled device's IP has changed, updates the config and restarts Gatecrash
# so iptables/arpspoof pick up the new IP immediately.

ip_watch_started = False

def ip_watch_loop():
    import time
    while True:
        time.sleep(60)
        try:
            devices = load_devices()
            if not any(d.get("enabled") for d in devices):
                continue

            arp_out, _ = run("ip neigh show 2>/dev/null")
            changed = False
            for dev in devices:
                if not dev.get("enabled") or not dev.get("mac"):
                    continue
                for line in arp_out.splitlines():
                    if dev["mac"] in line.lower():
                        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s", line)
                        if m and m.group(1) != dev.get("ip"):
                            dev["ip"] = m.group(1)
                            changed = True
                        break

            if changed:
                save_devices(devices)
                # Rebuild TARGET_IPS and restart Gatecrash
                new_ips = sync_targets_from_devices()
                audit_log.info("SERVICE  IP watchdog detected IP change — restarting Gatecrash (targets: %s)", new_ips)
                out, rc = run("systemctl restart gatecrash 2>&1", timeout=30)
                if rc == 0:
                    _record_service_state("gatecrash", True)
                else:
                    audit_log.error("SERVICE  Gatecrash restart FAILED after IP change: %s", out)
        except Exception as e:
            audit_log.error("SERVICE  IP watchdog error: %s", e)


def ensure_ip_watch():
    global ip_watch_started
    with _state_lock:
        if ip_watch_started:
            return
        ip_watch_started = True
    t = threading.Thread(target=ip_watch_loop, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Update check (background thread + settings)
# ---------------------------------------------------------------------------

UPDATE_SETTINGS_FILE = "/opt/gatecrash/update_settings.json"

_DEFAULT_UPDATE_SETTINGS = {
    "check_enabled": True,
    "interval":      "daily",   # hourly | daily | weekly
    "auto_update":   False,
}
_INTERVAL_SECS = {"5min": 300, "hourly": 3600, "daily": 86400, "weekly": 604800}

update_check_state = {
    "available":      False,
    "remote_version": None,
    "commit_message": None,
    "last_checked":   None,
    "error":          None,
}
update_check_thread_started = False


def load_update_settings():
    try:
        with open(UPDATE_SETTINGS_FILE) as f:
            return {**_DEFAULT_UPDATE_SETTINGS, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(_DEFAULT_UPDATE_SETTINGS)


def save_update_settings(settings):
    with open(UPDATE_SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


def _trigger_upgrade(repo):
    try:
        repo = _valid_repo(repo)
    except ValueError:
        audit_log.error("UPGRADE  Refused upgrade — unsafe repo path: %s", repo)
        return  # refuse to run upgrade with unsafe repo path
    audit_log.info("UPGRADE  Upgrade triggered from repo %s", repo)
    upgrade_script = f"""#!/bin/bash
> /var/log/gatecrash-upgrade.log
sleep 1
cd {repo}
git -c safe.directory={repo} pull >> /var/log/gatecrash-upgrade.log 2>&1
bash setup.sh >> /var/log/gatecrash-upgrade.log 2>&1
echo "=== Upgrade complete ===" >> /var/log/gatecrash-upgrade.log
"""
    fd, script_path = tempfile.mkstemp(suffix=".sh", prefix="gatecrash-upgrade-")
    with os.fdopen(fd, "w") as f:
        f.write(upgrade_script)
    os.chmod(script_path, 0o700)
    subprocess.Popen(["bash", script_path],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     start_new_session=True)


def run_update_check(allow_auto_upgrade=False):
    global update_check_state
    from datetime import datetime, timezone
    repo = get_repo_path()
    if not repo:
        with _state_lock:
            update_check_state["error"] = "Repo path not set"
        return
    try:
        repo = _valid_repo(repo)
    except ValueError:
        with _state_lock:
            update_check_state["error"] = "Repo path contains unsafe characters"
        return
    fetch_out, rc = run(f"git -c safe.directory={repo} -C {repo} fetch origin 2>&1")
    now = datetime.now(timezone.utc).isoformat()
    if rc != 0:
        with _state_lock:
            update_check_state = {**update_check_state, "error": fetch_out.strip(), "last_checked": now}
        return
    behind_out, _ = run(f"git -c safe.directory={repo} -C {repo} rev-list HEAD..@{{upstream}} --count 2>/dev/null")
    try:
        behind = int(behind_out.strip())
    except ValueError:
        behind = 0
    commit_msg, _    = run(f"git -c safe.directory={repo} -C {repo} log @{{upstream}} -1 --pretty=format:%s 2>/dev/null")
    remote_ver, _    = run(f"git -c safe.directory={repo} -C {repo} show @{{upstream}}:VERSION 2>/dev/null")
    with _state_lock:
        update_check_state = {
            "available":      behind > 0,
            "remote_version": remote_ver.strip()   if behind > 0 else None,
            "commit_message": commit_msg.strip()   if behind > 0 else None,
            "last_checked":   now,
            "error":          None,
        }
    if allow_auto_upgrade and behind > 0 and load_update_settings().get("auto_update"):
        audit_log.info("UPGRADE  Auto-update triggered (%d commits behind, remote %s)", behind, remote_ver.strip())
        _trigger_upgrade(repo)


def update_check_loop():
    import time
    from datetime import datetime, timezone, timedelta
    while True:
        try:
            settings = load_update_settings()
            if settings.get("check_enabled"):
                interval = _INTERVAL_SECS.get(settings.get("interval", "daily"), 86400)
                with _state_lock:
                    last = update_check_state.get("last_checked")
                should_check = last is None
                if not should_check:
                    try:
                        last_dt = datetime.fromisoformat(last)
                        should_check = datetime.now(timezone.utc) - last_dt > timedelta(seconds=interval)
                    except (ValueError, TypeError):
                        should_check = True
                if should_check:
                    run_update_check(allow_auto_upgrade=True)
        except Exception:
            pass
        time.sleep(300)  # re-evaluate every 5 minutes


def ensure_update_check_thread():
    global update_check_thread_started
    with _state_lock:
        if update_check_thread_started:
            return
        update_check_thread_started = True
    t = threading.Thread(target=update_check_loop, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Auto-stop — disable idle devices after configurable timeout
# ---------------------------------------------------------------------------

AUTO_STOP_SETTINGS_FILE = "/opt/gatecrash/auto_stop_settings.json"

_DEFAULT_AUTO_STOP_SETTINGS = {
    "enabled":           False,
    "threshold_kb_min":  250,     # KB/min — streaming is ~5-50 MB/min
    "idle_timeout_min":  30,      # minutes below threshold before auto-stop
    "min_active_min":    5,       # don't auto-stop within first N minutes
}


def load_auto_stop_settings():
    try:
        with open(AUTO_STOP_SETTINGS_FILE) as f:
            return {**_DEFAULT_AUTO_STOP_SETTINGS, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(_DEFAULT_AUTO_STOP_SETTINGS)


def save_auto_stop_settings(settings):
    with open(AUTO_STOP_SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


traffic_watch_started = False
_traffic_state = {}  # {ip: {"last_bytes": int, "idle_since": float|None, "active_since": float}}


def _fmt_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _parse_mangle_counters():
    """Parse per-device byte counters (upload + download) from iptables FORWARD chain."""
    out, rc = run("iptables -L FORWARD -n -v -x 2>/dev/null")
    if rc != 0:
        return {}
    result = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 9 or parts[2] != "ACCEPT":
            continue
        bytes_val = int(parts[1])
        src, dst = parts[7], parts[8]
        # Upload rule: src=<device> dst=0.0.0.0/0
        if src != "0.0.0.0/0" and dst == "0.0.0.0/0":
            result[src] = result.get(src, 0) + bytes_val
        # Download rule: src=0.0.0.0/0 dst=<device>
        elif src == "0.0.0.0/0" and dst != "0.0.0.0/0":
            result[dst] = result.get(dst, 0) + bytes_val
    return result


def _traffic_watch_loop():
    import time
    global _traffic_state
    POLL_INTERVAL = 30

    while True:
        time.sleep(POLL_INTERVAL)
        try:
            settings = load_auto_stop_settings()
            if not settings.get("enabled"):
                _traffic_state = {}
                continue

            counters = _parse_mangle_counters()
            now = time.time()
            threshold_bytes = settings["threshold_kb_min"] * 1024 * (POLL_INTERVAL / 60.0)
            idle_timeout_secs = settings["idle_timeout_min"] * 60
            min_active_secs = settings["min_active_min"] * 60
            devices = load_devices()

            for dev in devices:
                if not dev.get("enabled") or not dev.get("ip"):
                    continue
                if not dev.get("auto_stop", True):
                    continue

                ip = dev["ip"]
                current_bytes = counters.get(ip, 0)
                state = _traffic_state.get(ip)

                if state is None:
                    _traffic_state[ip] = {
                        "last_bytes": current_bytes,
                        "idle_since": None,
                        "active_since": now,
                    }
                    continue

                delta = current_bytes - state["last_bytes"]
                if delta < 0:
                    delta = current_bytes  # counter reset (iptables flush)
                state["last_bytes"] = current_bytes

                idle_since = state["idle_since"]
                idle_min = (now - idle_since) / 60 if idle_since else 0
                nick = dev.get("nickname") or dev.get("mac", "?")
                audit_log.info(
                    "AUTO-STOP  %s (%s): %s total, delta %s, idle %.1f min",
                    ip, nick, _fmt_bytes(current_bytes), _fmt_bytes(delta), idle_min,
                )

                if delta < threshold_bytes:
                    if state["idle_since"] is None:
                        state["idle_since"] = now
                    idle_dur = now - state["idle_since"]
                    active_dur = now - state["active_since"]

                    if idle_dur >= idle_timeout_secs and active_dur >= min_active_secs:
                        audit_log.info(
                            "AUTO-STOP  Device %s (%s) idle for %.0f min — disabling",
                            ip, dev.get("nickname") or dev.get("mac", "?"),
                            idle_dur / 60,
                        )
                        dev["enabled"] = False
                        save_devices(devices)
                        sync_targets_from_devices()
                        out, rc = run("systemctl restart gatecrash 2>&1", timeout=30)
                        if rc == 0:
                            _record_service_state("gatecrash", True)
                        else:
                            audit_log.error("AUTO-STOP  Gatecrash restart FAILED: %s", out)
                        _traffic_state.pop(ip, None)
                        break  # device list mutated — catch others next cycle
                else:
                    state["idle_since"] = None

            # Clean stale entries
            active_ips = {d["ip"] for d in devices if d.get("enabled") and d.get("ip")}
            for ip in list(_traffic_state):
                if ip not in active_ips:
                    del _traffic_state[ip]

        except Exception as e:
            audit_log.error("AUTO-STOP  Traffic watch error: %s", e)


def ensure_traffic_watch():
    global traffic_watch_started
    with _state_lock:
        if traffic_watch_started:
            return
        traffic_watch_started = True
    t = threading.Thread(target=_traffic_watch_loop, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Saved devices (MAC-based persistence)
# ---------------------------------------------------------------------------

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
    out, _ = run(f"ip neigh show {ip} 2>/dev/null")
    m = re.search(r"lladdr\s+([0-9a-f:]+)", out)
    return m.group(1).lower() if m else ""


def sync_targets_from_devices():
    """Update TARGET_IPS in gatecrash.conf from enabled saved devices.

    Uses ARP table to resolve current IPs from saved MAC addresses.
    Returns the list of active IPs written to config.
    """
    devices = load_devices()
    active_ips = []
    updated = False

    # Read ARP table once for all devices
    arp_out, _ = run("ip neigh show 2>/dev/null")
    arp_lines = arp_out.splitlines()

    for dev in devices:
        if not dev.get("enabled", False):
            continue
        mac = dev.get("mac", "")
        if not mac:
            continue
        # Find current IP for this MAC from ARP table
        for line in arp_lines:
            if mac in line.lower():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s", line)
                if m:
                    ip = m.group(1)
                    active_ips.append(ip)
                    # Update last-known IP
                    if dev.get("ip") != ip:
                        dev["ip"] = ip
                        updated = True
                    break
        else:
            # MAC not in ARP table — use last-known IP if available
            if dev.get("ip"):
                active_ips.append(dev["ip"])

    if updated:
        save_devices(devices)

    # Write to gatecrash.conf
    conf = read_conf()
    conf["TARGET_IPS"] = " ".join(active_ips)
    write_conf(conf)
    return active_ips


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    setup_required = _get_stored_token() is None
    login_required = not setup_required and not session.get("authenticated")
    if not setup_required and not login_required:
        ensure_dns_thread()
        ensure_ip_watch()
        ensure_update_check_thread()
        ensure_traffic_watch()
    csrf = _ensure_csrf_token() if not setup_required and not login_required else ""
    return render_template("index.html", version=get_version(),
                           setup_required=setup_required, login_required=login_required,
                           csrf_token=csrf)


@app.route("/api/setup-auth", methods=["POST"])
def api_setup_auth():
    """Bootstrap authentication — only usable when no token has been set yet."""
    if _get_stored_token() is not None:
        return jsonify({"ok": False, "error": "Authentication is already configured"}), 403
    password = (request.json or {}).get("password", "")
    if len(password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters"})
    try:
        _store_password(password)
        # Automatically log in so the page loads immediately after setup
        session["authenticated"] = True
        session.permanent = True
        audit_log.info("AUTH  Initial password configured from %s", request.remote_addr)
        return jsonify({"ok": True, "csrf_token": _ensure_csrf_token()})
    except Exception:
        return jsonify({"ok": False, "error": "Internal error"})


@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def api_login():
    stored = _get_stored_token()
    if stored is None:
        return jsonify({"ok": False, "error": "Setup not complete"})
    password = (request.json or {}).get("password", "")
    matched, needs_rehash = _check_password(password, stored)
    if matched:
        if needs_rehash:
            _store_password(password)
            audit_log.info("AUTH  Migrated legacy plaintext password to bcrypt from %s", request.remote_addr)
        session["authenticated"] = True
        session.permanent = True
        audit_log.info("AUTH  Login succeeded from %s", request.remote_addr)
        return jsonify({"ok": True, "csrf_token": _ensure_csrf_token()})
    audit_log.warning("AUTH  Login FAILED from %s", request.remote_addr)
    return jsonify({"ok": False, "error": "Incorrect password"})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    audit_log.info("AUTH  Logout from %s", request.remote_addr)
    return jsonify({"ok": True})


@app.route("/api/change-password", methods=["POST"])
def api_change_password():
    stored = _get_stored_token()
    if stored is None:
        return jsonify({"ok": False, "error": "No password set"}), 400
    data = request.json or {}
    current  = data.get("current", "")
    new_pw   = data.get("new", "")
    matched, _ = _check_password(current, stored)
    if not matched:
        audit_log.warning("AUTH  Password change FAILED (wrong current password) from %s", request.remote_addr)
        return jsonify({"ok": False, "error": "Current password is incorrect"})
    if len(new_pw) < 8:
        return jsonify({"ok": False, "error": "New password must be at least 8 characters"})
    try:
        _store_password(new_pw)
        audit_log.info("AUTH  Password changed from %s", request.remote_addr)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False, "error": "Internal error"})


@app.route("/api/factory-reset", methods=["POST"])
@limiter.limit("1 per minute")
def api_factory_reset():
    stored = _get_stored_token()
    if stored is not None:
        password = (request.json or {}).get("password", "")
        matched, _ = _check_password(password, stored)
        if not matched:
            return jsonify({"ok": False, "error": "Incorrect password"})
    # Stop running services before wiping config
    audit_log.warning("SYSTEM  Factory reset initiated from %s", request.remote_addr)
    run("systemctl stop gatecrash 2>/dev/null", timeout=10)
    run("wg-quick down wg0 2>/dev/null", timeout=10)
    # Delete all user data and credentials
    for path in [
        CONF_PATH,
        WG_CONF_PATH,
        DEVICES_FILE,
        WEBUI_TOKEN_PATH,
        SECRET_KEY_PATH,
        UPDATE_SETTINGS_FILE,
        AUTO_STOP_SETTINGS_FILE,
        BOOT_STATE_FILE,
    ]:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    session.clear()
    subprocess.Popen(["systemctl", "reboot"])
    return jsonify({"ok": True})


@app.route("/api/version")
def api_version():
    return jsonify({"version": get_version()})


@app.route("/api/status")
def api_status():
    ensure_dns_thread()  # auto-recover if thread died
    out, _ = run("systemctl is-active gatecrash 2>/dev/null")
    gc_running = out.strip() == "active"

    _, rc = run("ip link show wg0 2>/dev/null")
    wg_up = rc == 0

    arp_out, _ = run("pgrep -c arpspoof 2>/dev/null || echo 0")

    # Check if vpntarget has a VPN route (not just the fallback gateway)
    vt_out, _ = run("ip route show table vpntarget 2>/dev/null")
    vpn_route_missing = wg_up and gc_running and "dev wg0" not in (vt_out or "")

    # Auto-fix: restore VPN route if WireGuard is up but route is missing
    if vpn_route_missing:
        conf = read_conf()
        try:
            rt = _valid_table(conf.get("ROUTE_TABLE", "vpntarget"))
            run(f"ip route replace default dev wg0 table {rt} metric 100")
        except ValueError:
            pass  # invalid table name — skip route restore
        vpn_route_missing = False  # fixed

    return jsonify({
        "gatecrash_running": gc_running,
        "wg_up": wg_up,
        "arp_processes": arp_out.strip(),
        "wg": wg_stats(),
        "update": dict(update_check_state),
        "version": get_version(),
    })


@app.route("/api/start", methods=["POST"])
def api_start():
    audit_log.info("SERVICE  Gatecrash START requested from %s", request.remote_addr)
    out, rc = run("systemctl start gatecrash 2>&1", timeout=30)
    if rc == 0:
        _record_service_state("gatecrash", True)
        audit_log.info("SERVICE  Gatecrash started successfully")
    else:
        audit_log.error("SERVICE  Gatecrash start FAILED: %s", out)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    audit_log.info("SERVICE  Gatecrash STOP requested from %s", request.remote_addr)
    out, rc = run("systemctl stop gatecrash 2>&1", timeout=30)
    if rc == 0:
        _record_service_state("gatecrash", False)
        audit_log.info("SERVICE  Gatecrash stopped successfully")
    else:
        audit_log.error("SERVICE  Gatecrash stop FAILED: %s", out)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/wg/start", methods=["POST"])
def api_wg_start():
    audit_log.info("SERVICE  WireGuard START requested from %s", request.remote_addr)
    out, rc = run("wg-quick up wg0 2>&1", timeout=20)
    # Restore vpntarget VPN route (wg-quick wipes it on down/up)
    conf = read_conf()
    try:
        rt = _valid_table(conf.get("ROUTE_TABLE", "vpntarget"))
        run(f"ip route replace default dev wg0 table {rt} metric 100")
    except ValueError:
        pass  # invalid table name — skip route restore
    if rc == 0:
        _record_service_state("wg", True)
        audit_log.info("SERVICE  WireGuard started successfully")
    else:
        audit_log.error("SERVICE  WireGuard start FAILED: %s", out)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/wg/stop", methods=["POST"])
def api_wg_stop():
    audit_log.info("SERVICE  WireGuard STOP requested from %s", request.remote_addr)
    out, rc = run("wg-quick down wg0 2>&1", timeout=20)
    if rc == 0:
        _record_service_state("wg", False)
        audit_log.info("SERVICE  WireGuard stopped successfully")
    else:
        audit_log.error("SERVICE  WireGuard stop FAILED: %s", out)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/autostart", methods=["GET", "POST"])
def api_autostart():
    if request.method == "GET":
        wg_out, _ = run("systemctl is-enabled wg-quick@wg0 2>/dev/null")
        gc_out, _ = run("systemctl is-enabled gatecrash 2>/dev/null")
        state = _read_boot_state()
        return jsonify({
            "mode": state["mode"],
            "wg": wg_out.strip() == "enabled",
            "gatecrash": gc_out.strip() == "enabled",
        })
    data = request.json
    results = {}
    # Handle mode change
    if "mode" in data:
        state = _read_boot_state()
        new_mode = data["mode"]
        state["mode"] = new_mode
        if new_mode == "resume":
            # Disable manual systemd enable — the resume service handles it
            run("systemctl disable wg-quick@wg0 2>&1")
            run("systemctl disable gatecrash 2>&1")
            # Snapshot current running state
            wg_out, _ = run("systemctl is-active wg-quick@wg0 2>/dev/null")
            gc_out, _ = run("systemctl is-active gatecrash 2>/dev/null")
            state["wg_running"] = wg_out.strip() == "active"
            state["gc_running"] = gc_out.strip() == "active"
        _write_boot_state(state)
        audit_log.info("CONFIG  Boot mode changed to '%s' from %s", new_mode, request.remote_addr)
        results["mode"] = new_mode
    if "wg" in data:
        cmd = "enable" if data["wg"] else "disable"
        _, rc = run(f"systemctl {cmd} wg-quick@wg0 2>&1")
        results["wg"] = rc == 0
        audit_log.info("CONFIG  WireGuard autostart %sd from %s", cmd, request.remote_addr)
    if "gatecrash" in data:
        cmd = "enable" if data["gatecrash"] else "disable"
        _, rc = run(f"systemctl {cmd} gatecrash 2>&1")
        results["gatecrash"] = rc == 0
        audit_log.info("CONFIG  Gatecrash autostart %sd from %s", cmd, request.remote_addr)
    return jsonify({"ok": True, "results": results})





def parse_nmap_devices(output):
    """Parse nmap -sn output into a list of device dicts."""
    import re
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


@app.route("/api/devices/scan-stream")
def api_devices_scan_stream():
    """SSE stream of nmap scan output, followed by parsed device list."""
    audit_log.info("SCAN  Device scan started from %s", request.remote_addr)
    conf = read_conf()
    try:
        lan_if = _valid_if(conf.get("LAN_IF", "eth0"))
    except ValueError:
        return Response("data: ERROR: Invalid interface name in config\n\nevent: done\ndata: []\n\n",
                        mimetype="text/event-stream")

    def generate():
        subnet, rc = run(f"ip -o -f inet addr show {lan_if} | awk '{{print $4}}' | head -1")
        if rc != 0 or not subnet.strip():
            yield f"data: ERROR: Could not detect subnet for {lan_if}\n\n"
            yield "event: done\ndata: []\n\n"
            return

        # IPs to exclude from scan results: ourselves and the gateway
        own_ip_out, _ = run(f"ip -o -f inet addr show {lan_if} | awk '{{print $4}}' | cut -d/ -f1 | head -1")
        exclude_ips = {own_ip_out.strip()}
        gw = _detect_gateway()
        if gw:
            exclude_ips.add(gw)

        yield f"data: Scanning {subnet.strip()} ...\n\n"

        try:
            proc = subprocess.Popen(
                ["nmap", "-sn", "--stats-every", "3s", subnet.strip()],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            output_lines = []
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    output_lines.append(line)
                    yield f"data: {line}\n\n"
            proc.wait()
            full_output = "\n".join(output_lines)
            devices = parse_nmap_devices(full_output)

            # Augment with ARP entries nmap missed
            import re as _re
            arp_out, _ = run("ip neigh show")
            nmap_macs = {d["mac"] for d in devices if d["mac"]}
            for line in arp_out.splitlines():
                m = _re.match(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})\s+(\w+)", line)
                if not m:
                    continue
                ip, mac, state = m.group(1), m.group(2).lower(), m.group(3)
                if state == "FAILED" or mac in nmap_macs:
                    continue
                devices.append({"ip": ip, "mac": mac, "hostname": "", "vendor": ""})
                nmap_macs.add(mac)

            devices = [d for d in devices if d["ip"] not in exclude_ips]
            devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])
            yield f"event: devices\ndata: {json.dumps(devices)}\n\n"
        except Exception as e:
            yield f"data: ERROR: {e}\n\n"
            yield "event: devices\ndata: []\n\n"

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})



@app.route("/api/saved-devices", methods=["GET"])
def api_saved_devices():
    """Return the saved device list."""
    return jsonify({"devices": load_devices()})


@app.route("/api/saved-devices", methods=["POST"])
def api_save_device():
    """Add or update a saved device. Expects {mac, nickname?, ip?, enabled?}."""
    data = request.json
    mac = data.get("mac", "").lower().strip()
    if not mac:
        return jsonify({"ok": False, "error": "MAC address required"})
    if not _MAC_RE.match(mac):
        return jsonify({"ok": False, "error": "Invalid MAC address format"})
    if data.get("ip"):
        try:
            ipaddress.ip_address(data["ip"])
        except ValueError:
            return jsonify({"ok": False, "error": "Invalid IP address"})
    if data.get("nickname"):
        nick = str(data["nickname"])
        if len(nick) > _NICK_MAX or re.search(r'[<>"\'&;]', nick):
            return jsonify({"ok": False, "error": "Nickname contains invalid characters or is too long"})

    devices = load_devices()

    # Find existing device by MAC
    existing = next((d for d in devices if d["mac"] == mac), None)
    if existing:
        if "nickname" in data:
            existing["nickname"] = data["nickname"]
        if "ip" in data:
            existing["ip"] = data["ip"]
        if "enabled" in data:
            existing["enabled"] = data["enabled"]
        if "hostname" in data:
            existing["hostname"] = data["hostname"]
        if "auto_stop" in data:
            existing["auto_stop"] = data["auto_stop"]
    else:
        devices.append({
            "mac": mac,
            "nickname": data.get("nickname", ""),
            "ip": data.get("ip", ""),
            "hostname": data.get("hostname", ""),
            "enabled": data.get("enabled", True),
            "auto_stop": data.get("auto_stop", True),
        })

    save_devices(devices)
    nick = data.get("nickname", "")
    # Log what actually changed
    changes = []
    if "enabled" in data:
        changes.append("enabled=%s" % data["enabled"])
    if "nickname" in data:
        changes.append("nickname=%r" % data["nickname"])
    if "auto_stop" in data:
        changes.append("auto_stop=%s" % data["auto_stop"])
    if "ip" in data:
        changes.append("ip=%s" % data["ip"])
    detail = ", ".join(changes) if changes else "saved"
    if existing:
        audit_log.info("DEVICE  %s (%s): %s [from %s]", mac, nick, detail, request.remote_addr)
    else:
        audit_log.info("DEVICE  New %s (%s): %s [from %s]", mac, nick, detail, request.remote_addr)
    return jsonify({"ok": True, "devices": devices})


@app.route("/api/saved-devices/delete", methods=["POST"])
def api_delete_device():
    """Remove a saved device by MAC."""
    mac = request.json.get("mac", "").lower().strip()
    devices = [d for d in load_devices() if d["mac"] != mac]
    save_devices(devices)
    audit_log.info("DEVICE  Deleted %s from %s", mac, request.remote_addr)
    return jsonify({"ok": True, "devices": devices})


@app.route("/api/saved-devices/sync", methods=["POST"])
def api_sync_devices():
    """Sync enabled saved devices → TARGET_IPS in config, then restart Gatecrash."""
    active_ips = sync_targets_from_devices()
    audit_log.info("DEVICE  Synced targets → %s, restarting Gatecrash from %s",
                   active_ips or "(none)", request.remote_addr)
    # Restart Gatecrash to apply new targets
    out, rc = run("systemctl restart gatecrash 2>&1", timeout=30)
    if rc == 0:
        _record_service_state("gatecrash", True)
        audit_log.info("SERVICE  Gatecrash restarted after device sync")
    else:
        audit_log.error("SERVICE  Gatecrash restart FAILED after device sync: %s", out)
    return jsonify({"ok": rc == 0, "active_ips": active_ips, "output": out})


@app.route("/api/gateway")
def api_gateway():
    gw = _detect_gateway()
    return jsonify({"ok": bool(gw), "gateway": gw})


@app.route("/api/diagnostics/dump")
def api_diagnostics_dump():
    """Generate a full troubleshooting dump as a downloadable text file."""
    conf = read_conf()
    try:
        lan_if = _valid_if(conf.get("LAN_IF", "eth0"))
        vpn_if = _valid_if(conf.get("VPN_IF", "wg0"))
        rt = _valid_table(conf.get("ROUTE_TABLE", "vpntarget"))
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid config value"}), 400

    sections = []

    def section(title, cmd):
        out, _ = run(cmd, timeout=10)
        # Redact WireGuard private keys from all output
        redacted = re.sub(r'(?im)^(\s*PrivateKey\s*=\s*).*$', r'\1[redacted]', out or '')
        sections.append(f"{'=' * 70}\n{title}\n{'=' * 70}\n$ {cmd}\n\n{redacted or '(empty)'}\n")

    sections.append(f"Gatecrash Diagnostics Dump\nGenerated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nVersion: {get_version()}\n")

    section("Gatecrash Config", f"cat {CONF_PATH}")
    section("Gatecrash Service Status", "systemctl status gatecrash --no-pager -l 2>&1")
    section("Web UI Service Status", "systemctl status gatecrash-webui --no-pager -l 2>&1")

    section(f"LAN Interface ({lan_if})", f"ip addr show {lan_if} 2>&1")
    section("WireGuard Interface", f"ip addr show {vpn_if} 2>&1")
    section("WireGuard Status", f"wg show {vpn_if} 2>&1")
    section("Default Route", "ip route show default 2>&1")
    section(f"vpntarget Routing Table ({rt})", f"ip route show table {rt} 2>&1")
    section("IP Policy Rules", "ip rule show 2>&1")

    section("iptables — mangle PREROUTING (packet marks)",
            "iptables -t mangle -L PREROUTING -n -v --line-numbers 2>&1")
    section("iptables — nat PREROUTING (DNS DNAT)",
            "iptables -t nat -L PREROUTING -n -v --line-numbers 2>&1")
    section("iptables — nat POSTROUTING (MASQUERADE)",
            "iptables -t nat -L POSTROUTING -n -v --line-numbers 2>&1")
    section("iptables — FORWARD",
            "iptables -L FORWARD -n -v --line-numbers 2>&1")
    section("iptables — mangle FORWARD (MSS clamp)",
            "iptables -t mangle -L FORWARD -n -v --line-numbers 2>&1")

    section("Active arpspoof Processes", "ps -eo pid,args | grep arpspoof | grep -v grep 2>&1")
    section("VPN Exit IP Test", f"curl --interface {vpn_if} -m 10 -s http://ifconfig.me 2>&1")
    section("DNS Resolution via 1.1.1.1", "dig @1.1.1.1 google.com +short 2>&1")
    section("DNS Resolution via Gateway", f"dig @{conf.get('GATEWAY_IP', '192.168.1.254')} google.com +short 2>&1")

    section("IPv6 Addresses", "ip -6 addr show 2>&1")
    section("ARP Table", "ip neigh show 2>&1")
    section("Listening on Port 53", "ss -ulnp sport = :53 2>&1")

    body = "\n\n".join(sections)
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=gatecrash-diagnostics.txt"})


@app.route("/api/dns-test")
def api_dns_test():
    """Run tcpdump for 5 seconds on LAN interface, return raw lines for debugging."""
    conf = read_conf()
    try:
        lan_if = _valid_if(conf.get("LAN_IF", "eth0"))
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid interface name in config"}), 400
    # 'timeout 5' kills tcpdump after 5s; '|| true' so non-zero exit doesn't raise
    out, _ = run(f"timeout 5 tcpdump -i {lan_if} -n udp dst port 53 2>/dev/null || true", timeout=8)
    lines = [l for l in out.splitlines() if l.strip()]
    return jsonify({"ok": True, "interface": lan_if, "lines": lines})


@app.route("/api/diagnostics")
def api_diagnostics():
    conf = read_conf()
    try:
        lan_if = _valid_if(conf.get("LAN_IF", "eth0"))
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid interface name in config"}), 400

    # MAC address of the LAN interface
    mac_out, _ = run(f"ip link show {lan_if} 2>/dev/null")
    mac = ""
    m = re.search(r"link/ether ([0-9a-f:]+)", mac_out)
    if m:
        mac = m.group(1)

    # IP address of the LAN interface
    ip_out, _ = run(f"ip -4 addr show {lan_if} 2>/dev/null")
    lan_ip = ""
    m = re.search(r"inet (\S+)", ip_out)
    if m:
        lan_ip = m.group(1)

    # Active arpspoof processes
    arps_out, _ = run("ps -eo pid,args | grep arpspoof | grep -v grep")
    arps = [line.strip() for line in arps_out.splitlines() if line.strip()] if arps_out else []

    # iptables mangle PREROUTING rules
    ipt_out, _ = run("iptables -t mangle -L PREROUTING -n --line-numbers 2>/dev/null")

    # IP policy rules
    iprules_out, _ = run("ip rule show 2>/dev/null")

    # vpntarget routing table
    vt_out, _ = run("ip route show table vpntarget 2>/dev/null")

    # WireGuard interface
    wg_out, wg_rc = run("ip link show wg0 2>/dev/null")
    wg_if = wg_out.strip() if wg_rc == 0 else "wg0 not found"

    # Hostname
    hostname_out, _ = run("hostname 2>/dev/null")

    return jsonify({
        "lan_if": lan_if,
        "lan_mac": mac,
        "lan_ip": lan_ip,
        "hostname": hostname_out.strip(),
        "gateway": _detect_gateway(),
        "arpspoof_procs": arps,
        "iptables_mangle": ipt_out.strip(),
        "ip_rules": iprules_out.strip(),
        "vpntarget_routes": vt_out.strip() or "(empty — WireGuard may be down)",
        "wg_if": wg_if,
    })


@app.route("/api/reboot", methods=["POST"])
@limiter.limit("1 per minute")
def api_reboot():
    audit_log.warning("SYSTEM  Reboot requested from %s", request.remote_addr)
    subprocess.Popen(["shutdown", "-r", "now"])
    return jsonify({"ok": True})


@app.route("/api/shutdown", methods=["POST"])
@limiter.limit("1 per minute")
def api_shutdown():
    audit_log.warning("SYSTEM  Shutdown requested from %s", request.remote_addr)
    subprocess.Popen(["shutdown", "-h", "now"])
    return jsonify({"ok": True})


@app.route("/api/test-vpn")
def api_test_vpn():
    ip, rc = run("curl --interface wg0 -m 10 -s http://ifconfig.me 2>&1")
    return jsonify({"ok": rc == 0, "ip": ip})


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        conf = read_conf()
        # Always inject the live detected gateway
        conf["GATEWAY_IP"] = _detect_gateway() or conf.get("GATEWAY_IP", "")
        return jsonify(conf)
    try:
        data = request.json
        # Reject unknown keys — only permitted config fields may be written
        unknown = set(data.keys()) - _CONF_ALLOWED_KEYS
        if unknown:
            return jsonify({"ok": False, "error": f"Unknown config keys: {', '.join(sorted(unknown))}"}), 400
        # Validate every field with strict allowlists
        errors = []
        _conf_validators = {
            "LAN_IF": _valid_if,
            "VPN_IF": _valid_if,
            "ROUTE_TABLE": _valid_table,
            "GATEWAY_IP": _valid_ip,
            "FWMARK": _valid_fwmark,
            "TARGET_IPS": _valid_target_ips,
        }
        for key, validator in _conf_validators.items():
            if key in data:
                try:
                    validator(data[key])
                except ValueError as e:
                    errors.append(str(e))
        if errors:
            return jsonify({"ok": False, "error": "; ".join(errors)}), 400
        # Refresh gateway from routing table before saving
        gw = _detect_gateway()
        if gw:
            data["GATEWAY_IP"] = gw
        write_conf(data)
        audit_log.info("CONFIG  Configuration updated from %s: %s", request.remote_addr, data)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False, "error": "Internal error"})


@app.route("/api/wg-config", methods=["GET", "POST"])
def api_wg_config():
    if request.method == "GET":
        try:
            with open(WG_CONF_PATH) as f:
                content = f.read()
            # Redact PrivateKey — only accept it on writes
            content = re.sub(r'(?im)^(\s*PrivateKey\s*=\s*).*$', r'\1[redacted]', content)
            return jsonify({"ok": True, "content": content})
        except Exception:
            return jsonify({"ok": False, "content": "", "error": "Internal error"})
    try:
        content = _strip_wg_hooks(request.json.get("content", ""))
        # If client sent back [redacted], restore the real PrivateKey from disk
        if "[redacted]" in content:
            try:
                with open(WG_CONF_PATH) as f:
                    old = f.read()
                pk = re.search(r'(?im)^(\s*PrivateKey\s*=\s*)(.+)$', old)
                if pk:
                    content = re.sub(r'(?im)^(\s*PrivateKey\s*=\s*)\[redacted\]', pk.group(1) + pk.group(2), content)
            except FileNotFoundError:
                pass
        with open(WG_CONF_PATH, "w") as f:
            f.write(content)
        os.chmod(WG_CONF_PATH, 0o600)
        audit_log.info("CONFIG  WireGuard config updated from %s", request.remote_addr)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False, "error": "Internal error"})


@app.route("/api/wg-config/upload", methods=["POST"])
def api_wg_config_upload():
    """Accept a raw WireGuard config, fix it for Gatecrash, and save."""
    content = request.json.get("content", "")
    if not content.strip():
        return jsonify({"ok": False, "error": "Empty config file"})

    # Validate it looks like a WireGuard config
    if "[Interface]" not in content and "[Peer]" not in content:
        return jsonify({"ok": False, "error": "Not a valid WireGuard config (missing [Interface] or [Peer])"})

    # Validate private key exists and looks correct (base64, 44 chars with trailing =)
    pk_match = re.search(r"PrivateKey\s*=\s*(\S+)", content, re.IGNORECASE)
    if not pk_match:
        return jsonify({"ok": False, "error": "Missing PrivateKey — check your .conf file includes a PrivateKey line"})
    pk_value = pk_match.group(1)
    if len(pk_value) != 44 or not pk_value.endswith("="):
        return jsonify({"ok": False, "error": f"PrivateKey doesn't look valid (expected 44-char base64 string ending with '='). Got: {pk_value[:8]}..."})

    fixes = []
    lines = content.splitlines()
    new_lines = []
    in_interface = False
    has_table = False
    has_mtu = False

    for line in lines:
        stripped = line.strip()

        # Track which section we're in
        if stripped.startswith("[Interface]"):
            in_interface = True
        elif stripped.startswith("["):
            in_interface = False

        # Remove DNS lines (Gatecrash handles DNS routing)
        if in_interface and re.match(r"^\s*DNS\s*=", stripped, re.IGNORECASE):
            fixes.append("removed DNS")
            continue

        # Check for Table and MTU
        if in_interface and re.match(r"^\s*Table\s*=", stripped, re.IGNORECASE):
            has_table = True
            if "off" not in stripped.lower():
                line = "Table = off"
                fixes.append("set Table = off")
        if in_interface and re.match(r"^\s*MTU\s*=", stripped, re.IGNORECASE):
            has_mtu = True
            if "1280" not in stripped:
                line = "MTU = 1280"
                fixes.append("set MTU = 1280")

        new_lines.append(line)

    # Add missing Table/MTU after [Interface] line
    if not has_table or not has_mtu:
        result = []
        for line in new_lines:
            result.append(line)
            if line.strip() == "[Interface]":
                if not has_table:
                    result.append("Table = off")
                    fixes.append("added Table = off")
                if not has_mtu:
                    result.append("MTU = 1280")
                    fixes.append("added MTU = 1280")
        new_lines = result

    final_content = _strip_wg_hooks("\n".join(new_lines))
    if not final_content.endswith("\n"):
        final_content += "\n"

    try:
        with open(WG_CONF_PATH, "w") as f:
            f.write(final_content)
        os.chmod(WG_CONF_PATH, 0o600)
        audit_log.info("CONFIG  WireGuard config uploaded from %s (fixes: %s)", request.remote_addr, fixes)
        return jsonify({"ok": True, "fixes": fixes})
    except Exception:
        return jsonify({"ok": False, "error": "Internal error", "fixes": []})


@app.route("/api/dns-log")
def api_dns_log():
    with _state_lock:
        entries = list(dns_log)
    return jsonify({"entries": entries})


@app.route("/api/update/check")
def api_update_check():
    run_update_check()
    with _state_lock:
        s = dict(update_check_state)
    return jsonify({
        "ok":             s.get("error") is None,
        "available":      s.get("available", False),
        "remote_version": s.get("remote_version") or "",
        "commit_message": s.get("commit_message") or "",
        "last_checked":   s.get("last_checked"),
        "error":          s.get("error"),
    })


@app.route("/api/update-settings")
def api_get_update_settings():
    return jsonify(load_update_settings())


@app.route("/api/update-settings", methods=["POST"])
def api_save_update_settings():
    data = request.json or {}
    settings = load_update_settings()
    for key in ("check_enabled", "interval", "auto_update"):
        if key in data:
            settings[key] = data[key]
    save_update_settings(settings)
    return jsonify({"ok": True})


@app.route("/api/auto-stop-settings")
def api_get_auto_stop_settings():
    return jsonify(load_auto_stop_settings())


@app.route("/api/auto-stop-settings", methods=["POST"])
def api_save_auto_stop_settings():
    data = request.json or {}
    settings = load_auto_stop_settings()
    for key in ("enabled", "threshold_kb_min", "idle_timeout_min", "min_active_min"):
        if key in data:
            settings[key] = data[key]
    save_auto_stop_settings(settings)
    audit_log.info("CONFIG  Auto-stop settings updated from %s: %s", request.remote_addr, settings)
    return jsonify({"ok": True})


@app.route("/api/upgrade-log-content")
def api_upgrade_log_content():
    try:
        with open("/var/log/gatecrash-upgrade.log") as f:
            return jsonify({"ok": True, "content": f.read()})
    except Exception:
        return jsonify({"ok": False, "content": "", "error": "Internal error"})


@app.route("/api/update/apply", methods=["POST"])
@limiter.limit("1 per minute")
def api_update_apply():
    repo = get_repo_path()
    if not repo:
        return jsonify({"ok": False, "error": "Repo path not set — re-run setup.sh"})
    audit_log.info("UPGRADE  Update apply requested from %s", request.remote_addr)
    _trigger_upgrade(repo)
    return jsonify({"ok": True})


@app.route("/api/audit-log")
def api_audit_log():
    """Return the last N lines of the audit log."""
    try:
        lines_requested = min(int(request.args.get("lines", 200)), 1000)
    except (ValueError, TypeError):
        lines_requested = 200
    try:
        with open(LOG_PATH) as f:
            tail = deque(f, maxlen=lines_requested)
        return jsonify({"ok": True, "lines": [l.rstrip() for l in tail]})
    except FileNotFoundError:
        return jsonify({"ok": True, "lines": []})
    except Exception:
        return jsonify({"ok": False, "error": "Internal error"})


def _http_redirect_server():
    """Tiny HTTP server on port 80 that redirects everything to HTTPS."""
    from flask import Flask as _Flask
    redir = _Flask("redirect")

    @redir.route("/", defaults={"path": ""})
    @redir.route("/<path:path>")
    def _redir(path):
        return redirect(request.url.replace("http://", "https://", 1).replace(":80", ""), code=301)

    redir.run(host="0.0.0.0", port=80, debug=False)


CERT_DIR = "/opt/gatecrash/certs"

if __name__ == "__main__":
    ensure_dns_thread()
    ensure_ip_watch()
    ensure_traffic_watch()

    cert = os.path.join(CERT_DIR, "gatecrash.crt")
    key  = os.path.join(CERT_DIR, "gatecrash.key")

    if os.path.isfile(cert) and os.path.isfile(key):
        # Start HTTP→HTTPS redirect in background
        threading.Thread(target=_http_redirect_server, daemon=True).start()
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        app.run(host="0.0.0.0", port=443, debug=False, ssl_context=ctx)
    else:
        # Fallback to plain HTTP if no cert found
        app.run(host="0.0.0.0", port=80, debug=False)
