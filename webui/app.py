#!/usr/bin/env python3
"""Gatecrash web UI — serves HTTPS on 443 (with HTTP→HTTPS redirect on 80) or
plain HTTP on 80, depending on the user's pref. Must run as root to bind 80/443."""

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
import time
import shlex
import subprocess
from collections import deque
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, jsonify, request, Response, stream_with_context, session, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import stats as sysstats

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
NO_AUTH_PATH      = "/opt/gatecrash/webui_no_auth"
HTTPS_PREF_PATH   = "/opt/gatecrash/https_pref"
WELCOME_PATH      = "/opt/gatecrash/welcome_pending"
CERT_DIR          = "/opt/gatecrash/certs"

# Endpoints always accessible without a session
_PUBLIC_PATHS = {"/", "/api/login", "/api/setup-auth", "/api/skip-setup-auth"}


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
        # bcrypt hash — checkpw is already constant-time internally
        return bcrypt.checkpw(password.encode("utf-8"), stored), False
    # SECURITY: hmac.compare_digest prevents timing attacks — do NOT replace
    # with == even though it looks equivalent.  An attacker can measure response
    # time differences with == to guess the password byte-by-byte.  (CRIT-6)
    matched = hmac.compare_digest(password.encode("utf-8"), stored)
    return matched, True


def _store_password(password):
    """Hash and write a password to the token file (overwrites)."""
    hashed = _hash_password(password)
    with open(WEBUI_TOKEN_PATH, "wb") as f:
        f.write(hashed)
    # SECURITY: 0o600 = owner-only read/write.  Without this, other users on
    # the box could read the bcrypt hash and brute-force it offline.  (CRIT-5)
    os.chmod(WEBUI_TOKEN_PATH, 0o600)


def _no_auth_enabled():
    """True when the user opted out of authentication during initial setup."""
    return os.path.isfile(NO_AUTH_PATH)


def _https_enabled():
    """Return True if HTTPS should be served on the next service start.

    No pref file → fresh install in pre-setup state.  We come up on
    HTTP so the user lands on the friendly welcome / TLS-choice screen
    without an upfront self-signed cert warning.  That screen forces
    an explicit choice (HTTPS recommended; HTTP only on trusted
    networks) BEFORE the password is set, which is what closes the
    first-boot cleartext-password window. (vulnerabilities_3.md #2 /
    MED-17.)  Existing installs (token or no-auth marker present)
    without a pref file are treated as HTTPS-on for backward compat."""
    try:
        with open(HTTPS_PREF_PATH) as f:
            return f.read().strip() == "on"
    except FileNotFoundError:
        return os.path.isfile(WEBUI_TOKEN_PATH) or os.path.isfile(NO_AUTH_PATH)


def _set_https_pref(enabled):
    with open(HTTPS_PREF_PATH, "w") as f:
        f.write("on" if enabled else "off")
    os.chmod(HTTPS_PREF_PATH, 0o644)


def _mark_welcome_pending():
    """Create a marker so the next index() render shows the welcome modal.

    Survives the HTTPS switch (server-side) which localStorage cannot
    (http://host and https://host are separate Origins for storage)."""
    try:
        with open(WELCOME_PATH, "w") as f:
            f.write("1")
        os.chmod(WELCOME_PATH, 0o644)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# TLS certificate helpers — self-signed cert lives in CERT_DIR.
# Apple platforms reject self-signed certs with validity > 825 days, so we
# cap at that and renew before expiry.
# ---------------------------------------------------------------------------

CERT_VALIDITY_DAYS = 825
CERT_RENEW_THRESHOLD_DAYS = 60  # auto-renew when fewer days remain than this


def _cert_path():
    return os.path.join(CERT_DIR, "gatecrash.crt")


def _cert_key_path():
    return os.path.join(CERT_DIR, "gatecrash.key")


def _parse_openssl_date(line):
    """Parse 'notAfter=Mar 14 12:00:00 2027 GMT' → aware UTC datetime, or None."""
    if "=" not in line:
        return None
    try:
        return datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _cert_dates():
    """Return (not_before, not_after) as aware UTC datetimes, or (None, None)."""
    cert = _cert_path()
    if not os.path.isfile(cert):
        return (None, None)
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert, "-noout", "-startdate", "-enddate"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode != 0:
            return (None, None)
        nb = na = None
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("notBefore="):
                nb = _parse_openssl_date(line)
            elif line.startswith("notAfter="):
                na = _parse_openssl_date(line)
        return (nb, na)
    except Exception:
        return (None, None)


def _cert_not_after():
    """Return the cert's expiry as an aware UTC datetime, or None if unreadable."""
    return _cert_dates()[1]


def _cert_total_validity_days():
    """Return the cert's full validity span (notAfter - notBefore) in days, or None."""
    nb, na = _cert_dates()
    if nb is None or na is None:
        return None
    return int((na - nb).total_seconds() // 86400)


def _cert_days_remaining():
    exp = _cert_not_after()
    if exp is None:
        return None
    return int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)


def _generate_self_signed_cert():
    """(Re)generate the self-signed cert. Returns True on success."""
    os.makedirs(CERT_DIR, mode=0o700, exist_ok=True)
    cert = _cert_path()
    key  = _cert_key_path()
    try:
        proc = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert,
             "-days", str(CERT_VALIDITY_DAYS),
             "-subj", "/CN=gatecrash",
             "-addext", "subjectAltName=DNS:gatecrash,DNS:gatecrash.local,IP:127.0.0.1"],
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            return False
        os.chmod(key, 0o600)
        os.chmod(cert, 0o644)
        return True
    except Exception:
        return False


def _schedule_webui_restart(delay=1.0):
    """Restart the gatecrash-webui service after the current response is sent.

    Used when toggling HTTPS so the new transport mode takes effect. The delay
    gives Flask time to flush the response before systemd kills this process."""
    def _do():
        time.sleep(delay)
        subprocess.Popen(["systemctl", "restart", "gatecrash-webui"])
    threading.Thread(target=_do, daemon=True).start()


def _store_password_exclusive(password):
    """Atomically create the token file — fails if it already exists.

    Closes the setup-mode TOCTOU window: concurrent /api/setup-auth requests
    can't both win the check in `api_setup_auth()` and overwrite each other.
    """
    hashed = _hash_password(password)
    fd = os.open(WEBUI_TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(hashed)


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
    # SECURITY: 0o600 — the secret key signs session cookies.  If leaked,
    # an attacker can forge authenticated sessions without knowing the password.
    os.chmod(SECRET_KEY_PATH, 0o600)
    return key


app.secret_key = _get_or_create_secret()
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True
_TLS_ENABLED = _https_enabled() and os.path.isfile(os.path.join(CERT_DIR, "gatecrash.crt"))
app.config["SESSION_COOKIE_SECURE"] = _TLS_ENABLED


@app.errorhandler(429)
def rate_limit_exceeded(_e):
    return jsonify({"ok": False, "error": "Too many requests — please wait and try again"}), 429


@app.after_request
def set_security_headers(response):
    """Add security headers and prevent stale API caching."""
    # SECURITY: no-store prevents the browser (and proxies) from caching API
    # responses that may contain tokens, device lists, or config.  Without this,
    # sensitive data can persist in the disk cache after logout.
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';"
    # SECURITY: HSTS tells the browser to always use HTTPS for future visits,
    # preventing SSL-stripping attacks on the LAN.  (MED-16)
    # Pin for 1 day rather than 1 year — this is a self-signed LAN appliance,
    # not a public site. A short window means a misconfigured user (e.g. cert
    # rejected on iOS, HTTPS disabled to recover) isn't locked out for a year.
    # If the route already set Strict-Transport-Security (e.g. /api/set-https
    # disable flow sends max-age=0 to clear the pin), do not overwrite it.
    if _TLS_ENABLED and "Strict-Transport-Security" not in response.headers:
        response.headers["Strict-Transport-Security"] = "max-age=86400; includeSubDomains"
    # SECURITY: mask the real server identity (Werkzeug/Python version) to
    # prevent fingerprinting the exact framework and Python version.  (LOW-3)
    response.headers["Server"] = "Gatecrash"
    return response


@app.before_request
def require_auth():
    # Static assets are always public
    if request.path.startswith("/static/"):
        return
    # No-auth mode: user explicitly opted out during setup. Every endpoint
    # is open. Anyone on the LAN can configure the box — by design.
    if _no_auth_enabled():
        return
    stored = _get_stored_token()
    if stored is None:
        # SECURITY: setup mode locks down ALL endpoints except / and the
        # three setup endpoints (TLS choice, set password, skip password).
        # Without this, an attacker on the LAN could call /api/config,
        # /api/wg-config, etc. before a password is set.  (CRIT-7)
        if request.path in ("/", "/api/setup-tls", "/api/setup-auth", "/api/skip-setup-auth"):
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
_CSRF_EXEMPT = {"/api/login", "/api/setup-auth", "/api/skip-setup-auth", "/api/setup-tls"}


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
    # SECURITY: validate for every session, authenticated or not.  In no-auth
    # mode session["authenticated"] is never set, so a "skip when not
    # authenticated" gate would let a malicious page the user visits in
    # another tab POST to mutating endpoints with no token.  index() issues
    # a token whenever it serves the UI (no-auth or authenticated); setup
    # and login mode are short-circuited by require_auth() above.
    # (vulnerabilities_3.md #1)
    token = request.headers.get("X-CSRF-Token", "")
    # SECURITY: both checks matter — `not token` rejects empty/missing headers,
    # the comparison rejects forged values.  Do NOT simplify to just `!=`.  (HIGH-5)
    if not token or token != session.get("csrf_token"):
        audit_log.warning("AUTH  CSRF rejection on %s %s from %s",
                          request.method, request.path, request.remote_addr)
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

# SECURITY: gatecrash.conf is `source`d as bash by start.sh/stop.sh, so any
# key or value written here executes as root.  The allowlist + per-field
# validators below are the only thing preventing config-write → RCE.  (CRIT-4)
_CONF_ALLOWED_KEYS = {"LAN_IF", "VPN_IF", "GATEWAY_IP", "TARGET_IPS", "ROUTE_TABLE", "FWMARK"}

# SECURITY: wg-quick executes PostUp/PostDown/PreUp/PreDown as root shell
# commands.  A malicious WireGuard config upload could embed `PostUp = rm -rf /`
# and it would run when WireGuard starts.  _strip_wg_hooks() removes these
# lines from every config write path.  Do NOT remove this.  (HIGH-6)
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
_BRANCH_RE = re.compile(r'^[A-Za-z0-9._/-]{1,128}$')


def _valid_branch(name):
    """Return name if it's a safe git branch name, else raise ValueError."""
    if not _BRANCH_RE.match(name or ""):
        raise ValueError("Invalid branch name")
    if name.startswith("-") or ".." in name or name.endswith(".lock"):
        raise ValueError("Invalid branch name")
    return name


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
    validators = {
        "LAN_IF": _valid_if,
        "VPN_IF": _valid_if,
        "ROUTE_TABLE": _valid_table,
        "GATEWAY_IP": _valid_ip_or_empty,
        "FWMARK": _valid_fwmark,
        "TARGET_IPS": _valid_target_ips,
    }
    # GATEWAY_IP is intentionally allowed to be blank — start.sh auto-detects
    # from the default route on every boot, so the appliance works when moved
    # between networks. A non-blank value is a manual override.
    for key, value in data.items():
        if key in validators:
            validators[key](value)
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
    # Get our own LAN IP so we can exclude Gatecrash's own DNS queries.
    # Was: run(f"ip -o -f inet addr show {lan_if} | awk '{{print $4}}' | cut -d/ -f1 | head -1")
    # Replaced by _iface_addr() (JSON parse, shell=False). (HIGH-14)
    own_ip = _iface_addr(lan_if).get("ip", "")
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

            arp_out, _ = run_argv(["ip", "neigh", "show"])
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
                old_targets = read_conf().get("TARGET_IPS", "").split()
                new_ips = sync_targets_from_devices()
                audit_log.info("SERVICE  IP watchdog detected IP change (targets: %s)", new_ips)
                ok, out = _hot_reload_targets(old_targets, new_ips)
                if ok:
                    _record_service_state("gatecrash", True)
                    audit_log.info("SERVICE  Hot-reloaded after IP change: %s", out)
                else:
                    audit_log.error("SERVICE  Hot reload failed after IP change, restarting: %s", out)
                    out, rc = run_argv(["systemctl", "restart", "gatecrash"], timeout=30, merge_stderr=True)
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
    # SECURITY: shlex.quote prevents shell injection if the repo path contains
    # spaces, quotes, or metacharacters (e.g. "; rm -rf /").  (MED-7)
    q_repo = shlex.quote(repo)
    upgrade_script = f"""#!/bin/bash
# SECURITY: self-delete on exit so stale upgrade scripts don't accumulate
# in /tmp where another user could modify them before a re-run.  (LOW-4)
trap 'rm -f -- "$0"' EXIT
> /var/log/gatecrash-upgrade.log
sleep 1
cd {q_repo}
git -c safe.directory={q_repo} pull >> /var/log/gatecrash-upgrade.log 2>&1
bash setup.sh >> /var/log/gatecrash-upgrade.log 2>&1
echo "=== Upgrade complete ===" >> /var/log/gatecrash-upgrade.log
"""
    # SECURITY: mkstemp creates a unique file with 0o600 permissions, preventing
    # a symlink or race-condition attack on a predictable /tmp path.  (MED-1)
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
    git_base = ["git", "-c", f"safe.directory={repo}", "-C", repo]
    fetch_out, rc = run_argv(git_base + ["fetch", "origin"], merge_stderr=True)
    now = datetime.now(timezone.utc).isoformat()
    if rc != 0:
        with _state_lock:
            update_check_state = {**update_check_state, "error": fetch_out.strip(), "last_checked": now}
        return
    behind_out, _ = run_argv(git_base + ["rev-list", "HEAD..@{upstream}", "--count"])
    try:
        behind = int(behind_out.strip())
    except ValueError:
        behind = 0
    commit_msg, _    = run_argv(git_base + ["log", "@{upstream}", "-1", "--pretty=format:%s"])
    remote_ver, _    = run_argv(git_base + ["show", "@{upstream}:VERSION"])
    # Full subject list of every commit the user would gain by upgrading,
    # newest first. Capped at 50 to keep the payload sane.
    commit_log_out, _ = run_argv(git_base + ["log", "HEAD..@{upstream}", "--pretty=format:%s", "-n", "50"])
    commit_log = [l for l in (commit_log_out or "").splitlines() if l.strip()] if behind > 0 else []
    with _state_lock:
        update_check_state = {
            "available":      behind > 0,
            "remote_version": remote_ver.strip()   if behind > 0 else None,
            "commit_message": commit_msg.strip()   if behind > 0 else None,
            "commit_log":     commit_log,
            "commits_behind": behind,
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


# ---------------------------------------------------------------------------
# OS auto-updates (unattended-upgrades) — controls /etc/apt/apt.conf.d/*
# ---------------------------------------------------------------------------
# Two files we care about:
#   /etc/apt/apt.conf.d/20auto-upgrades        — enables periodic + unattended
#   /etc/apt/apt.conf.d/51gatecrash-auto-upgrade — our reboot/time overrides
# Both are written/edited by the web UI. The toggle drives whether
# unattended-upgrades runs at all; auto-reboot defaults off (a kernel update
# would otherwise drop the user's session unannounced).

OS_UPDATE_SETTINGS_FILE = "/opt/gatecrash/os_update_settings.json"
APT_AUTO_UP_FILE = "/etc/apt/apt.conf.d/20auto-upgrades"
APT_GC_UP_FILE   = "/etc/apt/apt.conf.d/51gatecrash-auto-upgrade"
UNATTENDED_LOG   = "/var/log/unattended-upgrades/unattended-upgrades.log"

_DEFAULT_OS_UPDATE_SETTINGS = {
    "auto_install":  True,    # apply security updates automatically
    "auto_reboot":   False,   # reboot if a package needs it
    "reboot_time":   "03:00", # local time, HH:MM
}

# Tight regex — only valid 24h HH:MM, no shell metachars (these values land
# inside an apt config string and a systemctl invocation if reboots happen).
_TIME_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def load_os_update_settings():
    try:
        with open(OS_UPDATE_SETTINGS_FILE) as f:
            return {**_DEFAULT_OS_UPDATE_SETTINGS, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(_DEFAULT_OS_UPDATE_SETTINGS)


def save_os_update_settings(settings):
    with open(OS_UPDATE_SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


def _apply_os_update_config(settings):
    """Write apt config files to match the user's chosen settings.
    Idempotent — safe to call repeatedly."""
    auto = "1" if settings.get("auto_install") else "0"
    auto_up_body = (
        f'APT::Periodic::Update-Package-Lists "1";\n'
        f'APT::Periodic::Unattended-Upgrade "{auto}";\n'
    )
    try:
        with open(APT_AUTO_UP_FILE, "w") as f:
            f.write(auto_up_body)
    except OSError as e:
        audit_log.error("OS-UPDATE  Failed to write %s: %s", APT_AUTO_UP_FILE, e)

    reboot   = "true" if settings.get("auto_reboot") else "false"
    rt = settings.get("reboot_time", "03:00")
    if not _TIME_HHMM_RE.match(rt):
        rt = "03:00"
    gc_body = (
        '// Managed by Gatecrash web UI — edit via Config -> Updates.\n'
        f'Unattended-Upgrade::Automatic-Reboot "{reboot}";\n'
        f'Unattended-Upgrade::Automatic-Reboot-Time "{rt}";\n'
    )
    try:
        with open(APT_GC_UP_FILE, "w") as f:
            f.write(gc_body)
    except OSError as e:
        audit_log.error("OS-UPDATE  Failed to write %s: %s", APT_GC_UP_FILE, e)


# ---------------------------------------------------------------------------
# System stats sampler config — interval is the only thing the user can tune
# ---------------------------------------------------------------------------

STATS_SETTINGS_FILE = "/opt/gatecrash/stats_settings.json"
_DEFAULT_STATS_SETTINGS = {"sample_interval": 2}


def load_stats_settings():
    try:
        with open(STATS_SETTINGS_FILE) as f:
            return {**_DEFAULT_STATS_SETTINGS, **json.load(f)}
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(_DEFAULT_STATS_SETTINGS)


def save_stats_settings(settings):
    with open(STATS_SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


def ensure_stats_sampler():
    """Start the background sampler. Reads LAN interface from gatecrash.conf
    so net throughput is measured on the right NIC."""
    s = load_stats_settings()
    lan_if = read_conf().get("LAN_IF", "eth0") or "eth0"
    sysstats.ensure_started(lan_if=lan_if, sample_interval=s.get("sample_interval", 2))


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
    out, rc = run_argv(["iptables", "-L", "FORWARD", "-n", "-v", "-x"])
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
                        old_targets = read_conf().get("TARGET_IPS", "").split()
                        new_targets = sync_targets_from_devices()
                        ok, out = _hot_reload_targets(old_targets, new_targets)
                        if ok:
                            _record_service_state("gatecrash", True)
                            audit_log.info("AUTO-STOP  Hot-reloaded: %s", out)
                        else:
                            audit_log.error("AUTO-STOP  Hot reload failed, restarting: %s", out)
                            out, rc = run_argv(["systemctl", "restart", "gatecrash"], timeout=30, merge_stderr=True)
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
    out, _ = run_argv(["ip", "neigh", "show", ip])
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
    arp_out, _ = run_argv(["ip", "neigh", "show"])
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
    no_auth = _no_auth_enabled()
    setup_required = not no_auth and _get_stored_token() is None
    # First boot only: until the user has explicitly picked HTTPS or HTTP,
    # show the welcome / TLS-choice screen instead of jumping straight to
    # the password form.  (MED-17)
    tls_choice_required = setup_required and not os.path.isfile(HTTPS_PREF_PATH)
    login_required = not no_auth and not setup_required and not session.get("authenticated")
    if not setup_required and not login_required:
        ensure_dns_thread()
        ensure_ip_watch()
        ensure_update_check_thread()
        ensure_traffic_watch()
    csrf = _ensure_csrf_token() if not setup_required and not login_required else ""
    # SECURITY: hide version from unauthenticated viewers so a drive-by visitor
    # can't fingerprint the build and target known vulnerabilities.  (LOW-1)
    version = get_version() if not setup_required and not login_required else ""
    show_welcome = (
        not setup_required and not login_required
        and os.path.isfile(WELCOME_PATH)
    )
    return render_template("index.html", version=version,
                           setup_required=setup_required,
                           tls_choice_required=tls_choice_required,
                           login_required=login_required,
                           show_welcome=show_welcome, csrf_token=csrf)


@app.route("/api/setup-tls", methods=["POST"])
def api_setup_tls():
    """First-boot TLS choice — write HTTPS_PREF before the password is set
    so the credential-bearing /api/setup-auth POST runs over the chosen
    transport.  Only usable in pre-setup state (no token, no no-auth
    marker, no pref yet).  Idempotent: rejects re-submission once the
    pref exists, so a fresh choice requires a factory reset."""
    if _get_stored_token() is not None or _no_auth_enabled():
        return jsonify({"ok": False, "error": "Setup is already complete"}), 403
    if os.path.isfile(HTTPS_PREF_PATH):
        return jsonify({"ok": False, "error": "TLS choice already made"}), 403
    enable = bool((request.json or {}).get("enable"))
    if enable:
        cert = os.path.join(CERT_DIR, "gatecrash.crt")
        key  = os.path.join(CERT_DIR, "gatecrash.key")
        if not (os.path.isfile(cert) and os.path.isfile(key)):
            return jsonify({"ok": False, "error": "TLS certificate is missing — run setup.sh"}), 500
        _set_https_pref(True)
        audit_log.info("AUTH  Initial TLS choice: HTTPS enabled from %s", request.remote_addr)
        _schedule_webui_restart()
        return jsonify({"ok": True, "switch_to_https": True})
    _set_https_pref(False)
    audit_log.warning("AUTH  Initial TLS choice: HTTP (no TLS) from %s — credentials will be sent in cleartext", request.remote_addr)
    return jsonify({"ok": True, "switch_to_https": False})


@app.route("/api/setup-auth", methods=["POST"])
def api_setup_auth():
    """Bootstrap authentication — only usable when no token has been set yet."""
    if _get_stored_token() is not None:
        return jsonify({"ok": False, "error": "Authentication is already configured"}), 403
    password = (request.json or {}).get("password", "")
    if len(password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters"})
    try:
        _store_password_exclusive(password)
    except FileExistsError:
        return jsonify({"ok": False, "error": "Authentication is already configured"}), 403
    try:
        # SECURITY: session.clear() before setting authenticated = True prevents
        # session fixation — an attacker who set a known session ID before setup
        # can't ride the new authentication.  Do NOT remove.  (HIGH-16)
        session.clear()
        session["authenticated"] = True
        session.permanent = True
        audit_log.info("AUTH  Initial password configured from %s", request.remote_addr)
        # HTTPS / HTTP was already chosen at the welcome screen via
        # /api/setup-tls, so we do NOT touch HTTPS_PREF or restart here.
        _mark_welcome_pending()
        return jsonify({"ok": True, "csrf_token": _ensure_csrf_token()})
    except Exception:
        return jsonify({"ok": False, "error": "Internal error"})


@app.route("/api/skip-setup-auth", methods=["POST"])
def api_skip_setup_auth():
    """Opt out of authentication entirely. Only callable during initial setup."""
    if _get_stored_token() is not None or _no_auth_enabled():
        return jsonify({"ok": False, "error": "Setup is already complete"}), 403
    try:
        # O_EXCL guards against concurrent skip + setup-auth requests racing.
        fd = os.open(NO_AUTH_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        audit_log.warning("AUTH  Authentication SKIPPED at initial setup from %s — web UI is now open to anyone on the LAN", request.remote_addr)
        _mark_welcome_pending()
        return jsonify({"ok": True})
    except FileExistsError:
        return jsonify({"ok": False, "error": "Setup is already complete"}), 403
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
        # SECURITY: session.clear() rotates the session ID on login, preventing
        # session fixation attacks.  Do NOT remove or move after the auth set.  (HIGH-16)
        session.clear()
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
    data = request.json or {}
    current  = data.get("current", "")
    new_pw   = data.get("new", "")
    if len(new_pw) < 8:
        return jsonify({"ok": False, "error": "New password must be at least 8 characters"})
    # Two flows:
    #   1. Normal change-password — must match current.
    #   2. Initial set from no-auth mode — no current password to verify; we
    #      just store the new password and clear the no-auth marker so the
    #      next request hits the auth gate.
    if stored is None:
        if not _no_auth_enabled():
            return jsonify({"ok": False, "error": "No password set"}), 400
        try:
            _store_password_exclusive(new_pw)
        except FileExistsError:
            return jsonify({"ok": False, "error": "Authentication is already configured"}), 403
        try:
            os.remove(NO_AUTH_PATH)
        except FileNotFoundError:
            pass
        # Promote this session to authenticated so the user isn't kicked out
        session.clear()
        session["authenticated"] = True
        session.permanent = True
        audit_log.info("AUTH  Initial password set from no-auth mode from %s", request.remote_addr)
        return jsonify({"ok": True, "csrf_token": _ensure_csrf_token()})
    matched, _ = _check_password(current, stored)
    if not matched:
        audit_log.warning("AUTH  Password change FAILED (wrong current password) from %s", request.remote_addr)
        return jsonify({"ok": False, "error": "Current password is incorrect"})
    try:
        _store_password(new_pw)
        audit_log.info("AUTH  Password changed from %s", request.remote_addr)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False, "error": "Internal error"})


@app.route("/api/remove-password", methods=["POST"])
def api_remove_password():
    """Disable authentication: verify the current password, then drop the
    token and create the no-auth marker. Only callable by an authenticated
    session — require_auth() guards the route."""
    stored = _get_stored_token()
    if stored is None:
        return jsonify({"ok": False, "error": "No password set"}), 400
    password = (request.json or {}).get("password", "")
    matched, _ = _check_password(password, stored)
    if not matched:
        audit_log.warning("AUTH  Password REMOVAL denied (wrong password) from %s", request.remote_addr)
        return jsonify({"ok": False, "error": "Incorrect password"})
    try:
        # Create the no-auth marker first; if we removed the token first and
        # the marker write failed, the next request would fall into setup mode.
        fd = os.open(NO_AUTH_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    except FileExistsError:
        pass  # already there; harmless
    try:
        os.remove(WEBUI_TOKEN_PATH)
    except FileNotFoundError:
        pass
    audit_log.warning("AUTH  Password REMOVED from %s — web UI is now open to anyone on the LAN", request.remote_addr)
    return jsonify({"ok": True})


@app.route("/api/welcome-dismiss", methods=["POST"])
def api_welcome_dismiss():
    try:
        os.remove(WELCOME_PATH)
    except FileNotFoundError:
        pass
    return jsonify({"ok": True})


@app.route("/api/set-https", methods=["POST"])
def api_set_https():
    """Enable or disable HTTPS for the next start, then restart the service."""
    enabled = bool((request.json or {}).get("enabled"))
    if enabled:
        cert = os.path.join(CERT_DIR, "gatecrash.crt")
        key  = os.path.join(CERT_DIR, "gatecrash.key")
        if not (os.path.isfile(cert) and os.path.isfile(key)):
            return jsonify({"ok": False, "error": "TLS certificate is missing — run setup.sh"}), 400
    _set_https_pref(enabled)
    audit_log.warning("HTTPS  %s by %s — service will restart", "enabled" if enabled else "DISABLED", request.remote_addr)
    _schedule_webui_restart()
    resp = jsonify({"ok": True, "https_on": enabled})
    if not enabled:
        # Clear any HSTS pin so the browser doesn't keep auto-upgrading
        # http:// → https:// after the service restarts as HTTP.  This
        # response is still served over HTTPS so the directive sticks.
        resp.headers["Strict-Transport-Security"] = "max-age=0"
        # Evict the Secure-flagged session cookie that was set during this
        # HTTPS session.  Chrome's "Leave Secure Cookies Alone" protection
        # blocks a non-Secure cookie from overwriting a Secure one with the
        # same name — without this delete, the user lands on the new HTTP
        # site, the browser refuses every Set-Cookie the HTTP server sends
        # (because the Secure cookie still occupies that slot in the jar),
        # and they're stuck with no session and CSRF rejections on every
        # POST.  We have the authority to delete the Secure cookie here
        # because we're still serving over HTTPS at this moment.  The user
        # will need to log in again on HTTP, which is the correct UX
        # signal anyway: "you are now on a less-secure transport."
        resp.set_cookie(app.config.get("SESSION_COOKIE_NAME", "session"),
                        "", expires=0, path="/", secure=True, httponly=True,
                        samesite="Strict")
    return resp


@app.route("/api/cert-info")
def api_cert_info():
    """Return TLS cert expiry info for the Security UI."""
    exp = _cert_not_after()
    if exp is None:
        return jsonify({"ok": True, "present": False})
    days = _cert_days_remaining()
    return jsonify({
        "ok": True,
        "present": True,
        "not_after": exp.isoformat(),
        "days_remaining": days,
        "validity_days": CERT_VALIDITY_DAYS,
        "renew_threshold_days": CERT_RENEW_THRESHOLD_DAYS,
    })


@app.route("/api/cert-renew", methods=["POST"])
@limiter.limit("5 per minute")
def api_cert_renew():
    """Regenerate the self-signed TLS cert and restart the web UI so it loads."""
    if not _generate_self_signed_cert():
        return jsonify({"ok": False, "error": "openssl failed — check that openssl is installed"}), 500
    audit_log.warning("CERT  TLS certificate renewed by %s — service will restart", request.remote_addr)
    if _https_enabled():
        _schedule_webui_restart()
    return jsonify({"ok": True, "restart": _https_enabled()})


@app.route("/api/factory-reset", methods=["POST"])
@limiter.limit("5 per minute")
def api_factory_reset():
    stored = _get_stored_token()
    if stored is not None:
        password = (request.json or {}).get("password", "")
        matched, _ = _check_password(password, stored)
        if not matched:
            return jsonify({"ok": False, "error": "Incorrect password"})
    # Stop running services before wiping config
    audit_log.warning("SYSTEM  Factory reset initiated from %s", request.remote_addr)
    run_argv(["systemctl", "stop", "gatecrash"], timeout=10)
    run_argv(["wg-quick", "down", "wg0"], timeout=10)
    # Delete all user data and credentials
    for path in [
        CONF_PATH,
        WG_CONF_PATH,
        DEVICES_FILE,
        WEBUI_TOKEN_PATH,
        SECRET_KEY_PATH,
        NO_AUTH_PATH,
        HTTPS_PREF_PATH,
        WELCOME_PATH,
        UPDATE_SETTINGS_FILE,
        AUTO_STOP_SETTINGS_FILE,
        BOOT_STATE_FILE,
    ]:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    session.clear()
    # Defer the reboot by ~1s so Flask gets to flush the response first.
    # The response carries Strict-Transport-Security: max-age=0 (below) to
    # clear the browser's HSTS pin — factory reset wipes HTTPS_PREF so the
    # box will come back on plain HTTP, and without clearing the pin the
    # browser would keep auto-upgrading http://gatecrash.local to https://
    # for up to 24 hours.  Same trick the /api/set-https disable path uses.
    def _do_reboot():
        time.sleep(1.0)
        subprocess.Popen(["systemctl", "reboot"])
    threading.Thread(target=_do_reboot, daemon=True).start()
    resp = jsonify({"ok": True})
    resp.headers["Strict-Transport-Security"] = "max-age=0"
    # Same Secure-cookie eviction as /api/set-https disable: the box is
    # rebooting onto HTTP and a Secure cookie left in the browser would
    # block every non-Secure Set-Cookie the post-reboot HTTP server tries
    # to issue, leaving the user stuck with CSRF failures.
    resp.set_cookie(app.config.get("SESSION_COOKIE_NAME", "session"),
                    "", expires=0, path="/", secure=True, httponly=True,
                    samesite="Strict")
    return resp


@app.route("/api/version")
def api_version():
    return jsonify({"version": get_version(), "boot_id": _boot_id()})


def _boot_id():
    """Return the kernel's boot ID — a UUID that changes on every reboot.
    Used by the post-reboot reconnect to confirm the device actually rebooted
    rather than just briefly hiccupping (which the polling loop would otherwise
    misinterpret as 'back up')."""
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return ""


@app.route("/api/status")
def api_status():
    ensure_dns_thread()  # auto-recover if thread died
    out, _ = run_argv(["systemctl", "is-active", "gatecrash"])
    gc_running = out.strip() == "active"

    _, rc = run_argv(["ip", "link", "show", "wg0"])
    wg_up = rc == 0

    # Was: run("pgrep -c arpspoof 2>/dev/null || echo 0") — the `|| echo 0`
    # fallback masked pgrep's exit-1-when-no-match behaviour. Under shell=False
    # we just take stdout (pgrep -c prints "0" even when no matches) and fall
    # back to "0" if pgrep itself failed to run. (HIGH-14)
    arp_count_out, _ = run_argv(["pgrep", "-c", "arpspoof"])
    arp_out = arp_count_out.strip() or "0"

    # Check if vpntarget has a VPN route (not just the fallback gateway)
    vt_out, _ = run_argv(["ip", "route", "show", "table", "vpntarget"])
    vpn_route_missing = wg_up and gc_running and "dev wg0" not in (vt_out or "")

    # Auto-fix: restore VPN route if WireGuard is up but route is missing
    if vpn_route_missing:
        conf = read_conf()
        try:
            rt = _valid_table(conf.get("ROUTE_TABLE", "vpntarget"))
            run_argv(["ip", "route", "replace", "default", "dev", "wg0", "table", rt, "metric", "100"])
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
        "no_auth": _no_auth_enabled(),
        "https_on": _TLS_ENABLED,
        "wg_configured": os.path.isfile(WG_CONF_PATH),
    })


@app.route("/api/start", methods=["POST"])
def api_start():
    audit_log.info("SERVICE  Gatecrash START requested from %s", request.remote_addr)
    out, rc = run_argv(["systemctl", "start", "gatecrash"], timeout=30, merge_stderr=True)
    if rc == 0:
        _record_service_state("gatecrash", True)
        audit_log.info("SERVICE  Gatecrash started successfully")
    else:
        audit_log.error("SERVICE  Gatecrash start FAILED: %s", out)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    audit_log.info("SERVICE  Gatecrash STOP requested from %s", request.remote_addr)
    out, rc = run_argv(["systemctl", "stop", "gatecrash"], timeout=30, merge_stderr=True)
    if rc == 0:
        _record_service_state("gatecrash", False)
        audit_log.info("SERVICE  Gatecrash stopped successfully")
    else:
        audit_log.error("SERVICE  Gatecrash stop FAILED: %s", out)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/wg/start", methods=["POST"])
def api_wg_start():
    audit_log.info("SERVICE  WireGuard START requested from %s", request.remote_addr)
    if not os.path.isfile(WG_CONF_PATH):
        return jsonify({"ok": False, "error": "no_config",
                        "output": "No WireGuard config — upload one on the Config tab first."})
    out, rc = run_argv(["wg-quick", "up", "wg0"], timeout=20, merge_stderr=True)
    # Restore vpntarget VPN route (wg-quick wipes it on down/up)
    conf = read_conf()
    try:
        rt = _valid_table(conf.get("ROUTE_TABLE", "vpntarget"))
        run_argv(["ip", "route", "replace", "default", "dev", "wg0", "table", rt, "metric", "100"])
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
    out, rc = run_argv(["wg-quick", "down", "wg0"], timeout=20, merge_stderr=True)
    if rc == 0:
        _record_service_state("wg", False)
        audit_log.info("SERVICE  WireGuard stopped successfully")
    else:
        audit_log.error("SERVICE  WireGuard stop FAILED: %s", out)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/autostart", methods=["GET", "POST"])
def api_autostart():
    if request.method == "GET":
        wg_out, _ = run_argv(["systemctl", "is-enabled", "wg-quick@wg0"])
        gc_out, _ = run_argv(["systemctl", "is-enabled", "gatecrash"])
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
            run_argv(["systemctl", "disable", "wg-quick@wg0"], merge_stderr=True)
            run_argv(["systemctl", "disable", "gatecrash"], merge_stderr=True)
            # Snapshot current running state
            wg_out, _ = run_argv(["systemctl", "is-active", "wg-quick@wg0"])
            gc_out, _ = run_argv(["systemctl", "is-active", "gatecrash"])
            state["wg_running"] = wg_out.strip() == "active"
            state["gc_running"] = gc_out.strip() == "active"
        _write_boot_state(state)
        audit_log.info("CONFIG  Boot mode changed to '%s' from %s", new_mode, request.remote_addr)
        results["mode"] = new_mode
    if "wg" in data:
        cmd = "enable" if data["wg"] else "disable"
        _, rc = run_argv(["systemctl", cmd, "wg-quick@wg0"], merge_stderr=True)
        results["wg"] = rc == 0
        audit_log.info("CONFIG  WireGuard autostart %sd from %s", cmd, request.remote_addr)
    if "gatecrash" in data:
        cmd = "enable" if data["gatecrash"] else "disable"
        _, rc = run_argv(["systemctl", cmd, "gatecrash"], merge_stderr=True)
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
        # Was: two separate shell pipelines —
        #   run(f"ip -o -f inet addr show {lan_if} | awk '{{print $4}}' | head -1")    # subnet (CIDR)
        #   run(f"ip -o -f inet addr show {lan_if} | awk '{{print $4}}' | cut -d/ -f1 | head -1")  # own IP
        # Both folded into one _iface_addr() call (JSON parse, shell=False). (HIGH-14)
        addr = _iface_addr(lan_if)
        subnet = addr.get("cidr", "")
        if not subnet:
            yield f"data: ERROR: Could not detect subnet for {lan_if}\n\n"
            yield "event: done\ndata: []\n\n"
            return

        # IPs to exclude from scan results: ourselves and the gateway
        exclude_ips = {addr.get("ip", "")}
        gw = _detect_gateway()
        if gw:
            exclude_ips.add(gw)

        yield f"data: Scanning {subnet} ...\n\n"

        try:
            proc = subprocess.Popen(
                ["nmap", "-sn", "--stats-every", "3s", subnet],
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
            arp_out, _ = run_argv(["ip", "neigh", "show"])
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
        # SECURITY: cap length and reject ASCII control chars only.
        # The frontend renders nicknames via textContent (no HTML parsing),
        # so quotes/apostrophes/ampersands are safe; control chars stay
        # blocked because they could forge fake lines in the audit log.  (MED-5)
        if len(nick) > _NICK_MAX:
            return jsonify({"ok": False, "error": f"Nickname too long (max {_NICK_MAX} chars)"})
        if re.search(r'[\x00-\x1f\x7f]', nick):
            return jsonify({"ok": False, "error": "Nickname contains control characters"})

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
    mac = (request.json or {}).get("mac", "").lower().strip()
    # SECURITY: validate MAC even on delete — without this, a crafted MAC value
    # could exploit downstream processing or log injection.  (LOW-7)
    if not _MAC_RE.match(mac):
        return jsonify({"ok": False, "error": "Invalid MAC address format"}), 400
    devices = [d for d in load_devices() if d["mac"] != mac]
    save_devices(devices)
    audit_log.info("DEVICE  Deleted %s from %s", mac, request.remote_addr)
    return jsonify({"ok": True, "devices": devices})


def _hot_reload_targets(old_ips, new_ips):
    """Incrementally add/remove iptables rules and arpspoof for changed targets.

    Returns (ok, output) — mirrors the shape of a systemctl restart result.
    Only touches rules for IPs that actually changed; unchanged devices keep
    their existing arpspoof processes running uninterrupted.
    """
    conf = read_conf()
    try:
        lan_if = _valid_if(conf.get("LAN_IF", "eth0"))
        vpn_if = _valid_if(conf.get("VPN_IF", "wg0"))
        fwmark = _valid_fwmark(conf.get("FWMARK", "0x1"))
    except ValueError as e:
        return False, f"Invalid config: {e}"

    old_set = set(old_ips)
    new_set = set(new_ips)
    removed = old_set - new_set
    added = new_set - old_set

    lines = []
    DEVNULL = open(os.devnull, "w")

    # Resolve gateway once — needed for both add and remove.
    # Was: an inline `run("ip route show default | awk ... | head -1")` —
    # collapsed to _detect_gateway() so the shell pipeline lives in one place. (HIGH-14)
    gw = conf.get("GATEWAY_IP", "") or _detect_gateway()

    # --- Remove targets that were disabled ---
    for ip in removed:
        try:
            _valid_ip(ip)
        except ValueError:
            continue
        # Kill arpspoof processes for this target (both directions).
        # pkill -f matches against the full command line; with shell=False the
        # pattern is one argv, so the space-separated string still works.
        if gw:
            run_argv(["pkill", "-f", f"arpspoof -i {lan_if} -t {ip} {gw}"], timeout=5)
            run_argv(["pkill", "-f", f"arpspoof -i {lan_if} -t {gw} {ip}"], timeout=5)

        # Remove per-target iptables rules (ignore errors if already gone)
        run_argv(["iptables", "-t", "mangle", "-D", "PREROUTING", "-s", ip, "-i", lan_if, "-j", "MARK", "--set-mark", fwmark])
        run_argv(["iptables", "-D", "FORWARD", "-i", lan_if, "-s", ip, "-j", "ACCEPT"])
        run_argv(["iptables", "-D", "FORWARD", "-d", ip, "-o", lan_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        run_argv(["iptables", "-D", "FORWARD", "-i", vpn_if, "-o", lan_if, "-d", ip, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        run_argv(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53"])
        run_argv(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53"])

        # Flush conntrack for this target
        run_argv(["conntrack", "-D", "-s", ip])
        run_argv(["conntrack", "-D", "-d", ip])
        lines.append(f"Removed target: {ip}")

    # --- Add targets that were enabled ---
    for ip in added:
        try:
            _valid_ip(ip)
        except ValueError:
            continue

        # Per-target iptables rules (same as start.sh)
        run_argv(["iptables", "-t", "mangle", "-A", "PREROUTING", "-s", ip, "-i", lan_if, "-j", "MARK", "--set-mark", fwmark])
        run_argv(["iptables", "-A", "FORWARD", "-i", lan_if, "-s", ip, "-j", "ACCEPT"])
        run_argv(["iptables", "-A", "FORWARD", "-d", ip, "-o", lan_if, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        run_argv(["iptables", "-A", "FORWARD", "-i", vpn_if, "-o", lan_if, "-d", ip, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        run_argv(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", ip, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53"])
        run_argv(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53"])

        # Flush conntrack so existing connections get re-routed
        run_argv(["conntrack", "-D", "-s", ip])
        run_argv(["conntrack", "-D", "-d", ip])

        # Kill any stale arpspoof for this target before starting
        if gw:
            run_argv(["pkill", "-f", f"arpspoof -i {lan_if} -t {ip} {gw}"], timeout=5)
            run_argv(["pkill", "-f", f"arpspoof -i {lan_if} -t {gw} {ip}"], timeout=5)

            # Launch arpspoof as detached processes (Popen so they don't block)
            subprocess.Popen(
                ["arpspoof", "-i", lan_if, "-t", ip, gw],
                stdout=DEVNULL, stderr=DEVNULL,
            )
            subprocess.Popen(
                ["arpspoof", "-i", lan_if, "-t", gw, ip],
                stdout=DEVNULL, stderr=DEVNULL,
            )
        lines.append(f"Added target: {ip}")

    output = "; ".join(lines) if lines else "No changes"
    return True, output


@app.route("/api/saved-devices/sync", methods=["POST"])
def api_sync_devices():
    """Sync enabled saved devices → TARGET_IPS in config, then restart Gatecrash."""
    # Capture old targets before syncing
    old_conf = read_conf()
    old_ips = old_conf.get("TARGET_IPS", "").split()

    active_ips = sync_targets_from_devices()
    audit_log.info("DEVICE  Synced targets → %s from %s",
                   active_ips or "(none)", request.remote_addr)

    # Check if gatecrash is currently running
    status_out, _ = run_argv(["systemctl", "is-active", "gatecrash"])
    gc_running = status_out.strip() == "active"

    if gc_running and set(old_ips) != set(active_ips):
        # Hot reload — only add/remove what changed
        ok, out = _hot_reload_targets(old_ips, active_ips)
        if ok:
            audit_log.info("SERVICE  Gatecrash hot-reloaded: %s", out)
        else:
            audit_log.error("SERVICE  Hot reload failed (%s), falling back to restart", out)
            out, rc = run_argv(["systemctl", "restart", "gatecrash"], timeout=30, merge_stderr=True)
            ok = rc == 0
            if ok:
                audit_log.info("SERVICE  Gatecrash restarted (hot reload fallback)")
            else:
                audit_log.error("SERVICE  Gatecrash restart FAILED: %s", out)
        _record_service_state("gatecrash", True)
        return jsonify({"ok": ok, "active_ips": active_ips, "output": out})
    elif gc_running:
        # Targets unchanged — nothing to do
        return jsonify({"ok": True, "active_ips": active_ips, "output": "No target changes"})
    else:
        # Gatecrash not running — full restart
        out, rc = run_argv(["systemctl", "restart", "gatecrash"], timeout=30, merge_stderr=True)
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

    def section(title, args):
        # args is an argv list (shell=False). The displayed `$ ...` line joins
        # them with spaces so the dump still reads like a transcript.
        out, _ = run_argv(args, timeout=10, merge_stderr=True)
        # SECURITY: redact WireGuard private keys from diagnostics output — the
        # dump is downloadable as a text file and may be shared for support.  (HIGH-1, HIGH-9)
        redacted = re.sub(r'(?im)^(\s*PrivateKey\s*=\s*).*$', r'\1[redacted]', out or '')
        cmd_display = " ".join(args)
        sections.append(f"{'=' * 70}\n{title}\n{'=' * 70}\n$ {cmd_display}\n\n{redacted or '(empty)'}\n")

    # GATEWAY_IP from config is validated via _valid_ip_or_empty when written,
    # so it's safe to use directly here. Falls back to a literal default.
    gw_for_dig = conf.get("GATEWAY_IP") or "192.168.1.254"
    try:
        _valid_ip(gw_for_dig)
    except ValueError:
        gw_for_dig = "192.168.1.254"

    sections.append(f"Gatecrash Diagnostics Dump\nGenerated: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nVersion: {get_version()}\n")

    section("Gatecrash Config", ["cat", CONF_PATH])
    section("Gatecrash Service Status", ["systemctl", "status", "gatecrash", "--no-pager", "-l"])
    section("Web UI Service Status", ["systemctl", "status", "gatecrash-webui", "--no-pager", "-l"])

    section(f"LAN Interface ({lan_if})", ["ip", "addr", "show", lan_if])
    section("WireGuard Interface", ["ip", "addr", "show", vpn_if])
    section("WireGuard Status", ["wg", "show", vpn_if])
    section("Default Route", ["ip", "route", "show", "default"])
    section(f"vpntarget Routing Table ({rt})", ["ip", "route", "show", "table", rt])
    section("IP Policy Rules", ["ip", "rule", "show"])

    section("iptables — mangle PREROUTING (packet marks)",
            ["iptables", "-t", "mangle", "-L", "PREROUTING", "-n", "-v", "--line-numbers"])
    section("iptables — nat PREROUTING (DNS DNAT)",
            ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"])
    section("iptables — nat POSTROUTING (MASQUERADE)",
            ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"])
    section("iptables — FORWARD",
            ["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"])
    section("iptables — mangle FORWARD (MSS clamp)",
            ["iptables", "-t", "mangle", "-L", "FORWARD", "-n", "-v", "--line-numbers"])

    # pgrep -af replaces shell-pipeline `ps -eo pid,args | grep arpspoof | grep -v grep`
    section("Active arpspoof Processes", ["pgrep", "-af", "arpspoof"])
    section("VPN Exit IP Test", ["curl", "--interface", vpn_if, "-m", "10", "-s", "http://ifconfig.me"])
    section("DNS Resolution via 1.1.1.1", ["dig", "@1.1.1.1", "google.com", "+short"])
    section("DNS Resolution via Gateway", ["dig", f"@{gw_for_dig}", "google.com", "+short"])

    section("IPv6 Addresses", ["ip", "-6", "addr", "show"])
    section("ARP Table", ["ip", "neigh", "show"])
    section("Listening on Port 53", ["ss", "-ulnp", "sport", "=", ":53"])

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
    # Was: run(f"timeout 5 tcpdump -i {lan_if} -n udp dst port 53 2>/dev/null || true", timeout=8)
    # `timeout` (coreutils) kills tcpdump after 5s; we ignore the rc since 124
    # (timeout fired) is the normal path. The remaining filter args ("udp",
    # "dst", "port", "53") are joined by tcpdump into a BPF expression.
    # Keep `timeout` as argv[0] — DON'T regress to Python's run_argv timeout=
    # because that loses tcpdump's already-printed output. (HIGH-14)
    out, _ = run_argv(
        ["timeout", "5", "tcpdump", "-i", lan_if, "-n", "udp", "dst", "port", "53"],
        timeout=8,
    )
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
    mac_out, _ = run_argv(["ip", "link", "show", lan_if])
    mac = ""
    m = re.search(r"link/ether ([0-9a-f:]+)", mac_out)
    if m:
        mac = m.group(1)

    # IP address of the LAN interface
    ip_out, _ = run_argv(["ip", "-4", "addr", "show", lan_if])
    lan_ip = ""
    m = re.search(r"inet (\S+)", ip_out)
    if m:
        lan_ip = m.group(1)

    # Active arpspoof processes — pgrep -af replaces shell-pipeline `ps | grep arpspoof | grep -v grep`
    arps_out, _ = run_argv(["pgrep", "-af", "arpspoof"])
    arps = [line.strip() for line in arps_out.splitlines() if line.strip()] if arps_out else []

    # iptables mangle PREROUTING rules
    ipt_out, _ = run_argv(["iptables", "-t", "mangle", "-L", "PREROUTING", "-n", "--line-numbers"])

    # IP policy rules
    iprules_out, _ = run_argv(["ip", "rule", "show"])

    # vpntarget routing table
    vt_out, _ = run_argv(["ip", "route", "show", "table", "vpntarget"])

    # WireGuard interface
    wg_out, wg_rc = run_argv(["ip", "link", "show", "wg0"])
    wg_if = wg_out.strip() if wg_rc == 0 else "wg0 not found"

    # Hostname
    hostname_out, _ = run_argv(["hostname"])

    return jsonify({
        "lan_if": lan_if,
        "lan_mac": mac,
        "lan_ip": lan_ip,
        "lan_ip6": _iface_addr6(lan_if),
        "hostname": hostname_out.strip(),
        "gateway": _detect_gateway(),
        "arpspoof_procs": arps,
        "iptables_mangle": ipt_out.strip(),
        "ip_rules": iprules_out.strip(),
        "vpntarget_routes": vt_out.strip() or "(empty — WireGuard may be down)",
        "wg_if": wg_if,
    })


def _require_password_confirmation():
    """Verify the current session's password against the POSTed `password` field.

    Returns None on success, or a (response, status) tuple on failure.
    Used to gate destructive operations (reboot/shutdown) against CSRF-chained
    session hijacks — even with a valid session, the caller must re-prove the
    password.

    In no-auth mode there is no password to check (the user opted out of auth
    entirely at setup), so the gate becomes a simple click-to-confirm in the UI.
    """
    if _no_auth_enabled():
        return None
    stored = _get_stored_token()
    if stored is None:
        return jsonify({"ok": False, "error": "No password set"}), 400
    password = (request.json or {}).get("password", "")
    matched, _ = _check_password(password, stored)
    if not matched:
        audit_log.warning("AUTH  Destructive op denied (bad password) from %s", request.remote_addr)
        return jsonify({"ok": False, "error": "Incorrect password"}), 403
    return None


@app.route("/api/reboot", methods=["POST"])
@limiter.limit("5 per minute")
def api_reboot():
    failure = _require_password_confirmation()
    if failure is not None:
        return failure
    audit_log.warning("SYSTEM  Reboot requested from %s", request.remote_addr)
    subprocess.Popen(["shutdown", "-r", "now"])
    return jsonify({"ok": True})


@app.route("/api/shutdown", methods=["POST"])
@limiter.limit("5 per minute")
def api_shutdown():
    failure = _require_password_confirmation()
    if failure is not None:
        return failure
    audit_log.warning("SYSTEM  Shutdown requested from %s", request.remote_addr)
    subprocess.Popen(["shutdown", "-h", "now"])
    return jsonify({"ok": True})


@app.route("/api/test-vpn")
def api_test_vpn():
    ip, rc = run_argv(["curl", "--interface", "wg0", "-m", "10", "-s", "http://ifconfig.me"], merge_stderr=True)
    return jsonify({"ok": rc == 0, "ip": ip})


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        conf = read_conf()
        # Surface the live-detected gateway alongside any saved override, so
        # the UI can show "auto-detect: 192.168.1.254" as a hint while keeping
        # the override field as the user actually saved it (blank = auto).
        conf["DETECTED_GATEWAY"] = _detect_gateway()
        return jsonify(conf)
    try:
        data = request.json
        # SECURITY: reject unknown keys — gatecrash.conf is `source`d as bash,
        # so an injected key like FOO="$(rm -rf /)" would execute as root.
        # This allowlist + write_conf() both check independently (defense in depth).  (CRIT-4)
        unknown = set(data.keys()) - _CONF_ALLOWED_KEYS
        if unknown:
            return jsonify({"ok": False, "error": f"Unknown config keys: {', '.join(sorted(unknown))}"}), 400
        # Validate every field with strict allowlists
        errors = []
        _conf_validators = {
            "LAN_IF": _valid_if,
            "VPN_IF": _valid_if,
            "ROUTE_TABLE": _valid_table,
            "GATEWAY_IP": _valid_ip_or_empty,
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
        # Blank GATEWAY_IP is intentional — start.sh will auto-detect on every
        # boot, so the appliance keeps working when moved between networks.
        write_conf(data)
        audit_log.info("CONFIG  Configuration updated from %s: %s", request.remote_addr, data)
        return jsonify({"ok": True})
    except Exception:
        # SECURITY: generic error — do not leak internal paths or stack traces.  (HIGH-8)
        return jsonify({"ok": False, "error": "Internal error"})


@app.route("/api/wg-config", methods=["GET", "POST"])
def api_wg_config():
    if request.method == "GET":
        try:
            with open(WG_CONF_PATH) as f:
                content = f.read()
            # SECURITY: never send the WireGuard private key to the browser.
            # The key stays on disk; the UI shows [redacted] and sends it back
            # unchanged on save (restored from disk below).  (HIGH-9)
            content = re.sub(r'(?im)^(\s*PrivateKey\s*=\s*).*$', r'\1[redacted]', content)
            return jsonify({"ok": True, "content": content})
        except Exception:
            return jsonify({"ok": False, "content": "", "error": "Internal error"})
    try:
        # SECURITY: strip PostUp/PostDown hooks — they execute as root via wg-quick.  (HIGH-6)
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
        # SECURITY: 0o600 — WireGuard config contains the VPN private key.
        os.chmod(WG_CONF_PATH, 0o600)
        audit_log.info("CONFIG  WireGuard config updated from %s", request.remote_addr)
        # Mark WG as wanted on boot — see /api/wg-config/upload for rationale.
        _record_service_state("wg", True)
        return jsonify({"ok": True})
    except Exception:
        # SECURITY: generic error — do not leak internal paths or stack traces.  (HIGH-8)
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

    # SECURITY: strip PostUp/PostDown hooks from uploaded configs — they execute
    # as root via wg-quick.  An uploaded .conf from a VPN provider could contain
    # arbitrary shell commands.  (HIGH-6)
    final_content = _strip_wg_hooks("\n".join(new_lines))
    if not final_content.endswith("\n"):
        final_content += "\n"

    try:
        with open(WG_CONF_PATH, "w") as f:
            f.write(final_content)
        # SECURITY: 0o600 — WireGuard config contains the VPN private key.
        os.chmod(WG_CONF_PATH, 0o600)
        audit_log.info("CONFIG  WireGuard config uploaded from %s (fixes: %s)", request.remote_addr, fixes)
        # Saving a WireGuard config implies the user wants WG up. Mark it as
        # "running" in boot state so the resume service brings it up on next
        # reboot — otherwise gatecrash auto-resumes but WG doesn't, leaving
        # the user with routing but no tunnel.
        _record_service_state("wg", True)
        return jsonify({"ok": True, "fixes": fixes})
    except Exception:
        # SECURITY: generic error — do not leak internal paths or stack traces.  (HIGH-8)
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


@app.route("/api/stats")
def api_stats():
    """Return tier of (ts, cpu%, mem%, rx_bps, tx_bps) for the requested range."""
    rng = request.args.get("range", "5m")
    return jsonify(sysstats.query(rng))


@app.route("/api/stats-settings", methods=["GET", "POST"])
def api_stats_settings():
    if request.method == "GET":
        return jsonify(load_stats_settings())
    data = request.json or {}
    settings = load_stats_settings()
    if "sample_interval" in data:
        try:
            iv = int(data["sample_interval"])
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid sample_interval"}), 400
        if not 1 <= iv <= 10:
            return jsonify({"ok": False, "error": "sample_interval must be 1..10"}), 400
        settings["sample_interval"] = iv
    save_stats_settings(settings)
    sysstats.update_settings(sample_interval=settings["sample_interval"])
    return jsonify({"ok": True, **settings})


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


@app.route("/api/os-update-settings", methods=["GET", "POST"])
def api_os_update_settings():
    if request.method == "GET":
        settings = load_os_update_settings()
        # Surface the most recent unattended-upgrades log line so the UI can
        # show "last run" without a separate endpoint.
        last_line = ""
        try:
            with open(UNATTENDED_LOG) as f:
                lines = [l.rstrip() for l in f if l.strip()]
                last_line = lines[-1] if lines else ""
        except (OSError, ValueError):
            pass
        return jsonify({**settings, "last_log_line": last_line})

    data = request.json or {}
    settings = load_os_update_settings()
    if "auto_install" in data:
        settings["auto_install"] = bool(data["auto_install"])
    if "auto_reboot" in data:
        settings["auto_reboot"] = bool(data["auto_reboot"])
    if "reboot_time" in data:
        rt = str(data["reboot_time"])
        if not _TIME_HHMM_RE.match(rt):
            return jsonify({"ok": False, "error": "reboot_time must be HH:MM (24h)"}), 400
        settings["reboot_time"] = rt
    save_os_update_settings(settings)
    _apply_os_update_config(settings)
    audit_log.info("OS-UPDATE  Settings updated from %s: %s", request.remote_addr, settings)
    return jsonify({"ok": True, **settings})


@app.route("/api/os-update-now", methods=["POST"])
@limiter.limit("2 per minute")
def api_os_update_now():
    """Manually trigger an unattended-upgrades run. Returns immediately;
    progress is visible in the unattended-upgrades log."""
    audit_log.info("OS-UPDATE  Manual run triggered from %s", request.remote_addr)
    # No user input goes into this command — argv list, not shell.
    subprocess.Popen(["unattended-upgrade", "-d"],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     start_new_session=True)
    return jsonify({"ok": True})


@app.route("/api/os-update-log")
def api_os_update_log():
    """Return the last N lines of the unattended-upgrades log."""
    try:
        n = min(int(request.args.get("lines", 50)), 500)
    except (ValueError, TypeError):
        n = 50
    try:
        with open(UNATTENDED_LOG) as f:
            lines = [l.rstrip() for l in f if l.strip()]
        return jsonify({"ok": True, "lines": lines[-n:]})
    except FileNotFoundError:
        return jsonify({"ok": True, "lines": [], "note": "No log yet — unattended-upgrades has not run."})
    except OSError:
        return jsonify({"ok": False, "error": "Internal error"}), 500


@app.route("/api/branch", methods=["GET"])
def api_branch_get():
    """Return the current git branch and the list of available remote branches."""
    repo = get_repo_path()
    if not repo:
        return jsonify({"ok": False, "error": "Repo path not set"})
    try:
        repo = _valid_repo(repo)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid repo path"})
    git_base = ["git", "-c", f"safe.directory={repo}", "-C", repo]
    cur_out, cur_rc = run_argv(git_base + ["rev-parse", "--abbrev-ref", "HEAD"], merge_stderr=True)
    if cur_rc != 0:
        return jsonify({"ok": False, "error": "Could not read current branch"})
    current = cur_out.strip()
    # Refresh remote refs so the list is current — quiet on failure (offline OK)
    run_argv(git_base + ["fetch", "origin", "--prune"], merge_stderr=True)
    branches_out, _ = run_argv(git_base + ["branch", "-r", "--format=%(refname:short)"], merge_stderr=True)
    branches = []
    for line in (branches_out or "").splitlines():
        ref = line.strip().strip("'")
        if not ref or "->" in ref:           # skip "origin/HEAD -> origin/master"
            continue
        if ref.startswith("origin/"):
            ref = ref[len("origin/"):]
        # Skip the symbolic HEAD pointer — not a real branch
        if ref in ("HEAD", "origin"):
            continue
        branches.append(ref)
    branches = sorted(set(branches))
    return jsonify({"ok": True, "current": current, "branches": branches})


@app.route("/api/branch", methods=["POST"])
@limiter.limit("3 per minute")
def api_branch_set():
    """Switch the working tree to a different branch, then trigger setup.sh
    to redeploy. Used during dev to point a device at a feature branch
    without breaking other users on master."""
    repo = get_repo_path()
    if not repo:
        return jsonify({"ok": False, "error": "Repo path not set"}), 400
    try:
        repo = _valid_repo(repo)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid repo path"}), 400
    branch = (request.json or {}).get("branch", "")
    try:
        branch = _valid_branch(branch)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    q_repo = shlex.quote(repo)
    q_branch = shlex.quote(branch)
    q_origin = shlex.quote("origin/" + branch)
    audit_log.warning("UPGRADE  Branch switch to '%s' requested from %s", branch, request.remote_addr)
    # Generate the same kind of background script as _trigger_upgrade so the
    # Flask process can return its response before the service restarts.
    script = f"""#!/bin/bash
trap 'rm -f -- "$0"' EXIT
> /var/log/gatecrash-upgrade.log
echo "=== Switching to branch {branch} ===" >> /var/log/gatecrash-upgrade.log
sleep 1
cd {q_repo}
git -c safe.directory={q_repo} fetch origin >> /var/log/gatecrash-upgrade.log 2>&1
git -c safe.directory={q_repo} checkout -B {q_branch} {q_origin} >> /var/log/gatecrash-upgrade.log 2>&1
git -c safe.directory={q_repo} pull >> /var/log/gatecrash-upgrade.log 2>&1
bash setup.sh >> /var/log/gatecrash-upgrade.log 2>&1
echo "=== Branch switch complete ===" >> /var/log/gatecrash-upgrade.log
"""
    fd, path = tempfile.mkstemp(suffix=".sh", prefix="gatecrash-branch-")
    with os.fdopen(fd, "w") as f:
        f.write(script)
    os.chmod(path, 0o700)
    subprocess.Popen(["bash", path],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     start_new_session=True)
    return jsonify({"ok": True, "branch": branch})


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
    """Tiny HTTP server on port 80 that redirects everything to HTTPS.

    Uses 307 Temporary Redirect (not 301 Moved Permanently): the user can
    toggle HTTPS off, so this redirect is NOT permanent.  301s get cached
    on disk by Chrome/Firefox essentially forever, which traps the user
    on https:// even after they've disabled HTTPS server-side.  307s are
    not disk-cached.  Cache-Control: no-store is belt-and-braces."""
    from flask import Flask as _Flask
    redir = _Flask("redirect")

    @redir.route("/", defaults={"path": ""})
    @redir.route("/<path:path>")
    def _redir(path):
        target = request.url.replace("http://", "https://", 1).replace(":80", "")
        resp = redirect(target, code=307)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    redir.run(host="0.0.0.0", port=80, debug=False)


if __name__ == "__main__":
    ensure_dns_thread()
    ensure_ip_watch()
    ensure_traffic_watch()
    ensure_stats_sampler()
    # Re-apply OS-update apt config from saved settings on every boot — keeps
    # the apt files in sync if they get removed by an OS upgrade or wiped.
    try:
        _apply_os_update_config(load_os_update_settings())
    except Exception as e:
        audit_log.error("OS-UPDATE  Failed to apply config at startup: %s", e)

    cert = _cert_path()
    key  = _cert_key_path()

    # Auto-renew if cert is close to expiry, OR if it was issued by a pre-0.67
    # setup.sh with a 10-year validity (Apple platforms reject self-signed certs
    # with a validity span > 825 days, so old installs need a one-shot re-issue).
    if os.path.isfile(cert) and os.path.isfile(key):
        total = _cert_total_validity_days()
        days  = _cert_days_remaining()
        if total is not None and total > CERT_VALIDITY_DAYS:
            audit_log.warning("CERT  Existing cert validity is %d days (> %d) — re-issuing for browser compatibility", total, CERT_VALIDITY_DAYS)
            _generate_self_signed_cert()
        elif days is not None and days < CERT_RENEW_THRESHOLD_DAYS:
            audit_log.warning("CERT  TLS cert has %d days left — auto-renewing", days)
            _generate_self_signed_cert()

    if _https_enabled() and os.path.isfile(cert) and os.path.isfile(key):
        # Start HTTP→HTTPS redirect in background
        threading.Thread(target=_http_redirect_server, daemon=True).start()
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        app.run(host="0.0.0.0", port=443, debug=False, ssl_context=ctx)
    else:
        # HTTP mode — the user explicitly disabled HTTPS, or the cert is
        # missing (e.g. setup.sh hasn't completed).  Fresh installs with a
        # cert default to HTTPS — see _https_enabled().
        app.run(host="0.0.0.0", port=80, debug=False)
