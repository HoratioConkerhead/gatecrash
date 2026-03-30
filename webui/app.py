#!/usr/bin/env python3
"""Gatecrash web UI — runs on port 8080, must run as root."""

import os
import re
import json
import threading
import subprocess
from collections import deque
from flask import Flask, render_template, jsonify, request, Response, stream_with_context

app = Flask(__name__)

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

DEVICES_FILE = "/opt/gatecrash/devices.json"


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
    return conf


def write_conf(data):
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
    lan_if = conf.get("LAN_IF", "eth0")
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
            if m:
                dns_log.appendleft({
                    "time":  m.group(1),
                    "src":   m.group(2),
                    "query": m.group(3).strip(),
                })
    except Exception:
        pass
    finally:
        # Allow thread to be restarted if it dies
        dns_thread_started = False


def ensure_dns_thread():
    global dns_thread_started
    if not dns_thread_started:
        dns_thread_started = True
        t = threading.Thread(target=capture_dns, daemon=True)
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
    ensure_dns_thread()
    return render_template("index.html", version=get_version())


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
        rt = conf.get("ROUTE_TABLE", "vpntarget")
        run(f"ip route replace default dev wg0 table {rt} metric 100")
        vpn_route_missing = False  # fixed

    return jsonify({
        "gatecrash_running": gc_running,
        "wg_up": wg_up,
        "arp_processes": arp_out.strip(),
        "wg": wg_stats(),
    })


@app.route("/api/start", methods=["POST"])
def api_start():
    out, rc = run("systemctl start gatecrash 2>&1", timeout=30)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    out, rc = run("systemctl stop gatecrash 2>&1", timeout=30)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/wg/start", methods=["POST"])
def api_wg_start():
    out, rc = run("wg-quick up wg0 2>&1", timeout=20)
    # Restore vpntarget VPN route (wg-quick wipes it on down/up)
    conf = read_conf()
    rt = conf.get("ROUTE_TABLE", "vpntarget")
    run(f"ip route replace default dev wg0 table {rt} metric 100")
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/wg/stop", methods=["POST"])
def api_wg_stop():
    out, rc = run("wg-quick down wg0 2>&1", timeout=20)
    return jsonify({"ok": rc == 0, "output": out})


@app.route("/api/autostart", methods=["GET", "POST"])
def api_autostart():
    if request.method == "GET":
        wg_out, _ = run("systemctl is-enabled wg-quick@wg0 2>/dev/null")
        gc_out, _ = run("systemctl is-enabled gatecrash 2>/dev/null")
        return jsonify({
            "wg": wg_out.strip() == "enabled",
            "gatecrash": gc_out.strip() == "enabled",
        })
    data = request.json
    results = {}
    if "wg" in data:
        cmd = "enable" if data["wg"] else "disable"
        _, rc = run(f"systemctl {cmd} wg-quick@wg0 2>&1")
        results["wg"] = rc == 0
    if "gatecrash" in data:
        cmd = "enable" if data["gatecrash"] else "disable"
        _, rc = run(f"systemctl {cmd} gatecrash 2>&1")
        results["gatecrash"] = rc == 0
    return jsonify({"ok": True, "results": results})


@app.route("/api/upgrading")
def api_upgrading():
    return jsonify({"upgrading": os.path.exists("/tmp/gatecrash-upgrading")})


@app.route("/api/upgrade-log")
def api_upgrade_log():
    """SSE stream of the upgrade log file."""
    def generate():
        log_path = "/var/log/gatecrash-upgrade.log"
        # Wait for the log file to appear
        for _ in range(20):
            if os.path.exists(log_path):
                break
            import time; time.sleep(0.5)

        try:
            with open(log_path) as f:
                while True:
                    line = f.readline()
                    if line:
                        yield f"data: {line.rstrip()}\n\n"
                    elif not os.path.exists("/tmp/gatecrash-upgrading"):
                        yield "data: \n\n"
                        yield "event: done\ndata: done\n\n"
                        break
                    else:
                        import time; time.sleep(0.3)
        except Exception as e:
            yield f"data: Error reading log: {e}\n\n"

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
    conf = read_conf()
    lan_if = conf.get("LAN_IF", "eth0")

    def generate():
        subnet, rc = run(f"ip -o -f inet addr show {lan_if} | awk '{{print $4}}' | head -1")
        if rc != 0 or not subnet.strip():
            yield f"data: ERROR: Could not detect subnet for {lan_if}\n\n"
            yield "event: done\ndata: []\n\n"
            return

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
    else:
        devices.append({
            "mac": mac,
            "nickname": data.get("nickname", ""),
            "ip": data.get("ip", ""),
            "hostname": data.get("hostname", ""),
            "enabled": data.get("enabled", True),
        })

    save_devices(devices)
    return jsonify({"ok": True, "devices": devices})


@app.route("/api/saved-devices/delete", methods=["POST"])
def api_delete_device():
    """Remove a saved device by MAC."""
    mac = request.json.get("mac", "").lower().strip()
    devices = [d for d in load_devices() if d["mac"] != mac]
    save_devices(devices)
    return jsonify({"ok": True, "devices": devices})


@app.route("/api/saved-devices/sync", methods=["POST"])
def api_sync_devices():
    """Sync enabled saved devices → TARGET_IPS in config, then restart Gatecrash."""
    active_ips = sync_targets_from_devices()
    # Restart Gatecrash to apply new targets
    out, rc = run("systemctl restart gatecrash 2>&1", timeout=30)
    return jsonify({"ok": rc == 0, "active_ips": active_ips, "output": out})


@app.route("/api/gateway")
def api_gateway():
    gw, rc = run("ip route show default | awk '/default/ {print $3}' | head -1")
    return jsonify({"ok": rc == 0, "gateway": gw.strip()})


@app.route("/api/diagnostics/dump")
def api_diagnostics_dump():
    """Generate a full troubleshooting dump as a downloadable text file."""
    conf = read_conf()
    lan_if = conf.get("LAN_IF", "eth0")
    vpn_if = conf.get("VPN_IF", "wg0")
    rt = conf.get("ROUTE_TABLE", "vpntarget")

    sections = []

    def section(title, cmd):
        out, _ = run(cmd, timeout=10)
        sections.append(f"{'=' * 70}\n{title}\n{'=' * 70}\n$ {cmd}\n\n{out or '(empty)'}\n")

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
    lan_if = conf.get("LAN_IF", "eth0")
    # 'timeout 5' kills tcpdump after 5s; '|| true' so non-zero exit doesn't raise
    out, _ = run(f"timeout 5 tcpdump -i {lan_if} -n udp dst port 53 2>/dev/null || true", timeout=8)
    lines = [l for l in out.splitlines() if l.strip()]
    return jsonify({"ok": True, "interface": lan_if, "lines": lines})


@app.route("/api/diagnostics")
def api_diagnostics():
    conf = read_conf()
    lan_if = conf.get("LAN_IF", "eth0")

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

    # Gateway
    gw_out, _ = run("ip route show default | awk '/default/ {print $3}' | head -1")

    return jsonify({
        "lan_if": lan_if,
        "lan_mac": mac,
        "lan_ip": lan_ip,
        "hostname": hostname_out.strip(),
        "gateway": gw_out.strip(),
        "arpspoof_procs": arps,
        "iptables_mangle": ipt_out.strip(),
        "ip_rules": iprules_out.strip(),
        "vpntarget_routes": vt_out.strip() or "(empty — WireGuard may be down)",
        "wg_if": wg_if,
    })


@app.route("/api/reboot", methods=["POST"])
def api_reboot():
    subprocess.Popen(["shutdown", "-r", "now"])
    return jsonify({"ok": True})


@app.route("/api/shutdown", methods=["POST"])
def api_shutdown():
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
        gw, _ = run("ip route show default | awk '/default/ {print $3}' | head -1")
        conf["GATEWAY_IP"] = gw.strip() or conf.get("GATEWAY_IP", "")
        return jsonify(conf)
    try:
        data = request.json
        # Refresh gateway from routing table before saving
        gw, _ = run("ip route show default | awk '/default/ {print $3}' | head -1")
        if gw.strip():
            data["GATEWAY_IP"] = gw.strip()
        write_conf(data)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/wg-config", methods=["GET", "POST"])
def api_wg_config():
    if request.method == "GET":
        try:
            with open(WG_CONF_PATH) as f:
                return jsonify({"ok": True, "content": f.read()})
        except Exception as e:
            return jsonify({"ok": False, "content": "", "error": str(e)})
    try:
        content = request.json.get("content", "")
        with open(WG_CONF_PATH, "w") as f:
            f.write(content)
        os.chmod(WG_CONF_PATH, 0o600)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/wg-config/upload", methods=["POST"])
def api_wg_config_upload():
    """Accept a raw WireGuard config, fix it for Gatecrash, and save."""
    content = request.json.get("content", "")
    if not content.strip():
        return jsonify({"ok": False, "error": "Empty config file"})

    # Validate it looks like a WireGuard config
    if "[Interface]" not in content and "[Peer]" not in content:
        return jsonify({"ok": False, "error": "Not a valid WireGuard config (missing [Interface] or [Peer])"})

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

    final_content = "\n".join(new_lines)
    if not final_content.endswith("\n"):
        final_content += "\n"

    try:
        with open(WG_CONF_PATH, "w") as f:
            f.write(final_content)
        os.chmod(WG_CONF_PATH, 0o600)
        return jsonify({"ok": True, "fixes": fixes})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "fixes": []})


@app.route("/api/dns-log")
def api_dns_log():
    return jsonify({"entries": list(dns_log)})


@app.route("/api/update/check")
def api_update_check():
    repo = get_repo_path()
    if not repo:
        return jsonify({"ok": False, "error": "Repo path not set — re-run setup.sh"})
    fetch_out, rc = run(f"git -c safe.directory={repo} -C {repo} fetch origin 2>&1")
    if rc != 0:
        return jsonify({"ok": False, "error": fetch_out})
    behind_out, _ = run(f"git -c safe.directory={repo} -C {repo} rev-list HEAD..@{{upstream}} --count 2>/dev/null")
    try:
        behind = int(behind_out.strip())
    except ValueError:
        behind = 0
    commit_msg, _ = run(f"git -c safe.directory={repo} -C {repo} log @{{upstream}} -1 --pretty=format:%s 2>/dev/null")
    remote_version, _ = run(f"git -c safe.directory={repo} -C {repo} show @{{upstream}}:VERSION 2>/dev/null")
    return jsonify({
        "ok": True,
        "behind": behind,
        "commit_message": commit_msg.strip(),
        "remote_version": remote_version.strip(),
    })


@app.route("/api/upgrade-log-content")
def api_upgrade_log_content():
    try:
        with open("/var/log/gatecrash-upgrade.log") as f:
            return jsonify({"ok": True, "content": f.read()})
    except Exception as e:
        return jsonify({"ok": False, "content": "", "error": str(e)})


@app.route("/api/update/apply", methods=["POST"])
def api_update_apply():
    repo = get_repo_path()
    if not repo:
        return jsonify({"ok": False, "error": "Repo path not set — re-run setup.sh"})
    # Write a small upgrade script and run it detached.
    # setup.sh restarts this service, so we must not wait for it.
    upgrade_script = f"""#!/bin/bash
touch /tmp/gatecrash-upgrading
> /var/log/gatecrash-upgrade.log
sleep 1
cd {repo}
git -c safe.directory={repo} pull >> /var/log/gatecrash-upgrade.log 2>&1
bash setup.sh >> /var/log/gatecrash-upgrade.log 2>&1
echo "=== Upgrade complete ===" >> /var/log/gatecrash-upgrade.log
rm -f /tmp/gatecrash-upgrading
"""
    script_path = "/tmp/gatecrash-upgrade.sh"
    with open(script_path, "w") as f:
        f.write(upgrade_script)
    os.chmod(script_path, 0o700)
    subprocess.Popen(["bash", script_path],
                     stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,
                     start_new_session=True)
    return jsonify({"ok": True})


if __name__ == "__main__":
    ensure_dns_thread()
    app.run(host="0.0.0.0", port=80, debug=False)
