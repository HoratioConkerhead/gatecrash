#!/usr/bin/env python3
"""Gatecrash web UI — runs on port 8080, must run as root."""

import os
import re
import threading
import subprocess
from collections import deque
from flask import Flask, render_template, jsonify, request

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
    conf = read_conf()
    lan_if = conf.get("LAN_IF", "eth0")
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", lan_if, "-n", "-l", "-q", "udp port 53"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in proc.stdout:
            # Match: "HH:MM:SS.usec IP src.port > dst.port: proto domain?"
            m = re.search(r"(\d+:\d+:\d+)\.\d+.*?(\d+\.\d+\.\d+\.\d+)\.\d+ > .+? (.+)\?$", line)
            if m:
                dns_log.appendleft({
                    "time": m.group(1),
                    "src":  m.group(2),
                    "query": m.group(3).strip(),
                })
    except Exception:
        pass


def ensure_dns_thread():
    global dns_thread_started
    if not dns_thread_started:
        dns_thread_started = True
        t = threading.Thread(target=capture_dns, daemon=True)
        t.start()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    ensure_dns_thread()
    return render_template("index.html", version=get_version())


@app.route("/api/status")
def api_status():
    out, _ = run("systemctl is-active gatecrash 2>/dev/null")
    gc_running = out.strip() == "active"

    _, rc = run("ip link show wg0 2>/dev/null")
    wg_up = rc == 0

    arp_out, _ = run("pgrep -c arpspoof 2>/dev/null || echo 0")

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


@app.route("/api/gateway")
def api_gateway():
    gw, rc = run("ip route show default | awk '/default/ {print $3}' | head -1")
    return jsonify({"ok": rc == 0, "gateway": gw.strip()})


@app.route("/api/reboot", methods=["POST"])
def api_reboot():
    subprocess.Popen(["shutdown", "-r", "now"])
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
    return jsonify({"ok": True, "behind": behind})


@app.route("/api/update/apply", methods=["POST"])
def api_update_apply():
    repo = get_repo_path()
    if not repo:
        return jsonify({"ok": False, "error": "Repo path not set — re-run setup.sh"})
    # Write a small upgrade script and run it detached.
    # setup.sh restarts this service, so we must not wait for it.
    upgrade_script = f"""#!/bin/bash
sleep 1
cd {repo}
git -c safe.directory={repo} pull
bash setup.sh >> /var/log/gatecrash-upgrade.log 2>&1
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
