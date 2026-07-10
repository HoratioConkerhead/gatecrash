#!/usr/bin/env python3
"""Per-target firewall plumbing — the single source for the per-target rule set.

_hot_reload_targets incrementally adds/removes the iptables rules, conntrack
flushes and arpspoof processes for targets that changed, without restarting the
daemon. The rule set here MUST stay in sync with start.sh's per-target loop
(CLAUDE.md invariant / review M3). No audit_log / boot-state coupling — the
caller (_apply_target_change in app.py) records service state and logs.
"""

import subprocess

from netutils import run_argv, _detect_gateway
from config import read_conf
from validators import _valid_if, _valid_ip, _valid_fwmark


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
        # Blank DNS_SERVER means "use the default" — mirror start.sh.
        dns_server = _valid_ip(conf.get("DNS_SERVER") or "1.1.1.1")
    except ValueError as e:
        return False, f"Invalid config: {e}"
    dns_dest = f"{dns_server}:53"

    old_set = set(old_ips)
    new_set = set(new_ips)
    removed = old_set - new_set
    added = new_set - old_set

    lines = []

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
        run_argv(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", dns_dest])
        run_argv(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", dns_dest])

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
        run_argv(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", ip, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", dns_dest])
        run_argv(["iptables", "-t", "nat", "-A", "PREROUTING", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", dns_dest])

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
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            subprocess.Popen(
                ["arpspoof", "-i", lan_if, "-t", gw, ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        lines.append(f"Added target: {ip}")

    output = "; ".join(lines) if lines else "No changes"
    return True, output
