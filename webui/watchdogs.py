#!/usr/bin/env python3
"""Background watchdog threads.

First subsystem: DNS query capture (tcpdump on UDP/53, last 100 queries). Each
watchdog is started lazily by its ensure_*() and re-checked on index()/status so
a thread that dies self-heals. This module owns its own lock + state (it does NOT
use app.py's shared _state_lock) and imports only downward (config / validators /
netutils), so there is no circular dependency with app.py.
"""

import re
import subprocess
import threading
from collections import deque

from config import read_conf
from validators import _valid_if
from netutils import _iface_addr

# Rolling DNS log — last 100 queries. _dns_lock guards the snapshot + the
# thread-started flag (local, so app.py's shared _state_lock isn't needed).
dns_log = deque(maxlen=100)
_dns_lock = threading.Lock()
_dns_thread_started = False


def dns_log_snapshot():
    """Return a consistent copy of the DNS log (for the /api/dns-log route)."""
    with _dns_lock:
        return list(dns_log)


def capture_dns():
    global _dns_thread_started
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
        with _dns_lock:
            _dns_thread_started = False


def ensure_dns_thread():
    global _dns_thread_started
    with _dns_lock:
        if _dns_thread_started:
            return
        _dns_thread_started = True
    t = threading.Thread(target=capture_dns, daemon=True)
    t.start()
