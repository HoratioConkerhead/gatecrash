"""System stats sampler — CPU, memory, network throughput, temperature.

In-memory tiered ring buffers (RRD-style) keep multiple resolutions of history
without ballooning memory or hammering the SD card. The whole state flushes to
a single JSON file on a slow cadence and on graceful shutdown.

Tiers:
    live    1s   x 300   = 5 minutes
    recent  10s  x 360   = 1 hour
    hour    1m   x 1440  = 24 hours
    day     5m   x 4032  = 14 days

Each tier holds tuples of (epoch_seconds, cpu_pct, mem_pct, rx_bps, tx_bps, temp_c).
Downsampling: the live tier feeds recent (mean over 10 samples), recent feeds
hour, hour feeds day. Whole-tier averaging keeps things simple and predictable.

temp_c = 0.0 means "no readable thermal sensor" (e.g. Hyper-V VMs); the UI
treats a max of 0 across the visible range as "hide the chart".
"""

import json
import os
import threading
import time
from collections import deque

STATS_PATH = "/opt/gatecrash/stats.json"
FLUSH_INTERVAL_SEC = 300   # 5 min — bounds SD writes to ~288/day

# (resolution_seconds, capacity)
TIERS = [
    ("live",   1,   300),
    ("recent", 10,  360),
    ("hour",   60,  1440),
    ("day",    300, 4032),
]

_DEFAULT_SAMPLE_INTERVAL = 2  # seconds; user-configurable 1..10

_lock = threading.Lock()
_buffers = {name: deque(maxlen=cap) for name, _, cap in TIERS}
_started = False
_thread = None
_settings = {"sample_interval": _DEFAULT_SAMPLE_INTERVAL, "lan_if": "eth0"}
_last_flush = 0.0


# ---------------------------------------------------------------------------
# Sampling primitives — read /proc directly, no subprocess
# ---------------------------------------------------------------------------

_prev_cpu = None   # (idle, total) from last read

def _read_cpu_pct():
    """Return CPU% used since the last call. First call returns 0.0."""
    global _prev_cpu
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        # cpu user nice system idle iowait irq softirq steal guest guest_nice
        nums = [int(x) for x in parts[1:]]
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
        total = sum(nums)
    except (OSError, ValueError, IndexError):
        return 0.0
    if _prev_cpu is None:
        _prev_cpu = (idle, total)
        return 0.0
    d_idle = idle - _prev_cpu[0]
    d_total = total - _prev_cpu[1]
    _prev_cpu = (idle, total)
    if d_total <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (1 - d_idle / d_total)))


def _read_mem_pct():
    """Return memory in use as a % of MemTotal (MemTotal - MemAvailable)."""
    try:
        with open("/proc/meminfo") as f:
            data = f.read()
    except OSError:
        return 0.0
    info = {}
    for line in data.splitlines():
        k, _, v = line.partition(":")
        info[k.strip()] = v.strip().split()
    try:
        total = int(info["MemTotal"][0])
        avail = int(info["MemAvailable"][0])
    except (KeyError, ValueError, IndexError):
        return 0.0
    if total <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * (total - avail) / total))


_prev_net = None  # (rx_bytes, tx_bytes, monotonic_time)

def _read_net_bps(iface):
    """Return (rx_bps, tx_bps) since last call. First call returns (0, 0)."""
    global _prev_net
    try:
        with open("/proc/net/dev") as f:
            data = f.read()
    except OSError:
        return (0, 0)
    rx = tx = None
    for line in data.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        if name.strip() != iface:
            continue
        cols = rest.split()
        # rx_bytes ... tx_bytes is column 8 (0-indexed)
        try:
            rx = int(cols[0])
            tx = int(cols[8])
        except (ValueError, IndexError):
            return (0, 0)
        break
    if rx is None:
        return (0, 0)
    now = time.monotonic()
    if _prev_net is None:
        _prev_net = (rx, tx, now)
        return (0, 0)
    dt = now - _prev_net[2]
    if dt <= 0:
        _prev_net = (rx, tx, now)
        return (0, 0)
    rx_bps = max(0, (rx - _prev_net[0]) * 8 / dt)
    tx_bps = max(0, (tx - _prev_net[1]) * 8 / dt)
    _prev_net = (rx, tx, now)
    return (int(rx_bps), int(tx_bps))


# Cached path for the thermal sensor — set on first successful read so we don't
# stat thermal_zone* every sample. None = unknown, "" = no sensor, "<path>" = use it.
_temp_path = None

def _read_temp_c():
    """Return CPU temperature in degrees C, or 0.0 if no sensor is available.

    Pi/most ARM SBCs expose this at /sys/class/thermal/thermal_zone0/temp in
    millidegrees C. On boards with multiple zones the first readable one wins."""
    global _temp_path
    if _temp_path == "":
        return 0.0
    if _temp_path is None:
        for i in range(8):
            p = f"/sys/class/thermal/thermal_zone{i}/temp"
            try:
                with open(p) as f:
                    int(f.read().strip())
                _temp_path = p
                break
            except (OSError, ValueError):
                continue
        else:
            _temp_path = ""
            return 0.0
    try:
        with open(_temp_path) as f:
            return max(0.0, min(150.0, int(f.read().strip()) / 1000.0))
    except (OSError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# Tiered ring buffer — downsample as samples age into higher tiers
# ---------------------------------------------------------------------------

def _avg_sample(samples):
    """Average a list of (ts, cpu, mem, rx, tx, temp) tuples; ts = last in window."""
    if not samples:
        return None
    n = len(samples)
    return (
        samples[-1][0],
        sum(s[1] for s in samples) / n,
        sum(s[2] for s in samples) / n,
        sum(s[3] for s in samples) / n,
        sum(s[4] for s in samples) / n,
        sum(s[5] for s in samples) / n,
    )


def _maybe_downsample():
    """Walk tiers and, where the lower tier holds enough samples to fill one
    bucket of the higher tier, write that average up. Called inside _lock."""
    for i in range(len(TIERS) - 1):
        lower_name, lower_res, _ = TIERS[i]
        upper_name, upper_res, _ = TIERS[i + 1]
        ratio = upper_res // lower_res
        upper = _buffers[upper_name]
        lower = _buffers[lower_name]
        if not lower:
            continue
        # We promote whenever the most recent lower sample lands on a fresh
        # upper bucket boundary (and we have enough lower samples to cover it).
        last_ts = lower[-1][0]
        bucket = last_ts - (last_ts % upper_res)
        if upper and upper[-1][0] >= bucket:
            continue   # already wrote this bucket
        window = [s for s in lower if bucket <= s[0] < bucket + upper_res]
        if len(window) < ratio:
            continue   # bucket not yet full
        avg = _avg_sample(window)
        if avg is not None:
            # Snap timestamp to bucket boundary for stable x-axis
            upper.append((bucket + upper_res, avg[1], avg[2], avg[3], avg[4], avg[5]))


# ---------------------------------------------------------------------------
# Persistence — flush every N seconds, load on start
# ---------------------------------------------------------------------------

def _flush_to_disk():
    """Atomic write of all tier buffers to disk."""
    snapshot = {}
    with _lock:
        for name in _buffers:
            snapshot[name] = list(_buffers[name])
    tmp = STATS_PATH + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(snapshot, f)
        os.replace(tmp, STATS_PATH)
    except OSError:
        pass   # SD card full / read-only / etc — drop silently rather than crash sampler


def _load_from_disk():
    """Restore tier buffers from disk on startup. Silent on failure."""
    try:
        with open(STATS_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    with _lock:
        for name in _buffers:
            for sample in data.get(name, []):
                if not isinstance(sample, list):
                    continue
                if len(sample) == 6:
                    _buffers[name].append(tuple(sample))
                elif len(sample) == 5:
                    # Pre-temperature data — pad with 0.0 so the UI hides the chart
                    # for those points rather than spiking on first real reading.
                    _buffers[name].append(tuple(sample) + (0.0,))


# ---------------------------------------------------------------------------
# Sampler thread
# ---------------------------------------------------------------------------

def _sampler_loop():
    global _last_flush
    _last_flush = time.monotonic()
    # Prime the deltas — first reading just establishes baselines.
    _read_cpu_pct()
    _read_net_bps(_settings.get("lan_if", "eth0"))
    while True:
        interval = max(1, min(10, int(_settings.get("sample_interval", _DEFAULT_SAMPLE_INTERVAL))))
        time.sleep(interval)
        ts = int(time.time())
        cpu = _read_cpu_pct()
        mem = _read_mem_pct()
        rx, tx = _read_net_bps(_settings.get("lan_if", "eth0"))
        temp = _read_temp_c()
        with _lock:
            _buffers["live"].append((ts, cpu, mem, rx, tx, temp))
            _maybe_downsample()
        if time.monotonic() - _last_flush >= FLUSH_INTERVAL_SEC:
            _flush_to_disk()
            _last_flush = time.monotonic()


def ensure_started(lan_if="eth0", sample_interval=None):
    """Start the sampler thread once. Safe to call repeatedly."""
    global _started, _thread
    _settings["lan_if"] = lan_if or "eth0"
    if sample_interval is not None:
        _settings["sample_interval"] = sample_interval
    if _started:
        return
    _started = True
    _load_from_disk()
    _thread = threading.Thread(target=_sampler_loop, name="stats-sampler", daemon=True)
    _thread.start()


def update_settings(lan_if=None, sample_interval=None):
    """Update the sampler's runtime config. Picked up on the next sleep cycle."""
    if lan_if:
        _settings["lan_if"] = lan_if
    if sample_interval is not None:
        _settings["sample_interval"] = max(1, min(10, int(sample_interval)))


def get_settings():
    return {
        "sample_interval": int(_settings.get("sample_interval", _DEFAULT_SAMPLE_INTERVAL)),
    }


# ---------------------------------------------------------------------------
# Query API — pick the appropriate tier for the requested range
# ---------------------------------------------------------------------------

# Range key -> (seconds, preferred tier name)
RANGES = {
    "5m":  (5 * 60,         "live"),
    "1h":  (60 * 60,        "recent"),
    "6h":  (6 * 60 * 60,    "hour"),
    "12h": (12 * 60 * 60,   "hour"),
    "24h": (24 * 60 * 60,   "hour"),
    "5d":  (5 * 86400,      "day"),
    "2w":  (14 * 86400,     "day"),
    "max": (None,           "day"),
}


def query(range_key):
    """Return {tier, resolution, samples:[[ts,cpu,mem,rx,tx,temp],...]} for the
    requested range. Falls back to 'live' if the range is unknown."""
    if range_key not in RANGES:
        range_key = "5m"
    span_sec, tier_name = RANGES[range_key]
    with _lock:
        buf = list(_buffers[tier_name])
    res = next(r for n, r, _ in TIERS if n == tier_name)
    if span_sec is not None and buf:
        cutoff = int(time.time()) - span_sec
        buf = [s for s in buf if s[0] >= cutoff]
    return {
        "tier": tier_name,
        "resolution_sec": res,
        "range": range_key,
        "samples": buf,
    }


def flush_now():
    """Force a flush — used on graceful shutdown."""
    _flush_to_disk()
