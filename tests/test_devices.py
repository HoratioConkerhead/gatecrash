"""Unit tests for webui/devices.py — persistence + MAC->IP resolution.

DEVICES_FILE is monkeypatched to a tmp file; run_argv is monkeypatched where a
test needs to feed canned `ip neigh` output (no real `ip` command involved).

Run from the repo root with:  pytest
"""

import devices


# ---------------------------------------------------------------------------
# load_devices / save_devices
# ---------------------------------------------------------------------------

def test_load_devices_missing_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(devices, "DEVICES_FILE", str(tmp_path / "d.json"))
    assert devices.load_devices() == []


def test_load_devices_corrupt_returns_empty(tmp_path, monkeypatch):
    p = tmp_path / "d.json"
    p.write_text("{ not valid json")
    monkeypatch.setattr(devices, "DEVICES_FILE", str(p))
    assert devices.load_devices() == []


def test_save_then_load_roundtrips(tmp_path, monkeypatch):
    monkeypatch.setattr(devices, "DEVICES_FILE", str(tmp_path / "d.json"))
    data = [{"mac": "aa:bb:cc:dd:ee:ff", "nickname": "TV", "enabled": True}]
    devices.save_devices(data)
    assert devices.load_devices() == data


# ---------------------------------------------------------------------------
# resolve_mac — rejects non-IPs before touching the ARP table
# ---------------------------------------------------------------------------

def test_resolve_mac_rejects_bad_ip():
    assert devices.resolve_mac("not-an-ip") == ""
    assert devices.resolve_mac("") == ""


# ---------------------------------------------------------------------------
# _neigh_map — freshest-entry-per-MAC ranking
# ---------------------------------------------------------------------------

def test_neigh_map_prefers_freshest_state(monkeypatch):
    # Same MAC appears at two IPs; REACHABLE (rank 4) must beat STALE (rank 2).
    out = (
        "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:05 STALE\n"
        "192.168.1.9 dev eth0 lladdr aa:bb:cc:dd:ee:05 REACHABLE\n"
    )
    monkeypatch.setattr(devices, "run_argv", lambda *a, **k: (out, 0))
    m = devices._neigh_map()
    assert m["aa:bb:cc:dd:ee:05"] == "192.168.1.9"


def test_neigh_map_skips_failed(monkeypatch):
    out = "192.168.1.7 dev eth0 lladdr aa:bb:cc:dd:ee:07 FAILED\n"
    monkeypatch.setattr(devices, "run_argv", lambda *a, **k: (out, 0))
    assert devices._neigh_map() == {}
