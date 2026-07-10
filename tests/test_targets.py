"""Unit tests for webui/targets.py — the per-target firewall reload.

_hot_reload_targets mostly issues iptables/arpspoof commands, so the tests
target the two branches that don't shell out: the config-validation guard
(bad config must issue NO rules) and the no-change fast path. read_conf is
monkeypatched so no real config file or `ip` command is involved.

Run from the repo root with:  pytest
"""

import targets


def test_hot_reload_rejects_invalid_config(monkeypatch):
    # A bad interface name must be refused before any rule is issued — this is
    # the guard that stops a poisoned config from reaching iptables as root.
    monkeypatch.setattr(targets, "read_conf", lambda: {"LAN_IF": "bad if!"})
    ok, msg = targets._hot_reload_targets([], ["192.168.1.5"])
    assert ok is False
    assert "Invalid config" in msg


def test_hot_reload_no_changes_is_noop(monkeypatch):
    # old == new → nothing added or removed → "No changes", and (because the
    # add/remove loops never run) no subprocess is touched. GATEWAY_IP is set so
    # even the gateway lookup doesn't shell out.
    monkeypatch.setattr(targets, "read_conf", lambda: {
        "LAN_IF": "eth0", "VPN_IF": "wg0", "FWMARK": "0x1",
        "DNS_SERVER": "", "GATEWAY_IP": "192.168.1.1",
    })
    ok, out = targets._hot_reload_targets(["192.168.1.5"], ["192.168.1.5"])
    assert ok is True
    assert out == "No changes"
