"""Unit tests for webui/config.py — gatecrash.conf read/write.

CONF_PATH is monkeypatched to a tmp file so nothing touches the real config.
write_conf is the security-critical path (the file is sourced as bash), so the
tests confirm it rejects unknown keys and injection-y values.

Run from the repo root with:  pytest
"""

import pytest

import config


def test_write_conf_rejects_unknown_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONF_PATH", str(tmp_path / "gc.conf"))
    with pytest.raises(ValueError):
        config.write_conf({"EVIL": "x"})   # not in _CONF_ALLOWED_KEYS


def test_write_conf_rejects_injection_value(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONF_PATH", str(tmp_path / "gc.conf"))
    with pytest.raises(ValueError):
        config.write_conf({"LAN_IF": "eth0; rm -rf /"})


def test_write_then_read_roundtrips(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONF_PATH", str(tmp_path / "gc.conf"))
    config.write_conf({"LAN_IF": "eth0", "TARGET_IPS": "192.168.1.5"})
    conf = config.read_conf()
    assert conf["LAN_IF"] == "eth0"
    assert conf["TARGET_IPS"] == "192.168.1.5"


def test_read_conf_defaults_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONF_PATH", str(tmp_path / "does-not-exist.conf"))
    conf = config.read_conf()
    # Defaults are present even with no file (LAN_IF may be auto-filled from the
    # host's default route, so only assert the static ones).
    assert conf["VPN_IF"] == "wg0"
    assert conf["ROUTE_TABLE"] == "vpntarget"
    assert conf["FWMARK"] == "0x1"
