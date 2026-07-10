"""Unit tests for webui/settings.py — the JsonSettings store.

Uses pytest's tmp_path so nothing touches a real /opt/gatecrash file.

Run from the repo root with:  pytest
"""

import json

from settings import JsonSettings


DEFAULTS = {"enabled": True, "interval": "daily", "count": 5}


def test_load_missing_file_returns_defaults(tmp_path):
    s = JsonSettings(str(tmp_path / "s.json"), DEFAULTS)
    assert s.load() == DEFAULTS
    # Must be a copy — mutating the result must not corrupt the defaults.
    s.load()["enabled"] = False
    assert DEFAULTS["enabled"] is True


def test_load_merges_on_disk_over_defaults(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"interval": "hourly"}))
    s = JsonSettings(str(path), DEFAULTS)
    loaded = s.load()
    assert loaded["interval"] == "hourly"   # on-disk value wins
    assert loaded["enabled"] is True        # missing key filled from defaults
    assert loaded["count"] == 5


def test_load_preserves_extra_on_disk_keys(tmp_path):
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"extra": "kept"}))
    s = JsonSettings(str(path), DEFAULTS)
    assert s.load()["extra"] == "kept"


def test_load_corrupt_json_returns_defaults(tmp_path):
    path = tmp_path / "s.json"
    path.write_text("{ this is not valid json")
    s = JsonSettings(str(path), DEFAULTS)
    assert s.load() == DEFAULTS


def test_save_then_load_roundtrips(tmp_path):
    s = JsonSettings(str(tmp_path / "s.json"), DEFAULTS)
    s.save({"enabled": False, "interval": "weekly", "count": 9})
    assert s.load() == {"enabled": False, "interval": "weekly", "count": 9}


def test_save_is_atomic_no_tmp_left(tmp_path):
    path = tmp_path / "s.json"
    s = JsonSettings(str(path), DEFAULTS)
    s.save({"enabled": True})
    assert path.exists()
    assert not (tmp_path / "s.json.tmp").exists()   # temp file cleaned up by os.replace
    # File is valid JSON (not truncated).
    assert json.loads(path.read_text()) == {"enabled": True}


def test_save_overwrites_existing(tmp_path):
    path = tmp_path / "s.json"
    s = JsonSettings(str(path), DEFAULTS)
    s.save({"count": 1})
    s.save({"count": 2})
    assert s.load()["count"] == 2
