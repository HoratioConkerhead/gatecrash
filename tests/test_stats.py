"""Unit tests for webui/stats.py — the tiered ring-buffer downsampling.

The interesting logic is _maybe_downsample(): as 1-second "live" samples age,
a completed bucket's average is promoted up into the coarser "recent" tier.
The subtle rule (which broke once — see the docstring in stats.py) is that a
bucket must NOT be promoted while it's still the *current* bucket; only once a
later sample proves the window is complete. These tests pin that behaviour.

_maybe_downsample() mutates module-level buffers, so the clean_buffers fixture
resets them around every test.

Run from the repo root with:  pytest
"""

import json

import pytest

import stats


@pytest.fixture(autouse=True)
def clean_buffers():
    """Empty every tier buffer before and after each test so they don't leak."""
    for name in stats._buffers:
        stats._buffers[name].clear()
    yield
    for name in stats._buffers:
        stats._buffers[name].clear()


def _sample(ts, cpu=0.0, mem=0.0, rx=0, tx=0, temp=0.0):
    return (ts, cpu, mem, rx, tx, temp)


# ---------------------------------------------------------------------------
# _avg_sample
# ---------------------------------------------------------------------------

def test_avg_sample_empty_is_none():
    assert stats._avg_sample([]) is None


def test_avg_sample_averages_fields_and_keeps_last_ts():
    samples = [
        _sample(100, cpu=10, mem=20, rx=100, tx=200, temp=40),
        _sample(101, cpu=30, mem=40, rx=300, tx=400, temp=50),
    ]
    ts, cpu, mem, rx, tx, temp = stats._avg_sample(samples)
    assert ts == 101              # timestamp is the last sample in the window
    assert cpu == 20              # (10 + 30) / 2
    assert mem == 30
    assert rx == 200
    assert tx == 300
    assert temp == 45


# ---------------------------------------------------------------------------
# _maybe_downsample — live (1s) -> recent (10s)
# ---------------------------------------------------------------------------

def test_downsample_promotes_completed_bucket():
    # Fill the [1000,1010) bucket, then add one sample in the NEXT bucket so the
    # first one counts as complete. cpu is constant so the average is obvious.
    for ts in range(1000, 1010):
        stats._buffers["live"].append(_sample(ts, cpu=50.0))
    stats._buffers["live"].append(_sample(1010, cpu=99.0))  # current bucket

    stats._maybe_downsample()

    recent = list(stats._buffers["recent"])
    assert len(recent) == 1
    ts, cpu = recent[0][0], recent[0][1]
    assert ts == 1010            # snapped to the bucket-end boundary
    assert cpu == 50.0           # average of the completed bucket only (not the 99)


def test_downsample_does_not_promote_current_bucket_early():
    # Only the [1000,1010) bucket has samples and none has landed later, so the
    # bucket is still "current" and must NOT be promoted yet — promoting it would
    # lock in a partial average. This is the regression the docstring describes.
    for ts in range(1000, 1010):
        stats._buffers["live"].append(_sample(ts, cpu=50.0))

    stats._maybe_downsample()

    assert list(stats._buffers["recent"]) == []


def test_downsample_is_idempotent():
    for ts in range(1000, 1010):
        stats._buffers["live"].append(_sample(ts, cpu=50.0))
    stats._buffers["live"].append(_sample(1010, cpu=99.0))

    stats._maybe_downsample()
    stats._maybe_downsample()  # second call must not re-promote the same bucket

    assert len(list(stats._buffers["recent"])) == 1


def test_downsample_empty_live_is_noop():
    stats._maybe_downsample()
    assert all(len(stats._buffers[n]) == 0 for n in stats._buffers)


# ---------------------------------------------------------------------------
# query — range/tier selection
# ---------------------------------------------------------------------------

def test_query_unknown_range_falls_back_to_live():
    result = stats.query("not-a-range")
    assert result["tier"] == "live"
    assert result["range"] == "5m"


def test_query_returns_tier_resolution_and_samples():
    import time
    now = int(time.time())
    stats._buffers["live"].append(_sample(now, cpu=12.0))
    result = stats.query("5m")
    assert result["tier"] == "live"
    assert result["resolution_sec"] == 1
    assert result["samples"] and result["samples"][0][1] == 12.0


def test_query_filters_out_samples_older_than_range():
    import time
    now = int(time.time())
    stats._buffers["live"].append(_sample(now - 10_000, cpu=1.0))  # well outside 5m
    stats._buffers["live"].append(_sample(now, cpu=2.0))
    result = stats.query("5m")
    cpus = [s[1] for s in result["samples"]]
    assert 2.0 in cpus
    assert 1.0 not in cpus


# ---------------------------------------------------------------------------
# _load_from_disk — pre-temperature (5-tuple) migration
# ---------------------------------------------------------------------------

def test_load_pads_pre_temperature_samples(tmp_path, monkeypatch):
    # Old on-disk data has 5-field samples (no temp). Loader must pad a 0.0 temp
    # so the UI hides the temperature chart for those points instead of spiking.
    disk = {
        "live": [
            [100, 10.0, 20.0, 30, 40],        # 5-field: pre-temperature
            [101, 11.0, 21.0, 31, 41, 55.0],  # 6-field: current format
        ],
        "recent": [], "hour": [], "day": [],
    }
    path = tmp_path / "stats.json"
    path.write_text(json.dumps(disk))
    monkeypatch.setattr(stats, "STATS_PATH", str(path))

    stats._load_from_disk()

    live = list(stats._buffers["live"])
    assert live[0] == (100, 10.0, 20.0, 30, 40, 0.0)   # padded with 0.0 temp
    assert live[1] == (101, 11.0, 21.0, 31, 41, 55.0)  # unchanged
