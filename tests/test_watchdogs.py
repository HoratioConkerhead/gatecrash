"""Unit tests for webui/watchdogs.py.

The DNS capture thread itself shells out to tcpdump (not unit-testable), but the
snapshot accessor that backs /api/dns-log is pure and worth pinning: it must
return an independent copy so a caller can't mutate the live deque.

Run from the repo root with:  pytest
"""

import watchdogs


def test_dns_log_snapshot_returns_independent_copy():
    watchdogs.dns_log.clear()
    watchdogs.dns_log.appendleft({"time": "12:00:00", "src": "192.168.1.5", "query": "example.com"})
    snap = watchdogs.dns_log_snapshot()
    assert snap == [{"time": "12:00:00", "src": "192.168.1.5", "query": "example.com"}]
    # Mutating the snapshot must not touch the live log.
    snap.clear()
    assert len(watchdogs.dns_log) == 1
    watchdogs.dns_log.clear()
