"""Unit tests for webui/tls.py — the pure bits.

Only _parse_openssl_date is pure (the rest shell out to openssl). It turns an
`openssl x509 -enddate` line into an aware UTC datetime, so the tests feed real
openssl output shapes and a couple of malformed ones.

Run from the repo root with:  pytest
"""

from datetime import datetime, timezone

import tls


def test_parse_openssl_date_valid():
    dt = tls._parse_openssl_date("notAfter=Mar 14 12:00:00 2027 GMT")
    assert dt == datetime(2027, 3, 14, 12, 0, 0, tzinfo=timezone.utc)


def test_parse_openssl_date_is_utc_aware():
    dt = tls._parse_openssl_date("notBefore=Jan  1 00:00:00 2024 GMT")
    assert dt is not None
    assert dt.tzinfo == timezone.utc


def test_parse_openssl_date_no_equals_returns_none():
    assert tls._parse_openssl_date("garbage with no equals") is None


def test_parse_openssl_date_bad_format_returns_none():
    assert tls._parse_openssl_date("notAfter=not-a-real-date") is None
