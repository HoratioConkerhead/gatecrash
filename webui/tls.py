#!/usr/bin/env python3
"""Self-signed TLS certificate helpers.

The cert lives in CERT_DIR. Apple platforms reject self-signed certs with a
validity span > 825 days, so we cap at that and renew before expiry. Depends
only on os/subprocess/datetime (no Flask, no app globals).
"""

import os
import subprocess
from datetime import datetime, timezone

CERT_DIR = "/opt/gatecrash/certs"
CERT_VALIDITY_DAYS = 825
CERT_RENEW_THRESHOLD_DAYS = 60  # auto-renew when fewer days remain than this


def _cert_path():
    return os.path.join(CERT_DIR, "gatecrash.crt")


def _cert_key_path():
    return os.path.join(CERT_DIR, "gatecrash.key")


def _parse_openssl_date(line):
    """Parse 'notAfter=Mar 14 12:00:00 2027 GMT' → aware UTC datetime, or None."""
    if "=" not in line:
        return None
    try:
        return datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _cert_dates():
    """Return (not_before, not_after) as aware UTC datetimes, or (None, None)."""
    cert = _cert_path()
    if not os.path.isfile(cert):
        return (None, None)
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert, "-noout", "-startdate", "-enddate"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode != 0:
            return (None, None)
        nb = na = None
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("notBefore="):
                nb = _parse_openssl_date(line)
            elif line.startswith("notAfter="):
                na = _parse_openssl_date(line)
        return (nb, na)
    except Exception:
        return (None, None)


def _cert_not_after():
    """Return the cert's expiry as an aware UTC datetime, or None if unreadable."""
    return _cert_dates()[1]


def _cert_total_validity_days():
    """Return the cert's full validity span (notAfter - notBefore) in days, or None."""
    nb, na = _cert_dates()
    if nb is None or na is None:
        return None
    return int((na - nb).total_seconds() // 86400)


def _cert_days_remaining():
    exp = _cert_not_after()
    if exp is None:
        return None
    return int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)


def _generate_self_signed_cert():
    """(Re)generate the self-signed cert. Returns True on success."""
    os.makedirs(CERT_DIR, mode=0o700, exist_ok=True)
    cert = _cert_path()
    key  = _cert_key_path()
    try:
        proc = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert,
             "-days", str(CERT_VALIDITY_DAYS),
             "-subj", "/CN=gatecrash",
             "-addext", "subjectAltName=DNS:gatecrash,DNS:gatecrash.local,IP:127.0.0.1"],
            capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            return False
        os.chmod(key, 0o600)
        os.chmod(cert, 0o644)
        return True
    except Exception:
        return False
