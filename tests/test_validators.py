"""Unit tests for webui/validators.py — the pure config/WireGuard validators.

These functions guard the boundary between a config write and root-level code
execution (gatecrash.conf is sourced as bash; wg0.conf feeds wg-quick), so the
tests deliberately include hostile inputs (shell metacharacters, injection
attempts) alongside the happy path.

Run from the repo root with:  pytest
"""

import pytest

import validators as v


# ---------------------------------------------------------------------------
# _valid_if — Linux interface names (IFNAMSIZ-1 = 15 chars)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["eth0", "wg0", "enp3s0", "br-lan", "eth0.100"])
def test_valid_if_accepts_real_names(name):
    assert v._valid_if(name) == name


@pytest.mark.parametrize("name", [
    "",                       # empty
    "eth 0",                  # space
    "eth0; rm -rf /",         # shell injection
    "a" * 16,                 # too long (>15)
    "eth0\n",                 # newline
    "$(reboot)",              # command substitution
])
def test_valid_if_rejects_bad_names(name):
    with pytest.raises(ValueError):
        v._valid_if(name)


# ---------------------------------------------------------------------------
# _valid_ip / _valid_ip_or_empty
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("addr", ["192.168.1.1", "10.0.0.2", "255.255.255.255", "0.0.0.0"])
def test_valid_ip_accepts_dotted_quads(addr):
    assert v._valid_ip(addr) == addr


@pytest.mark.parametrize("addr", [
    "",
    "192.168.1.256",          # octet > 255
    "192.168.1",              # too few octets
    "192.168.1.1.1",          # too many
    "1.1.1.1; echo hi",       # injection
    "not.an.ip.addr",
    "::1",                    # IPv6 — appliance is IPv4-only
])
def test_valid_ip_rejects_bad(addr):
    with pytest.raises(ValueError):
        v._valid_ip(addr)


def test_valid_ip_or_empty_allows_blank():
    assert v._valid_ip_or_empty("") == ""
    assert v._valid_ip_or_empty("192.168.1.1") == "192.168.1.1"
    with pytest.raises(ValueError):
        v._valid_ip_or_empty("999.0.0.0")


# ---------------------------------------------------------------------------
# _valid_fwmark
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mark", ["0x1", "0xff", "0xDEADBEEF"])
def test_valid_fwmark_accepts_hex(mark):
    assert v._valid_fwmark(mark) == mark


@pytest.mark.parametrize("mark", ["", "1", "0x", "0xGG", "0x1; reboot", "0x123456789"])
def test_valid_fwmark_rejects_bad(mark):
    with pytest.raises(ValueError):
        v._valid_fwmark(mark)


# ---------------------------------------------------------------------------
# _valid_target_ips — space-separated list, blank allowed
# ---------------------------------------------------------------------------

def test_valid_target_ips_accepts_list_and_blank():
    assert v._valid_target_ips("") == ""
    assert v._valid_target_ips("   ") == ""
    assert v._valid_target_ips("192.168.1.5 192.168.1.6") == "192.168.1.5 192.168.1.6"


def test_valid_target_ips_rejects_bad_member():
    with pytest.raises(ValueError):
        v._valid_target_ips("192.168.1.5 999.1.1.1")


# ---------------------------------------------------------------------------
# _valid_branch — git ref names, no shell/git metacharacters
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["master", "dev", "feature/foo-bar", "release_1.2"])
def test_valid_branch_accepts(name):
    assert v._valid_branch(name) == name


@pytest.mark.parametrize("name", [
    "",
    "-rf",                    # leading dash (looks like a flag)
    "foo..bar",               # git range syntax
    "foo.lock",               # git lock suffix
    "foo;reboot",             # shell injection
    "foo bar",                # space
])
def test_valid_branch_rejects(name):
    with pytest.raises(ValueError):
        v._valid_branch(name)


# ---------------------------------------------------------------------------
# _valid_repo — path with no shell metacharacters
# ---------------------------------------------------------------------------

def test_valid_repo_accepts_normal_path():
    assert v._valid_repo("/opt/gatecrash-src") == "/opt/gatecrash-src"


@pytest.mark.parametrize("path", [
    "/opt/x; rm -rf /",
    "/opt/$(reboot)",
    "/opt/`id`",
    "/opt/x\ny",
])
def test_valid_repo_rejects_metachars(path):
    with pytest.raises(ValueError):
        v._valid_repo(path)


# ---------------------------------------------------------------------------
# _normalize_wg_config — parse, whitelist, force invariants, re-emit.
# This pins two CLAUDE.md invariants: Table = off and MTU = 1280.
# ---------------------------------------------------------------------------

KEY_A = "A" * 43 + "="   # a syntactically valid 44-char base64 WG key
KEY_B = "B" * 43 + "="


def _minimal_config(extra_interface="", extra_peer=""):
    return (
        "[Interface]\n"
        f"PrivateKey = {KEY_A}\n"
        "Address = 10.0.0.2/32\n"
        f"{extra_interface}"
        "[Peer]\n"
        f"PublicKey = {KEY_B}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"{extra_peer}"
    )


def test_normalize_forces_table_off_and_mtu():
    canon, _fixes = v._normalize_wg_config(
        _minimal_config(extra_interface="Table = on\nMTU = 1420\n")
    )
    assert "Table = off" in canon
    assert "MTU = 1280" in canon
    assert "Table = on" not in canon
    assert "1420" not in canon


def test_normalize_drops_postup_and_dns():
    canon, fixes = v._normalize_wg_config(
        _minimal_config(extra_interface="PostUp = /bin/evil\nDNS = 8.8.8.8\n")
    )
    assert "PostUp" not in canon
    assert "DNS" not in canon
    # The dropped PostUp is surfaced to the user as a "fix".
    assert any("PostUp" in f for f in fixes)


def test_normalize_requires_interface_and_peer():
    with pytest.raises(ValueError):
        v._normalize_wg_config("[Interface]\nPrivateKey = " + KEY_A + "\nAddress = 10.0.0.2/32\n")
    with pytest.raises(ValueError):
        v._normalize_wg_config("[Peer]\nPublicKey = " + KEY_B + "\nAllowedIPs = 0.0.0.0/0\n")


def test_normalize_rejects_bad_key():
    with pytest.raises(ValueError):
        v._normalize_wg_config(
            "[Interface]\nPrivateKey = not-a-key\nAddress = 10.0.0.2/32\n"
            "[Peer]\nPublicKey = " + KEY_B + "\nAllowedIPs = 0.0.0.0/0\n"
        )


def test_normalize_roundtrip_is_stable():
    # Re-normalising canonical output should be a no-op (idempotent).
    canon1, _ = v._normalize_wg_config(_minimal_config())
    canon2, _ = v._normalize_wg_config(canon1)
    assert canon1 == canon2


# ---------------------------------------------------------------------------
# redact_private_keys / restore_private_keys — the "never leak the key" pair.
# The redacted config must never contain the real key; the browser round-trip
# (GET redacts, user edits, POST sends [redacted] back, we restore) must recover
# the original byte-for-byte.
# ---------------------------------------------------------------------------

WG_WITH_KEY = (
    "[Interface]\n"
    "PrivateKey = " + KEY_A + "\n"
    "Address = 10.0.0.2/32\n"
    "[Peer]\n"
    "PublicKey = " + KEY_B + "\n"
    "AllowedIPs = 0.0.0.0/0\n"
)


def test_redact_replaces_value_keeps_name():
    red = v.redact_private_keys(WG_WITH_KEY)
    assert "PrivateKey = [redacted]" in red
    assert KEY_A not in red                 # the real key must be gone
    assert "PublicKey = " + KEY_B in red    # public key untouched


def test_redact_handles_empty_and_none():
    assert v.redact_private_keys("") == ""
    assert v.redact_private_keys(None) == ""


def test_redact_is_case_and_indent_insensitive():
    # wg-quick tolerates indentation and case; redaction must too.
    text = "  privatekey=" + KEY_A + "\n"
    assert KEY_A not in v.redact_private_keys(text)


def test_restore_recovers_original_roundtrip():
    red = v.redact_private_keys(WG_WITH_KEY)
    restored = v.restore_private_keys(red, WG_WITH_KEY)
    assert restored == WG_WITH_KEY          # byte-for-byte recovery


def test_restore_noop_when_source_has_no_key():
    red = v.redact_private_keys(WG_WITH_KEY)
    # Source with no PrivateKey → nothing to restore, placeholder stays.
    assert v.restore_private_keys(red, "[Peer]\nPublicKey = x\n") == red


def test_restore_noop_when_content_not_redacted():
    # Content already has a real key (no placeholder) → unchanged.
    assert v.restore_private_keys(WG_WITH_KEY, WG_WITH_KEY) == WG_WITH_KEY
