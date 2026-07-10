"""Unit tests for webui/parsing.py — the pure tool-output parsers.

Each test pastes representative real output from `ip neigh`, `nmap -sn`, or
`iptables -L -n -v -x` and asserts the structured result. No device needed.

Run from the repo root with:  pytest
"""

import parsing as p


# ---------------------------------------------------------------------------
# parse_neigh — kernel neighbour table
# ---------------------------------------------------------------------------

def test_parse_neigh_basic_fields():
    out = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE"
    entries = p.parse_neigh(out)
    assert entries == [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "state": "REACHABLE"}]


def test_parse_neigh_state_is_last_token_with_flags():
    # A router/proxy/extern_learn flag can sit between the MAC and the NUD
    # state. The state is the LAST token — this is the case the old scan-stream
    # copy got wrong (it took the first word after the MAC, i.e. "router").
    out = "192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:05 router STALE"
    entries = p.parse_neigh(out)
    assert entries[0]["state"] == "STALE"


def test_parse_neigh_uppercases_state():
    # `ip neigh` emits lowercase MACs (the regex only accepts lowercase, unlike
    # the nmap parser). It can emit the state in lower case though, so we
    # normalise it to upper so callers can compare against "FAILED" etc.
    out = "10.0.0.2 dev eth0 lladdr aa:bb:cc:dd:ee:ff reachable"
    e = p.parse_neigh(out)[0]
    assert e["mac"] == "aa:bb:cc:dd:ee:ff"
    assert e["state"] == "REACHABLE"


def test_parse_neigh_skips_lines_without_lladdr():
    out = (
        "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
        "192.168.1.7 dev eth0  INCOMPLETE\n"          # no lladdr → skipped
        "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE\n"  # v6 ip → no v4 match
    )
    entries = p.parse_neigh(out)
    ips = [e["ip"] for e in entries]
    assert "192.168.1.1" in ips
    assert "192.168.1.7" not in ips


def test_parse_neigh_empty_input():
    assert p.parse_neigh("") == []


# ---------------------------------------------------------------------------
# parse_nmap_devices — nmap -sn output
# ---------------------------------------------------------------------------

NMAP_SAMPLE = """Starting Nmap 7.93
Nmap scan report for router.lan (192.168.1.1)
Host is up (0.0021s latency).
MAC Address: AA:BB:CC:DD:EE:01 (Acme Corp)
Nmap scan report for 192.168.1.20
Host is up.
MAC Address: AA:BB:CC:DD:EE:20 (Contoso)
Nmap scan report for 192.168.1.5
Host is up.
Nmap done: 3 IP addresses scanned
"""


def test_parse_nmap_devices_extracts_and_sorts():
    devs = p.parse_nmap_devices(NMAP_SAMPLE)
    # Sorted numerically by IP: .1, .5, .20 (not lexically, which would give .1, .20, .5)
    assert [d["ip"] for d in devs] == ["192.168.1.1", "192.168.1.5", "192.168.1.20"]


def test_parse_nmap_devices_hostname_and_vendor():
    devs = {d["ip"]: d for d in p.parse_nmap_devices(NMAP_SAMPLE)}
    assert devs["192.168.1.1"]["hostname"] == "router.lan"
    assert devs["192.168.1.1"]["mac"] == "aa:bb:cc:dd:ee:01"
    assert devs["192.168.1.1"]["vendor"] == "Acme Corp"


def test_parse_nmap_devices_host_without_mac():
    # .5 had no MAC Address line — mac stays "", no vendor key required.
    devs = {d["ip"]: d for d in p.parse_nmap_devices(NMAP_SAMPLE)}
    assert devs["192.168.1.5"]["mac"] == ""


def test_parse_nmap_devices_empty():
    assert p.parse_nmap_devices("") == []


# ---------------------------------------------------------------------------
# parse_mangle_counters — iptables -L FORWARD -n -v -x
# ---------------------------------------------------------------------------

IPTABLES_SAMPLE = """Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target prot opt in     out     source          destination
   10  5000 ACCEPT all  --  eth0   *       192.168.1.5     0.0.0.0/0
   20  8000 ACCEPT all  --  *      eth0    0.0.0.0/0       192.168.1.5
   30  1500 ACCEPT all  --  eth0   *       192.168.1.9     0.0.0.0/0
    0     0 DROP   all  --  *      *       0.0.0.0/0       0.0.0.0/0
"""


def test_parse_mangle_counters_sums_up_and_down():
    counters = p.parse_mangle_counters(IPTABLES_SAMPLE)
    assert counters["192.168.1.5"] == 13000   # 5000 upload + 8000 download
    assert counters["192.168.1.9"] == 1500


def test_parse_mangle_counters_ignores_drop_and_header():
    counters = p.parse_mangle_counters(IPTABLES_SAMPLE)
    # The DROP catch-all (0.0.0.0/0 -> 0.0.0.0/0) and header rows contribute nothing.
    assert "0.0.0.0/0" not in counters


def test_parse_mangle_counters_empty():
    assert p.parse_mangle_counters("") == {}
