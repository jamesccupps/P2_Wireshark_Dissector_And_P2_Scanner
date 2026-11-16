"""`parse_ip_range` returns exactly the addresses its operator named.

Through 2.11.0 it honored only /24 and /16. Any other prefix scanned the /24
around its base address -- a /30 asking for two hosts touched 254, a /8 touched
one /24 -- and an entry like 192.0.2.300 was passed straight to the port scan.
Found by an outside review, 2026-11-15.

Documentation addresses only (RFC 5737, RFC 2544). Nothing here opens a socket.
"""
from __future__ import annotations

import pytest

import p2_scanner as ps


def _span(ips):
    return len(ips), ips[0], ips[-1]


def test_a_24_is_unchanged():
    assert _span(ps.parse_ip_range("192.0.2.0/24")) == (254, "192.0.2.1",
                                                        "192.0.2.254")


@pytest.mark.parametrize("cidr, expected", [
    ("192.0.2.0/30", (2, "192.0.2.1", "192.0.2.2")),
    ("192.0.2.128/25", (126, "192.0.2.129", "192.0.2.254")),
    ("192.0.2.64/26", (62, "192.0.2.65", "192.0.2.126")),
    ("192.0.2.4/31", (2, "192.0.2.4", "192.0.2.5")),
    ("192.0.2.9/32", (1, "192.0.2.9", "192.0.2.9")),
    ("192.0.2.77/28", (14, "192.0.2.65", "192.0.2.78")),   # host bits ignored
])
def test_a_prefix_other_than_24_scans_only_its_own_hosts(cidr, expected):
    assert _span(ps.parse_ip_range(cidr)) == expected


def test_a_16_is_every_host_in_the_16():
    assert _span(ps.parse_ip_range("198.18.0.0/16")) == (65534, "198.18.0.1",
                                                         "198.18.255.254")


@pytest.mark.parametrize("cidr", ["192.0.2.0/15", "192.0.2.0/8", "192.0.2.0/0"])
def test_wider_than_a_16_is_refused_not_narrowed(cidr):
    with pytest.raises(ValueError, match="/16"):
        ps.parse_ip_range(cidr)


def test_the_other_formats_are_unchanged():
    assert ps.parse_ip_range("192.0.2.50") == ["192.0.2.50"]
    assert _span(ps.parse_ip_range("192.0.2.10-20")) == (11, "192.0.2.10",
                                                         "192.0.2.20")
    assert _span(ps.parse_ip_range("192.0.2")) == (254, "192.0.2.1",
                                                   "192.0.2.254")
    both = ps.parse_ip_range("192.0.2.0/30, 198.51.100.7,")
    assert both == ["192.0.2.1", "192.0.2.2", "198.51.100.7"]


@pytest.mark.parametrize("bad", [
    "192.0.2.x/24", "192.0.2.1-", "192.0.2.20-10", "192.0.2.1-300",
    "192.0.2.300", "192.0.2.0/33", "192.0.2.1-192.0.2.9", "scan-everything",
])
def test_a_malformed_entry_is_refused_and_named(bad):
    with pytest.raises(ValueError) as exc:
        ps.parse_ip_range("192.0.2.5," + bad)
    assert repr(bad) in str(exc.value)
