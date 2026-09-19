"""Which ASCII TLV is the engineering unit, when more than one could be.

`eng_units` is a `TEXT_` field an engineer types into, so the scanner cannot
decide by looking at the string: a site can hold a unit that ships in no
catalog, and discarding those was a real defect (eleven real unit strings lost,
fixed earlier). The parser therefore accepts an unknown string.

That leaves the case where a body carries **both**. One real body in sixty
holds `DEG F` and then, further on, a lone `?`. Both pass the shape test;
taking the last one reported `?` and threw the unit away.

Bodies here are synthetic, in the structure real ones have -- name repeated
three times each followed by an empty TLV, description, then the units TLV --
with invented names.
"""
from __future__ import annotations

import struct

from p2_scanner import P2Connection, known_unit_strings

ROUTING = b"\x01" + b"BLN\x00" + b"NODE\x00" + b"BLN\x00" + b"SUP\x00"


def tlv(s: bytes = b"") -> bytes:
    return b"\x01\x00" + bytes([len(s)]) + s


def enum_body(*units: bytes, value: float = 72.5) -> bytes:
    name, descr = b"PT0001", b"TEST POINT01"
    return (b"\x00\x00"
            + tlv(name) + tlv() + tlv(name) + tlv() + tlv(name) + tlv()
            + tlv(descr) + tlv() + tlv()
            + b"\x3f\xff\xff\xff\x00\x00\x04" + struct.pack(">f", value)
            + b"".join(tlv(u) for u in units)
            + b"\x00" * 12)


def parse(*units: bytes):
    conn = P2Connection.__new__(P2Connection)
    return conn._parse_enum_points_response(ROUTING + enum_body(*units))


def test_a_catalog_unit_wins_over_a_later_placeholder():
    rec = parse(b"DEG F", b"?")
    assert rec is not None
    assert rec["units"] == "DEG F"
    assert rec["value"] == 72.5


def test_the_placeholder_is_still_reported_when_it_is_all_there_is():
    """Not a denylist. The scanner reports what the panel holds."""
    assert parse(b"?")["units"] == "?"


def test_an_unknown_string_is_kept_when_no_catalog_unit_is_present():
    """A site-configured unit ships in no catalog and must survive.

    This is the defect from the other direction: a filter tight enough to
    reject a placeholder also rejects a real unit nobody anticipated.
    """
    assert b"WIDGETS".decode() not in known_unit_strings()
    assert parse(b"WIDGETS")["units"] == "WIDGETS"


def test_the_last_catalog_unit_wins_when_several_are_present():
    assert parse(b"DEG F", b"PSI")["units"] == "PSI"
