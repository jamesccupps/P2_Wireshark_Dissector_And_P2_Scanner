"""A CHOICE's width is a function of its arm, so a fixed width cannot stand in.

`p2_asdu` carries a `WIDTHS` entry for two types that are also CHOICEs:
`which_trend_` (4) and `cov_limit_` (5). The walker consulted `WIDTHS` first,
so those two were read as opaque fixed-width blobs and never dispatched.

`cov_limit_`'s width is harmless -- both arms are four bytes after the tag.
`which_trend_`'s is right only when the nested `Trend_type` selects
`point_cov`, whose arm is `NULL_`. Select `trend_cov` or `time` and a
**declared** four-byte `FLOAT_` falls outside the walk -- which is how
`cov_limit` and `seconds_interval` came to be recorded in `PROTOCOL.md` 10.2.3
as an undeclared trailing resume key on the trend-delete request.

Measured over the cached corpus, letting the CHOICE win: exact decodes
3,933 -> 3,939 and errors 26 -> 20, with nothing else moving.
"""
from __future__ import annotations

import struct

import pytest

import p2_asdu
import p2_body


def which_trend(samples, trend_tag, payload=b""):
    """tag=specific | number_of_samples u16 | Trend_type tag | arm payload."""
    return (bytes([0x01]) + struct.pack(">H", samples)
            + bytes([trend_tag]) + payload)


def walk(body):
    return p2_body.decode(0, "req", body, struct_name="which_trend_")


def test_the_two_catalog_types_that_are_both_a_choice_and_have_a_width():
    """If this set grows, the walker's guard needs looking at again."""
    both = {n for n, f in p2_asdu.STRUCTS.items()
            if f and f[0][0] == "tag_" and p2_asdu.WIDTHS.get(n) is not None}
    assert both == {"which_trend_", "cov_limit_"}


def test_a_null_arm_stops_where_the_fixed_width_did():
    """`point_cov` is NULL_, so the field really is four bytes here.

    This is the case the fixed width was right for -- and the only one.
    """
    body = which_trend(100, 0x00)
    r = walk(body)
    assert r.error is None
    assert r.consumed == len(body) == 4
    tags = [f for f in r.fields if f.path.endswith("trend_type.tag_")]
    assert tags and tags[0].note == "point_cov"


@pytest.mark.parametrize("tag,arm,value", [
    (0x01, "trend_cov", 3.0),      # a COV delta
    (0x02, "time", 60.0),          # a sample interval in seconds
])
def test_an_arm_with_a_payload_is_no_longer_lost(tag, arm, value):
    """Four more bytes than the fixed width, and they are declared."""
    body = which_trend(200, tag, struct.pack(">f", value))
    r = walk(body)
    assert r.error is None
    assert r.consumed == len(body) == 8, "the arm payload fell outside the walk"

    tags = [f for f in r.fields if f.path.endswith("trend_type.tag_")]
    assert tags and tags[0].note == arm
    armf = [f for f in r.fields if f.path.endswith("trend_type." + arm)]
    assert armf, "the selected arm produced no field"
    assert struct.pack(">I", armf[0].value) == struct.pack(">f", value)


def test_the_arm_types_are_the_declared_float_carriers():
    """Named, not guessed: the catalog says what each arm holds."""
    assert p2_asdu.STRUCTS["trend_cov_"] == [["cov_limit", "FLOAT_"]]
    assert p2_asdu.STRUCTS["time_"] == [["seconds_interval", "FLOAT_"]]
    assert p2_asdu.CHOICE_TAGS["Trend_type"]["complete"] is True
    assert p2_asdu.CHOICE_TAGS["Trend_type"]["map"] == {
        0: "point_cov", 1: "trend_cov", 2: "time"}


def test_all_points_still_reaches_its_own_handler():
    """`All_points` begins with a tag too, and must NOT be dispatched here.

    Sending every tag-led structure to the generic CHOICE handler intercepts
    it and breaks every point body: 26 corpus decode errors became 446.
    """
    assert p2_asdu.STRUCTS["All_points"][0][0] == "tag_"
    assert p2_asdu.WIDTHS.get("All_points") is None
